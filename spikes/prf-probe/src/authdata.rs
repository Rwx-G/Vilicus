//! What the signed authenticator data says about a ceremony, read after webauthn-rs has verified
//! it. webauthn-rs keeps the AAGUID and the authenticator extension outputs of a passkey private,
//! so this module parses the same bytes again with webauthn-rs-core's public parser.
//!
//! The authenticator extension keys are the signed side of PRF when the browser maps `prf` to the
//! CTAP `hmac-secret` extension (`hmac-secret-mc` for an evaluation at registration): their
//! presence shows the authenticator itself took part, whatever the page reports. Their absence
//! proves nothing: a platform or password manager can implement PRF without a signed trace, and
//! Chromium's virtual authenticator returns PRF outputs with no authenticator extension at all.

use serde::Serialize;
use serde_cbor_2::Value;
use webauthn_rs_core::internals::AuthenticatorData;
use webauthn_rs_core::proto::{Authentication, Registration};

/// Fields of the signed authenticator data the probe records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignedFacts {
    /// The authenticator model identifier, all zeros when the authenticator withholds it.
    pub aaguid: Option<String>,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    /// Authenticator extension outputs present, as `key` or `key=value` for booleans.
    pub authenticator_extensions: Vec<String>,
}

/// Why the authenticator data could not be read.
#[derive(Debug, PartialEq, Eq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn extension_label(key: &str, value: &Value) -> String {
    match value {
        Value::Bool(b) => format!("{key}={b}"),
        _ => key.to_owned(),
    }
}

/// Reads a registration's attestation object (CBOR map with `authData`).
pub fn from_attestation_object(attestation_object: &[u8]) -> Result<SignedFacts, ParseError> {
    let value: Value = serde_cbor_2::from_slice(attestation_object)
        .map_err(|e| ParseError(format!("attestation object is not CBOR: {e}")))?;
    let Value::Map(map) = value else {
        return Err(ParseError("attestation object is not a map".into()));
    };
    let auth_data = map
        .iter()
        .find_map(|(k, v)| match (k, v) {
            (Value::Text(k), Value::Bytes(b)) if k == "authData" => Some(b.as_slice()),
            _ => None,
        })
        .ok_or_else(|| ParseError("attestation object has no authData".into()))?;
    let data = AuthenticatorData::<Registration>::try_from(auth_data)
        .map_err(|e| ParseError(format!("registration authData: {e:?}")))?;
    let mut extensions = Vec::new();
    if data.extensions.cred_protect.is_some() {
        extensions.push("credProtect".to_owned());
    }
    if let Some(hmac) = data.extensions.hmac_secret {
        extensions.push(format!("hmac-secret={hmac}"));
    }
    extensions.extend(
        data.extensions
            .unknown_keys
            .iter()
            .map(|(k, v)| extension_label(k, v)),
    );
    Ok(SignedFacts {
        aaguid: data.acd.as_ref().map(|acd| format_aaguid(&acd.aaguid)),
        user_verified: data.user_verified,
        backup_eligible: data.backup_eligible,
        backup_state: data.backup_state,
        authenticator_extensions: extensions,
    })
}

/// Reads an assertion's authenticator data. Assertions carry no AAGUID.
pub fn from_assertion(authenticator_data: &[u8]) -> Result<SignedFacts, ParseError> {
    let data = AuthenticatorData::<Authentication>::try_from(authenticator_data)
        .map_err(|e| ParseError(format!("assertion authData: {e:?}")))?;
    Ok(SignedFacts {
        aaguid: None,
        user_verified: data.user_verified,
        backup_eligible: data.backup_eligible,
        backup_state: data.backup_state,
        authenticator_extensions: data
            .extensions
            .unknown_keys
            .iter()
            .map(|(k, v)| extension_label(k, v))
            .collect(),
    })
}

fn format_aaguid(bytes: &[u8; 16]) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const FLAG_UP: u8 = 0x01;
    const FLAG_UV: u8 = 0x04;
    const FLAG_BE: u8 = 0x08;
    const FLAG_BS: u8 = 0x10;
    const FLAG_AT: u8 = 0x40;
    const FLAG_ED: u8 = 0x80;

    fn cbor(value: &Value) -> Vec<u8> {
        serde_cbor_2::to_vec(value).unwrap()
    }

    fn extensions(entries: Vec<(&str, Value)>) -> Vec<u8> {
        cbor(&Value::Map(
            entries
                .into_iter()
                .map(|(k, v)| (Value::Text(k.into()), v))
                .collect::<BTreeMap<_, _>>(),
        ))
    }

    /// A P-256 COSE key with fixed coordinates; the parser checks its shape, not the point.
    fn cose_key() -> Vec<u8> {
        let mut map = BTreeMap::new();
        map.insert(Value::Integer(1), Value::Integer(2));
        map.insert(Value::Integer(3), Value::Integer(-7));
        map.insert(Value::Integer(-1), Value::Integer(1));
        map.insert(Value::Integer(-2), Value::Bytes(vec![7; 32]));
        map.insert(Value::Integer(-3), Value::Bytes(vec![9; 32]));
        cbor(&Value::Map(map))
    }

    fn registration_auth_data(aaguid: [u8; 16], ext: &[u8], flags: u8) -> Vec<u8> {
        let mut out = vec![0x11; 32];
        out.push(flags | FLAG_AT | FLAG_ED);
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&aaguid);
        out.extend_from_slice(&16u16.to_be_bytes());
        out.extend_from_slice(&[0x22; 16]);
        out.extend_from_slice(&cose_key());
        out.extend_from_slice(ext);
        out
    }

    #[test]
    fn registration_facts_carry_aaguid_flags_and_prf_extensions() {
        let aaguid = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ];
        let ext = extensions(vec![
            ("hmac-secret", Value::Bool(true)),
            ("hmac-secret-mc", Value::Bytes(vec![0; 80])),
        ]);
        let auth_data = registration_auth_data(aaguid, &ext, FLAG_UP | FLAG_UV | FLAG_BE);
        let object = cbor(&Value::Map(BTreeMap::from([
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("attStmt".into()), Value::Map(BTreeMap::new())),
            (Value::Text("authData".into()), Value::Bytes(auth_data)),
        ])));
        let facts = from_attestation_object(&object).unwrap();
        assert_eq!(
            facts.aaguid.as_deref(),
            Some("01234567-89ab-cdef-0123-456789abcdef")
        );
        assert!(facts.user_verified);
        assert!(facts.backup_eligible);
        assert!(!facts.backup_state);
        assert_eq!(
            facts.authenticator_extensions,
            ["hmac-secret=true", "hmac-secret-mc"]
        );
    }

    #[test]
    fn assertion_facts_list_hmac_secret_output() {
        let mut auth_data = vec![0x11; 32];
        auth_data.push(FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_ED);
        auth_data.extend_from_slice(&5u32.to_be_bytes());
        auth_data.extend_from_slice(&extensions(vec![(
            "hmac-secret",
            Value::Bytes(vec![0; 80]),
        )]));
        let facts = from_assertion(&auth_data).unwrap();
        assert_eq!(facts.aaguid, None);
        assert!(facts.backup_state);
        assert_eq!(facts.authenticator_extensions, ["hmac-secret"]);
    }

    #[test]
    fn malformed_inputs_are_errors() {
        assert!(from_attestation_object(b"not cbor").is_err());
        assert!(from_attestation_object(&cbor(&Value::Integer(1))).is_err());
        assert!(from_assertion(&[0; 10]).is_err());
    }
}
