//! The step-up challenge: derived from the hash of exactly one pending request and a public
//! handle of the session that created it (AD-8 rule 3, D71), then placed into a `webauthn-rs`
//! authentication state.
//!
//! `webauthn-rs` 0.5.5 draws every challenge from its own CSPRNG and offers no way to supply
//! one: `ChallengeAuthenticateBuilder` has no challenge field and the state's fields are
//! `pub(crate)`. With the `danger-allow-state-serialisation` feature the state serializes, so
//! [`bind_challenge`] rewrites the challenge in the serialized state and in the options sent to
//! the browser. The state never leaves the server; the feature's danger (state held by the
//! client) does not apply. [`bind_challenge`] fails closed: it refuses unless the state
//! round-trips through its serialization unchanged, and unless the rewritten state differs from
//! the original at the challenge only.

use aws_lc_rs::digest;
use serde_json::Value;
use webauthn_rs::prelude::{Base64UrlSafeData, PasskeyAuthentication, RequestChallengeResponse};

/// Length of a session identifier, chosen by the server with its CSPRNG. It is the bearer
/// secret carried by the session cookie.
pub const SESSION_ID_LEN: usize = 16;
/// Domain label of the session handle.
pub const SESSION_HANDLE_LABEL: &[u8] = b"vilicus/v1/session-handle";
/// Domain label of the challenge derivation. Every field after it has a fixed length, so the
/// concatenation is unambiguous.
pub const STEP_UP_LABEL: &[u8] = b"vilicus/v1/step-up";
/// Where `webauthn-rs` 0.5.5 keeps the challenge in a serialized `PasskeyAuthentication`.
const STATE_CHALLENGE_POINTER: &str = "/ast/challenge";

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut context = digest::Context::new(&digest::SHA256);
    for part in parts {
        context.update(part);
    }
    let mut output = [0u8; 32];
    output.copy_from_slice(context.finish().as_ref());
    output
}

/// A non-secret handle of a session: SHA-256 of a label and the session identifier. It can sit
/// in a challenge, a log or an audit record without disclosing the bearer secret.
pub fn session_handle(session_id: &[u8; SESSION_ID_LEN]) -> [u8; 32] {
    sha256(&[SESSION_HANDLE_LABEL, session_id])
}

/// The WebAuthn challenge of a step-up: SHA-256 over the label, the session handle and the
/// request hash. The request hash covers the server-chosen request identifier, so the challenge
/// is unpredictable and never repeats across requests.
pub fn derive_challenge(session_handle: &[u8; 32], request_hash: &[u8; 32]) -> [u8; 32] {
    sha256(&[STEP_UP_LABEL, session_handle, request_hash])
}

/// Why the derived challenge could not be put into the `webauthn-rs` state.
#[derive(Debug)]
pub enum BindError {
    /// The serialized state is not what 0.5.5 produces: the library changed.
    StateShapeChanged,
    Serde(serde_json::Error),
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StateShapeChanged => write!(
                f,
                "the serialized authentication state is not the 0.5.5 shape with a challenge at {STATE_CHALLENGE_POINTER}"
            ),
            Self::Serde(error) => write!(f, "state serialization: {error}"),
        }
    }
}

impl std::error::Error for BindError {}

fn encoded_challenge(challenge: &[u8; 32]) -> Result<Value, BindError> {
    serde_json::to_value(Base64UrlSafeData::from(challenge.to_vec())).map_err(BindError::Serde)
}

/// Replaces the challenge string of a serialized state, refusing a state with no string there.
fn rewrite_challenge(mut serialized: Value, challenge: &[u8; 32]) -> Result<Value, BindError> {
    let slot = serialized
        .pointer_mut(STATE_CHALLENGE_POINTER)
        .ok_or(BindError::StateShapeChanged)?;
    if !slot.is_string() {
        return Err(BindError::StateShapeChanged);
    }
    *slot = encoded_challenge(challenge)?;
    Ok(serialized)
}

/// Replaces the random challenge `webauthn-rs` chose with `challenge`, in the options for the
/// browser and in the server-side state that verifies the assertion.
pub fn bind_challenge(
    options: &mut RequestChallengeResponse,
    state: &PasskeyAuthentication,
    challenge: &[u8; 32],
) -> Result<PasskeyAuthentication, BindError> {
    let original = serde_json::to_value(state).map_err(BindError::Serde)?;
    // Every field must survive serialization, or rewriting one would silently drop another.
    let reparsed: PasskeyAuthentication =
        serde_json::from_value(original.clone()).map_err(BindError::Serde)?;
    if serde_json::to_value(&reparsed).map_err(BindError::Serde)? != original {
        return Err(BindError::StateShapeChanged);
    }
    let rewritten = rewrite_challenge(original, challenge)?;
    let bound: PasskeyAuthentication =
        serde_json::from_value(rewritten.clone()).map_err(BindError::Serde)?;
    if serde_json::to_value(&bound).map_err(BindError::Serde)? != rewritten {
        return Err(BindError::StateShapeChanged);
    }
    options.public_key.challenge = Base64UrlSafeData::from(challenge.to_vec());
    Ok(bound)
}

/// The challenge an authentication state will verify against, read back from its serialization.
pub fn state_challenge(state: &PasskeyAuthentication) -> Result<Vec<u8>, BindError> {
    let serialized = serde_json::to_value(state).map_err(BindError::Serde)?;
    let slot = serialized
        .pointer(STATE_CHALLENGE_POINTER)
        .ok_or(BindError::StateShapeChanged)?;
    let decoded: Base64UrlSafeData =
        serde_json::from_value(Value::clone(slot)).map_err(BindError::Serde)?;
    Ok(decoded.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use webauthn_rs::prelude::{Url, WebauthnBuilder};

    #[test]
    fn handle_hides_the_session_identifier_and_is_stable() {
        let session = [5u8; SESSION_ID_LEN];
        assert_eq!(
            session_handle(&session).as_slice(),
            digest::digest(&digest::SHA256, &[SESSION_HANDLE_LABEL, &session].concat()).as_ref()
        );
        assert_ne!(
            session_handle(&session),
            session_handle(&[6u8; SESSION_ID_LEN])
        );
    }

    #[test]
    fn challenge_depends_on_session_and_request() {
        let base = derive_challenge(&[1; 32], &[2; 32]);
        assert_ne!(base, derive_challenge(&[3; 32], &[2; 32]));
        assert_ne!(base, derive_challenge(&[1; 32], &[4; 32]));
        assert_eq!(base, derive_challenge(&[1; 32], &[2; 32]));
    }

    #[test]
    fn challenge_is_sha256_of_label_handle_and_hash() {
        let handle = [7u8; 32];
        let hash = [9u8; 32];
        let expected = digest::digest(&digest::SHA256, &[STEP_UP_LABEL, &handle, &hash].concat());
        assert_eq!(
            derive_challenge(&handle, &hash).as_slice(),
            expected.as_ref()
        );
    }

    #[test]
    fn rewrite_refuses_a_missing_or_non_string_challenge() {
        let missing = json!({ "ast": { "credentials": [] } });
        assert!(matches!(
            rewrite_challenge(missing, &[0; 32]),
            Err(BindError::StateShapeChanged)
        ));
        let not_a_string = json!({ "ast": { "challenge": [1, 2, 3] } });
        assert!(matches!(
            rewrite_challenge(not_a_string, &[0; 32]),
            Err(BindError::StateShapeChanged)
        ));
    }

    /// A real 0.5.5 authentication state, with no credential (a discoverable request).
    fn real_state() -> (RequestChallengeResponse, PasskeyAuthentication) {
        let origin = Url::parse("https://rp.vilicus.test:8443").unwrap();
        WebauthnBuilder::new("rp.vilicus.test", &origin)
            .unwrap()
            .build()
            .unwrap()
            .start_passkey_authentication(&[])
            .unwrap()
    }

    #[test]
    fn bound_state_differs_from_the_original_at_the_challenge_only() {
        let (mut options, state) = real_state();
        let challenge = [0x42u8; 32];
        let bound = bind_challenge(&mut options, &state, &challenge).unwrap();
        assert_eq!(state_challenge(&bound).unwrap(), challenge.to_vec());
        let mut original = serde_json::to_value(&state).unwrap();
        let bound = serde_json::to_value(&bound).unwrap();
        assert_ne!(original, bound);
        *original.pointer_mut(STATE_CHALLENGE_POINTER).unwrap() =
            encoded_challenge(&challenge).unwrap();
        assert_eq!(original, bound);
        assert_eq!(
            serde_json::to_value(&options.public_key.challenge).unwrap(),
            encoded_challenge(&challenge).unwrap()
        );
    }
}
