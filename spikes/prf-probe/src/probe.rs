//! What the page reports about PRF, what the server records, and the per-credential verdict.
//!
//! The page sends the SHA-256 of each PRF output and its length, never the output. The server
//! accepts only digest-shaped values, which refuses an output sent as base64url, but it cannot
//! tell a 32-byte output written as 64 hex characters from a digest. What keeps the output off
//! the wire is the page code, which the end-to-end check verifies against the raw outputs it
//! captures in the browser.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::authdata::SignedFacts;

/// The page's report about one ceremony. Deserialized from the client: unknown fields refused.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeReport {
    /// Whether `getClientExtensionResults()` had a `prf` member at all.
    pub prf_extension_output: bool,
    /// `prf.enabled`, only defined at registration.
    pub prf_enabled: Option<bool>,
    /// SHA-256 (lowercase hex) of `prf.results.first`, when present.
    pub first_sha256: Option<String>,
    /// Byte length of `prf.results.first`, when present.
    pub first_len: Option<u32>,
    /// SHA-256 (lowercase hex) of `prf.results.second`, when present.
    pub second_sha256: Option<String>,
    /// Byte length of `prf.results.second`, when present.
    pub second_len: Option<u32>,
    /// `getTransports()` at registration, empty at login.
    pub transports: Vec<String>,
    pub user_agent: String,
    /// Member names of the client extension results, values left out.
    pub client_extension_keys: Vec<String>,
}

const MAX_USER_AGENT: usize = 512;
const MAX_SHORT_FIELD: usize = 32;
const MAX_LIST: usize = 16;
/// Longest label a person can give a device and browser pair.
pub const MAX_LABEL: usize = 40;

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_short_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SHORT_FIELD
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A device label: letters, digits, space, dot, dash, underscore. No free text, so a label cannot
/// smuggle anything the record should not hold.
pub fn validate_label(label: &str) -> Result<(), String> {
    let ok = !label.trim().is_empty()
        && label.len() <= MAX_LABEL
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'.' | b'-' | b'_'));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "label must be 1 to {MAX_LABEL} characters among letters, digits, space, '.', '-', '_'"
        ))
    }
}

impl ProbeReport {
    /// Refuses anything that is not a digest where a digest is expected, and oversized fields.
    pub fn validate(&self) -> Result<(), String> {
        for (name, hash, len) in [
            ("first", &self.first_sha256, self.first_len),
            ("second", &self.second_sha256, self.second_len),
        ] {
            match (hash, len) {
                (Some(h), Some(l)) if is_sha256_hex(h) && l <= 64 => {}
                (None, None) => {}
                _ => {
                    return Err(format!(
                        "{name}: expected a lowercase SHA-256 hex digest and its length"
                    ));
                }
            }
        }
        if self.second_sha256.is_some() && self.first_sha256.is_none() {
            return Err("second output without first".into());
        }
        if self.user_agent.len() > MAX_USER_AGENT {
            return Err("user agent too long".into());
        }
        for list in [&self.transports, &self.client_extension_keys] {
            if list.len() > MAX_LIST || !list.iter().all(|v| is_short_token(v)) {
                return Err("transports or extension keys malformed".into());
            }
        }
        Ok(())
    }
}

/// Ceremony a record comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Registration,
    Login,
}

/// One line of `results.jsonl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub unix_time: u64,
    pub phase: Phase,
    pub label: String,
    /// First 16 hex characters of SHA-256 of the credential ID.
    pub credential: String,
    pub aaguid: Option<String>,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub authenticator_extensions: Vec<String>,
    pub prf_extension_output: bool,
    pub prf_enabled: Option<bool>,
    pub first_sha256: Option<String>,
    pub first_len: Option<u32>,
    pub second_sha256: Option<String>,
    pub second_len: Option<u32>,
    pub transports: Vec<String>,
    pub user_agent: String,
    pub client_extension_keys: Vec<String>,
}

impl Record {
    /// Combines the verified ceremony facts with the page's report.
    pub fn new(
        unix_time: u64,
        phase: Phase,
        label: &str,
        credential: &str,
        aaguid: Option<String>,
        facts: SignedFacts,
        probe: ProbeReport,
    ) -> Self {
        Self {
            unix_time,
            phase,
            label: label.to_owned(),
            credential: credential.to_owned(),
            aaguid: facts.aaguid.or(aaguid),
            user_verified: facts.user_verified,
            backup_eligible: facts.backup_eligible,
            backup_state: facts.backup_state,
            authenticator_extensions: facts.authenticator_extensions,
            prf_extension_output: probe.prf_extension_output,
            prf_enabled: probe.prf_enabled,
            first_sha256: probe.first_sha256,
            first_len: probe.first_len,
            second_sha256: probe.second_sha256,
            second_len: probe.second_len,
            transports: probe.transports,
            user_agent: probe.user_agent,
            client_extension_keys: probe.client_extension_keys,
        }
    }

    fn has_outputs(&self) -> bool {
        self.first_sha256.is_some()
    }
}

/// The outcome for one credential, from every record about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// Two or more logins, each with both outputs, equal per salt, 32 bytes, distinct salts.
    Stable,
    /// Some login or the registration gave a different output for the same salt.
    Unstable,
    /// Some logins returned outputs and others did not.
    Intermittent,
    /// An output was not 32 bytes long.
    WrongLength,
    /// Both salts gave the same output.
    SaltsCollide,
    /// No login returned an output.
    NoPrf,
    /// Fewer than two logins so far.
    NeedsMoreLogins,
}

/// Logins needed before a credential can be called stable.
pub const MIN_LOGINS: usize = 2;

/// The per-credential table row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub label: String,
    pub credential: String,
    pub aaguid: Option<String>,
    pub transports: Vec<String>,
    pub backup_eligible: bool,
    /// `prf.enabled` at registration.
    pub prf_enabled: Option<bool>,
    /// Whether the registration already returned outputs (evaluation at creation).
    pub outputs_at_registration: bool,
    pub logins: usize,
    pub logins_with_outputs: usize,
    pub verdict: Verdict,
}

fn distinct<'a>(values: impl Iterator<Item = &'a Option<String>>) -> usize {
    values.flatten().collect::<BTreeSet<_>>().len()
}

/// The verdict for one credential's records (registration first when present).
pub fn verdict(records: &[&Record]) -> Verdict {
    let logins: Vec<&&Record> = records.iter().filter(|r| r.phase == Phase::Login).collect();
    let with_outputs: Vec<&&Record> = records.iter().filter(|r| r.has_outputs()).collect();
    if distinct(with_outputs.iter().map(|r| &r.first_sha256)) > 1
        || distinct(with_outputs.iter().map(|r| &r.second_sha256)) > 1
    {
        return Verdict::Unstable;
    }
    let logins_with_outputs = logins.iter().filter(|r| r.has_outputs()).count();
    if logins_with_outputs == 0 {
        return if logins.is_empty() {
            Verdict::NeedsMoreLogins
        } else {
            Verdict::NoPrf
        };
    }
    if logins_with_outputs < logins.len() || logins.iter().any(|r| r.second_sha256.is_none()) {
        return Verdict::Intermittent;
    }
    if with_outputs
        .iter()
        .any(|r| r.first_len != Some(32) || r.second_len.is_some_and(|l| l != 32))
    {
        return Verdict::WrongLength;
    }
    if with_outputs
        .iter()
        .any(|r| r.second_sha256.is_some() && r.first_sha256 == r.second_sha256)
    {
        return Verdict::SaltsCollide;
    }
    if logins.len() < MIN_LOGINS {
        return Verdict::NeedsMoreLogins;
    }
    Verdict::Stable
}

/// One row per credential, in order of first appearance.
pub fn summarize(records: &[Record]) -> Vec<Summary> {
    let mut order: Vec<&str> = Vec::new();
    for r in records {
        if !order.contains(&r.credential.as_str()) {
            order.push(&r.credential);
        }
    }
    order
        .into_iter()
        .map(|credential| {
            let own: Vec<&Record> = records
                .iter()
                .filter(|r| r.credential == credential)
                .collect();
            let registration = own.iter().find(|r| r.phase == Phase::Registration);
            let first = own[0];
            let logins: Vec<&&Record> = own.iter().filter(|r| r.phase == Phase::Login).collect();
            Summary {
                label: first.label.clone(),
                credential: credential.to_owned(),
                aaguid: own.iter().find_map(|r| r.aaguid.clone()),
                transports: registration
                    .map(|r| r.transports.clone())
                    .unwrap_or_default(),
                backup_eligible: first.backup_eligible,
                prf_enabled: registration.and_then(|r| r.prf_enabled),
                outputs_at_registration: registration.is_some_and(|r| r.has_outputs()),
                logins: logins.len(),
                logins_with_outputs: logins.iter().filter(|r| r.has_outputs()).count(),
                verdict: verdict(&own),
            }
        })
        .collect()
}

/// The table as Markdown, ready to paste into the result record. Holds no user agent: the
/// label is the only device identifier, and the person chooses it.
pub fn render(summaries: &[Summary]) -> String {
    let mut out = String::from(
        "| Label | Credential | AAGUID | Transports | Backup eligible | prf.enabled | Outputs at registration | Logins (with outputs) | Verdict |\n|---|---|---|---|---|---|---|---|---|\n",
    );
    for s in summaries {
        let verdict = serde_json::to_value(s.verdict)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} ({}) | {} |\n",
            s.label,
            s.credential,
            s.aaguid.as_deref().unwrap_or("-"),
            if s.transports.is_empty() {
                "-".to_owned()
            } else {
                s.transports.join(",")
            },
            s.backup_eligible,
            s.prf_enabled.map_or("-".to_owned(), |b| b.to_string()),
            s.outputs_at_registration,
            s.logins,
            s.logins_with_outputs,
            verdict,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn report(first: Option<&str>, second: Option<&str>) -> ProbeReport {
        ProbeReport {
            prf_extension_output: true,
            prf_enabled: None,
            first_sha256: first.map(str::to_owned),
            first_len: first.map(|_| 32),
            second_sha256: second.map(str::to_owned),
            second_len: second.map(|_| 32),
            transports: vec!["internal".into(), "hybrid".into()],
            user_agent: "Mozilla/5.0".into(),
            client_extension_keys: vec!["prf".into()],
        }
    }

    fn record(phase: Phase, first: Option<&str>, second: Option<&str>) -> Record {
        let facts = SignedFacts {
            aaguid: None,
            user_verified: true,
            backup_eligible: true,
            backup_state: true,
            authenticator_extensions: Vec::new(),
        };
        Record::new(
            0,
            phase,
            "device-1",
            "0011223344556677",
            None,
            facts,
            report(first, second),
        )
    }

    fn verdict_of(records: &[Record]) -> Verdict {
        verdict(&records.iter().collect::<Vec<_>>())
    }

    #[test]
    fn digests_are_accepted_and_anything_else_refused() {
        assert_eq!(report(Some(A), Some(B)).validate(), Ok(()));
        assert_eq!(report(None, None).validate(), Ok(()));
        // A 32-byte output in base64url or uppercase hex is not a digest-shaped value.
        for bad in [
            "q83vEjRWeJC6ze8SNFZ4kLrN7xI0VniQus3vEjRWeJA",
            &A.to_uppercase(),
            &A[..63],
            &format!("{A}0"),
        ] {
            assert!(report(Some(bad), None).validate().is_err(), "{bad}");
        }
        let mut no_len = report(Some(A), None);
        no_len.first_len = None;
        assert!(no_len.validate().is_err());
        assert!(report(None, Some(B)).validate().is_err());
        let mut long_ua = report(None, None);
        long_ua.user_agent = "x".repeat(MAX_USER_AGENT + 1);
        assert!(long_ua.validate().is_err());
        let mut bad_transport = report(None, None);
        bad_transport.transports = vec!["usb; drop".into()];
        assert!(bad_transport.validate().is_err());
    }

    #[test]
    fn unknown_fields_are_refused() {
        let json = r#"{"prf_extension_output":true,"prf_enabled":null,"first_sha256":null,
            "first_len":null,"second_sha256":null,"second_len":null,"transports":[],
            "user_agent":"","client_extension_keys":[],"first":"AAAA"}"#;
        assert!(serde_json::from_str::<ProbeReport>(json).is_err());
    }

    #[test]
    fn labels_are_restricted() {
        assert!(validate_label("device-1 chrome").is_ok());
        for bad in [
            "",
            "   ",
            "a/b",
            "name@example.com",
            &"x".repeat(MAX_LABEL + 1),
        ] {
            assert!(validate_label(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn verdicts() {
        use Phase::{Login, Registration};
        let reg = record(Registration, Some(A), Some(B));
        let reg_no_eval = record(Registration, None, None);
        let ok = record(Login, Some(A), Some(B));
        assert_eq!(
            verdict_of(&[reg.clone(), ok.clone(), ok.clone()]),
            Verdict::Stable
        );
        assert_eq!(
            verdict_of(&[reg_no_eval.clone(), ok.clone(), ok.clone()]),
            Verdict::Stable
        );
        assert_eq!(
            verdict_of(&[reg.clone(), ok.clone()]),
            Verdict::NeedsMoreLogins
        );
        assert_eq!(
            verdict_of(std::slice::from_ref(&reg)),
            Verdict::NeedsMoreLogins
        );
        assert_eq!(
            verdict_of(&[reg.clone(), ok.clone(), record(Login, Some(C), Some(B))]),
            Verdict::Unstable
        );
        assert_eq!(
            verdict_of(&[
                record(Registration, Some(C), Some(B)),
                ok.clone(),
                ok.clone()
            ]),
            Verdict::Unstable
        );
        assert_eq!(
            verdict_of(&[reg_no_eval.clone(), ok.clone(), record(Login, None, None)]),
            Verdict::Intermittent
        );
        assert_eq!(
            verdict_of(&[reg_no_eval.clone(), record(Login, None, None)]),
            Verdict::NoPrf
        );
        assert_eq!(
            verdict_of(&[
                reg_no_eval.clone(),
                record(Login, Some(A), Some(A)),
                record(Login, Some(A), Some(A))
            ]),
            Verdict::SaltsCollide
        );
        let mut short = ok.clone();
        short.first_len = Some(16);
        assert_eq!(
            verdict_of(&[reg_no_eval, short.clone(), short]),
            Verdict::WrongLength
        );
    }

    #[test]
    fn summary_and_table() {
        let mut other = record(Phase::Registration, None, None);
        other.credential = "8899aabbccddeeff".into();
        let records = vec![
            record(Phase::Registration, Some(A), Some(B)),
            other,
            record(Phase::Login, Some(A), Some(B)),
            record(Phase::Login, Some(A), Some(B)),
        ];
        let summaries = summarize(&records);
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].logins, 2);
        assert!(summaries[0].outputs_at_registration);
        assert_eq!(summaries[0].verdict, Verdict::Stable);
        assert_eq!(summaries[1].verdict, Verdict::NeedsMoreLogins);
        let table = render(&summaries);
        assert!(table.contains("| 2 (2) | stable |"), "{table}");
        assert!(table.contains("needs-more-logins"), "{table}");
        assert!(
            !table.contains("Mozilla"),
            "the table must not carry the user agent"
        );
    }
}
