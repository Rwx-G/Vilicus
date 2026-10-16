//! The probe's data directory: registered passkeys (public keys only) and the result records.
//! Both survive a server restart, so a login days after the registration is a later session.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use webauthn_rs::prelude::Passkey;

use crate::probe::Record;

const REGISTRATIONS_FILE: &str = "registrations.json";
const RESULTS_FILE: &str = "results.jsonl";

/// A registered credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub label: String,
    pub aaguid: Option<String>,
    pub passkey: Passkey,
}

/// The on-disk state.
pub struct Store {
    dir: PathBuf,
    credentials: BTreeMap<String, StoredCredential>,
}

/// The short identifier of a credential: the first 16 hex characters of SHA-256 of its ID.
pub fn credential_key(credential_id: &[u8]) -> String {
    Sha256::digest(credential_id)
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl Store {
    /// Opens `dir`, loading the registrations written by an earlier run.
    pub fn open(dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let path = dir.join(REGISTRATIONS_FILE);
        let credentials = if path.exists() {
            serde_json::from_slice(&fs::read(&path)?).map_err(io::Error::other)?
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            dir: dir.to_owned(),
            credentials,
        })
    }

    /// Registered credentials by key.
    pub fn credentials(&self) -> &BTreeMap<String, StoredCredential> {
        &self.credentials
    }

    /// Adds a credential and rewrites the registration file atomically.
    pub fn add_credential(&mut self, key: &str, credential: StoredCredential) -> io::Result<()> {
        self.credentials.insert(key.to_owned(), credential);
        self.save_credentials()
    }

    /// Replaces a credential's passkey (sign counter, backup state) after a login.
    pub fn update_passkey(&mut self, key: &str, passkey: Passkey) -> io::Result<()> {
        if let Some(stored) = self.credentials.get_mut(key) {
            stored.passkey = passkey;
        }
        self.save_credentials()
    }

    fn save_credentials(&self) -> io::Result<()> {
        let tmp = self.dir.join(format!("{REGISTRATIONS_FILE}.tmp"));
        let json = serde_json::to_vec_pretty(&self.credentials).map_err(io::Error::other)?;
        fs::write(&tmp, json)?;
        fs::rename(&tmp, self.dir.join(REGISTRATIONS_FILE))
    }

    /// Appends one record to the result file.
    pub fn append(&self, record: &Record) -> io::Result<()> {
        let mut line = serde_json::to_string(record).map_err(io::Error::other)?;
        line.push('\n');
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join(RESULTS_FILE))?
            .write_all(line.as_bytes())
    }

    /// Every record so far, in file order.
    pub fn records(&self) -> io::Result<Vec<Record>> {
        read_records(&self.dir)
    }
}

/// Reads `results.jsonl` from `dir` (empty when absent).
pub fn read_records(dir: &Path) -> io::Result<Vec<Record>> {
    let path = dir.join(RESULTS_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    BufReader::new(fs::File::open(path)?)
        .lines()
        .filter(|line| !matches!(line, Ok(l) if l.trim().is_empty()))
        .map(|line| serde_json::from_str(&line?).map_err(io::Error::other))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authdata::SignedFacts;
    use crate::probe::{Phase, ProbeReport};

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("prf-probe-store-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn record(n: u64) -> Record {
        let facts = SignedFacts {
            aaguid: Some("00000000-0000-0000-0000-000000000000".into()),
            user_verified: true,
            backup_eligible: false,
            backup_state: false,
            authenticator_extensions: vec!["hmac-secret".into()],
        };
        let probe = ProbeReport {
            prf_extension_output: false,
            prf_enabled: None,
            first_sha256: None,
            first_len: None,
            second_sha256: None,
            second_len: None,
            transports: Vec::new(),
            user_agent: String::new(),
            client_extension_keys: Vec::new(),
        };
        Record::new(
            n,
            Phase::Login,
            "device-1",
            "0011223344556677",
            None,
            facts,
            probe,
        )
    }

    #[test]
    fn records_survive_reopening_in_order() {
        let dir = scratch("records");
        let store = Store::open(&dir).unwrap();
        assert!(store.records().unwrap().is_empty());
        store.append(&record(1)).unwrap();
        store.append(&record(2)).unwrap();
        let reopened = Store::open(&dir).unwrap();
        let times: Vec<u64> = reopened
            .records()
            .unwrap()
            .iter()
            .map(|r| r.unix_time)
            .collect();
        assert_eq!(times, [1, 2]);
        assert!(reopened.credentials().is_empty());
    }

    #[test]
    fn credential_key_is_sixteen_hex_characters_and_input_dependent() {
        let a = credential_key(b"credential-a");
        assert_eq!(a.len(), 16);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(a, credential_key(b"credential-b"));
    }
}
