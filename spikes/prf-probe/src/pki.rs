//! The local CA and the server certificate the probe serves. The CA is name-constrained to the
//! probe's host name and its private key is never written anywhere: once the server certificate is
//! signed, the CA can sign nothing else, so installing it on a phone trusts this one host only.

use std::fs;
use std::io;
use std::path::Path;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, GeneralSubtree, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, NameConstraints,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::{Duration, OffsetDateTime};

/// CA certificate (PEM), installed on each device; Android takes a `.crt` file.
pub const CA_FILE: &str = "ca.crt";
/// Server certificate (PEM), signed by the CA.
pub const CERT_FILE: &str = "server.crt";
/// Server private key.
pub const KEY_FILE: &str = "server.key";
/// The host name the certificates were generated for.
pub const HOST_FILE: &str = "host.txt";

/// Leaf validity. Some platforms refuse TLS leaves valid for more than 825 days even under a
/// user-installed CA; a year is enough for a spike.
const LEAF_VALIDITY_DAYS: i64 = 365;

/// A CA certificate and a server certificate and key it signed.
pub struct ProbePki {
    pub host: String,
    pub ca_pem: String,
    pub cert_pem: String,
    pub key_pem: String,
}

/// Errors while generating or loading the certificates.
#[derive(Debug)]
pub enum PkiError {
    Generate(rcgen::Error),
    Io(io::Error),
    Pem(String),
    HostMismatch { existing: String, requested: String },
}

impl std::fmt::Display for PkiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PkiError::Generate(e) => write!(f, "certificate generation failed: {e}"),
            PkiError::Io(e) => write!(f, "certificate file error: {e}"),
            PkiError::Pem(e) => write!(f, "certificate parse error: {e}"),
            PkiError::HostMismatch {
                existing,
                requested,
            } => write!(
                f,
                "the certificates in this data directory are for {existing}, not {requested};                  use another data directory (devices trust the CA they installed)"
            ),
        }
    }
}

impl std::error::Error for PkiError {}

impl From<rcgen::Error> for PkiError {
    fn from(e: rcgen::Error) -> Self {
        PkiError::Generate(e)
    }
}

impl From<io::Error> for PkiError {
    fn from(e: io::Error) -> Self {
        PkiError::Io(e)
    }
}

impl ProbePki {
    /// Generates a CA constrained to `host` and a server certificate for `host`.
    pub fn generate(host: &str) -> Result<Self, PkiError> {
        let now = OffsetDateTime::now_utc();
        let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Vilicus PRF probe local CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_params.name_constraints = Some(NameConstraints {
            permitted_subtrees: vec![GeneralSubtree::DnsName(host.to_owned())],
            excluded_subtrees: Vec::new(),
        });
        ca_params.not_before = now - Duration::days(1);
        ca_params.not_after = now + Duration::days(LEAF_VALIDITY_DAYS + 1);
        let ca_key = KeyPair::generate()?;
        let ca_cert = ca_params.self_signed(&ca_key)?;
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        let mut server_params = CertificateParams::new(vec![host.to_owned()])?;
        server_params
            .distinguished_name
            .push(DnType::CommonName, host);
        server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        server_params.not_before = now - Duration::days(1);
        server_params.not_after = now + Duration::days(LEAF_VALIDITY_DAYS);
        let server_key = KeyPair::generate()?;
        let server_cert = server_params.signed_by(&server_key, &issuer)?;

        Ok(Self {
            host: host.to_owned(),
            ca_pem: ca_cert.pem(),
            cert_pem: server_cert.pem(),
            key_pem: server_key.serialize_pem(),
        })
    }

    /// Writes the certificates, the key and the host name into `dir`.
    pub fn write_to(&self, dir: &Path) -> io::Result<()> {
        fs::create_dir_all(dir)?;
        fs::write(dir.join(HOST_FILE), &self.host)?;
        fs::write(dir.join(CA_FILE), &self.ca_pem)?;
        fs::write(dir.join(CERT_FILE), &self.cert_pem)?;
        fs::write(dir.join(KEY_FILE), &self.key_pem)
    }
}

/// Generates the certificates for `host` in `dir` when the CA is missing, and refuses a
/// directory generated for another host. Returns whether they were generated.
pub fn ensure(dir: &Path, host: &str) -> Result<bool, PkiError> {
    if dir.join(CA_FILE).exists() {
        let existing = fs::read_to_string(dir.join(HOST_FILE))?;
        if existing != host {
            return Err(PkiError::HostMismatch {
                existing,
                requested: host.to_owned(),
            });
        }
        return Ok(false);
    }
    ProbePki::generate(host)?.write_to(dir)?;
    Ok(true)
}

/// The server chain (leaf only) and key from `dir`, in the form rustls takes.
pub fn load_server(
    dir: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), PkiError> {
    use rustls::pki_types::pem::PemObject;
    let chain = CertificateDer::pem_file_iter(dir.join(CERT_FILE))
        .map_err(|e| PkiError::Pem(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| PkiError::Pem(e.to_string()))?;
    let key = PrivatePkcs8KeyDer::from_pem_file(dir.join(KEY_FILE))
        .map_err(|e| PkiError::Pem(e.to_string()))?;
    Ok((chain, PrivateKeyDer::Pkcs8(key)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("prf-probe-pki-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn ensure_generates_once_and_keeps_existing_files() {
        let dir = scratch("once");
        assert!(ensure(&dir, "prf-probe.test").unwrap());
        let first = fs::read_to_string(dir.join(CA_FILE)).unwrap();
        assert!(!ensure(&dir, "prf-probe.test").unwrap());
        assert_eq!(first, fs::read_to_string(dir.join(CA_FILE)).unwrap());
        let (chain, _key) = load_server(&dir).unwrap();
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn a_directory_for_another_host_is_refused() {
        let dir = scratch("host");
        ensure(&dir, "prf-probe.test").unwrap();
        let refused = ensure(&dir, "other.test");
        assert!(matches!(refused, Err(PkiError::HostMismatch { .. })));
    }

    #[test]
    fn no_ca_private_key_is_written() {
        let dir = scratch("nokey");
        ensure(&dir, "prf-probe.test").unwrap();
        let mut names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        let mut expected = [CA_FILE, CERT_FILE, HOST_FILE, KEY_FILE];
        expected.sort_unstable();
        assert_eq!(names, expected);
    }
}
