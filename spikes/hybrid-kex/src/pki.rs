//! A throwaway test CA and the server certificate it signs. Nothing here is a production PKI: the
//! keys live in memory or in the run's scratch volume and die with it.

use std::fs;
use std::io;
use std::path::Path;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// File names written by [`TestPki::write_to`] and read by the server and the clients.
pub const CA_FILE: &str = "ca.pem";
pub const CERT_FILE: &str = "server.pem";
pub const KEY_FILE: &str = "server.key";

/// A test CA certificate and a server certificate and key signed by it.
pub struct TestPki {
    pub ca_pem: String,
    pub ca_der: CertificateDer<'static>,
    pub cert_pem: String,
    pub cert_der: CertificateDer<'static>,
    pub key_pem: String,
    pub key_der: PrivatePkcs8KeyDer<'static>,
}

impl TestPki {
    /// Generates a CA and a server certificate for `names` (DNS names or IP addresses).
    pub fn generate(names: &[String]) -> Result<Self, rcgen::Error> {
        let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Vilicus E3 spike test CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate()?;
        let ca_cert = ca_params.self_signed(&ca_key)?;
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        let mut server_params = CertificateParams::new(names.to_vec())?;
        server_params
            .distinguished_name
            .push(DnType::CommonName, "Vilicus E3 spike server");
        server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate()?;
        let server_cert = server_params.signed_by(&server_key, &issuer)?;

        Ok(Self {
            ca_pem: ca_cert.pem(),
            ca_der: ca_cert.der().clone(),
            cert_pem: server_cert.pem(),
            cert_der: server_cert.der().clone(),
            key_pem: server_key.serialize_pem(),
            key_der: PrivatePkcs8KeyDer::from(server_key.serialize_der()),
        })
    }

    /// The server's certificate chain, leaf first.
    pub fn server_chain(&self) -> Vec<CertificateDer<'static>> {
        vec![self.cert_der.clone()]
    }

    /// The server's private key in the form rustls takes.
    pub fn server_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(self.key_der.clone_key())
    }

    /// Writes the CA certificate, the server certificate and the server key into `dir`.
    pub fn write_to(&self, dir: &Path) -> io::Result<()> {
        fs::create_dir_all(dir)?;
        fs::write(dir.join(CA_FILE), &self.ca_pem)?;
        fs::write(dir.join(CERT_FILE), &self.cert_pem)?;
        fs::write(dir.join(KEY_FILE), &self.key_pem)
    }
}
