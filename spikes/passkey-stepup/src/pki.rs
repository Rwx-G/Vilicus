//! A throwaway test CA and the server certificate it signs. Nothing here is a production PKI:
//! the keys live in memory or in the run's scratch volume and die with it.

use std::fs;
use std::io;
use std::path::Path;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// File name of the CA certificate written by [`TestPki::write_ca`], read by the browsers.
pub const CA_FILE: &str = "ca.pem";

/// A test CA and a server certificate and key signed by it.
pub struct TestPki {
    pub ca_pem: String,
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivatePkcs8KeyDer<'static>,
}

impl TestPki {
    /// Generates a CA and a server certificate for one DNS name.
    pub fn generate(name: &str) -> Result<Self, rcgen::Error> {
        let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Vilicus E2 spike test CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate()?;
        let ca_cert = ca_params.self_signed(&ca_key)?;
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        let mut server_params = CertificateParams::new(vec![name.to_owned()])?;
        server_params
            .distinguished_name
            .push(DnType::CommonName, name);
        server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate()?;
        let server_cert = server_params.signed_by(&server_key, &issuer)?;

        Ok(Self {
            ca_pem: ca_cert.pem(),
            cert_der: server_cert.der().clone(),
            key_der: PrivatePkcs8KeyDer::from(server_key.serialize_der()),
        })
    }

    pub fn server_chain(&self) -> Vec<CertificateDer<'static>> {
        vec![self.cert_der.clone()]
    }

    pub fn server_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(self.key_der.clone_key())
    }

    /// Writes the CA certificate into `dir`, for the browsers to trust.
    pub fn write_ca(&self, dir: &Path) -> io::Result<()> {
        fs::create_dir_all(dir)?;
        fs::write(dir.join(CA_FILE), &self.ca_pem)
    }
}
