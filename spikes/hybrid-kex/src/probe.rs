//! The rustls client: the same library and provider the native app is expected to build on.

use std::io;
use std::sync::Arc;

use rustls::crypto::SupportedKxGroup;
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore, SupportedProtocolVersion};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::server::{ALPN_HTTP11, CLIENT_PATH_PREFIX};

/// Which groups the probe offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    /// The aws-lc-rs provider's default list, X25519MLKEM768 first.
    ProviderDefault,
    /// X25519 only: a client without the hybrid group.
    ClassicalOnly,
}

impl Offer {
    /// The key exchange groups the client configuration carries.
    pub fn kx_groups(self) -> Vec<&'static dyn SupportedKxGroup> {
        match self {
            Self::ProviderDefault => aws_lc_rs::default_provider().kx_groups,
            Self::ClassicalOnly => vec![kx_group::X25519],
        }
    }
}

/// What the probe saw.
#[derive(Debug)]
pub struct ProbeResult {
    /// The group as the client saw it negotiated.
    pub group: Option<u16>,
    /// The server's response body (its own record of the connection).
    pub body: String,
}

/// Connects to `address`, verifies the server against `ca`, sends `GET /client/<client_name>`
/// and returns the negotiated group and the response body.
pub async fn fetch(
    address: &str,
    server_name: &str,
    ca: CertificateDer<'static>,
    client_name: &str,
    kx_groups: Vec<&'static dyn SupportedKxGroup>,
    versions: &[&'static SupportedProtocolVersion],
) -> io::Result<ProbeResult> {
    let mut roots = RootCertStore::empty();
    roots.add(ca).map_err(io::Error::other)?;
    let provider = rustls::crypto::CryptoProvider {
        kx_groups,
        ..aws_lc_rs::default_provider()
    };
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .map_err(io::Error::other)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];

    let name = ServerName::try_from(server_name.to_owned()).map_err(io::Error::other)?;
    let tcp = TcpStream::connect(address).await?;
    let mut tls = TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await?;
    let group = tls
        .get_ref()
        .1
        .negotiated_key_exchange_group()
        .map(|group| u16::from(group.name()));

    let request = format!(
        "GET {CLIENT_PATH_PREFIX}{client_name} HTTP/1.1\r\nHost: {server_name}\r\nUser-Agent: hybrid-kex-probe (rustls)\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    match tls.read_to_end(&mut response).await {
        Ok(_) => {}
        // Tolerated: some servers close without close_notify; the body is already complete.
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
        Err(error) => return Err(error),
    }
    let response = String::from_utf8_lossy(&response);
    let body = response
        .split_once("\r\n\r\n")
        .map_or("", |(_, body)| body)
        .to_owned();
    Ok(ProbeResult { group, body })
}
