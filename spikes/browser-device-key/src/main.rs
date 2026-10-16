//! `browser-device-key serve <listen> <pki-dir> <web-dir> <deps-dir>`: generates a test CA and
//! a certificate for the Core and relay names, a second, untrusted CA for the rogue name,
//! writes the trusted CA to `<pki-dir>/ca.pem` once the listener is bound, and serves the E22
//! pages and API over TLS 1.3 and HTTP/1.1, choosing the certificate by SNI.

use std::path::PathBuf;
use std::sync::Arc;

use browser_device_key::http::{self, CORE_HOST, RELAY_HOST, ROGUE_HOST, Site, State};
use browser_device_key::pki::{CA_FILE, TestPki};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::ServerConfig;
use rustls::server::ResolvesServerCertUsingSni;
use rustls::sign::CertifiedKey;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let [_, command, listen, pki_dir, web_dir, deps_dir] = args.as_slice() else {
        return Err(
            "usage: browser-device-key serve <listen> <pki-dir> <web-dir> <deps-dir>".into(),
        );
    };
    if command != "serve" {
        return Err(format!("unknown command {command}").into());
    }

    let pki = TestPki::generate(&[CORE_HOST.to_owned(), RELAY_HOST.to_owned()])?;
    let rogue = TestPki::generate_with_ca(&[ROGUE_HOST.to_owned()], "Vilicus E22 untrusted CA")?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut resolver = ResolvesServerCertUsingSni::new();
    for (names, issued) in [
        (&[CORE_HOST, RELAY_HOST][..], &pki),
        (&[ROGUE_HOST][..], &rogue),
    ] {
        let key = provider
            .key_provider
            .load_private_key(issued.server_key())?;
        let certified = CertifiedKey::new(issued.server_chain(), key);
        for name in names {
            resolver.add(name, certified.clone())?;
        }
    }
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let state = State::new(Site::load(
        &PathBuf::from(web_dir),
        &PathBuf::from(deps_dir),
    )?);
    let listener = TcpListener::bind(listen.as_str()).await?;
    std::fs::create_dir_all(pki_dir)?;
    std::fs::write(PathBuf::from(pki_dir).join(CA_FILE), &pki.ca_pem)?;
    println!("SERVER ready listen={listen} names={CORE_HOST},{RELAY_HOST},{ROGUE_HOST}");

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let state = state.clone();
        let source = peer.ip().to_string();
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(stream).await else {
                return;
            };
            let service =
                service_fn(move |request| http::serve(state.clone(), source.clone(), request));
            // A browser closing a keep-alive connection ends here; nothing to report.
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(tls), service)
                .await;
        });
    }
}
