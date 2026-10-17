//! Both origins over real TLS: the PKI, the SNI certificate choice, and the headers a browser
//! receives on each port, checked with a rustls client that trusts only the test CA.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use separate_origin::instances::Layout;
use separate_origin::pki;
use separate_origin::routes::{Gateway, Role, Transport};
use separate_origin::server::{self, Service};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

const NAME: &str = "vilicus-test.internal";
const LAYOUT: &str = "ca household Household local CA
deployment direct 10.0.0.10
deployment caddy 10.0.0.20
instance localca direct vilicus-test.internal household
instance localca caddy vilicus-proxied.internal household
";

struct Fixture {
    dir: PathBuf,
    app: u16,
    content: u16,
    plain_content: u16,
    connector: TlsConnector,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn start(tag: &str) -> Fixture {
    let dir = std::env::temp_dir().join(format!("e26-{tag}-{}", std::process::id()));
    let layout = Layout::parse(LAYOUT).expect("layout");
    assert!(pki::generate(&layout, &dir).expect("pki"));
    assert!(!pki::generate(&layout, &dir).expect("second pki run"));

    let gateway = Arc::new(Gateway::new(
        layout.direct_names(),
        layout.proxied_names(),
        false,
    ));
    let tls = server::tls_config(&dir, &layout.direct_names()).expect("tls config");
    let mut ports = Vec::new();
    for (label, role, transport) in [
        ("app-tls", Role::App, Transport::Tls),
        ("content-tls", Role::Content, Transport::Tls),
        ("content-plain", Role::Content, Transport::Plain),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        ports.push(listener.local_addr().expect("addr").port());
        let tls =
            (transport == Transport::Tls).then(|| (Arc::clone(&tls), Arc::clone(&gateway.log)));
        let service = Service::Gateway(Arc::clone(&gateway), role, transport);
        tokio::spawn(server::serve(listener, label, tls, service));
    }
    Fixture {
        connector: connector(&dir.join("ca-household.crt")),
        dir,
        app: ports[0],
        content: ports[1],
        plain_content: ports[2],
    }
}

fn connector(ca: &Path) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_file(ca).expect("ca"))
        .expect("root");
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

/// Sends one HTTP/1.1 request and returns the status line and headers (lowercase names).
async fn exchange(
    f: &Fixture,
    port: u16,
    sni: Option<&str>,
    request: &str,
) -> Result<(String, Vec<(String, String)>), String> {
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    match sni {
        Some(sni) => {
            let name = ServerName::try_from(sni.to_owned()).map_err(|e| e.to_string())?;
            let mut tls = f
                .connector
                .connect(name, tcp)
                .await
                .map_err(|e| e.to_string())?;
            tls.write_all(request.as_bytes())
                .await
                .map_err(|e| e.to_string())?;
            tls.read_to_end(&mut raw).await.map_err(|e| e.to_string())?;
        }
        None => {
            let mut tcp = tcp;
            tcp.write_all(request.as_bytes())
                .await
                .map_err(|e| e.to_string())?;
            tcp.read_to_end(&mut raw).await.map_err(|e| e.to_string())?;
        }
    }
    let text = String::from_utf8_lossy(&raw).into_owned();
    let head = text.split("\r\n\r\n").next().unwrap_or("");
    let mut lines = head.lines();
    let status = lines.next().unwrap_or("").to_owned();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    Ok((status, headers))
}

fn get(path: &str, host: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> &'a str {
    headers
        .iter()
        .find(|(n, _)| n == name)
        .map_or("", |(_, v)| v.as_str())
}

#[tokio::test]
async fn client_origin_serves_strict_csp_and_the_session_cookie_over_tls() {
    let f = start("client").await;
    let (status, headers) = exchange(&f, f.app, Some(NAME), &get("/", NAME))
        .await
        .expect("page");
    assert!(status.contains(" 200 "), "{status}");
    let csp = header(&headers, "content-security-policy");
    assert!(
        csp.contains("'nonce-") && csp.contains("trusted-types lit-html"),
        "{csp}"
    );
    assert!(csp.contains(&format!("frame-src https://{NAME}:8443")));

    let login = format!(
        "POST /api/login HTTP/1.1\r\nHost: {NAME}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let (status, headers) = exchange(&f, f.app, Some(NAME), &login)
        .await
        .expect("login");
    assert!(status.contains(" 204 "), "{status}");
    let cookie = header(&headers, "set-cookie");
    assert!(cookie.starts_with("__Host-vilicus_session="), "{cookie}");
    assert!(
        cookie.ends_with("; Path=/; Secure; HttpOnly; SameSite=Strict"),
        "{cookie}"
    );
}

#[tokio::test]
async fn content_origin_serves_fixtures_with_the_sandbox_csp_on_its_port_only() {
    let f = start("content").await;
    let content_host = format!("{NAME}:8443");
    let (status, headers) = exchange(
        &f,
        f.content,
        Some(NAME),
        &get("/content/passive?run=t1", &content_host),
    )
    .await
    .expect("fixture");
    assert!(status.contains(" 200 "), "{status}");
    let csp = header(&headers, "content-security-policy");
    assert!(
        csp.contains("default-src 'none'") && csp.contains("sandbox;"),
        "{csp}"
    );
    assert!(
        csp.contains(&format!("frame-ancestors https://{NAME};")),
        "{csp}"
    );
    assert_eq!(header(&headers, "x-dns-prefetch-control"), "off");

    // The client's Host on the content port, and the raw mode without test controls, are refused.
    let (status, _) = exchange(
        &f,
        f.content,
        Some(NAME),
        &get("/content/passive?run=t1", NAME),
    )
    .await
    .expect("misdirected");
    assert!(status.contains(" 421 "), "{status}");
    let (status, _) = exchange(
        &f,
        f.content,
        Some(NAME),
        &get("/raw/passive?run=t1", &content_host),
    )
    .await
    .expect("raw");
    assert!(status.contains(" 404 "), "{status}");
}

#[tokio::test]
async fn names_are_bound_to_their_transport() {
    let f = start("transport").await;
    // A proxied name has no certificate on the TLS listener.
    assert!(
        exchange(
            &f,
            f.content,
            Some("vilicus-proxied.internal"),
            &get("/", "x")
        )
        .await
        .is_err()
    );
    // The plain listener serves proxied names only.
    let proxied = "vilicus-proxied.internal:8443";
    let (status, _) = exchange(
        &f,
        f.plain_content,
        None,
        &get("/content/passive?run=t1", proxied),
    )
    .await
    .expect("proxied");
    assert!(status.contains(" 200 "), "{status}");
    let direct = format!("{NAME}:8443");
    let (status, _) = exchange(
        &f,
        f.plain_content,
        None,
        &get("/content/passive?run=t1", &direct),
    )
    .await
    .expect("direct over plain");
    assert!(status.contains(" 421 "), "{status}");
}
