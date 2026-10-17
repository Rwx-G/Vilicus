//! The HTTP stack: hyper over TCP, with or without rustls, serving HTTP/1.1 and HTTP/2.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ResolvesServerCertUsingSni;
use rustls::sign::CertifiedKey;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::log::{Entry, Log};
use crate::routes::{self, Gateway, Request, Response, Role, Transport};

const MAX_BODY: usize = 64 * 1024;

/// What a listener serves.
#[derive(Clone)]
pub enum Service {
    /// One origin of the Gateway stand-in.
    Gateway(Arc<Gateway>, Role, Transport),
    /// The attacker's sink.
    Sink(Arc<Log>),
    /// The control listener over a log, and the Gateway's state counter when there is one.
    Control(Arc<Log>, Option<Arc<Gateway>>),
}

impl Service {
    fn respond(&self, listener: &'static str, request: &Request) -> Response {
        match self {
            Self::Gateway(gateway, role, transport) => {
                gateway.handle(*role, *transport, listener, request)
            }
            Self::Sink(log) => routes::sink(listener, request, log),
            Self::Control(log, gateway) => {
                routes::control(request, log, gateway.as_ref().map(|g| g.mutations()))
            }
        }
    }
}

/// Builds a TLS configuration that picks the certificate by SNI among `names`, each read from
/// `<pki>/<name>.crt` and `<pki>/<name>.key`. ALPN offers HTTP/2 and HTTP/1.1.
pub fn tls_config(pki: &Path, names: &[String]) -> Result<Arc<ServerConfig>, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut resolver = ResolvesServerCertUsingSni::new();
    for name in names {
        let (chain, key) = read_pair(pki, name)?;
        let signing_key = provider
            .key_provider
            .load_private_key(key)
            .map_err(|e| format!("{name}: {e}"))?;
        resolver
            .add(name, CertifiedKey::new(chain, signing_key))
            .map_err(|e| format!("{name}: {e}"))?;
    }
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Reads `<pki>/<stem>.crt` (the chain) and `<pki>/<stem>.key`.
fn read_pair(
    pki: &Path,
    stem: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let cert_path = pki.join(format!("{stem}.crt"));
    let key_path = pki.join(format!("{stem}.key"));
    let chain = CertificateDer::pem_file_iter(&cert_path)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .map_err(|e| format!("{}: {e}", cert_path.display()))?;
    let key = PrivateKeyDer::from_pem_file(&key_path)
        .map_err(|e| format!("{}: {e}", key_path.display()))?;
    Ok((chain, key))
}

/// Builds a TLS configuration that serves one certificate to every client, whatever its SNI:
/// the sink's wildcard certificate.
pub fn single_cert_config(pki: &Path, file_stem: &str) -> Result<Arc<ServerConfig>, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let (chain, key) = read_pair(pki, file_stem)?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| e.to_string())?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Serves `service` on `listener` until the process ends. With `tls`, each handshake is logged
/// into `tls_log` with its SNI, so a preconnect that sends no request is still seen.
pub async fn serve(
    listener: TcpListener,
    label: &'static str,
    tls: Option<(Arc<ServerConfig>, Arc<Log>)>,
    service: Service,
) {
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            continue;
        };
        let service = service.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            match tls {
                Some((config, tls_log)) => {
                    let Ok(stream) = TlsAcceptor::from(config).accept(stream).await else {
                        return;
                    };
                    let sni = stream.get_ref().1.server_name().unwrap_or("").to_owned();
                    tls_log.push(Entry {
                        kind: "tls",
                        listener: label,
                        peer: peer.ip().to_string(),
                        host: sni,
                        ..Entry::default()
                    });
                    connection(TokioIo::new(stream), peer, label, service).await;
                }
                None => connection(TokioIo::new(stream), peer, label, service).await,
            }
        });
    }
}

async fn connection<I>(io: I, peer: SocketAddr, label: &'static str, service: Service)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let handler = service_fn(move |request: hyper::Request<Incoming>| {
        let service = service.clone();
        async move { Ok::<_, Infallible>(handle(request, peer, label, &service).await) }
    });
    // A connection error ends that connection only.
    let _ = Builder::new(TokioExecutor::new())
        .serve_connection(io, handler)
        .await;
}

async fn handle(
    request: hyper::Request<Incoming>,
    peer: SocketAddr,
    label: &'static str,
    service: &Service,
) -> hyper::Response<Full<Bytes>> {
    let (parts, body) = request.into_parts();
    let Ok(body) = Limited::new(body, MAX_BODY).collect().await else {
        return reply(Response {
            status: 413,
            headers: Vec::new(),
            body: Vec::new(),
        });
    };
    let host = parts
        .uri
        .authority()
        .map(ToString::to_string)
        .or_else(|| {
            parts
                .headers
                .get(hyper::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        })
        .unwrap_or_default();
    let mut headers: Vec<(String, String)> = Vec::new();
    for (name, value) in &parts.headers {
        let value = String::from_utf8_lossy(value.as_bytes()).into_owned();
        // HTTP/2 clients may split the Cookie header; join it back as HTTP/1.1 sends it.
        match headers.iter_mut().find(|(n, _)| n == "cookie") {
            Some((_, joined)) if name == hyper::header::COOKIE => {
                joined.push_str("; ");
                joined.push_str(&value);
            }
            _ => headers.push((name.as_str().to_owned(), value)),
        }
    }
    let request = Request {
        method: parts.method.as_str().to_owned(),
        host,
        path: parts.uri.path().to_owned(),
        query: parts.uri.query().unwrap_or("").to_owned(),
        headers,
        body: body.to_bytes().to_vec(),
        peer: peer.ip().to_string(),
    };
    let head = request.method == "HEAD";
    let mut response = service.respond(label, &request);
    if head {
        response.body.clear();
    }
    reply(response)
}

fn reply(response: Response) -> hyper::Response<Full<Bytes>> {
    let mut builder = hyper::Response::builder().status(response.status);
    for (name, value) in &response.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder
        .body(Full::new(Bytes::from(response.body)))
        .unwrap_or_else(|_| {
            let mut fallback = hyper::Response::new(Full::new(Bytes::new()));
            *fallback.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
            fallback
        })
}
