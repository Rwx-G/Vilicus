//! The HTTP client: one pooled hyper client over rustls, used for the push webhook, the
//! simulated phone's subscription stream and its acknowledgements.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;

use crate::config::Target;
use crate::payload::alert_body;

pub type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// How long a publish may take before it counts as failed.
pub const PUBLISH_TIMEOUT: Duration = Duration::from_secs(30);

/// Builds the client. Server certificates are checked against the bundled Mozilla roots and, if
/// given, the certificates of `ca_file` (a household CA for a self-hosted server behind TLS).
pub fn client(ca_file: Option<&Path>) -> Result<HttpClient, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca_file {
        for cert in CertificateDer::pem_file_iter(path)
            .map_err(|e| format!("cannot read CA file {}: {e}", path.display()))?
        {
            let cert = cert.map_err(|e| format!("bad certificate in {}: {e}", path.display()))?;
            roots
                .add(cert)
                .map_err(|e| format!("unusable CA certificate in {}: {e}", path.display()))?;
        }
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS configuration: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .build();
    Ok(Client::builder(TokioExecutor::new()).build(connector))
}

fn uri(text: &str) -> Result<Uri, String> {
    text.parse().map_err(|e| format!("bad URL `{text}`: {e}"))
}

/// Sends a request and returns the response with its body still streaming.
pub async fn request(
    client: &HttpClient,
    method: Method,
    url: &str,
    bearer: Option<&str>,
    body: String,
) -> Result<Response<Incoming>, String> {
    let mut builder = Request::builder().method(method).uri(uri(url)?);
    if let Some(token) = bearer {
        builder = builder.header(hyper::header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if !body.is_empty() {
        builder = builder.header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8");
    }
    let request = builder
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| format!("cannot build request: {e}"))?;
    client
        .request(request)
        .await
        .map_err(|e| format!("request failed: {e}"))
}

/// Sends a request and reads the whole response body.
pub async fn request_to_end(
    client: &HttpClient,
    method: Method,
    url: &str,
    bearer: Option<&str>,
    body: String,
) -> Result<(StatusCode, Bytes), String> {
    let response = request(client, method, url, bearer, body).await?;
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("cannot read response: {e}"))?
        .to_bytes();
    Ok((status, bytes))
}

/// Publishes the alert `id` to the target's topic: a plain body, no title, tag, priority or
/// other header, and the target's access token if it has one.
pub async fn publish(client: &HttpClient, target: &Target, id: &str) -> Result<(), String> {
    let url = target.topic_url();
    let attempt = request_to_end(
        client,
        Method::POST,
        &url,
        target.token.as_deref(),
        alert_body(id),
    );
    match tokio::time::timeout(PUBLISH_TIMEOUT, attempt).await {
        Err(_) => Err("publish timed out".to_owned()),
        Ok(Err(e)) => Err(e),
        Ok(Ok((status, _))) if status.is_success() => Ok(()),
        Ok(Ok((status, _))) => Err(format!("push server answered {status}")),
    }
}
