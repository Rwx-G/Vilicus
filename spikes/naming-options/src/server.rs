//! HTTPS server: the installable page and the passkey ceremony routes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use webauthn_rs::Webauthn;
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Uuid,
};

use crate::png;
use crate::rp::RelyingParty;

const INDEX_HTML: &str = include_str!("../site/index.html");
const APP_JS: &str = include_str!("../site/app.js");
const SERVICE_WORKER_JS: &str = include_str!("../site/sw.js");
const MANIFEST: &str = include_str!("../site/manifest.webmanifest");

pub struct AppState {
    relying_party: RelyingParty,
    ceremonies: Mutex<Ceremonies>,
    icon_192: Vec<u8>,
    icon_512: Vec<u8>,
}

/// Test users by name (the driver uses one per browser, so each login lists that browser's
/// passkey only), with their ceremonies in progress and their passkeys.
#[derive(Default)]
struct Ceremonies {
    users: HashMap<String, User>,
}

struct User {
    id: Uuid,
    registration: Option<PasskeyRegistration>,
    authentication: Option<PasskeyAuthentication>,
    passkeys: Vec<Passkey>,
}

impl Ceremonies {
    fn user(&mut self, name: &str) -> &mut User {
        let next_id = Uuid::from_u128(self.users.len() as u128 + 1);
        self.users.entry(name.to_owned()).or_insert_with(|| User {
            id: next_id,
            registration: None,
            authentication: None,
            passkeys: Vec::new(),
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserRequest {
    user: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterFinish {
    user: String,
    credential: RegisterPublicKeyCredential,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginFinish {
    user: String,
    credential: PublicKeyCredential,
}

impl AppState {
    pub fn new(relying_party: RelyingParty) -> Self {
        Self {
            relying_party,
            ceremonies: Mutex::default(),
            icon_192: png::icon(192),
            icon_512: png::icon(512),
        }
    }

    fn webauthn(&self) -> Result<&Webauthn, ApiError> {
        self.relying_party
            .webauthn
            .as_ref()
            .map_err(|reason| ApiError(StatusCode::SERVICE_UNAVAILABLE, reason.clone()))
    }

    fn ceremonies(&self) -> std::sync::MutexGuard<'_, Ceremonies> {
        self.ceremonies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

fn bad_request(context: &str, err: impl std::fmt::Display) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, format!("{context}: {err}"))
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    INDEX_HTML,
                )
            }),
        )
        .route(
            "/app.js",
            get(|| async { ([(header::CONTENT_TYPE, "text/javascript")], APP_JS) }),
        )
        .route(
            "/sw.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript")],
                    SERVICE_WORKER_JS,
                )
            }),
        )
        .route(
            "/manifest.webmanifest",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "application/manifest+json")],
                    MANIFEST,
                )
            }),
        )
        .route(
            "/icon-192.png",
            get(|State(s): State<Arc<AppState>>| async move { png_response(&s.icon_192) }),
        )
        .route(
            "/icon-512.png",
            get(|State(s): State<Arc<AppState>>| async move { png_response(&s.icon_512) }),
        )
        .route("/api/info", get(info))
        .route("/api/register/start", post(register_start))
        .route("/api/register/finish", post(register_finish))
        .route("/api/login/start", post(login_start))
        .route("/api/login/finish", post(login_finish))
        .with_state(state)
}

fn png_response(bytes: &[u8]) -> Response {
    ([(header::CONTENT_TYPE, "image/png")], bytes.to_vec()).into_response()
}

async fn info(State(state): State<Arc<AppState>>) -> Json<Value> {
    let rp = &state.relying_party;
    Json(json!({
        "origin": rp.origin,
        "rp_id": rp.rp_id,
        "webauthn": rp.webauthn.is_ok(),
        "reason": rp.webauthn.as_ref().err(),
    }))
}

async fn register_start(
    State(state): State<Arc<AppState>>,
    Json(request): Json<UserRequest>,
) -> Result<Json<Value>, ApiError> {
    let user_id = state.ceremonies().user(&request.user).id;
    let (challenge, registration) = state
        .webauthn()?
        .start_passkey_registration(user_id, &request.user, &request.user, None)
        .map_err(|err| bad_request("start_passkey_registration", err))?;
    state.ceremonies().user(&request.user).registration = Some(registration);
    Ok(Json(json!(challenge)))
}

async fn register_finish(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RegisterFinish>,
) -> Result<Json<Value>, ApiError> {
    let registration = state
        .ceremonies()
        .user(&request.user)
        .registration
        .take()
        .ok_or_else(|| bad_request("register_finish", "no registration in progress"))?;
    let passkey = state
        .webauthn()?
        .finish_passkey_registration(&request.credential, &registration)
        .map_err(|err| bad_request("finish_passkey_registration", err))?;
    let credential_id = json!(passkey.cred_id());
    state
        .ceremonies()
        .user(&request.user)
        .passkeys
        .push(passkey);
    Ok(Json(
        json!({ "rp_id": state.relying_party.rp_id, "credential_id": credential_id }),
    ))
}

async fn login_start(
    State(state): State<Arc<AppState>>,
    Json(request): Json<UserRequest>,
) -> Result<Json<Value>, ApiError> {
    let passkeys = state.ceremonies().user(&request.user).passkeys.clone();
    // webauthn-rs did not refuse an empty passkey list in this spike's test; refuse it here.
    if passkeys.is_empty() {
        return Err(bad_request("login_start", "no passkey registered"));
    }
    let (challenge, authentication) = state
        .webauthn()?
        .start_passkey_authentication(&passkeys)
        .map_err(|err| bad_request("start_passkey_authentication", err))?;
    state.ceremonies().user(&request.user).authentication = Some(authentication);
    Ok(Json(json!(challenge)))
}

async fn login_finish(
    State(state): State<Arc<AppState>>,
    Json(request): Json<LoginFinish>,
) -> Result<Json<Value>, ApiError> {
    let authentication = state
        .ceremonies()
        .user(&request.user)
        .authentication
        .take()
        .ok_or_else(|| bad_request("login_finish", "no login in progress"))?;
    let result = state
        .webauthn()?
        .finish_passkey_authentication(&request.credential, &authentication)
        .map_err(|err| bad_request("finish_passkey_authentication", err))?;
    Ok(Json(json!({
        "rp_id": state.relying_party.rp_id,
        "credential_id": result.cred_id(),
        "user_verified": result.user_verified(),
    })))
}

/// TLS 1.2 and 1.3 with the ring provider, HTTP/1.1 only.
pub fn tls_config(
    cert_path: &str,
    key_path: &str,
) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
    let chain = CertificateDer::pem_file_iter(cert_path)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(key_path)?;
    let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

pub async fn serve(
    listen: &str,
    tls: Arc<ServerConfig>,
    state: Arc<AppState>,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let acceptor = TlsAcceptor::from(tls);
    let app = router(state);
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let service = TowerToHyperService::new(app.clone());
        tokio::spawn(async move {
            // A refused handshake is evidence (a browser that rejects the certificate).
            let tls_stream = match acceptor.accept(stream).await {
                Ok(tls_stream) => tls_stream,
                Err(err) => {
                    println!("E24 tls handshake from {} failed: {err}", peer.ip());
                    return;
                }
            };
            let connection = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tls_stream), service);
            if let Err(err) = connection.await {
                println!("E24 connection from {} ended: {err}", peer.ip());
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use tower::ServiceExt;

    async fn call(origin: &str, method: &str, path: &str) -> (StatusCode, String, Vec<u8>) {
        let app = router(Arc::new(AppState::new(RelyingParty::from_origin(origin))));
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"user":"member01"}"#))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|value| value.to_str().unwrap().to_owned())
            .unwrap_or_default();
        (
            status,
            content_type,
            to_bytes(response.into_body(), 4 << 20)
                .await
                .unwrap()
                .to_vec(),
        )
    }

    #[tokio::test]
    async fn every_manifest_icon_is_served_as_a_png_of_its_declared_size() {
        let manifest: Value = serde_json::from_str(MANIFEST).unwrap();
        let icons = manifest["icons"].as_array().unwrap();
        assert!(!icons.is_empty());
        for icon in icons {
            let src = icon["src"].as_str().unwrap();
            let (status, content_type, body) = call("https://vilicus.home.arpa", "GET", src).await;
            assert_eq!(status, StatusCode::OK, "{src}");
            assert_eq!(content_type, icon["type"].as_str().unwrap(), "{src}");
            let width = u32::from_be_bytes(body[16..20].try_into().unwrap());
            let height = u32::from_be_bytes(body[20..24].try_into().unwrap());
            assert_eq!(
                format!("{width}x{height}"),
                icon["sizes"].as_str().unwrap(),
                "{src}"
            );
        }
    }

    #[tokio::test]
    async fn manifest_and_service_worker_are_served_with_their_types() {
        let manifest: Value = serde_json::from_str(MANIFEST).unwrap();
        assert_eq!(manifest["display"], "standalone");
        let (status, content_type, _) =
            call("https://vilicus.home.arpa", "GET", "/manifest.webmanifest").await;
        assert_eq!(
            (status, content_type.as_str()),
            (StatusCode::OK, "application/manifest+json")
        );
        let (status, content_type, _) = call("https://vilicus.home.arpa", "GET", "/sw.js").await;
        assert_eq!(
            (status, content_type.as_str()),
            (StatusCode::OK, "text/javascript")
        );
        let (_, _, index) = call("https://vilicus.home.arpa", "GET", "/").await;
        assert!(
            String::from_utf8(index)
                .unwrap()
                .contains(r#"<link rel="manifest" href="/manifest.webmanifest">"#)
        );
    }

    #[tokio::test]
    async fn registration_options_name_the_instance_as_rp_id() {
        let (status, _, body) =
            call("https://vilicus.home.arpa", "POST", "/api/register/start").await;
        assert_eq!(status, StatusCode::OK);
        let options: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(options["publicKey"]["rp"]["id"], "vilicus.home.arpa");
    }

    #[tokio::test]
    async fn an_ip_origin_serves_the_page_but_no_ceremony() {
        let (status, _, _) = call("https://10.88.0.24", "GET", "/").await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, body) = call("https://10.88.0.24", "POST", "/api/register/start").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            String::from_utf8(body)
                .unwrap()
                .contains("refused rp_id 10.88.0.24")
        );
    }

    #[tokio::test]
    async fn login_without_a_registered_passkey_is_refused() {
        let (status, _, _) = call("https://vilicus.home.arpa", "POST", "/api/login/start").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
