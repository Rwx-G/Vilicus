//! HTTPS front: TLS 1.3 with rustls on the aws-lc-rs provider, a static page, and a JSON API over
//! the relying party. Session identifiers travel in a `__Host-` cookie with `Secure; HttpOnly;
//! SameSite=Strict`. A refusal tells the client its reason code only; the detail is logged.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{Json, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

use crate::action::{ActionInput, REQUEST_ID_LEN};
use crate::rp::{RelyingParty, RpError, SessionId};
use crate::stepup::SESSION_ID_LEN;

const INDEX_HTML: &str = include_str!("../static/index.html");
const APP_JS: &str = include_str!("../static/app.js");
// `__Host-`: the browser accepts it only with `Secure`, `Path=/` and no `Domain`, so no other
// host or plain-HTTP response can set or shadow it.
const SESSION_COOKIE: &str = "__Host-vilicus_sid";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// TLS 1.3 only, the aws-lc-rs provider with its default groups, HTTP/1.1.
pub fn tls_config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, rustls::Error> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// Accepts TCP connections and completes the TLS handshake before handing them to axum. The
/// handshake runs inside `accept`, one at a time with a timeout: enough for one test browser.
struct TlsListener {
    tcp: TcpListener,
    acceptor: TlsAcceptor,
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let Ok((stream, peer)) = self.tcp.accept().await else {
                continue;
            };
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, self.acceptor.accept(stream)).await {
                Ok(Ok(tls)) => return (tls, peer),
                Ok(Err(error)) => eprintln!("TLS handshake from {peer} failed: {error}"),
                Err(_) => eprintln!("TLS handshake from {peer} timed out"),
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.tcp.local_addr()
    }
}

pub async fn serve(
    tcp: TcpListener,
    tls: ServerConfig,
    relying_party: Arc<RelyingParty>,
) -> io::Result<()> {
    let listener = TlsListener {
        tcp,
        acceptor: TlsAcceptor::from(Arc::new(tls)),
    };
    axum::serve(listener, router(relying_party)).await
}

pub fn router(relying_party: Arc<RelyingParty>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/api/session", get(session_info))
        .route("/api/register/start", post(register_start))
        .route("/api/register/finish", post(register_finish))
        .route("/api/login/start", post(login_start))
        .route("/api/login/finish", post(login_finish))
        .route("/api/step-up/start", post(step_up_start))
        .route("/api/step-up/finish", post(step_up_finish))
        .with_state(relying_party)
}

type Rp = State<Arc<RelyingParty>>;

async fn index() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
        ],
        INDEX_HTML,
    )
        .into_response()
}

async fn app_js() -> Response {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        APP_JS,
    )
        .into_response()
}

fn decode_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != 2 * N {
        return None;
    }
    let mut bytes = [0u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(2 * index..2 * index + 2)?, 16).ok()?;
    }
    Some(bytes)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The session cookie of a request: `Ok(None)` without one, an error response when the request
/// carries it more than once (a shadowing attempt or a client bug; neither is guessed at).
fn session_from(headers: &HeaderMap) -> Result<Option<SessionId>, Box<Response>> {
    let mut values = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .filter(|(name, _)| *name == SESSION_COOKIE)
        .map(|(_, value)| value);
    let first = values.next();
    if values.next().is_some() {
        println!("REFUSED duplicate_session_cookie");
        return Err(Box::new(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "duplicate_session_cookie" })),
            )
                .into_response(),
        ));
    }
    Ok(first.and_then(decode_hex::<SESSION_ID_LEN>))
}

fn required_session(headers: &HeaderMap) -> Result<SessionId, Box<Response>> {
    session_from(headers)?.ok_or_else(|| Box::new(refusal(&RpError::NoSession)))
}

fn session_cookie(session: &SessionId) -> HeaderValue {
    let cookie = format!(
        "{SESSION_COOKIE}={}; Path=/; Secure; HttpOnly; SameSite=Strict",
        encode_hex(session)
    );
    HeaderValue::from_str(&cookie).expect("hex and fixed text form a valid header value")
}

/// The caller's session, or a new anonymous one with the cookie to set.
fn session_or_open(
    rp: &RelyingParty,
    headers: &HeaderMap,
) -> Result<(SessionId, Option<HeaderValue>), Box<Response>> {
    Ok(match session_from(headers)? {
        Some(session) if rp.has_session(&session) => (session, None),
        _ => {
            let session = rp.open_session();
            (session, Some(session_cookie(&session)))
        }
    })
}

/// The client gets the reason code only; the detail goes to the server log.
fn refusal(error: &RpError) -> Response {
    let status = match error {
        RpError::NoSession | RpError::NotAuthenticated => StatusCode::UNAUTHORIZED,
        RpError::UnknownRequest => StatusCode::NOT_FOUND,
        RpError::AlreadyUsed | RpError::UserExists => StatusCode::CONFLICT,
        RpError::Expired => StatusCode::GONE,
        RpError::ActionMismatch
        | RpError::ChallengeMismatch
        | RpError::CounterRegressed
        | RpError::Webauthn(_) => StatusCode::FORBIDDEN,
        RpError::Bind(_) => StatusCode::INTERNAL_SERVER_ERROR,
        RpError::InvalidUsername | RpError::NoCeremony | RpError::Action(_) => {
            StatusCode::BAD_REQUEST
        }
    };
    println!("REFUSED {error}");
    (status, Json(json!({ "error": error.code() }))).into_response()
}

fn with_cookie(mut response: Response, cookie: Option<HeaderValue>) -> Response {
    if let Some(cookie) = cookie {
        response.headers_mut().insert(header::SET_COOKIE, cookie);
    }
    response
}

fn json_or_refusal<T: Serialize>(result: Result<T, RpError>) -> Response {
    match result {
        Ok(body) => Json(body).into_response(),
        Err(error) => refusal(&error),
    }
}

async fn session_info(State(rp): Rp, headers: HeaderMap) -> Response {
    let session = match session_from(&headers) {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let user = session.and_then(|session| rp.session_user(&session));
    Json(json!({ "user": user })).into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UsernameBody {
    username: String,
}

async fn register_start(
    State(rp): Rp,
    headers: HeaderMap,
    Json(body): Json<UsernameBody>,
) -> Response {
    let (session, cookie) = match session_or_open(&rp, &headers) {
        Ok(found) => found,
        Err(response) => return *response,
    };
    with_cookie(
        json_or_refusal(rp.register_start(&session, &body.username, Instant::now())),
        cookie,
    )
}

async fn register_finish(
    State(rp): Rp,
    headers: HeaderMap,
    Json(credential): Json<RegisterPublicKeyCredential>,
) -> Response {
    let session = match required_session(&headers) {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let result = rp.register_finish(&session, &credential, Instant::now());
    println!("REGISTER outcome={}", outcome(&result));
    json_or_refusal(result.map(|user| json!({ "registered": user })))
}

async fn login_start(
    State(rp): Rp,
    headers: HeaderMap,
    Json(body): Json<UsernameBody>,
) -> Response {
    let (session, cookie) = match session_or_open(&rp, &headers) {
        Ok(found) => found,
        Err(response) => return *response,
    };
    with_cookie(
        json_or_refusal(rp.login_start(&session, &body.username, Instant::now())),
        cookie,
    )
}

async fn login_finish(
    State(rp): Rp,
    headers: HeaderMap,
    Json(credential): Json<PublicKeyCredential>,
) -> Response {
    let session = match required_session(&headers) {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let result = rp.login_finish(&session, &credential, Instant::now());
    println!("LOGIN outcome={}", outcome(&result));
    match result {
        Ok((new_session, user)) => with_cookie(
            Json(json!({ "user": user })).into_response(),
            Some(session_cookie(&new_session)),
        ),
        Err(error) => refusal(&error),
    }
}

async fn step_up_start(
    State(rp): Rp,
    headers: HeaderMap,
    Json(input): Json<ActionInput>,
) -> Response {
    let session = match required_session(&headers) {
        Ok(session) => session,
        Err(response) => return *response,
    };
    json_or_refusal(
        rp.step_up_start(&session, &input, Instant::now())
            .map(|start| {
                json!({
                    "request_id": encode_hex(&start.request_id),
                    "request_hash": encode_hex(&start.request_hash),
                    "canonical_request": encode_hex(&start.canonical_request),
                    "options": start.options,
                })
            }),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StepUpFinishBody {
    request_id: String,
    request_hash: String,
    credential: PublicKeyCredential,
}

async fn step_up_finish(
    State(rp): Rp,
    headers: HeaderMap,
    Json(body): Json<StepUpFinishBody>,
) -> Response {
    let session = match required_session(&headers) {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let (Some(request_id), Some(claimed_hash)) = (
        decode_hex::<REQUEST_ID_LEN>(&body.request_id),
        decode_hex::<32>(&body.request_hash),
    ) else {
        return refusal(&RpError::UnknownRequest);
    };
    let result = rp.step_up_finish(
        &session,
        &request_id,
        &claimed_hash,
        &body.credential,
        Instant::now(),
    );
    println!(
        "STEP_UP request={} outcome={}",
        body.request_id,
        outcome(&result)
    );
    json_or_refusal(result.map(|approved| {
        json!({
            "approved": encode_hex(&approved.request_id),
            "request_hash": encode_hex(&approved.request_hash),
            "canonical_request": encode_hex(&approved.canonical_request),
        })
    }))
}

fn outcome<T>(result: &Result<T, RpError>) -> String {
    match result {
        Ok(_) => "accepted".to_owned(),
        Err(error) => format!("refused:{error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_refuses_bad_input() {
        let bytes = [0x00, 0x7f, 0xff, 0x10];
        assert_eq!(decode_hex::<4>(&encode_hex(&bytes)), Some(bytes));
        assert_eq!(decode_hex::<4>("00ff"), None);
        assert_eq!(decode_hex::<2>("zzzz"), None);
        assert_eq!(decode_hex::<2>("\u{e9}0f"), None);
    }

    fn cookie_pair(session: &SessionId) -> String {
        let set = session_cookie(session);
        set.to_str().unwrap().split(';').next().unwrap().to_owned()
    }

    #[test]
    fn session_cookie_is_read_back() {
        let session = [0xabu8; SESSION_ID_LEN];
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("other=1; {}", cookie_pair(&session))).unwrap(),
        );
        assert_eq!(session_from(&headers).ok(), Some(Some(session)));
        assert!(cookie_pair(&session).starts_with("__Host-"));
    }

    #[test]
    fn duplicate_session_cookie_is_refused() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!(
                "{}; {}",
                cookie_pair(&[1; SESSION_ID_LEN]),
                cookie_pair(&[2; SESSION_ID_LEN])
            ))
            .unwrap(),
        );
        let refused = session_from(&headers).unwrap_err();
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    }
}
