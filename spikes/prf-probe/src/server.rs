//! The HTTPS relying party: serves the page, runs registration and login through webauthn-rs, and
//! appends one record per verified ceremony.
//!
//! webauthn-rs 0.5.5 builds the options without `prf`; the page adds `prf` before calling the
//! browser. The `prf` client extension output is unsigned and never reaches the server: the page
//! sends digests in a separate `probe` object. The signed authenticator data still shows whether
//! the authenticator ran `hmac-secret`, which this module records next to the page's report.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use webauthn_rs::prelude::{
    PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    Url, Uuid, Webauthn, WebauthnBuilder,
};

use crate::authdata;
use crate::pki;
use crate::probe::{self, Phase, ProbeReport, Record};
use crate::store::{Store, StoredCredential, credential_key};

const INDEX_HTML: &str = include_str!("../static/index.html");
const PROBE_JS: &str = include_str!("../static/probe.js");
const MAX_BODY: usize = 64 * 1024;
/// Ceremonies started and not finished. A person runs one at a time; the cap only stops a
/// misbehaving client from growing the map without bound.
const MAX_PENDING: usize = 256;

/// Where and as what the probe serves.
pub struct Config {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub rp_id: String,
    pub origin: Url,
}

enum Pending {
    Registration {
        label: String,
        state: PasskeyRegistration,
    },
    Login {
        key: String,
        state: PasskeyAuthentication,
    },
}

/// Shared server state.
pub struct App {
    webauthn: Webauthn,
    store: Mutex<Store>,
    pending: Mutex<HashMap<String, Pending>>,
    ca_pem: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartRegistration {
    label: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishRegistration {
    session: String,
    credential: RegisterPublicKeyCredential,
    probe: ProbeReport,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartLogin {
    credential: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishLogin {
    session: String,
    credential: PublicKeyCredential,
    probe: ProbeReport,
}

#[derive(Serialize)]
struct Started<'a, T: Serialize> {
    session: String,
    options: &'a T,
}

#[derive(Serialize)]
struct CredentialEntry<'a> {
    credential: &'a str,
    label: &'a str,
}

type HttpResponse = Response<Full<Bytes>>;

fn respond(status: StatusCode, content_type: &'static str, body: impl Into<Bytes>) -> HttpResponse {
    let mut response = Response::new(Full::new(body.into()));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'"),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn json(value: &impl Serialize) -> HttpResponse {
    match serde_json::to_vec(value) {
        Ok(body) => respond(StatusCode::OK, "application/json", body),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

fn error(status: StatusCode, message: &str) -> HttpResponse {
    let body = serde_json::json!({ "error": message }).to_string();
    respond(status, "application/json", body)
}

fn bad_request(message: impl std::fmt::Display) -> HttpResponse {
    error(StatusCode::BAD_REQUEST, &message.to_string())
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// SHA-256 fingerprint of the first certificate in a PEM text, colon-separated uppercase hex,
/// the form certificate viewers show.
pub fn pem_fingerprint(pem: &str) -> Option<String> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let der = CertificateDer::from_pem_slice(pem.as_bytes()).ok()?;
    Some(
        Sha256::digest(der.as_ref())
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

impl App {
    /// Builds the relying party for `rp_id` and `origin` over the data directory `dir`.
    pub fn new(rp_id: &str, origin: &Url, dir: &Path) -> Result<Self, String> {
        let webauthn = WebauthnBuilder::new(rp_id, origin)
            .map_err(|e| format!("relying party: {e:?}"))?
            .rp_name("Vilicus PRF probe")
            .build()
            .map_err(|e| format!("relying party: {e:?}"))?;
        let store = Store::open(dir).map_err(|e| format!("data directory: {e}"))?;
        let ca_pem = std::fs::read_to_string(dir.join(pki::CA_FILE)).unwrap_or_default();
        Ok(Self {
            webauthn,
            store: Mutex::new(store),
            pending: Mutex::new(HashMap::new()),
            ca_pem,
        })
    }

    /// Stores a started ceremony and answers with its session and options.
    fn add_pending(&self, pending: Pending, options: &impl Serialize) -> HttpResponse {
        let mut map = self.pending.lock().expect("pending lock");
        if map.len() >= MAX_PENDING {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "too many pending ceremonies",
            );
        }
        let session = Uuid::new_v4().to_string();
        map.insert(session.clone(), pending);
        json(&Started { session, options })
    }

    /// Removes the session whatever the outcome: a ceremony is finished once.
    fn take_pending(&self, session: &str) -> Option<Pending> {
        self.pending.lock().expect("pending lock").remove(session)
    }

    fn start_registration(&self, body: &[u8]) -> HttpResponse {
        let request: StartRegistration = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(e) => return bad_request(e),
        };
        if let Err(e) = probe::validate_label(&request.label) {
            return bad_request(e);
        }
        // A fresh random user per registration: the passkey manager shows this name, so the
        // person can find and delete the test passkey later.
        let user = Uuid::new_v4();
        let name = format!("vilicus-prf-probe {}", request.label);
        let (options, state) = match self
            .webauthn
            .start_passkey_registration(user, &name, &name, None)
        {
            Ok(started) => started,
            Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e:?}")),
        };
        self.add_pending(
            Pending::Registration {
                label: request.label,
                state,
            },
            &options,
        )
    }

    fn finish_registration(&self, body: &[u8]) -> HttpResponse {
        let request: FinishRegistration = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(e) => return bad_request(e),
        };
        let Some(Pending::Registration { label, state }) = self.take_pending(&request.session)
        else {
            return bad_request("unknown or already used registration session");
        };
        if let Err(e) = request.probe.validate() {
            return bad_request(e);
        }
        let passkey = match self
            .webauthn
            .finish_passkey_registration(&request.credential, &state)
        {
            Ok(p) => p,
            Err(e) => return bad_request(format!("registration rejected: {e:?}")),
        };
        let facts = match authdata::from_attestation_object(
            request.credential.response.attestation_object.as_ref(),
        ) {
            Ok(f) => f,
            Err(e) => return bad_request(e),
        };
        let key = credential_key(passkey.cred_id().as_ref());
        let record = Record::new(
            unix_time(),
            Phase::Registration,
            &label,
            &key,
            None,
            facts,
            request.probe,
        );
        let stored = StoredCredential {
            label,
            aaguid: record.aaguid.clone(),
            passkey,
        };
        let mut store = self.store.lock().expect("store lock");
        if let Err(e) = store
            .add_credential(&key, stored)
            .and_then(|()| store.append(&record))
        {
            return error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
        }
        log_record(&record);
        json(&record)
    }

    fn start_login(&self, body: &[u8]) -> HttpResponse {
        let request: StartLogin = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(e) => return bad_request(e),
        };
        let passkey = {
            let store = self.store.lock().expect("store lock");
            match store.credentials().get(&request.credential) {
                Some(stored) => stored.passkey.clone(),
                None => return bad_request("unknown credential"),
            }
        };
        let (options, state) = match self
            .webauthn
            .start_passkey_authentication(std::slice::from_ref(&passkey))
        {
            Ok(started) => started,
            Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e:?}")),
        };
        self.add_pending(
            Pending::Login {
                key: request.credential,
                state,
            },
            &options,
        )
    }

    fn finish_login(&self, body: &[u8]) -> HttpResponse {
        let request: FinishLogin = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(e) => return bad_request(e),
        };
        let Some(Pending::Login { key, state }) = self.take_pending(&request.session) else {
            return bad_request("unknown or already used login session");
        };
        if let Err(e) = request.probe.validate() {
            return bad_request(e);
        }
        let result = match self
            .webauthn
            .finish_passkey_authentication(&request.credential, &state)
        {
            Ok(r) => r,
            Err(e) => return bad_request(format!("assertion rejected: {e:?}")),
        };
        let facts =
            match authdata::from_assertion(request.credential.response.authenticator_data.as_ref())
            {
                Ok(f) => f,
                Err(e) => return bad_request(e),
            };
        let mut store = self.store.lock().expect("store lock");
        let Some(stored) = store.credentials().get(&key).cloned() else {
            return bad_request("credential removed during the ceremony");
        };
        let record = Record::new(
            unix_time(),
            Phase::Login,
            &stored.label,
            &key,
            stored.aaguid.clone(),
            facts,
            request.probe,
        );
        let mut passkey = stored.passkey;
        let saved = if passkey.update_credential(&result).is_some() {
            store.update_passkey(&key, passkey)
        } else {
            Ok(())
        };
        if let Err(e) = saved.and_then(|()| store.append(&record)) {
            return error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
        }
        log_record(&record);
        json(&record)
    }

    fn credentials(&self) -> HttpResponse {
        let store = self.store.lock().expect("store lock");
        let entries: Vec<CredentialEntry<'_>> = store
            .credentials()
            .iter()
            .map(|(key, c)| CredentialEntry {
                credential: key,
                label: &c.label,
            })
            .collect();
        json(&entries)
    }

    fn summaries(&self) -> std::io::Result<Vec<probe::Summary>> {
        let store = self.store.lock().expect("store lock");
        store.records().map(|records| probe::summarize(&records))
    }

    /// Routes one request. Public so tests can drive it without a socket.
    pub fn route(&self, method: &Method, path: &str, body: &[u8]) -> HttpResponse {
        match (method, path) {
            (&Method::GET, "/") => respond(StatusCode::OK, "text/html; charset=utf-8", INDEX_HTML),
            (&Method::GET, "/probe.js") => {
                respond(StatusCode::OK, "text/javascript; charset=utf-8", PROBE_JS)
            }
            (&Method::GET, "/ca.crt") => respond(
                StatusCode::OK,
                "application/x-x509-ca-cert",
                self.ca_pem.clone(),
            ),
            (&Method::GET, "/api/credentials") => self.credentials(),
            (&Method::GET, "/api/summary") => match self.summaries() {
                Ok(s) => json(&s),
                Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
            },
            (&Method::GET, "/api/report") => match self.summaries() {
                Ok(s) => respond(
                    StatusCode::OK,
                    "text/plain; charset=utf-8",
                    probe::render(&s),
                ),
                Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
            },
            (&Method::POST, "/api/register/start") => self.start_registration(body),
            (&Method::POST, "/api/register/finish") => self.finish_registration(body),
            (&Method::POST, "/api/login/start") => self.start_login(body),
            (&Method::POST, "/api/login/finish") => self.finish_login(body),
            _ => error(StatusCode::NOT_FOUND, "not found"),
        }
    }
}

fn log_record(record: &Record) {
    println!(
        "CEREMONY phase={:?} credential={} prf_outputs={} authenticator_extensions={}",
        record.phase,
        record.credential,
        record.first_sha256.is_some(),
        record.authenticator_extensions.join(",")
    );
}

async fn handle(app: Arc<App>, request: Request<Incoming>) -> Result<HttpResponse, hyper::Error> {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let body = match Limited::new(request.into_body(), MAX_BODY).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return Ok(error(StatusCode::PAYLOAD_TOO_LARGE, "body too large")),
    };
    Ok(app.route(&method, &path, &body))
}

/// Generates the certificates when missing, then serves until the process is stopped.
pub async fn serve(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let generated = pki::ensure(&config.data_dir, &config.rp_id)?;
    let (chain, key) = pki::load_server(&config.data_dir)?;
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(chain, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let app = Arc::new(App::new(&config.rp_id, &config.origin, &config.data_dir)?);
    let listener = TcpListener::bind(config.listen).await?;
    println!(
        "SERVER listening={} rp_id={} origin={} certificates={} ca_sha256={}",
        listener.local_addr()?,
        config.rp_id,
        config.origin,
        if generated { "generated" } else { "loaded" },
        pem_fingerprint(&app.ca_pem).unwrap_or_else(|| "-".into()),
    );
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                eprintln!("accept failed: {e}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(stream).await else {
                return;
            };
            let service = hyper::service::service_fn(move |request| handle(app.clone(), request));
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tls), service)
                .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(name: &str) -> App {
        let dir = std::env::temp_dir().join(format!("prf-probe-app-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        pki::ensure(&dir, "prf-probe.test").unwrap();
        let origin = Url::parse("https://prf-probe.test:8443").unwrap();
        App::new("prf-probe.test", &origin, &dir).unwrap()
    }

    fn body_json(response: HttpResponse) -> serde_json::Value {
        let bytes = body_bytes(response);
        serde_json::from_slice(&bytes).unwrap()
    }

    fn body_bytes(response: HttpResponse) -> Bytes {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async { response.into_body().collect().await.unwrap().to_bytes() })
    }

    #[test]
    fn registration_options_carry_no_prf_and_a_fresh_session() {
        let app = app("options");
        let response = app.route(
            &Method::POST,
            "/api/register/start",
            br#"{"label":"device-1"}"#,
        );
        assert_eq!(response.status(), StatusCode::OK);
        let value = body_json(response);
        let public_key = &value["options"]["publicKey"];
        assert_eq!(public_key["rp"]["id"], "prf-probe.test");
        // webauthn-rs 0.5.5 does not request PRF: the page has to add it.
        assert!(
            public_key["extensions"].get("prf").is_none(),
            "{public_key}"
        );
        assert!(value["session"].as_str().is_some_and(|s| s.len() == 36));
    }

    #[test]
    fn bad_requests_are_refused() {
        let app = app("refused");
        for (path, body) in [
            ("/api/register/start", r#"{"label":"a/b"}"#),
            ("/api/register/start", r#"{"label":"ok","extra":1}"#),
            ("/api/login/start", r#"{"credential":"0000000000000000"}"#),
            ("/api/register/finish", r#"{"session":"x"}"#),
        ] {
            let response = app.route(&Method::POST, path, body.as_bytes());
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path} {body}");
        }
        let unknown = app.route(&Method::GET, "/nothing", b"");
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn page_and_script_are_served_with_a_restrictive_policy() {
        let app = app("page");
        let page = app.route(&Method::GET, "/", b"");
        assert_eq!(page.status(), StatusCode::OK);
        let csp = page.headers()["content-security-policy"].to_str().unwrap();
        assert!(csp.starts_with("default-src 'self'"));
        let script = app.route(&Method::GET, "/probe.js", b"");
        assert_eq!(script.status(), StatusCode::OK);
        let ca = body_bytes(app.route(&Method::GET, "/ca.crt", b""));
        assert!(ca.starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(pem_fingerprint(std::str::from_utf8(&ca).unwrap()).is_some_and(|f| f.len() == 95));
    }

    #[test]
    fn empty_report_is_a_header_only_table() {
        let app = app("report");
        let report = body_bytes(app.route(&Method::GET, "/api/report", b""));
        assert_eq!(std::str::from_utf8(&report).unwrap().lines().count(), 2);
    }
}
