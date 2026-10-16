//! HTTPS front: the test pages under the production-like CSP, the JSON API in front of
//! [`Core`], the test harness endpoints, and the relay.
//!
//! The server answers three names of the compose network. `core.vilicus.test` is the honest
//! path. `relay.vilicus.test` reaches the same Core through [`Relay`], which plays an on-path
//! attacker: it reads every request and response, records the pairing messages, and can
//! rewrite the new browser's public key and proof before the Core sees them. In
//! `substitute-registration` mode the relay also sits on the issuing browser's path to
//! `core.vilicus.test` and replaces the Core's OPAQUE registration response with its own. It
//! forwards the pages and scripts unchanged: an attacker who serves modified code is the
//! compromised Gateway that D35 and PRD section 8.2 exclude. `rogue.vilicus.test` carries a
//! certificate from a CA the browsers do not trust, for the negative TLS check.

use std::collections::HashMap;
use std::convert::Infallible;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::HeaderValue;
use hyper::{Request, Response, StatusCode};
use opaque_ke::{RegistrationRequest, ServerRegistration, ServerSetup};
use rand_core::OsRng;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::b64;
use crate::core::{Core, Origin, Refusal};
use crate::device::{self, Id};
use crate::pairing::{self, Suite};

/// The honest name of the server.
pub const CORE_HOST: &str = "core.vilicus.test";
/// The name that routes through the relay.
pub const RELAY_HOST: &str = "relay.vilicus.test";
/// The name whose certificate comes from an untrusted CA.
pub const ROGUE_HOST: &str = "rogue.vilicus.test";

/// Largest request body accepted; it also bounds the fields of the AD-21 byte string.
pub const MAX_BODY: usize = 64 * 1024;

/// Header carrying the session id (base64url). The product carries it in the `__Host-` cookie.
pub const SESSION_HEADER: &str = "x-vilicus-session";
/// Header carrying the per-session counter, in decimal.
pub const COUNTER_HEADER: &str = "x-vilicus-counter";
/// Header carrying the request signature (base64url).
pub const SIGNATURE_HEADER: &str = "x-vilicus-signature";

/// The CSP each page gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageKind {
    /// The application page: the production policy.
    App,
    /// The pairing page: the production policy plus `'wasm-unsafe-eval'` (AD-21).
    Pair,
    /// A test-only page that allows `eval` and enforces no Trusted Types: the positive control
    /// that shows the probes can see a weaker policy.
    Control,
}

/// The CSP of a page (spine AD-19, architecture section 6).
pub fn content_security_policy(nonce: &str, kind: PageKind) -> String {
    match kind {
        PageKind::App | PageKind::Pair => {
            let wasm = if kind == PageKind::Pair {
                " 'wasm-unsafe-eval'"
            } else {
                ""
            };
            format!(
                "default-src 'none'; script-src 'self' 'nonce-{nonce}'{wasm}; style-src 'self'; \
                 img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; \
                 frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types lit-html"
            )
        }
        PageKind::Control => format!(
            "default-src 'none'; script-src 'self' 'nonce-{nonce}' 'unsafe-eval'; connect-src 'self'; \
             base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        ),
    }
}

/// The pages and scripts the server serves, read once at start.
pub struct Site {
    pages: HashMap<&'static str, (String, PageKind)>,
    scripts: HashMap<String, Vec<u8>>,
}

fn add_scripts(
    scripts: &mut HashMap<String, Vec<u8>>,
    dir: &Path,
    prefix: &str,
) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".js") {
            scripts.insert(format!("{prefix}{name}"), std::fs::read(entry.path())?);
        }
    }
    Ok(())
}

impl Site {
    /// Reads the pages and `static/*.js` from `web_dir`, and from the `node_modules` under
    /// `deps_dir` the OPAQUE browser package (served as `/static/opaque.js`) and the `cbor2`
    /// decoder with its one dependency (served under `/vendor/`).
    pub fn load(web_dir: &Path, deps_dir: &Path) -> std::io::Result<Self> {
        let mut pages = HashMap::new();
        for (path, file, kind) in [
            ("/", "index.html", PageKind::App),
            ("/pair", "pair.html", PageKind::Pair),
            ("/control", "control.html", PageKind::Control),
        ] {
            pages.insert(path, (std::fs::read_to_string(web_dir.join(file))?, kind));
        }
        let mut scripts = HashMap::new();
        add_scripts(&mut scripts, &web_dir.join("static"), "/static/")?;
        let modules = deps_dir.join("node_modules");
        scripts.insert(
            "/static/opaque.js".to_owned(),
            std::fs::read(modules.join("@serenity-kit/opaque/esm/index.js"))?,
        );
        add_scripts(&mut scripts, &modules.join("cbor2/lib"), "/vendor/cbor2/")?;
        add_scripts(
            &mut scripts,
            &modules.join("@cto.af/wtf8/lib"),
            "/vendor/wtf8/",
        )?;
        Ok(Self { pages, scripts })
    }
}

/// What the relay does to the messages it forwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayMode {
    /// Forward unchanged and record.
    Pass,
    /// Replace the new browser's public key and proof of possession with the relay's own.
    SubstituteKey,
    /// On the issuing browser's path, replace the Core's OPAQUE registration response with an
    /// evaluation under the relay's own OPRF key, keeping the Core's server public key and
    /// signature: the record the issuer then uploads would let the relay test guesses offline.
    SubstituteRegistration,
}

/// The on-path attacker of the relay host.
pub struct Relay {
    mode: RelayMode,
    key: EcdsaKeyPair,
    opaque: ServerSetup<Suite>,
    rng: SystemRandom,
    login_start: Option<Vec<u8>>,
    login_finish: Option<Vec<u8>>,
}

impl Relay {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("key generation works");
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
            .expect("a fresh PKCS#8 parses");
        Self {
            mode: RelayMode::Pass,
            key,
            opaque: ServerSetup::<Suite>::new(&mut OsRng),
            rng,
            login_start: None,
            login_finish: None,
        }
    }

    fn public_key(&self) -> &[u8] {
        self.key.public_key().as_ref()
    }

    /// Rewrites a login finish body under [`RelayMode::SubstituteKey`]: the relay's public key,
    /// with a valid proof of possession under the relay's key. It cannot recompute the binding
    /// tag, which needs the OPAQUE session key, so it keeps the browser's.
    fn substitute_key(&self, body: &[u8]) -> Option<Vec<u8>> {
        let mut finish: Value = serde_json::from_slice(body).ok()?;
        let start: Value = serde_json::from_slice(self.login_start.as_deref()?).ok()?;
        let handle = start.get("handle")?.as_str()?;
        let login_id = b64::decode(finish.get("login_id")?.as_str()?)?;
        let relay_key = self.public_key();
        let message = pairing::bind_message(handle, &login_id, relay_key);
        let proof = self
            .key
            .sign(&self.rng, &device::pop_message(&message, relay_key))
            .ok()?;
        finish["public_key"] = Value::from(b64::encode(relay_key));
        finish["proof"] = Value::from(b64::encode(proof.as_ref()));
        serde_json::to_vec(&finish).ok()
    }

    /// Rewrites an issue-start response under [`RelayMode::SubstituteRegistration`]: the
    /// evaluation element becomes the relay's, the server public key (the last 32 bytes) and
    /// the Core's signature stay.
    fn substitute_registration(
        &self,
        request_body: &[u8],
        response_body: &[u8],
    ) -> Option<Vec<u8>> {
        let request: Value = serde_json::from_slice(request_body).ok()?;
        let mut response: Value = serde_json::from_slice(response_body).ok()?;
        let blinded = b64::decode(request.get("registration_request")?.as_str()?)?;
        let core_response = b64::decode(response.get("registration_response")?.as_str()?)?;
        let message = RegistrationRequest::<Suite>::deserialize(&blinded).ok()?;
        let mut forged = ServerRegistration::<Suite>::start(&self.opaque, message, b"relay")
            .ok()?
            .message
            .serialize()
            .to_vec();
        let key_start = forged.len().checked_sub(32)?;
        forged[key_start..].copy_from_slice(core_response.get(key_start..)?);
        response["registration_response"] = Value::from(b64::encode(&forged));
        serde_json::to_vec(&response).ok()
    }
}

/// Shared server state.
pub struct State {
    core: Mutex<Core>,
    relay: Mutex<Relay>,
    site: Site,
    rng: SystemRandom,
}

impl State {
    /// A fresh Core and relay serving `site`.
    pub fn new(site: Site) -> Arc<Self> {
        Arc::new(Self {
            core: Mutex::new(Core::new()),
            relay: Mutex::new(Relay::new()),
            site,
            rng: SystemRandom::new(),
        })
    }

    fn core(&self) -> MutexGuard<'_, Core> {
        self.core
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn relay(&self) -> MutexGuard<'_, Relay> {
        self.relay
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// A request as the handlers see it.
#[derive(Clone)]
pub struct Req {
    /// The peer address of the connection, the key of the login rate limit.
    pub source: String,
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Req {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// A response as the handlers produce it.
pub struct Resp {
    pub status: StatusCode,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

fn json_response(status: StatusCode, value: &Value) -> Resp {
    Resp {
        status,
        headers: vec![
            ("content-type", "application/json".to_owned()),
            ("cache-control", "no-store".to_owned()),
        ],
        body: serde_json::to_vec(value).unwrap_or_default(),
    }
}

fn ok(value: Value) -> Resp {
    json_response(StatusCode::OK, &value)
}

fn refused(refusal: Refusal) -> Resp {
    let status = match refusal {
        Refusal::UnknownSession
        | Refusal::MissingSignature
        | Refusal::BadRequestSignature
        | Refusal::CounterNotIncreasing => StatusCode::UNAUTHORIZED,
        Refusal::BadMessage => StatusCode::BAD_REQUEST,
        Refusal::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        _ => StatusCode::FORBIDDEN,
    };
    json_response(status, &json!({ "error": refusal.code() }))
}

fn not_found() -> Resp {
    json_response(StatusCode::NOT_FOUND, &json!({ "error": "not_found" }))
}

fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, Refusal> {
    serde_json::from_slice(body).map_err(|_| Refusal::BadMessage)
}

fn id(text: &str) -> Result<Id, Refusal> {
    b64::decode_array(text).ok_or(Refusal::BadMessage)
}

fn bytes(text: &str) -> Result<Vec<u8>, Refusal> {
    b64::decode(text).ok_or(Refusal::BadMessage)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollBody {
    token: String,
    public_key: String,
    proof: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceBody {
    device_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenSessionBody {
    device_id: String,
    nonce: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueStartBody {
    registration_request: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueFinishBody {
    handle: String,
    registration_upload: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginStartBody {
    handle: String,
    credential_request: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginFinishBody {
    login_id: String,
    credential_finalization: String,
    public_key: String,
    tag: String,
    proof: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestIdBody {
    request_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveBody {
    request_id: String,
    nonce: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingBody {
    device_id: String,
    title: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClockBody {
    seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyBody {
    public_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HandleBody {
    handle: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModeBody {
    mode: String,
}

/// Verifies the AD-21 signature headers of a request; returns the session's device.
fn signed_device(state: &State, req: &Req) -> Result<Id, Refusal> {
    let session_id = req
        .header(SESSION_HEADER)
        .ok_or(Refusal::UnknownSession)
        .and_then(id)?;
    let counter = req
        .header(COUNTER_HEADER)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(Refusal::MissingSignature)?;
    let signature = req.header(SIGNATURE_HEADER).map(bytes).transpose()?;
    state.core().verify_request(
        &session_id,
        counter,
        &req.method,
        &req.path,
        &req.body,
        signature.as_deref(),
    )
}

fn script(body: &[u8]) -> Resp {
    Resp {
        status: StatusCode::OK,
        headers: vec![
            ("content-type", "text/javascript; charset=utf-8".to_owned()),
            ("x-content-type-options", "nosniff".to_owned()),
            ("cache-control", "no-store".to_owned()),
        ],
        body: body.to_vec(),
    }
}

/// The API and the pages, as the Core-side Gateway serves them.
fn handle_core(state: &State, req: &Req) -> Result<Resp, Refusal> {
    let path = req.path.split('?').next().unwrap_or_default();
    match (req.method.as_str(), path) {
        ("GET", "/" | "/pair" | "/control") => Ok(page(state, path)),
        ("GET", name) if state.site.scripts.contains_key(name) => {
            Ok(script(&state.site.scripts[name]))
        }
        ("POST", "/api/enroll") => {
            let body: EnrollBody = parse(&req.body)?;
            let mut core = state.core();
            let registered = core.enroll(
                &id(&body.token)?,
                &bytes(&body.public_key)?,
                &bytes(&body.proof)?,
            )?;
            Ok(ok(json!({
                "device_id": b64::encode(&registered.device_id),
                "session_id": b64::encode(&registered.session_id),
                "core_key": b64::encode(&core.identity_public_key()),
            })))
        }
        ("POST", "/api/session/challenge") => {
            let body: DeviceBody = parse(&req.body)?;
            let nonce = state.core().session_challenge(&id(&body.device_id)?)?;
            Ok(ok(json!({ "nonce": b64::encode(&nonce) })))
        }
        ("POST", "/api/session/open") => {
            let body: OpenSessionBody = parse(&req.body)?;
            let session_id = state.core().open_session(
                &id(&body.device_id)?,
                &id(&body.nonce)?,
                &bytes(&body.signature)?,
            )?;
            Ok(ok(json!({ "session_id": b64::encode(&session_id) })))
        }
        ("POST", "/api/echo") => {
            let device_id = signed_device(state, req)?;
            Ok(ok(json!({
                "device_id": b64::encode(&device_id),
                "body_sha256": b64::encode(&device::sha256(&req.body)),
            })))
        }
        ("POST", "/api/pair/issue/start") => {
            let device_id = signed_device(state, req)?;
            let body: IssueStartBody = parse(&req.body)?;
            let issued = state
                .core()
                .issue_start(&device_id, &bytes(&body.registration_request)?)?;
            Ok(ok(json!({
                "handle": issued.handle,
                "registration_response": b64::encode(&issued.response),
                "signature": b64::encode(&issued.signature),
            })))
        }
        ("POST", "/api/pair/issue/finish") => {
            let device_id = signed_device(state, req)?;
            let body: IssueFinishBody = parse(&req.body)?;
            let expires_in = state.core().issue_finish(
                &device_id,
                &body.handle,
                &bytes(&body.registration_upload)?,
            )?;
            Ok(ok(json!({ "expires_in": expires_in })))
        }
        ("POST", "/api/pair/login/start") => {
            let body: LoginStartBody = parse(&req.body)?;
            let (login_id, response) = state.core().login_start(
                &req.source,
                &body.handle,
                &bytes(&body.credential_request)?,
            )?;
            Ok(ok(json!({
                "login_id": b64::encode(&login_id),
                "credential_response": b64::encode(&response),
            })))
        }
        ("POST", "/api/pair/login/finish") => {
            let body: LoginFinishBody = parse(&req.body)?;
            let mut core = state.core();
            let (registered, core_key_tag) = core.login_finish(
                &id(&body.login_id)?,
                &bytes(&body.credential_finalization)?,
                &bytes(&body.public_key)?,
                &bytes(&body.tag)?,
                &bytes(&body.proof)?,
            )?;
            Ok(ok(json!({
                "device_id": b64::encode(&registered.device_id),
                "session_id": b64::encode(&registered.session_id),
                "core_key": b64::encode(&core.identity_public_key()),
                "core_key_tag": b64::encode(&core_key_tag),
            })))
        }
        ("POST", "/api/pending/challenge") => {
            let device_id = signed_device(state, req)?;
            let body: RequestIdBody = parse(&req.body)?;
            let (nonce, bytes) = state
                .core()
                .confirmation_challenge(&device_id, &id(&body.request_id)?)?;
            Ok(ok(
                json!({ "nonce": b64::encode(&nonce), "bytes": b64::encode(&bytes) }),
            ))
        }
        ("POST", "/api/pending/approve") => {
            let device_id = signed_device(state, req)?;
            let body: ApproveBody = parse(&req.body)?;
            state.core().approve(
                &device_id,
                &id(&body.request_id)?,
                &id(&body.nonce)?,
                &bytes(&body.signature)?,
            )?;
            Ok(ok(json!({ "approved": true })))
        }
        _ => Ok(not_found()),
    }
}

/// Test harness endpoints, on the Core's name only: they stand for the host CLI and for the
/// assistant that creates pending requests.
fn handle_harness(state: &State, req: &Req) -> Result<Resp, Refusal> {
    match (req.method.as_str(), req.path.as_str()) {
        ("POST", "/__test/enrollment-token") => {
            let token = state.core().issue_enrollment_token();
            Ok(ok(json!({ "token": b64::encode(&token) })))
        }
        ("POST", "/__test/host-pair") => {
            let code = state.core().issue_on_host()?;
            Ok(ok(json!({ "code": code.display() })))
        }
        ("POST", "/__test/advance-clock") => {
            let body: ClockBody = parse(&req.body)?;
            state.core().advance_clock(body.seconds);
            Ok(ok(json!({ "advanced": body.seconds })))
        }
        ("POST", "/__test/reset-login-rate") => {
            state.core().reset_login_rate();
            Ok(ok(json!({ "reset": true })))
        }
        ("POST", "/__test/pending") => {
            let body: PendingBody = parse(&req.body)?;
            let request_id =
                state
                    .core()
                    .create_pending(&id(&body.device_id)?, "tasks.create", &body.title)?;
            Ok(ok(json!({ "request_id": b64::encode(&request_id) })))
        }
        ("POST", "/__test/pairing-state") => {
            let body: HandleBody = parse(&req.body)?;
            let found = state.core().pairing_state(&body.handle);
            Ok(ok(match found {
                Some(s) => json!({
                    "exists": true,
                    "registered": s.registered,
                    "attempts": s.attempts,
                    "used": s.used,
                    "expired": s.expired,
                }),
                None => json!({ "exists": false }),
            }))
        }
        ("POST", "/__test/device-by-key") => {
            let body: KeyBody = parse(&req.body)?;
            let found = state.core().device_by_key(&bytes(&body.public_key)?);
            Ok(ok(json!({
                "registered": found.is_some(),
                "origin": found.map(|(_, origin)| match origin {
                    Origin::Enrollment => "enrollment",
                    Origin::Pairing => "pairing",
                }),
            })))
        }
        _ => Ok(not_found()),
    }
}

/// The relay host: control endpoints, then the Core behind the attacker.
fn handle_relay(state: &State, req: &Req) -> Result<Resp, Refusal> {
    match (req.method.as_str(), req.path.as_str()) {
        ("POST", "/__relay/mode") => {
            let body: ModeBody = parse(&req.body)?;
            let mode = match body.mode.as_str() {
                "pass" => RelayMode::Pass,
                "substitute-key" => RelayMode::SubstituteKey,
                "substitute-registration" => RelayMode::SubstituteRegistration,
                _ => return Err(Refusal::BadMessage),
            };
            let mut relay = state.relay();
            relay.mode = mode;
            relay.login_start = None;
            relay.login_finish = None;
            Ok(ok(json!({ "mode": body.mode })))
        }
        ("GET", "/__relay/key") => Ok(ok(
            json!({ "public_key": b64::encode(state.relay().public_key()) }),
        )),
        ("POST", "/__relay/replay") => {
            // An observer resends the recorded pairing messages to the Core, unchanged.
            let (start, finish) = {
                let relay = state.relay();
                (relay.login_start.clone(), relay.login_finish.clone())
            };
            let outcome = |body: Option<Vec<u8>>, path: &str| -> Value {
                let Some(body) = body else {
                    return Value::from("not_recorded");
                };
                let forged = Req {
                    source: req.source.clone(),
                    method: "POST".to_owned(),
                    path: path.to_owned(),
                    headers: Vec::new(),
                    body,
                };
                let resp = handle_core(state, &forged).unwrap_or_else(refused);
                let value: Value = serde_json::from_slice(&resp.body).unwrap_or(Value::Null);
                value
                    .get("error")
                    .cloned()
                    .unwrap_or_else(|| Value::from("accepted"))
            };
            Ok(ok(json!({
                "finish": outcome(finish, "/api/pair/login/finish"),
                "start": outcome(start, "/api/pair/login/start"),
            })))
        }
        _ => {
            let mut forwarded = req.clone();
            {
                let mut relay = state.relay();
                match req.path.as_str() {
                    "/api/pair/login/start" => relay.login_start = Some(req.body.clone()),
                    "/api/pair/login/finish" => {
                        relay.login_finish = Some(req.body.clone());
                        if relay.mode == RelayMode::SubstituteKey
                            && let Some(body) = relay.substitute_key(&req.body)
                        {
                            forwarded.body = body;
                        }
                    }
                    _ => {}
                }
            }
            handle_core(state, &forwarded)
        }
    }
}

fn page(state: &State, path: &str) -> Resp {
    let (template, kind) = &state.site.pages[path];
    let mut raw = [0u8; 16];
    state.rng.fill(&mut raw).expect("the system RNG works");
    let nonce = b64::encode(&raw);
    Resp {
        status: StatusCode::OK,
        headers: vec![
            ("content-type", "text/html; charset=utf-8".to_owned()),
            (
                "content-security-policy",
                content_security_policy(&nonce, *kind),
            ),
            ("x-content-type-options", "nosniff".to_owned()),
            ("referrer-policy", "no-referrer".to_owned()),
            ("cache-control", "no-store".to_owned()),
        ],
        body: template.replace("{{NONCE}}", &nonce).into_bytes(),
    }
}

/// Routes one request by host name.
pub fn route(state: &State, host: &str, req: &Req) -> Resp {
    let result = match host {
        CORE_HOST if req.path.starts_with("/__test/") => handle_harness(state, req),
        CORE_HOST => handle_core(state, req).map(|resp| {
            // The relay on the issuing browser's path, in its registration mode only.
            let relay = state.relay();
            if relay.mode == RelayMode::SubstituteRegistration
                && req.path == "/api/pair/issue/start"
                && resp.status == StatusCode::OK
                && let Some(body) = relay.substitute_registration(&req.body, &resp.body)
            {
                Resp { body, ..resp }
            } else {
                resp
            }
        }),
        RELAY_HOST => handle_relay(state, req),
        _ => Ok(not_found()),
    };
    result.unwrap_or_else(refused)
}

/// Adapts [`route`] to hyper.
pub async fn serve(
    state: Arc<State>,
    source: String,
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = request.into_parts();
    let host = parts
        .headers
        .get(hyper::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(':').next().unwrap_or_default().to_owned())
        .unwrap_or_default();
    let body = match Limited::new(body, MAX_BODY).collect().await {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(_) => {
            return Ok(into_hyper(json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                &json!({ "error": "too_large" }),
            )));
        }
    };
    let req = Req {
        source,
        method: parts.method.as_str().to_owned(),
        path: parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str().to_owned())
            .unwrap_or_default(),
        headers: parts
            .headers
            .iter()
            .filter_map(|(name, value)| {
                Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
            })
            .collect(),
        body,
    };
    let resp = route(&state, &host, &req);
    Ok(into_hyper(resp))
}

fn into_hyper(resp: Resp) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(resp.body)));
    *response.status_mut() = resp.status;
    for (name, value) in resp.headers {
        if let Ok(value) = HeaderValue::from_str(&value) {
            response.headers_mut().insert(name, value);
        }
    }
    response
}
