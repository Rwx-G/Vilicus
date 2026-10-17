//! Request handling for every role, independent of the HTTP stack so it can be unit tested.
//!
//! The client origin's GET routes are dispatched to a function that receives a read-only snapshot
//! of the state ([`ReadView`]), so no GET route can have a side effect: that is the property AD-19
//! relies on, because the session cookie accompanies requests from the same-site content origin.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::fixtures;
use crate::json;
use crate::log::{Entry, Log};
use crate::policy::{self, CONTENT_PORT, ContentMode};

/// Which server a listener belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The client origin: `https://<name>`.
    App,
    /// The external-content origin: `https://<name>:8443`.
    Content,
    /// The attacker's site.
    Sink,
    /// The test-only control listener.
    Control,
}

/// Whether the listener terminates TLS itself or sits behind a reverse proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tls,
    Plain,
}

/// A request as the handlers see it.
#[derive(Debug, Clone, Default)]
pub struct Request {
    pub method: String,
    /// The `Host` header or the HTTP/2 `:authority`.
    pub host: String,
    pub path: String,
    pub query: String,
    /// Header names in lowercase.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub peer: String,
}

impl Request {
    /// The first value of header `name` (lowercase), or an empty string.
    pub fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map_or("", |(_, v)| v.as_str())
    }

    /// The value of query parameter `name`, or an empty string.
    pub fn query_param(&self, name: &str) -> &str {
        self.query
            .split('&')
            .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
            .unwrap_or("")
    }
}

/// A response as the handlers produce it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    fn new(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), content_type.into())],
            body: body.into(),
        }
    }

    fn with(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    fn with_all(self, headers: &[(&str, &str)]) -> Self {
        headers.iter().fold(self, |r, (n, v)| r.with(n, v))
    }

    /// The first value of header `name`, or an empty string.
    pub fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map_or("", |(_, v)| v.as_str())
    }
}

/// How the client page frames each mode: the content path prefix and the iframe's `sandbox`
/// attribute (`None`: no attribute). `prod` is the configuration under test.
pub const CLIENT_MODES: [(&str, ContentMode, Option<&str>); 7] = [
    ("prod", ContentMode::Production, Some("")),
    ("unsanitized", ContentMode::Unsanitized, Some("")),
    ("csp-only", ContentMode::CspOnly, None),
    ("inline-style", ContentMode::InlineStyle, Some("")),
    (
        "open",
        ContentMode::Raw,
        Some("allow-scripts allow-forms allow-popups allow-top-navigation-by-user-activation"),
    ),
    ("scripts", ContentMode::Raw, Some("allow-scripts")),
    ("sandbox-only", ContentMode::Raw, Some("")),
];

/// The header the API requires on a state-changing request: a stand-in for the device-key
/// signature of AD-21, which a cross-origin form or a no-cors fetch cannot add.
pub const SIGNATURE_HEADER: &str = "x-vilicus-signature";

/// The client page. The first script has no nonce and must not run; the second runs, checks
/// Trusted Types, logs in, records any `postMessage` it receives (acting on none), and frames the
/// external content in the requested mode.
const APP_PAGE: &str = r#"<!doctype html>
<html><head><meta charset="utf-8"><title>Vilicus E26 client</title></head>
<body><h1>client</h1>
<script>document.documentElement.setAttribute('data-unnonced-ran', '1');</script>
<script nonce="{NONCE}">
(async function () {
  const root = document.documentElement;
  const mark = (k, v) => root.setAttribute('data-' + k, String(v));
  mark('nonce-ran', '1');
  try { document.body.insertAdjacentHTML('beforeend', '<b>x</b>'); mark('tt', 'not-enforced'); }
  catch (e) { mark('tt', 'enforced:' + e.name); }
  try { trustedTypes.createPolicy('not-allowed', { createHTML: (s) => s }); mark('tt-policy', 'created'); }
  catch (e) { mark('tt-policy', 'refused:' + e.name); }
  let messages = 0;
  window.addEventListener('message', (event) => {
    messages += 1;
    mark('messages', messages);
    mark('message-origin', event.origin);
  });
  const login = await fetch('/api/login', { method: 'POST' });
  mark('login', login.status);
  mark('cookie-visible', document.cookie.includes('vilicus_session') ? 'yes' : 'no');
  const params = new URLSearchParams(location.search);
  const modes = {MODES};
  const mode = modes[params.get('mode')];
  if (!mode) { mark('ready', 'bad-mode'); return; }
  const frame = document.createElement('iframe');
  if (mode.sandbox !== null) { frame.setAttribute('sandbox', mode.sandbox); }
  frame.id = 'external';
  frame.width = '800';
  frame.height = '600';
  frame.addEventListener('load', () => {
    mark('frame-loads', Number(root.getAttribute('data-frame-loads') || 0) + 1);
  });
  frame.src = 'https://' + location.hostname + ':{CONTENT_PORT}' + mode.prefix
    + encodeURIComponent(params.get('fixture') || '') + '?run=' + encodeURIComponent(params.get('run') || '');
  document.body.append(frame);
  mark('ready', '1');
})();
</script>
</body></html>
"#;

fn modes_json() -> String {
    let members: Vec<String> = CLIENT_MODES
        .iter()
        .map(|(name, mode, sandbox)| {
            let prefix = ContentMode::PREFIXES
                .iter()
                .find(|(_, m)| m == mode)
                .map_or("", |(p, _)| p);
            let sandbox = sandbox.map_or_else(|| "null".to_owned(), json::string);
            format!(
                "{}:{{\"prefix\":{},\"sandbox\":{sandbox}}}",
                json::string(name),
                json::string(prefix)
            )
        })
        .collect();
    format!("{{{}}}", members.join(","))
}

/// The client page with `nonce`.
pub fn app_page(nonce: &str) -> String {
    APP_PAGE
        .replace("{NONCE}", nonce)
        .replace("{MODES}", &modes_json())
        .replace("{CONTENT_PORT}", &CONTENT_PORT.to_string())
}

/// Hex of `n` random bytes from the TLS provider's generator.
pub fn random_hex(n: usize) -> String {
    let mut bytes = vec![0_u8; n];
    // The aws-lc-rs generator does not fail in practice; a zeroed buffer would only weaken a
    // test nonce, and the tests check that two values differ.
    let _ = rustls::crypto::aws_lc_rs::default_provider()
        .secure_random
        .fill(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Session state as a GET handler may see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Session {
    Absent,
    Unknown,
    Valid,
}

/// The read-only snapshot GET handlers receive.
#[derive(Debug, Clone, Copy)]
pub struct ReadView {
    pub mutations: u64,
    pub session: Session,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppGet {
    Page,
    State,
    Probe,
    ActionGet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppPost {
    Login,
    Action,
    CspReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppRoute {
    Get(AppGet),
    Post(AppPost),
    NotFound,
}

/// How a route matches the request path.
#[derive(Debug, Clone, Copy)]
enum PathMatch {
    Exact(&'static str),
    Prefix(&'static str),
}

/// Every route of the client origin. GET routes serve HEAD too. A GET route reaches only
/// `app_get`, which sees a read-only snapshot; the tests iterate this table.
const APP_ROUTES: [(&str, PathMatch, AppRoute); 7] = [
    ("GET", PathMatch::Exact("/"), AppRoute::Get(AppGet::Page)),
    (
        "GET",
        PathMatch::Exact("/api/state"),
        AppRoute::Get(AppGet::State),
    ),
    (
        "GET",
        PathMatch::Exact("/api/action"),
        AppRoute::Get(AppGet::ActionGet),
    ),
    (
        "GET",
        PathMatch::Prefix("/api/probe/"),
        AppRoute::Get(AppGet::Probe),
    ),
    (
        "POST",
        PathMatch::Exact("/api/login"),
        AppRoute::Post(AppPost::Login),
    ),
    (
        "POST",
        PathMatch::Exact("/api/action"),
        AppRoute::Post(AppPost::Action),
    ),
    (
        "POST",
        PathMatch::Exact("/csp-report"),
        AppRoute::Post(AppPost::CspReport),
    ),
];

fn route_app(method: &str, path: &str) -> AppRoute {
    let method = if method == "HEAD" { "GET" } else { method };
    APP_ROUTES
        .iter()
        .find(|(m, matcher, _)| {
            *m == method
                && match matcher {
                    PathMatch::Exact(p) => path == *p,
                    PathMatch::Prefix(p) => path.starts_with(p),
                }
        })
        .map_or(AppRoute::NotFound, |(_, _, route)| *route)
}

/// Every GET handler of the client origin. It cannot change state: it only sees a [`ReadView`].
fn app_get(route: AppGet, view: ReadView, frame_src: &str) -> (Response, &'static str) {
    match route {
        AppGet::Page => {
            let nonce = random_hex(16);
            let response = Response::new(200, "text/html; charset=utf-8", app_page(&nonce)).with(
                "content-security-policy",
                &policy::app_csp(&nonce, frame_src),
            );
            (response, "page")
        }
        AppGet::State => {
            let body = json::Object::default()
                .num("mutations", view.mutations)
                .str(
                    "session",
                    match view.session {
                        Session::Absent => "absent",
                        Session::Unknown => "unknown",
                        Session::Valid => "valid",
                    },
                )
                .finish();
            (api(200, body), "state")
        }
        AppGet::Probe => (api(204, ""), "probe"),
        AppGet::ActionGet => (api(405, "").with("allow", "POST"), "method-not-allowed"),
    }
}

fn api(status: u16, body: impl Into<Vec<u8>>) -> Response {
    Response::new(status, "application/json", body).with("content-security-policy", policy::API_CSP)
}

/// The Gateway stand-in: both origins of every instance name, and their shared state.
pub struct Gateway {
    direct: Vec<String>,
    proxied: Vec<String>,
    test_controls: bool,
    sessions: Mutex<HashSet<String>>,
    mutations: AtomicU64,
    pub log: Arc<Log>,
}

impl Gateway {
    /// `direct` names are served over the TLS listeners, `proxied` names over the plain ones.
    /// `test_controls` enables the raw (no CSP) content mode.
    pub fn new(direct: Vec<String>, proxied: Vec<String>, test_controls: bool) -> Self {
        Self {
            direct,
            proxied,
            test_controls,
            sessions: Mutex::new(HashSet::new()),
            mutations: AtomicU64::new(0),
            log: Arc::new(Log::default()),
        }
    }

    /// The number of state changes so far.
    pub fn mutations(&self) -> u64 {
        self.mutations.load(Ordering::SeqCst)
    }

    /// The instance name of `host` if this listener serves it, else `None`.
    fn instance<'a>(&self, role: Role, transport: Transport, host: &'a str) -> Option<&'a str> {
        let names = match transport {
            Transport::Tls => &self.direct,
            Transport::Plain => &self.proxied,
        };
        let content_port = format!(":{CONTENT_PORT}");
        let name = match role {
            Role::App => host.strip_suffix(":443").unwrap_or(host),
            Role::Content => host.strip_suffix(content_port.as_str())?,
            Role::Sink | Role::Control => return None,
        };
        names.iter().any(|n| n == name).then_some(name)
    }

    fn session(&self, request: &Request) -> Session {
        let Some(value) = policy::session_from_cookie_header(request.header("cookie")) else {
            return Session::Absent;
        };
        let sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if sessions.contains(value) {
            Session::Valid
        } else {
            Session::Unknown
        }
    }

    /// Handles one request on a client or content listener and logs it.
    pub fn handle(
        &self,
        role: Role,
        transport: Transport,
        listener: &'static str,
        request: &Request,
    ) -> Response {
        let (response, outcome) = match self.instance(role, transport, &request.host) {
            None => (api(421, ""), "misdirected"),
            Some(name) => match role {
                Role::App => self.app(request, name),
                Role::Content => self.content(request, name),
                Role::Sink | Role::Control => (api(404, ""), "not-found"),
            },
        };
        let is_report = request.path == "/csp-report";
        self.log
            .push(request_entry(listener, request, outcome, is_report));
        let common = response.with_all(&policy::COMMON_HEADERS);
        match role {
            Role::App => common.with_all(&policy::APP_HEADERS),
            _ => common,
        }
    }

    fn app(&self, request: &Request, name: &str) -> (Response, &'static str) {
        match route_app(&request.method, &request.path) {
            AppRoute::Get(route) => {
                let view = ReadView {
                    mutations: self.mutations(),
                    session: self.session(request),
                };
                let frame_src = if self.test_controls && request.query_param("relax") == "1" {
                    policy::RELAXED_FRAME_SOURCE.to_owned()
                } else {
                    policy::content_frame_source(name)
                };
                app_get(route, view, &frame_src)
            }
            AppRoute::Post(route) => self.app_post(route, request),
            AppRoute::NotFound => (api(404, ""), "not-found"),
        }
    }

    fn app_post(&self, route: AppPost, request: &Request) -> (Response, &'static str) {
        match route {
            AppPost::Login => {
                let value = random_hex(32);
                self.sessions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(value.clone());
                let response = api(204, "").with("set-cookie", &policy::session_cookie(&value));
                (response, "login")
            }
            AppPost::Action => {
                if self.session(request) != Session::Valid {
                    return (api(403, ""), "refused-no-session");
                }
                if request.header(SIGNATURE_HEADER).is_empty() {
                    return (api(403, ""), "refused-no-signature");
                }
                self.mutations.fetch_add(1, Ordering::SeqCst);
                (api(200, "{}"), "mutated")
            }
            AppPost::CspReport => (api(204, ""), "csp-report"),
        }
    }

    fn content(&self, request: &Request, name: &str) -> (Response, &'static str) {
        if request.method == "POST" && request.path == "/csp-report" {
            return (api(204, ""), "csp-report");
        }
        if request.method != "GET" && request.method != "HEAD" {
            return (api(405, ""), "method-not-allowed");
        }
        let Some((mode, fixture)) = ContentMode::from_path(&request.path) else {
            return (api(404, ""), "not-found");
        };
        if mode == ContentMode::Raw && !self.test_controls {
            return (api(404, ""), "not-found");
        }
        let app_origin = format!("https://{name}");
        let run = request.query_param("run");
        let rendered = if mode == ContentMode::Production {
            fixtures::render_sanitized(fixture, run, &app_origin)
        } else {
            fixtures::render(fixture, run, &app_origin)
        };
        let Some(html) = rendered else {
            return (api(404, ""), "not-found");
        };
        let mut response = Response::new(200, "text/html; charset=utf-8", html);
        if let Some(csp) = policy::content_csp(mode, &app_origin) {
            response = response.with("content-security-policy", &csp);
        }
        // Every mode but the raw control keeps the non-CSP headers, so the CSP-only ablation
        // differs from production by the `sandbox` directive alone.
        if mode != ContentMode::Raw {
            response = response.with_all(&policy::CONTENT_HEADERS);
        }
        (response, "fixture")
    }
}

/// The attacker's site: logs everything and answers with a page only where a click lands.
pub fn sink(listener: &'static str, request: &Request, log: &Log) -> Response {
    log.push(request_entry(listener, request, "sink", false));
    if request.path.starts_with("/v/click-link") {
        let run = request.host.split('-').next().unwrap_or("");
        if fixtures::valid_run(run) {
            return Response::new(200, "text/html; charset=utf-8", fixtures::sink_page(run));
        }
    }
    Response::new(200, "text/plain", "sink")
}

/// The constants the browser harness derives its checks from: the fixtures and their vectors,
/// the session cookie's name, the content port and the production content CSP for the instance
/// name `NAME`.
pub fn catalogue() -> String {
    let content_csp =
        policy::content_csp(ContentMode::Production, "https://NAME").unwrap_or_default();
    let modes: Vec<String> = CLIENT_MODES
        .iter()
        .map(|(name, _, _)| json::string(name))
        .collect();
    format!(
        "{{\"session_cookie\":{},\"content_port\":{CONTENT_PORT},\"content_csp\":{},         \"content_headers\":{},\"modes\":{},\"fixtures\":{}}}",
        json::string(policy::SESSION_COOKIE),
        json::string(&content_csp),
        json::array(
            &policy::CONTENT_HEADERS
                .iter()
                .map(|(n, v)| json::Object::default()
                    .str("name", n)
                    .str("value", v)
                    .finish())
                .collect::<Vec<_>>()
        ),
        json::array(&modes),
        fixtures::catalogue_json()
    )
}

/// The test-only control listener: the observation log, the state counter and the catalogue.
pub fn control(request: &Request, log: &Log, mutations: Option<u64>) -> Response {
    match request.path.as_str() {
        "/log" => Response::new(
            200,
            "application/json",
            log.to_json(request.query_param("contains")),
        ),
        "/state" => Response::new(
            200,
            "application/json",
            json::Object::default()
                .num("mutations", mutations.unwrap_or(0))
                .finish(),
        ),
        "/catalogue" => Response::new(200, "application/json", catalogue()),
        _ => Response::new(404, "text/plain", ""),
    }
}

fn request_entry(
    listener: &'static str,
    request: &Request,
    outcome: &str,
    keep_body: bool,
) -> Entry {
    let cookie = request.header("cookie");
    let cookie_names: Vec<&str> = cookie
        .split(';')
        .filter_map(|pair| pair.split('=').next())
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .collect();
    let target = if request.query.is_empty() {
        request.path.clone()
    } else {
        format!("{}?{}", request.path, request.query)
    };
    let body = if keep_body {
        String::from_utf8_lossy(&request.body[..request.body.len().min(16 * 1024)]).into_owned()
    } else {
        String::new()
    };
    Entry {
        kind: "http",
        listener,
        peer: request.peer.clone(),
        method: request.method.clone(),
        host: request.host.clone(),
        target,
        session_cookie: policy::session_from_cookie_header(cookie).is_some(),
        cookie_names: cookie_names.join(","),
        sec_fetch_site: request.header("sec-fetch-site").into(),
        sec_fetch_mode: request.header("sec-fetch-mode").into(),
        sec_fetch_dest: request.header("sec-fetch-dest").into(),
        origin: request.header("origin").into(),
        content_type: request.header("content-type").into(),
        outcome: outcome.into(),
        body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME: &str = "vilicus.internal";

    fn gateway() -> Gateway {
        Gateway::new(vec![NAME.into()], vec!["proxied.internal".into()], true)
    }

    fn request(method: &str, host: &str, path: &str) -> Request {
        let (path, query) = path.split_once('?').unwrap_or((path, ""));
        Request {
            method: method.into(),
            host: host.into(),
            path: path.into(),
            query: query.into(),
            ..Request::default()
        }
    }

    fn login(gateway: &Gateway) -> String {
        let response = gateway.handle(
            Role::App,
            Transport::Tls,
            "app-tls",
            &request("POST", NAME, "/api/login"),
        );
        let cookie = response.header("set-cookie");
        cookie.split(';').next().unwrap_or("").to_owned()
    }

    #[test]
    fn hosts_are_bound_to_their_role_and_transport() {
        let g = gateway();
        assert_eq!(g.instance(Role::App, Transport::Tls, NAME), Some(NAME));
        assert_eq!(
            g.instance(Role::App, Transport::Tls, "vilicus.internal:443"),
            Some(NAME)
        );
        assert_eq!(
            g.instance(Role::App, Transport::Tls, "vilicus.internal:8443"),
            None
        );
        assert_eq!(
            g.instance(Role::Content, Transport::Tls, "vilicus.internal:8443"),
            Some(NAME)
        );
        assert_eq!(g.instance(Role::Content, Transport::Tls, NAME), None);
        assert_eq!(g.instance(Role::App, Transport::Plain, NAME), None);
        assert_eq!(
            g.instance(Role::App, Transport::Plain, "proxied.internal"),
            Some("proxied.internal")
        );
        assert_eq!(
            g.instance(Role::App, Transport::Tls, "other.internal"),
            None
        );
        let response = g.handle(
            Role::App,
            Transport::Tls,
            "app-tls",
            &request("GET", "other.internal", "/"),
        );
        assert_eq!(response.status, 421);
    }

    #[test]
    fn no_get_route_changes_state() {
        let g = gateway();
        let cookie = login(&g);
        let sessions_before = g.sessions.lock().map(|s| s.clone()).unwrap_or_default();
        let mut paths: Vec<String> = APP_ROUTES
            .iter()
            .map(|(_, matcher, _)| match matcher {
                PathMatch::Exact(p) => (*p).to_owned(),
                PathMatch::Prefix(p) => format!("{p}x"),
            })
            .collect();
        paths.push("/nope".into());
        for path in &paths {
            for method in ["GET", "HEAD"] {
                assert!(
                    !matches!(route_app(method, path), AppRoute::Post(_)),
                    "{method} {path} reaches a POST route"
                );
                let mut r = request(method, NAME, path);
                r.headers = vec![
                    ("cookie".into(), cookie.clone()),
                    (SIGNATURE_HEADER.into(), "s".into()),
                ];
                let response = g.handle(Role::App, Transport::Tls, "app-tls", &r);
                assert_ne!(response.status, 500, "{method} {path}");
                assert!(
                    response.header("set-cookie").is_empty(),
                    "{method} {path} sets a cookie"
                );
            }
        }
        assert_eq!(g.mutations(), 0);
        let sessions_after = g.sessions.lock().map(|s| s.clone()).unwrap_or_default();
        assert_eq!(sessions_after, sessions_before);
    }

    #[test]
    fn no_content_response_sets_a_cookie() {
        let g = gateway();
        let mut fixtures: Vec<String> =
            vec!["passive".into(), fixtures::PASSIVE_WITHOUT_LINKS.into()];
        fixtures.extend(fixtures::SINGLES.iter().map(|s| s.name.to_owned()));
        fixtures.extend(
            fixtures::PASSIVE
                .iter()
                .map(|v| format!("{}{}", fixtures::ONLY_PREFIX, v.name)),
        );
        fixtures.push("unknown".into());
        let host = format!("{NAME}:8443");
        for (prefix, _) in ContentMode::PREFIXES {
            for fixture in &fixtures {
                for method in ["GET", "HEAD"] {
                    let r = request(method, &host, &format!("{prefix}{fixture}?run=r1"));
                    let response = g.handle(Role::Content, Transport::Tls, "content-tls", &r);
                    assert!(
                        response.header("set-cookie").is_empty(),
                        "{prefix}{fixture}"
                    );
                }
            }
        }
        let mut report = request("POST", &host, "/csp-report");
        report.body = b"{}".to_vec();
        let response = g.handle(Role::Content, Transport::Tls, "content-tls", &report);
        assert!(response.header("set-cookie").is_empty());
    }

    #[test]
    fn csp_only_differs_from_production_by_the_sandbox_directive_only() {
        let g = gateway();
        let host = format!("{NAME}:8443");
        let get = |prefix: &str| {
            g.handle(
                Role::Content,
                Transport::Tls,
                "content-tls",
                &request("GET", &host, &format!("{prefix}passive?run=r1")),
            )
        };
        let production = get("/content/");
        let csp_only = get("/csp-only/");
        let others = |r: &Response| {
            let mut h: Vec<(String, String)> = r
                .headers
                .iter()
                .filter(|(n, _)| n != "content-security-policy")
                .cloned()
                .collect();
            h.sort();
            h
        };
        assert_eq!(others(&production), others(&csp_only));
        assert_eq!(
            production
                .header("content-security-policy")
                .replace(" sandbox;", ""),
            csp_only.header("content-security-policy")
        );
    }

    #[test]
    fn action_needs_a_session_and_the_signature_header() {
        let g = gateway();
        let cookie = login(&g);
        let mut no_session = request("POST", NAME, "/api/action");
        no_session.headers = vec![(SIGNATURE_HEADER.into(), "s".into())];
        let mut no_signature = request("POST", NAME, "/api/action");
        no_signature.headers = vec![("cookie".into(), cookie.clone())];
        let mut signed = no_signature.clone();
        signed.headers.push((SIGNATURE_HEADER.into(), "s".into()));
        assert_eq!(
            g.handle(Role::App, Transport::Tls, "app-tls", &no_session)
                .status,
            403
        );
        assert_eq!(
            g.handle(Role::App, Transport::Tls, "app-tls", &no_signature)
                .status,
            403
        );
        assert_eq!(g.mutations(), 0);
        assert_eq!(
            g.handle(Role::App, Transport::Tls, "app-tls", &signed)
                .status,
            200
        );
        assert_eq!(g.mutations(), 1);
        let outcomes: Vec<String> = g.log.snapshot().into_iter().map(|e| e.outcome).collect();
        assert!(outcomes.ends_with(&[
            "refused-no-session".into(),
            "refused-no-signature".into(),
            "mutated".into()
        ]));
    }

    #[test]
    fn login_sets_the_session_cookie() {
        let g = gateway();
        let response = g.handle(
            Role::App,
            Transport::Tls,
            "app-tls",
            &request("POST", NAME, "/api/login"),
        );
        assert_eq!(response.status, 204);
        let cookie = response.header("set-cookie");
        assert!(cookie.starts_with("__Host-vilicus_session="));
        assert!(cookie.ends_with("; Path=/; Secure; HttpOnly; SameSite=Strict"));
    }

    #[test]
    fn client_page_has_a_fresh_nonce_and_strict_headers() {
        let g = gateway();
        let first = g.handle(
            Role::App,
            Transport::Tls,
            "app-tls",
            &request("GET", NAME, "/"),
        );
        let second = g.handle(
            Role::App,
            Transport::Tls,
            "app-tls",
            &request("GET", NAME, "/"),
        );
        let csp = first.header("content-security-policy");
        assert!(csp.contains("'nonce-"));
        assert_ne!(csp, second.header("content-security-policy"));
        let nonce = csp
            .split("'nonce-")
            .nth(1)
            .and_then(|r| r.split('\'').next())
            .unwrap_or("");
        let body = String::from_utf8_lossy(&first.body);
        assert!(body.contains(&format!("nonce=\"{nonce}\"")));
        assert_eq!(body.matches("nonce=").count(), 1);
        assert!(!body.contains("{MODES}") && !body.contains("{CONTENT_PORT}"));
        assert_eq!(first.header("x-frame-options"), "DENY");
        assert_eq!(first.header("x-content-type-options"), "nosniff");
    }

    #[test]
    fn client_modes_name_a_content_prefix() {
        let modes = modes_json();
        for (name, mode, _) in CLIENT_MODES {
            let prefix = ContentMode::PREFIXES
                .iter()
                .find(|(_, m)| *m == mode)
                .map(|(p, _)| *p);
            assert!(prefix.is_some(), "{name}");
            assert!(modes.contains(&format!(
                "\"{name}\":{{\"prefix\":\"{}\"",
                prefix.unwrap_or("")
            )));
        }
    }

    #[test]
    fn content_is_served_only_on_the_content_origin_with_its_csp() {
        let g = gateway();
        let content = g.handle(
            Role::Content,
            Transport::Tls,
            "content-tls",
            &request("GET", "vilicus.internal:8443", "/content/passive?run=r1"),
        );
        assert_eq!(content.status, 200);
        let csp = content.header("content-security-policy");
        assert!(
            csp.contains("sandbox;") && csp.contains("frame-ancestors https://vilicus.internal;")
        );
        assert_eq!(content.header("x-dns-prefetch-control"), "off");
        assert!(content.header("x-frame-options").is_empty());
        let on_app = g.handle(
            Role::App,
            Transport::Tls,
            "app-tls",
            &request("GET", NAME, "/content/passive?run=r1"),
        );
        assert_eq!(on_app.status, 404);
        let app_on_content = g.handle(
            Role::Content,
            Transport::Tls,
            "content-tls",
            &request("GET", "vilicus.internal:8443", "/"),
        );
        assert_eq!(app_on_content.status, 404);
        let raw = g.handle(
            Role::Content,
            Transport::Tls,
            "content-tls",
            &request("GET", "vilicus.internal:8443", "/raw/passive?run=r1"),
        );
        assert!(raw.header("content-security-policy").is_empty());
    }

    #[test]
    fn relaxed_frame_source_needs_test_controls() {
        let strict = format!("frame-src {};", policy::content_frame_source(NAME));
        let relaxed = format!("frame-src {};", policy::RELAXED_FRAME_SOURCE);
        let page = |g: &Gateway, path: &str| {
            g.handle(
                Role::App,
                Transport::Tls,
                "app-tls",
                &request("GET", NAME, path),
            )
            .header("content-security-policy")
            .to_owned()
        };
        assert!(page(&gateway(), "/?relax=1").contains(&relaxed));
        assert!(page(&gateway(), "/").contains(&strict));
        let without_controls = Gateway::new(vec![NAME.into()], Vec::new(), false);
        assert!(page(&without_controls, "/?relax=1").contains(&strict));
    }

    #[test]
    fn raw_mode_needs_test_controls() {
        let g = Gateway::new(vec![NAME.into()], Vec::new(), false);
        let raw = g.handle(
            Role::Content,
            Transport::Tls,
            "content-tls",
            &request("GET", "vilicus.internal:8443", "/raw/passive?run=r1"),
        );
        assert_eq!(raw.status, 404);
    }

    #[test]
    fn csp_reports_are_logged_with_their_body() {
        let g = gateway();
        let mut report = request("POST", "vilicus.internal:8443", "/csp-report");
        report.body =
            br#"{"csp-report":{"blocked-uri":"https://r1-img.attacker.example/v/img"}}"#.to_vec();
        assert_eq!(
            g.handle(Role::Content, Transport::Tls, "content-tls", &report)
                .status,
            204
        );
        assert!(g.log.to_json("r1-img").contains("csp-report"));
    }

    #[test]
    fn requests_record_cookie_names_without_values() {
        let g = gateway();
        let mut r = request("GET", NAME, "/api/state");
        r.headers = vec![(
            "cookie".into(),
            "__Host-vilicus_session=secret; other=x".into(),
        )];
        g.handle(Role::App, Transport::Tls, "app-tls", &r);
        let entry = g.log.snapshot().pop().unwrap_or_default();
        assert!(entry.session_cookie);
        assert_eq!(entry.cookie_names, "__Host-vilicus_session,other");
        assert!(!format!("{entry:?}").contains("secret"));
    }

    #[test]
    fn sink_serves_a_page_only_where_a_click_lands() {
        let log = Log::default();
        let page = sink(
            "sink-tls",
            &request("GET", "r1-click-link.attacker.example", "/v/click-link"),
            &log,
        );
        assert!(String::from_utf8_lossy(&page.body).contains("r1-sink-script"));
        let other = sink(
            "sink-tls",
            &request("GET", "r1-img.attacker.example", "/v/img"),
            &log,
        );
        assert_eq!(other.body, b"sink");
        assert_eq!(log.snapshot().len(), 2);
    }

    #[test]
    fn query_params_are_read() {
        let r = request("GET", NAME, "/log?contains=r1&x=2");
        assert_eq!(r.query_param("contains"), "r1");
        assert_eq!(r.query_param("x"), "2");
        assert_eq!(r.query_param("y"), "");
    }
}
