//! Response headers of both origins: the client's strict CSP with a per-response nonce and Trusted
//! Types (spine AD-19, FR-17), the external-content origin's CSP that forbids every subresource,
//! script and form, and the session cookie of `doc/architecture.md` section 6.

/// The external-content origin's port. The client origin keeps 443.
pub const CONTENT_PORT: u16 = 8443;

/// Session cookie name. The `__Host-` prefix makes the browser refuse it unless it is `Secure`,
/// has `Path=/` and has no `Domain`, so it is host-only.
pub const SESSION_COOKIE: &str = "__Host-vilicus_session";

/// The Trusted Types policy name the client may create (AD-19: Lit's policy only).
pub const TRUSTED_TYPES_POLICY: &str = "lit-html";

/// How the external-content origin serves a fixture. `Production` is the configuration under test;
/// the others exist to show which layer blocks what and that the browser checks can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentMode {
    /// The sanitizer, then the full CSP, including the `sandbox` directive.
    Production,
    /// The full CSP without the sanitizer (control): what the sanitizer adds.
    Unsanitized,
    /// The same CSP without the `sandbox` directive (the client also omits the iframe attribute):
    /// the CSP layer on its own.
    CspOnly,
    /// The production CSP with `style-src 'unsafe-inline'`: whether inline styles could be allowed
    /// for rendering fidelity without reopening CSS exfiltration.
    InlineStyle,
    /// No CSP at all (test control only).
    Raw,
}

impl ContentMode {
    /// The path prefix that selects the mode, and the mode for each prefix.
    pub const PREFIXES: [(&'static str, Self); 5] = [
        ("/content/", Self::Production),
        ("/unsanitized/", Self::Unsanitized),
        ("/csp-only/", Self::CspOnly),
        ("/inline-style/", Self::InlineStyle),
        ("/raw/", Self::Raw),
    ];

    /// Splits `/content/<fixture>` into the mode and the fixture name.
    pub fn from_path(path: &str) -> Option<(Self, &str)> {
        Self::PREFIXES
            .iter()
            .find_map(|(prefix, mode)| path.strip_prefix(prefix).map(|rest| (*mode, rest)))
    }
}

/// The client origin's `frame-src` source: the external-content origin on the same instance name
/// (`host`, without a port). Because `frame-src` also governs every later navigation of the
/// iframe, the framed content cannot navigate its frame anywhere else.
pub fn content_frame_source(host: &str) -> String {
    format!("https://{host}:{CONTENT_PORT}")
}

/// A `frame-src` source that lets the iframe navigate to any HTTPS origin: test controls only,
/// to show what the iframe's own sandbox and CSP do without the client's `frame-src`.
pub const RELAXED_FRAME_SOURCE: &str = "https:";

/// The client origin's CSP, with `frame_src` as its only frame source.
pub fn app_csp(nonce: &str, frame_src: &str) -> String {
    format!(
        "default-src 'none'; script-src 'self' 'nonce-{nonce}'; style-src 'self'; img-src 'self'; \
         connect-src 'self'; frame-src {frame_src}; frame-ancestors 'none'; \
         base-uri 'none'; form-action 'self'; object-src 'none'; \
         require-trusted-types-for 'script'; trusted-types {TRUSTED_TYPES_POLICY}; \
         report-uri /csp-report"
    )
}

/// The CSP of every API response: nothing loads, nothing frames it, and a browser that renders it
/// as a document sandboxes it.
pub const API_CSP: &str = "default-src 'none'; frame-ancestors 'none'; sandbox";

/// The external-content origin's CSP for `mode`, or `None` for the raw control. `app_origin` is
/// the only origin allowed to frame the content.
pub fn content_csp(mode: ContentMode, app_origin: &str) -> Option<String> {
    let style = match mode {
        ContentMode::InlineStyle => "'unsafe-inline'",
        ContentMode::Production | ContentMode::Unsanitized | ContentMode::CspOnly => "'none'",
        ContentMode::Raw => return None,
    };
    let sandbox = if mode == ContentMode::CspOnly {
        ""
    } else {
        " sandbox;"
    };
    Some(format!(
        "default-src 'none'; script-src 'none'; style-src {style}; img-src 'none'; \
         font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; \
         child-src 'none'; worker-src 'none'; manifest-src 'none'; connect-src 'none'; \
         form-action 'none'; base-uri 'none'; frame-ancestors {app_origin};{sandbox} \
         report-uri /csp-report"
    ))
}

/// Headers every response of both origins carries, besides its CSP.
pub const COMMON_HEADERS: [(&str, &str); 4] = [
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    ("cache-control", "no-store"),
    ("cross-origin-resource-policy", "same-origin"),
];

/// Extra headers of the client origin's responses.
pub const APP_HEADERS: [(&str, &str); 2] = [
    ("x-frame-options", "DENY"),
    ("cross-origin-opener-policy", "same-origin"),
];

/// Extra header of the external-content origin's production responses: DNS prefetching is not
/// covered by CSP, so it is switched off explicitly.
pub const CONTENT_HEADERS: [(&str, &str); 1] = [("x-dns-prefetch-control", "off")];

/// The `Set-Cookie` value for a new session.
pub fn session_cookie(value: &str) -> String {
    format!("{SESSION_COOKIE}={value}; Path=/; Secure; HttpOnly; SameSite=Strict")
}

/// Reads the session value from a `Cookie` header.
pub fn session_from_cookie_header(header: &str) -> Option<&str> {
    header
        .split(';')
        .map(str::trim)
        .find_map(|pair| pair.strip_prefix(SESSION_COOKIE)?.strip_prefix('='))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directives(csp: &str) -> Vec<String> {
        csp.split(';')
            .map(|d| d.split_whitespace().collect::<Vec<_>>().join(" "))
            .filter(|d| !d.is_empty())
            .collect()
    }

    #[test]
    fn app_csp_is_strict_with_nonce_and_trusted_types() {
        let d = directives(&app_csp("abc", &content_frame_source("vilicus.internal")));
        for expected in [
            "default-src 'none'",
            "script-src 'self' 'nonce-abc'",
            "frame-src https://vilicus.internal:8443",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "object-src 'none'",
            "require-trusted-types-for 'script'",
            "trusted-types lit-html",
        ] {
            assert!(d.contains(&expected.to_owned()), "missing {expected}");
        }
        assert!(!d.iter().any(|x| x.contains("unsafe")));
    }

    #[test]
    fn production_content_csp_forbids_every_fetch_directive_and_forms() {
        let d = directives(
            &content_csp(ContentMode::Production, "https://vilicus.internal").unwrap_or_default(),
        );
        for name in [
            "default-src",
            "script-src",
            "style-src",
            "img-src",
            "font-src",
            "media-src",
            "object-src",
            "frame-src",
            "child-src",
            "worker-src",
            "manifest-src",
            "connect-src",
            "form-action",
            "base-uri",
        ] {
            assert!(
                d.contains(&format!("{name} 'none'")),
                "{name} is not 'none'"
            );
        }
        assert!(d.contains(&"sandbox".to_owned()));
        assert!(d.contains(&"frame-ancestors https://vilicus.internal".to_owned()));
    }

    #[test]
    fn csp_only_mode_drops_only_the_sandbox_directive() {
        let origin = "https://vilicus.internal";
        let production = content_csp(ContentMode::Production, origin).unwrap_or_default();
        let csp_only = content_csp(ContentMode::CspOnly, origin).unwrap_or_default();
        let mut without_sandbox = directives(&production);
        without_sandbox.retain(|d| d != "sandbox");
        assert_eq!(directives(&csp_only), without_sandbox);
        assert!(content_csp(ContentMode::Raw, origin).is_none());
    }

    #[test]
    fn inline_style_mode_changes_only_style_src() {
        let origin = "https://vilicus.internal";
        let production =
            directives(&content_csp(ContentMode::Production, origin).unwrap_or_default());
        let styled = directives(&content_csp(ContentMode::InlineStyle, origin).unwrap_or_default());
        let changed: Vec<_> = styled.iter().filter(|d| !production.contains(d)).collect();
        assert_eq!(changed, ["style-src 'unsafe-inline'"]);
    }

    #[test]
    fn session_cookie_is_host_only_secure_httponly_strict() {
        let cookie = session_cookie("v");
        let attributes: Vec<&str> = cookie.split("; ").collect();
        assert_eq!(attributes[0], "__Host-vilicus_session=v");
        for expected in ["Path=/", "Secure", "HttpOnly", "SameSite=Strict"] {
            assert!(attributes.contains(&expected), "missing {expected}");
        }
        assert!(!cookie.to_ascii_lowercase().contains("domain"));
    }

    #[test]
    fn session_is_read_from_a_cookie_header() {
        assert_eq!(
            session_from_cookie_header("a=1; __Host-vilicus_session=xyz; b=2"),
            Some("xyz")
        );
        assert_eq!(session_from_cookie_header("vilicus_session=xyz"), None);
    }

    #[test]
    fn mode_prefixes_round_trip() {
        for (prefix, mode) in ContentMode::PREFIXES {
            assert_eq!(
                ContentMode::from_path(&format!("{prefix}passive")),
                Some((mode, "passive"))
            );
        }
        assert_eq!(ContentMode::from_path("/api/state"), None);
    }
}
