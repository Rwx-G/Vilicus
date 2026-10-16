//! The `host:port` of a CONNECT request and of an allowlist entry.
//!
//! One parser serves both, so an entry and a request compare as equal strings. It accepts only
//! a DNS hostname: an IP literal, a trailing dot, userinfo, or any form the C library's
//! `inet_aton` would read as an address (`3405803786`, `0xcb.0x71.0.10`) is refused, so the name
//! that is checked is the name that is resolved.

/// A canonical hostname and a port.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostPort {
    /// Lowercase ASCII LDH labels, no trailing dot.
    pub host: String,
    /// 1 to 65535.
    pub port: u16,
}

impl std::fmt::Display for HostPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// Why a target was refused before any lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetError {
    /// No `:port`, or a port that is not canonical decimal in range.
    BadPort,
    /// An IPv4 or bracketed IPv6 literal.
    IpLiteral,
    /// Not a hostname under the rules above.
    BadHostname,
}

impl TargetError {
    /// The fixed text sent back to the caller.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::BadPort => "malformed or missing port",
            Self::IpLiteral => "IP literals are not allowed",
            Self::BadHostname => "malformed hostname",
        }
    }
}

/// Parses `host:port` in authority form.
///
/// ```
/// use egress_filter::target::{parse_authority, TargetError};
/// assert_eq!(parse_authority("Example.ORG:443").unwrap().to_string(), "example.org:443");
/// assert_eq!(parse_authority("203.0.113.10:443"), Err(TargetError::IpLiteral));
/// assert_eq!(parse_authority("example.org:0443"), Err(TargetError::BadPort));
/// ```
///
/// # Errors
/// Returns the first rule the text breaks.
pub fn parse_authority(text: &str) -> Result<HostPort, TargetError> {
    if text.starts_with('[') {
        return Err(TargetError::IpLiteral);
    }
    let (host, port) = text.rsplit_once(':').ok_or(TargetError::BadPort)?;
    let port = parse_port(port)?;
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Err(TargetError::IpLiteral);
    }
    Ok(HostPort {
        host: parse_hostname(host)?,
        port,
    })
}

fn parse_port(text: &str) -> Result<u16, TargetError> {
    let canonical = !text.is_empty()
        && text.len() <= 5
        && text.bytes().all(|b| b.is_ascii_digit())
        && !text.starts_with('0');
    if !canonical {
        return Err(TargetError::BadPort);
    }
    text.parse::<u16>().map_err(|_| TargetError::BadPort)
}

/// Parses a hostname under the rules of [`parse_authority`] and returns its canonical form.
///
/// # Errors
/// Returns [`TargetError::BadHostname`] when a rule is broken.
pub fn parse_hostname(text: &str) -> Result<String, TargetError> {
    if text.is_empty() || text.len() > 253 || !text.is_ascii() {
        return Err(TargetError::BadHostname);
    }
    let host = text.to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    let label_ok = |label: &&str| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    if !labels.iter().all(label_ok) {
        return Err(TargetError::BadHostname);
    }
    // Every `inet_aton` form ends in a component that starts with a digit; no top-level domain
    // does. An empty last label (trailing dot) was already refused.
    let last_starts_with_letter = labels
        .last()
        .and_then(|label| label.bytes().next())
        .is_some_and(|b| b.is_ascii_lowercase());
    if !last_starts_with_letter {
        return Err(TargetError::BadHostname);
    }
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostnames_are_canonicalised_and_ports_kept() {
        let cases = [
            ("allowed.test:443", "allowed.test", 443),
            ("ALLOWED.Test:443", "allowed.test", 443),
            ("a-b.c0.example:65535", "a-b.c0.example", 65535),
            ("xn--bcher-kva.example:1", "xn--bcher-kva.example", 1),
            ("localhost:80", "localhost", 80),
        ];
        for (text, host, port) in cases {
            let parsed = parse_authority(text).unwrap();
            assert_eq!((parsed.host.as_str(), parsed.port), (host, port), "{text}");
        }
    }

    #[test]
    fn non_canonical_targets_are_refused() {
        let cases = [
            ("allowed.test", TargetError::BadPort),
            ("allowed.test:", TargetError::BadPort),
            ("allowed.test:0", TargetError::BadPort),
            ("allowed.test:0443", TargetError::BadPort),
            ("allowed.test:+443", TargetError::BadPort),
            ("allowed.test:65536", TargetError::BadPort),
            ("allowed.test:443 ", TargetError::BadPort),
            ("allowed.test:443:443", TargetError::BadHostname),
            ("203.0.113.10:443", TargetError::IpLiteral),
            ("[2001:db8::10]:443", TargetError::IpLiteral),
            ("[::ffff:10.0.0.1]:443", TargetError::IpLiteral),
            ("::1:443", TargetError::IpLiteral),
            ("3405803786:443", TargetError::BadHostname),
            ("0xcb.0x71.0.10:443", TargetError::BadHostname),
            ("0x7f.1:443", TargetError::BadHostname),
            ("127.1:443", TargetError::BadHostname),
            ("allowed.test.:443", TargetError::BadHostname),
            ("allowed..test:443", TargetError::BadHostname),
            (".allowed.test:443", TargetError::BadHostname),
            ("allowed.test@forbidden.test:443", TargetError::BadHostname),
            ("forbidden.test#allowed.test:443", TargetError::BadHostname),
            ("allowed.test/x:443", TargetError::BadHostname),
            ("allowed_test.example:443", TargetError::BadHostname),
            ("-allowed.test:443", TargetError::BadHostname),
            ("allowed-.test:443", TargetError::BadHostname),
            ("allowed.tést:443", TargetError::BadHostname),
            ("allowed.test%00:443", TargetError::BadHostname),
            (":443", TargetError::BadHostname),
        ];
        for (text, expected) in cases {
            assert_eq!(parse_authority(text), Err(expected), "{text}");
        }
        let long_label = format!("{}.test:443", "a".repeat(64));
        assert_eq!(parse_authority(&long_label), Err(TargetError::BadHostname));
        let long_name = format!("{}test:443", "a.".repeat(127));
        assert_eq!(parse_authority(&long_name), Err(TargetError::BadHostname));
    }
}
