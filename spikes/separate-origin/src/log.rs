//! The observation log every server keeps: each HTTP request, TLS handshake and DNS query it saw.
//! The browser harness reads it through the control listener to tell what reached a server, with
//! which cookie and fetch metadata, and what a hostile page never managed to send.

use std::sync::Mutex;

use crate::json;

/// One observation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entry {
    /// `http`, `tls` or `dns`.
    pub kind: &'static str,
    /// Which listener saw it, for example `app-tls` or `content-plain`.
    pub listener: &'static str,
    /// The peer address.
    pub peer: String,
    /// HTTP method, or the DNS query type.
    pub method: String,
    /// HTTP host (or `:authority`), TLS SNI, or DNS name.
    pub host: String,
    /// Path and query.
    pub target: String,
    /// Whether the request carried the session cookie.
    pub session_cookie: bool,
    /// The `Cookie` header names, without values.
    pub cookie_names: String,
    pub sec_fetch_site: String,
    pub sec_fetch_mode: String,
    pub sec_fetch_dest: String,
    pub origin: String,
    pub content_type: String,
    /// What the server did with it, for example `mutated` or `refused-no-signature`.
    pub outcome: String,
    /// The body of a CSP report, empty otherwise.
    pub body: String,
}

impl Entry {
    fn to_json(&self, seq: usize) -> String {
        json::Object::default()
            .num("seq", u64::try_from(seq).unwrap_or(u64::MAX))
            .str("kind", self.kind)
            .str("listener", self.listener)
            .str("peer", &self.peer)
            .str("method", &self.method)
            .str("host", &self.host)
            .str("target", &self.target)
            .bool("session_cookie", self.session_cookie)
            .str("cookie_names", &self.cookie_names)
            .str("sec_fetch_site", &self.sec_fetch_site)
            .str("sec_fetch_mode", &self.sec_fetch_mode)
            .str("sec_fetch_dest", &self.sec_fetch_dest)
            .str("origin", &self.origin)
            .str("content_type", &self.content_type)
            .str("outcome", &self.outcome)
            .str("body", &self.body)
            .finish()
    }

    fn mentions(&self, needle: &str) -> bool {
        [&self.host, &self.target, &self.body]
            .iter()
            .any(|field| field.contains(needle))
    }
}

/// An append-only, in-memory log.
#[derive(Default)]
pub struct Log {
    entries: Mutex<Vec<Entry>>,
}

impl Log {
    /// Appends one entry.
    pub fn push(&self, entry: Entry) {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(entry);
    }

    /// The entries whose host, target or body contains `needle`, as a JSON array.
    pub fn to_json(&self, needle: &str) -> String {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let selected: Vec<String> = entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.mentions(needle))
            .map(|(seq, e)| e.to_json(seq))
            .collect();
        json::array(&selected)
    }

    /// A copy of every entry.
    pub fn snapshot(&self) -> Vec<Entry> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_matches_host_target_or_body() {
        let log = Log::default();
        log.push(Entry {
            kind: "http",
            host: "r1-img.attacker.example".into(),
            ..Entry::default()
        });
        log.push(Entry {
            kind: "http",
            target: "/content/passive?run=r2".into(),
            ..Entry::default()
        });
        log.push(Entry {
            kind: "http",
            body: "{\"document-uri\":\"https://x:8443/content/p?run=r3\"}".into(),
            ..Entry::default()
        });
        for run in ["r1", "r2", "r3"] {
            assert_eq!(log.to_json(run).matches("\"seq\"").count(), 1, "{run}");
        }
        assert_eq!(log.to_json("").matches("\"seq\"").count(), 3);
        assert_eq!(log.snapshot().len(), 3);
    }
}
