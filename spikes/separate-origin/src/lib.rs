//! Spike E26 (story 1.14): external content rendered in a script-less sandboxed iframe served
//! from a separate origin, the same instance name on a separate port (spine AD-19).
//!
//! One binary plays every server of the test network: the Gateway stand-in (the client origin and
//! the external-content origin, over TLS directly or over plain HTTP behind a reverse proxy), the
//! attacker's sink, the DNS server of the test network and the test PKI. The browser harness under
//! `harness/` drives Chromium and Firefox against it.
#![forbid(unsafe_code)]

pub mod dns;
pub mod fixtures;
pub mod instances;
pub mod json;
pub mod log;
pub mod pki;
pub mod policy;
pub mod routes;
pub mod sanitize;
pub mod server;
