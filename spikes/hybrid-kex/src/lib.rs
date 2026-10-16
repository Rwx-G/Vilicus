//! Spike E3 (story 1.16): records which TLS key exchange group each client negotiates against a
//! rustls server built with the aws-lc-rs provider, whose default group list starts with
//! X25519MLKEM768 (D27).
#![forbid(unsafe_code)]

pub mod client_hello;
pub mod groups;
pub mod pki;
pub mod probe;
pub mod server;
