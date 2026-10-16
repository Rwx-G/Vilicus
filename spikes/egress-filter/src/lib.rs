//! Spike E14: a CONNECT-only egress proxy with an exact-hostname allowlist per caller.
//!
//! Not product code. It exists to test, against real client traffic, the rule of spine AD-16:
//! callers reach the proxy on their own Unix socket, the proxy resolves every name itself,
//! checks each resolved address, and dials the address it checked.
//! Linux only: it relies on Unix sockets and peer credentials, and is built and run in Docker.
#![forbid(unsafe_code)]

pub mod address;
pub mod budget;
pub mod config;
pub mod proxy;
pub mod sni;
pub mod target;
