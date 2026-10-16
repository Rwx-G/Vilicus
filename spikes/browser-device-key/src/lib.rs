//! Spike E22 (story 1.3): the server side of a browser device key (AD-21), OPAQUE-bound pairing
//! codes (D35) and device-signed light confirmations (D38).
//!
//! [`core::Core`] plays the Core: it alone registers device public keys and verifies every
//! signature. [`http`] serves the test pages and the JSON API over HTTPS and contains the relay
//! that plays a network attacker between a browser and the Core.

#![forbid(unsafe_code)]

pub mod b64;
pub mod confirm;
pub mod core;
pub mod device;
pub mod http;
pub mod pairing;
pub mod pki;
