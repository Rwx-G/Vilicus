//! Spike E2, login half (story 1.5): a minimal relying party on `webauthn-rs` with passkey
//! registration, login, and a step-up whose challenge derives from the canonical hash of exactly
//! one pending request (AD-8 rule 3, D71), served over TLS 1.3 to real browsers.

#![forbid(unsafe_code)]

pub mod action;
pub mod http;
pub mod pki;
pub mod rp;
pub mod stepup;
