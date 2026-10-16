//! Spike E1 and E2, PRF half (story 1.17): a WebAuthn relying party that asks for the `prf`
//! extension, records only SHA-256 digests of the outputs, and tabulates per credential whether
//! the output is a stable 32-byte value across sessions.
#![forbid(unsafe_code)]

pub mod authdata;
pub mod pki;
pub mod probe;
pub mod server;
pub mod store;
