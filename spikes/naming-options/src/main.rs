//! Spike E24 (story 1.4): one HTTPS test instance under one naming option.
//!
//! Serves a minimal installable web app (page, manifest, service worker, icons) and a passkey
//! registration and login with webauthn-rs, for the relying party given by the environment:
//!
//! - `E24_ORIGIN`: the origin browsers load, for example `https://vilicus.home.arpa`;
//! - `E24_CERT`, `E24_KEY`: PEM certificate chain and private key for that name;
//! - `E24_LISTEN`: listening address, `0.0.0.0:443` by default.
//!
//! The relying party ID is the origin's host. When webauthn-rs refuses it (an IP address), the
//! server still serves the page, and the ceremony routes answer 503 with the library's reason.
#![forbid(unsafe_code)]

mod png;
mod rp;
mod server;

use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let origin = std::env::var("E24_ORIGIN")?;
    let cert = std::env::var("E24_CERT")?;
    let key = std::env::var("E24_KEY")?;
    let listen = std::env::var("E24_LISTEN").unwrap_or_else(|_| "0.0.0.0:443".to_owned());

    let relying_party = rp::RelyingParty::from_origin(&origin);
    match &relying_party.webauthn {
        Ok(_) => println!("E24 serving {origin} with rp_id {}", relying_party.rp_id),
        Err(reason) => println!("E24 serving {origin} without WebAuthn: {reason}"),
    }
    let tls = server::tls_config(&cert, &key)?;
    let state = Arc::new(server::AppState::new(relying_party));
    server::serve(&listen, tls, state).await
}
