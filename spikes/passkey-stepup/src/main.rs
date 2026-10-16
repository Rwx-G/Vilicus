//! `passkey-stepup serve <address> <pki-dir> <host-name> <prompt-timeout-ms>` writes a fresh test
//! CA for `<host-name>` into `<pki-dir>`, then serves the relying party on `<address>` with the
//! origin `https://<host-name>:<port>` and the RP ID `<host-name>`.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use passkey_stepup::http;
use passkey_stepup::pki::TestPki;
use passkey_stepup::rp::RelyingParty;
use tokio::net::TcpListener;
use webauthn_rs::prelude::Url;

const USAGE: &str =
    "usage: passkey-stepup serve <address> <pki-dir> <host-name> <prompt-timeout-ms>";

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let outcome = match args.as_slice() {
        [command, address, pki_dir, host, ttl] if command == "serve" => {
            serve(address, Path::new(pki_dir), host, ttl).await
        }
        _ => Err(USAGE.into()),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn serve(
    address: &str,
    pki_dir: &Path,
    host: &str,
    ttl_ms: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let address: SocketAddr = address.parse()?;
    let prompt_timeout = Duration::from_millis(ttl_ms.parse()?);
    let origin = Url::parse(&format!("https://{host}:{}", address.port()))?;
    let relying_party = Arc::new(RelyingParty::new(host, &origin, prompt_timeout)?);
    let pki = TestPki::generate(host)?;
    let tls = http::tls_config(pki.server_chain(), pki.server_key())?;
    let listener = TcpListener::bind(address).await?;
    // Written after the bind, so a browser that finds the CA file also finds the port open.
    pki.write_ca(pki_dir)?;
    println!(
        "SERVER origin={origin} rp_id={host} prompt_timeout_ms={} expiry_ms={}",
        prompt_timeout.as_millis(),
        relying_party.ceremony_lifetime().as_millis()
    );
    http::serve(listener, tls, relying_party).await?;
    Ok(())
}
