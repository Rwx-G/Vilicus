//! `hybrid-kex serve <address> <pki-dir> <name>...` runs the test server; it writes a fresh test
//! CA and server certificate for the names into `<pki-dir>`, then logs one `HANDSHAKE` line per
//! connection on stdout.
//!
//! `hybrid-kex probe <address> <server-name> <ca.pem> <client-name> <default|classical>` runs the
//! rustls client and prints its own view of the negotiated group, then the server's record.
#![forbid(unsafe_code)]

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use hybrid_kex::pki::TestPki;
use hybrid_kex::probe::{self, Offer};
use hybrid_kex::{groups, server};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

const USAGE: &str = "usage:\n  hybrid-kex serve <address> <pki-dir> <name>...\n  hybrid-kex probe <address> <server-name> <ca.pem> <client-name> <default|classical>";

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let outcome = match args.first().map(String::as_str) {
        Some("serve") if args.len() >= 4 => {
            run_server(&args[1], Path::new(&args[2]), &args[3..]).await
        }
        Some("probe") if args.len() == 6 => run_probe(&args[1..]).await,
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

async fn run_server(
    address: &str,
    pki_dir: &Path,
    names: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let pki = TestPki::generate(names)?;
    let config = server::config(pki.server_chain(), pki.server_key())?;
    let listener = TcpListener::bind(address).await?;
    // Written after the bind, so a client that finds the CA file also finds the port open.
    pki.write_to(pki_dir)?;
    println!(
        "SERVER provider=aws-lc-rs groups={} listening={address}",
        groups::join(&server::configured_groups(&config))
    );
    let (sender, mut receiver) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(record) = receiver.recv().await {
            println!("{record}");
        }
    });
    server::serve(listener, Arc::new(config), sender).await?;
    Ok(())
}

async fn run_probe(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let [address, server_name, ca_path, client_name, offer] = args else {
        return Err(USAGE.into());
    };
    let offer = match offer.as_str() {
        "default" => Offer::ProviderDefault,
        "classical" => Offer::ClassicalOnly,
        _ => return Err(USAGE.into()),
    };
    let ca = CertificateDer::from_pem_file(ca_path)?;
    let result = probe::fetch(
        address,
        server_name,
        ca,
        client_name,
        offer.kx_groups(),
        &[&rustls::version::TLS13],
    )
    .await?;
    println!(
        "PROBE client={client_name} client_side_group={}",
        result.group.map_or_else(|| "none".to_owned(), groups::name)
    );
    print!("{}", result.body);
    Ok(())
}
