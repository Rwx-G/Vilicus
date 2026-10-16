//! In-process handshakes between the spike server and the rustls client probe.

use std::sync::Arc;

use hybrid_kex::groups::{X25519, X25519MLKEM768};
use hybrid_kex::pki::TestPki;
use hybrid_kex::probe::{self, Offer, ProbeResult};
use hybrid_kex::server::{self, HandshakeRecord};
use rustls::crypto::SupportedKxGroup;
use rustls::crypto::aws_lc_rs::kx_group;
use rustls::{ProtocolVersion, SupportedProtocolVersion};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

const SECP256R1: u16 = 0x0017;
const MLKEM768: u16 = 0x0201;
const SERVER_NAME: &str = "localhost";

struct Harness {
    address: String,
    pki: TestPki,
    records: mpsc::UnboundedReceiver<HandshakeRecord>,
}

async fn start_server() -> Harness {
    let pki = TestPki::generate(&[SERVER_NAME.to_owned()]).unwrap();
    let config = server::config(pki.server_chain(), pki.server_key()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let (sender, records) = mpsc::unbounded_channel();
    tokio::spawn(server::serve(listener, Arc::new(config), sender));
    Harness {
        address,
        pki,
        records,
    }
}

async fn handshake(
    harness: &mut Harness,
    client_name: &str,
    kx_groups: Vec<&'static dyn SupportedKxGroup>,
    versions: &[&'static SupportedProtocolVersion],
) -> (std::io::Result<ProbeResult>, HandshakeRecord) {
    let result = probe::fetch(
        &harness.address,
        SERVER_NAME,
        harness.pki.ca_der.clone(),
        client_name,
        kx_groups,
        versions,
    )
    .await;
    let record = harness.records.recv().await.unwrap();
    (result, record)
}

#[test]
fn server_lists_the_hybrid_group_first_and_keeps_x25519() {
    let pki = TestPki::generate(&[SERVER_NAME.to_owned()]).unwrap();
    let config = server::config(pki.server_chain(), pki.server_key()).unwrap();
    let groups = server::configured_groups(&config);
    assert_eq!(groups.first(), Some(&X25519MLKEM768));
    assert!(groups.contains(&X25519));
}

#[tokio::test]
async fn provider_default_client_negotiates_the_hybrid_group() {
    let mut harness = start_server().await;
    let (result, record) = handshake(
        &mut harness,
        "rustls-default",
        Offer::ProviderDefault.kx_groups(),
        &[&rustls::version::TLS13],
    )
    .await;
    let result = result.unwrap();
    assert_eq!(result.group, Some(X25519MLKEM768));
    assert_eq!(record.group, Some(X25519MLKEM768));
    assert_eq!(record.client, "rustls-default");
    assert_eq!(record.protocol, Some(ProtocolVersion::TLSv1_3));
    assert!(!record.hello_retry);
    assert_eq!(record.hello_retry_inferred, record.hello_retry);
    assert_eq!(record.offer.groups.first(), Some(&X25519MLKEM768));
    assert_eq!(record.offer.key_shares, vec![X25519MLKEM768, X25519]);
    assert!(result.body.contains("group=X25519MLKEM768"));
}

#[tokio::test]
async fn classical_only_client_falls_back_to_x25519() {
    let mut harness = start_server().await;
    let (result, record) = handshake(
        &mut harness,
        "rustls-classical",
        Offer::ClassicalOnly.kx_groups(),
        &[&rustls::version::TLS13],
    )
    .await;
    assert_eq!(result.unwrap().group, Some(X25519));
    assert_eq!(record.group, Some(X25519));
    assert_eq!(record.offer.groups, vec![X25519]);
    assert!(!record.hello_retry);
    assert_eq!(record.hello_retry_inferred, record.hello_retry);
}

#[tokio::test]
async fn nist_curve_only_client_still_connects() {
    let mut harness = start_server().await;
    let (result, record) = handshake(
        &mut harness,
        "rustls-secp256r1",
        vec![kx_group::SECP256R1],
        &[&rustls::version::TLS13],
    )
    .await;
    assert_eq!(result.unwrap().group, Some(SECP256R1));
    assert_eq!(record.group, Some(SECP256R1));
}

/// rustls 0.23.45 picks the first group of the client's `supported_groups` that it supports
/// (`choose_suite_and_kx_group` in `server/hs.rs`); the server's own list order does not
/// override the client. A client that lists X25519 before the hybrid group gets X25519.
#[tokio::test]
async fn server_follows_the_client_group_order() {
    let mut harness = start_server().await;
    let (result, record) = handshake(
        &mut harness,
        "rustls-classical-first",
        vec![kx_group::X25519, kx_group::X25519MLKEM768],
        &[&rustls::version::TLS13],
    )
    .await;
    assert_eq!(result.unwrap().group, Some(X25519));
    assert_eq!(record.offer.groups, vec![X25519, X25519MLKEM768]);
    assert_eq!(record.group, Some(X25519));
}

/// The client lists standalone MLKEM768 first, with its only key share, then X25519. The server
/// does not list standalone MLKEM768, so it selects X25519 and must ask for its key share.
#[tokio::test]
async fn missing_key_share_for_the_selected_group_costs_a_hello_retry() {
    let mut harness = start_server().await;
    let (result, record) = handshake(
        &mut harness,
        "rustls-hrr",
        vec![kx_group::MLKEM768, kx_group::X25519],
        &[&rustls::version::TLS13],
    )
    .await;
    assert_eq!(result.unwrap().group, Some(X25519));
    assert_eq!(record.offer.groups, vec![MLKEM768, X25519]);
    assert_eq!(record.offer.key_shares, vec![MLKEM768]);
    assert_eq!(record.group, Some(X25519));
    assert!(record.hello_retry);
    assert_eq!(record.hello_retry_inferred, record.hello_retry);
}

#[tokio::test]
async fn tls12_only_client_is_refused() {
    let mut harness = start_server().await;
    let (result, record) = handshake(
        &mut harness,
        "rustls-tls12",
        Offer::ProviderDefault.kx_groups(),
        &[&rustls::version::TLS12],
    )
    .await;
    // The client receives a `protocol_version` alert; the server names the refusal as the
    // client offering TLS 1.2 only while the server has it disabled.
    let client_error = result.unwrap_err().to_string();
    assert!(
        client_error.contains("ProtocolVersion"),
        "client error: {client_error}"
    );
    let server_error = record.error.unwrap();
    assert!(
        server_error.contains("Tls12NotOfferedOrEnabled"),
        "server error: {server_error}"
    );
    assert_eq!(record.group, None);
}
