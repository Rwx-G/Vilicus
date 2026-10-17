//! `separate-origin <command> <layout file> ...`, one server of the E26 test network:
//!
//! - `pki <layout> <out dir>`: writes the test PKI;
//! - `dns <layout>`: the DNS server (UDP 53) and its control listener (9000);
//! - `gateway <layout> <pki dir> [--test-controls]`: the client origin on 443 and the content
//!   origin on 8443 over TLS for the direct names, the same two origins over plain HTTP on 8080
//!   and 8081 for the reverse proxies, and the control listener on 9000;
//! - `sink <layout> <pki dir>`: the attacker's site on 443 (TLS) and 80, and its control listener.
#![forbid(unsafe_code)]

use std::path::Path;
use std::sync::Arc;

use separate_origin::dns::{self, Zone};
use separate_origin::instances::Layout;
use separate_origin::log::Log;
use separate_origin::pki;
use separate_origin::policy::CONTENT_PORT;
use separate_origin::routes::{Gateway, Role, Transport};
use separate_origin::server::{self, Service};
use tokio::net::{TcpListener, UdpSocket};

const CONTROL: &str = "0.0.0.0:9000";
// The plain listeners trust the Host header and accept any peer on the test network. A product
// Gateway binds them to loopback, or accepts only the configured reverse proxy's address.
const APP_PLAIN: &str = "0.0.0.0:8080";
const CONTENT_PLAIN: &str = "0.0.0.0:8081";

fn usage() -> String {
    "usage: separate-origin pki <layout> <out dir> | dns <layout> | \
     gateway <layout> <pki dir> [--test-controls] | sink <layout> <pki dir>"
        .into()
}

async fn bind(addr: &str) -> Result<TcpListener, String> {
    TcpListener::bind(addr)
        .await
        .map_err(|e| format!("{addr}: {e}"))
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (command, layout_path) = match args.as_slice() {
        [command, layout, ..] => (command.as_str(), layout.as_str()),
        _ => return Err(usage()),
    };
    let text = std::fs::read_to_string(layout_path).map_err(|e| format!("{layout_path}: {e}"))?;
    let layout = Layout::parse(&text)?;
    let rest = &args[2..];
    match (command, rest) {
        ("pki", [out]) => {
            let written = pki::generate(&layout, Path::new(out))?;
            println!("event=pki written={written} dir={out}");
            Ok(())
        }
        ("dns", []) => run_dns(&layout).await,
        ("gateway", [pki_dir, flags @ ..]) => {
            let test_controls = match flags {
                [] => false,
                [flag] if flag == "--test-controls" => true,
                _ => return Err(usage()),
            };
            run_gateway(&layout, Path::new(pki_dir), test_controls).await
        }
        ("sink", [pki_dir]) => run_sink(&layout, Path::new(pki_dir)).await,
        _ => Err(usage()),
    }
}

async fn run_dns(layout: &Layout) -> Result<(), String> {
    let zone = Arc::new(Zone::from_layout(layout)?);
    let log = Arc::new(Log::default());
    let socket = UdpSocket::bind("0.0.0.0:53")
        .await
        .map_err(|e| format!("udp 53: {e}"))?;
    let control = bind(CONTROL).await?;
    tokio::spawn(server::serve(
        control,
        "control",
        None,
        Service::Control(Arc::clone(&log), None),
    ));
    println!("event=ready role=dns");
    dns::serve(socket, zone, log).await;
    Ok(())
}

async fn run_gateway(layout: &Layout, pki_dir: &Path, test_controls: bool) -> Result<(), String> {
    let direct = layout.direct_names();
    let gateway = Arc::new(Gateway::new(
        direct.clone(),
        layout.proxied_names(),
        test_controls,
    ));
    let tls = server::tls_config(pki_dir, &direct)?;
    let content_tls = format!("0.0.0.0:{CONTENT_PORT}");
    let listeners = [
        ("app-tls", "0.0.0.0:443", Role::App, Transport::Tls),
        (
            "content-tls",
            content_tls.as_str(),
            Role::Content,
            Transport::Tls,
        ),
        ("app-plain", APP_PLAIN, Role::App, Transport::Plain),
        (
            "content-plain",
            CONTENT_PLAIN,
            Role::Content,
            Transport::Plain,
        ),
    ];
    let mut tasks = Vec::new();
    for (label, addr, role, transport) in listeners {
        let listener = bind(addr).await?;
        let tls =
            (transport == Transport::Tls).then(|| (Arc::clone(&tls), Arc::clone(&gateway.log)));
        let service = Service::Gateway(Arc::clone(&gateway), role, transport);
        tasks.push(tokio::spawn(server::serve(listener, label, tls, service)));
    }
    let control = bind(CONTROL).await?;
    let service = Service::Control(Arc::clone(&gateway.log), Some(Arc::clone(&gateway)));
    tasks.push(tokio::spawn(server::serve(
        control, "control", None, service,
    )));
    println!("event=ready role=gateway test_controls={test_controls}");
    for task in tasks {
        task.await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

async fn run_sink(layout: &Layout, pki_dir: &Path) -> Result<(), String> {
    let (suffix, _) = layout
        .wildcards
        .first()
        .ok_or("the layout names no attacker suffix")?;
    let tls = server::single_cert_config(pki_dir, &format!("wildcard.{suffix}"))?;
    let log = Arc::new(Log::default());
    let mut tasks = Vec::new();
    let tls_listener = bind("0.0.0.0:443").await?;
    tasks.push(tokio::spawn(server::serve(
        tls_listener,
        "sink-tls",
        Some((tls, Arc::clone(&log))),
        Service::Sink(Arc::clone(&log)),
    )));
    let plain = bind("0.0.0.0:80").await?;
    tasks.push(tokio::spawn(server::serve(
        plain,
        "sink-plain",
        None,
        Service::Sink(Arc::clone(&log)),
    )));
    let control = bind(CONTROL).await?;
    tasks.push(tokio::spawn(server::serve(
        control,
        "control",
        None,
        Service::Control(Arc::clone(&log), None),
    )));
    println!("event=ready role=sink");
    for task in tasks {
        task.await.map_err(|e| e.to_string())?;
    }
    Ok(())
}
