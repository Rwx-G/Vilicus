//! The spike proxy: `egress-proxy <config file> <socket directory>`.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use egress_filter::config::Config;
use egress_filter::proxy::{DirectDialer, Proxy, SystemResolver};

#[tokio::main]
async fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [config_path, socket_dir] = args.as_slice() else {
        return Err("usage: egress-proxy <config file> <socket directory>".into());
    };
    let text = std::fs::read_to_string(config_path).map_err(|e| format!("{config_path}: {e}"))?;
    let config = Config::parse(&text)?;
    for caller in &config.callers {
        eprintln!(
            "caller={} kind={:?} uid={} allow={} private={}",
            caller.name,
            caller.kind,
            caller.uid,
            caller.allow.len(),
            caller.private.len()
        );
    }
    let proxy = Arc::new(Proxy::new(config, SystemResolver, DirectDialer));
    proxy
        .serve_all(&PathBuf::from(socket_dir))
        .await
        .map_err(|e| e.to_string())
}
