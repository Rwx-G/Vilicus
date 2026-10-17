//! The test PKI: one CA per `ca` line of the layout, one leaf per instance name, and one wildcard
//! leaf per attacker suffix. Nothing here is a production PKI; the keys live in the run's scratch
//! volume and die with it.
//!
//! Files written into the output directory:
//! - `ca-<label>.crt`: each CA certificate, which the browsers install as trust anchors;
//! - `<name>.crt` and `<name>.key`: each instance's leaf, read by the Gateway and nginx;
//! - `bundles/<deployment>/<name>.pem`: certificate and key together, the form Caddy loads;
//! - `wildcard.<suffix>.crt` and `.key`: the sink's leaf for `*.<suffix>`.

use std::fs;
use std::path::Path;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};

use crate::instances::Layout;

struct Authority {
    label: String,
    params: CertificateParams,
    key: KeyPair,
}

fn authority(label: &str, description: &str) -> Result<(Authority, String), String> {
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
    params
        .distinguished_name
        .push(DnType::CommonName, format!("Vilicus E26 {description}"));
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate().map_err(|e| e.to_string())?;
    let pem = params.self_signed(&key).map_err(|e| e.to_string())?.pem();
    Ok((
        Authority {
            label: label.into(),
            params,
            key,
        },
        pem,
    ))
}

fn leaf(name: &str, ca: &Authority) -> Result<(String, String), String> {
    let mut params = CertificateParams::new(vec![name.to_owned()]).map_err(|e| e.to_string())?;
    params.distinguished_name.push(DnType::CommonName, name);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate().map_err(|e| e.to_string())?;
    let issuer = Issuer::from_params(&ca.params, &ca.key);
    let cert = params.signed_by(&key, &issuer).map_err(|e| e.to_string())?;
    Ok((cert.pem(), key.serialize_pem()))
}

fn write(path: &Path, text: &str) -> Result<(), String> {
    fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Written last, so a directory that holds it holds a complete PKI.
pub const COMPLETE_MARKER: &str = "complete";

/// Generates the whole PKI for `layout` into `dir`, unless `dir` already holds a complete one:
/// servers that loaded the first PKI keep it in memory, so it must never be replaced under them.
/// Returns whether it generated anything.
pub fn generate(layout: &Layout, dir: &Path) -> Result<bool, String> {
    if dir.join(COMPLETE_MARKER).exists() {
        return Ok(false);
    }
    fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut authorities = Vec::new();
    for (label, description) in &layout.cas {
        let (ca, pem) = authority(label, description)?;
        write(&dir.join(format!("ca-{label}.crt")), &pem)?;
        authorities.push(ca);
    }
    let find = |label: &str| {
        authorities
            .iter()
            .find(|a| a.label == label)
            .ok_or_else(|| format!("unknown CA {label}"))
    };
    for instance in &layout.instances {
        let (cert, key) = leaf(&instance.name, find(&instance.ca)?)?;
        write(&dir.join(format!("{}.crt", instance.name)), &cert)?;
        write(&dir.join(format!("{}.key", instance.name)), &key)?;
        let bundles = dir.join("bundles").join(&instance.deployment);
        fs::create_dir_all(&bundles).map_err(|e| format!("{}: {e}", bundles.display()))?;
        write(
            &bundles.join(format!("{}.pem", instance.name)),
            &format!("{cert}{key}"),
        )?;
    }
    for (suffix, label) in &layout.wildcards {
        let (cert, key) = leaf(&format!("*.{suffix}"), find(label)?)?;
        write(&dir.join(format!("wildcard.{suffix}.crt")), &cert)?;
        write(&dir.join(format!("wildcard.{suffix}.key")), &key)?;
    }
    write(&dir.join(COMPLETE_MARKER), "")?;
    Ok(true)
}
