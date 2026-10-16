//! RFC 9180 test vectors for the AD-18 suite (mode 0, KEM 0x0020, KDF 0x0001, AEAD 0x0002),
//! run against the crate under review and against the independent implementation.
//!
//! The vector is driven through the public API only: the ephemeral key comes from `ikmE`
//! served as the 32 random bytes each implementation draws, so `enc`, every ciphertext of the
//! sequence and every exported value must match the published bytes.

mod common;

use std::path::PathBuf;

use common::{QueuedBytes, SeededLibcrux, SeededRustCrypto, hex, independent_on};
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use hpke_review::{PrivateKey, SuiteAead, SuiteKdf, SuiteKem};
use hpke_rs::{HpkePrivateKey, HpkePublicKey};
use hpke_rs_crypto::HpkeCrypto;
use serde_json::Value;

const SUBSET: &str = include_str!("../vectors/rfc9180-base-x25519-sha256-aes256gcm.json");
const UPSTREAM_FILE_NAME: &str = "test-vectors-5f503c5.json";

fn vector() -> Value {
    let all: Value = serde_json::from_str(SUBSET).expect("vector subset is JSON");
    let list = all.as_array().expect("vector subset is a list");
    assert_eq!(
        list.len(),
        1,
        "the subset holds the one base-mode vector of the suite"
    );
    list[0].clone()
}

fn field(v: &Value, name: &str) -> Vec<u8> {
    hex(v[name].as_str().unwrap_or_else(|| panic!("field {name}")))
}

fn is_ad18_suite(v: &Value) -> bool {
    v["mode"] == 0 && v["kem_id"] == 0x20 && v["kdf_id"] == 1 && v["aead_id"] == 2
}

/// The hpke crate ships the official vector file in its package. Cargo extracts it into the
/// registry source directory when it builds the crate, so a test can read it without network.
fn upstream_file() -> PathBuf {
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo")))
        .or_else(|| std::env::var_os("USERPROFILE").map(|h| PathBuf::from(h).join(".cargo")))
        .expect("CARGO_HOME, HOME or USERPROFILE");
    let registry = cargo_home.join("registry").join("src");
    std::fs::read_dir(&registry)
        .unwrap_or_else(|e| panic!("cannot list {}: {e}", registry.display()))
        .filter_map(Result::ok)
        .map(|index| index.path().join("hpke-0.13.0").join(UPSTREAM_FILE_NAME))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| {
            panic!(
                "{UPSTREAM_FILE_NAME} not found under {}",
                registry.display()
            )
        })
}

#[test]
fn subset_is_exactly_the_suite_entries_of_the_upstream_file() {
    let path = upstream_file();
    let text = std::fs::read_to_string(&path).expect("upstream vector file");
    let upstream: Value = serde_json::from_str(&text).expect("upstream vectors are JSON");
    let from_upstream: Vec<Value> = upstream
        .as_array()
        .expect("upstream vectors are a list")
        .iter()
        .filter(|v| is_ad18_suite(v))
        .cloned()
        .collect();
    let subset: Value = serde_json::from_str(SUBSET).expect("vector subset is JSON");
    assert_eq!(
        Value::Array(from_upstream),
        subset,
        "subset differs from {}",
        path.display()
    );
}

#[test]
fn hpke_crate_matches_the_base_mode_vector() {
    let v = vector();
    assert!(is_ad18_suite(&v));
    let info = field(&v, "info");

    let (sk_r, pk_r) = SuiteKem::derive_keypair(&field(&v, "ikmR"));
    assert_eq!(
        sk_r.to_bytes().as_slice(),
        field(&v, "skRm"),
        "DeriveKeyPair skR"
    );
    assert_eq!(
        pk_r.to_bytes().as_slice(),
        field(&v, "pkRm"),
        "DeriveKeyPair pkR"
    );
    let (sk_e, pk_e) = SuiteKem::derive_keypair(&field(&v, "ikmE"));
    assert_eq!(
        sk_e.to_bytes().as_slice(),
        field(&v, "skEm"),
        "DeriveKeyPair skE"
    );
    assert_eq!(
        pk_e.to_bytes().as_slice(),
        field(&v, "pkEm"),
        "DeriveKeyPair pkE"
    );

    let mut ephemeral = QueuedBytes::new(&field(&v, "ikmE"));
    let (enc, mut sender) = hpke::setup_sender::<SuiteAead, SuiteKdf, SuiteKem, _>(
        &OpModeS::Base,
        &pk_r,
        &info,
        &mut ephemeral,
    )
    .expect("setup_sender");
    assert!(
        ephemeral.is_drained(),
        "the sender draws exactly the 32 bytes of ikmE"
    );
    assert_eq!(enc.to_bytes().as_slice(), field(&v, "enc"), "enc");

    // The receiver uses the private key as serialized in the vector, not the derived object.
    let sk_from_bytes = PrivateKey::from_bytes(&field(&v, "skRm")).expect("skRm");
    let mut receiver = hpke::setup_receiver::<SuiteAead, SuiteKdf, SuiteKem>(
        &OpModeR::Base,
        &sk_from_bytes,
        &enc,
        &info,
    )
    .expect("setup_receiver");

    let encryptions = v["encryptions"].as_array().expect("encryptions");
    assert!(!encryptions.is_empty());
    for (seq, e) in encryptions.iter().enumerate() {
        let (aad, pt, ct) = (field(e, "aad"), field(e, "pt"), field(e, "ct"));
        assert_eq!(
            sender.seal(&pt, &aad).expect("seal"),
            ct,
            "seal at sequence {seq}"
        );
        assert_eq!(
            receiver.open(&ct, &aad).expect("open"),
            pt,
            "open at sequence {seq}"
        );
    }

    let exports = v["exports"].as_array().expect("exports");
    assert!(!exports.is_empty());
    for x in exports {
        let context = field(x, "exporter_context");
        let expected = field(x, "exported_value");
        let length = usize::try_from(x["L"].as_u64().expect("L")).expect("L fits");
        assert_eq!(expected.len(), length);
        let mut from_sender = vec![0u8; length];
        let mut from_receiver = vec![0u8; length];
        sender
            .export(&context, &mut from_sender)
            .expect("sender export");
        receiver
            .export(&context, &mut from_receiver)
            .expect("receiver export");
        assert_eq!(from_sender, expected, "sender export");
        assert_eq!(from_receiver, expected, "receiver export");
    }
}

#[test]
fn hpke_crate_single_shot_matches_the_first_encryption() {
    let v = vector();
    let first = &v["encryptions"][0];
    let pk_r = <SuiteKem as Kem>::PublicKey::from_bytes(&field(&v, "pkRm")).expect("pkRm");
    let (enc, ct) = hpke::single_shot_seal::<SuiteAead, SuiteKdf, SuiteKem, _>(
        &OpModeS::Base,
        &pk_r,
        &field(&v, "info"),
        &field(first, "pt"),
        &field(first, "aad"),
        &mut QueuedBytes::new(&field(&v, "ikmE")),
    )
    .expect("single_shot_seal");
    assert_eq!(enc.to_bytes().as_slice(), field(&v, "enc"));
    assert_eq!(ct, field(first, "ct"));

    let sk_r = PrivateKey::from_bytes(&field(&v, "skRm")).expect("skRm");
    let mut out = vec![0u8; field(first, "pt").len()];
    hpke_review::open_into(
        &sk_r,
        &field(&v, "enc"),
        &field(&v, "info"),
        &field(first, "aad"),
        &ct,
        &mut out,
    )
    .expect("open_into");
    assert_eq!(out, field(first, "pt"));
}

#[test]
fn independent_implementation_matches_the_base_mode_vector_with_rustcrypto() {
    independent_implementation_matches::<SeededRustCrypto>();
}

#[test]
fn independent_implementation_matches_the_base_mode_vector_with_libcrux() {
    independent_implementation_matches::<SeededLibcrux>();
}

fn independent_implementation_matches<P: HpkeCrypto<HpkePrng = QueuedBytes> + 'static>() {
    let v = vector();
    let info = field(&v, "info");

    let mut hpke = independent_on::<P>(&field(&v, "ikmE"));
    let derived = hpke
        .derive_key_pair(&field(&v, "ikmR"))
        .expect("derive_key_pair");
    assert_eq!(
        derived.public_key().as_slice(),
        field(&v, "pkRm"),
        "DeriveKeyPair pkR"
    );

    let pk_r = HpkePublicKey::new(field(&v, "pkRm"));
    let (enc, mut sender) = hpke
        .setup_sender(&pk_r, &info, None, None, None)
        .expect("setup_sender");
    assert_eq!(enc, field(&v, "enc"), "enc");

    let sk_r = HpkePrivateKey::new(field(&v, "skRm"));
    let mut receiver = hpke
        .setup_receiver(&enc, &sk_r, &info, None, None, None)
        .expect("setup_receiver");
    let mut receiver_derived_key = hpke
        .setup_receiver(&enc, derived.private_key(), &info, None, None, None)
        .expect("setup_receiver with the derived key");

    for (seq, e) in v["encryptions"]
        .as_array()
        .expect("encryptions")
        .iter()
        .enumerate()
    {
        let (aad, pt, ct) = (field(e, "aad"), field(e, "pt"), field(e, "ct"));
        assert_eq!(
            sender.seal(&aad, &pt).expect("seal"),
            ct,
            "seal at sequence {seq}"
        );
        assert_eq!(
            receiver.open(&aad, &ct).expect("open"),
            pt,
            "open at sequence {seq}"
        );
        assert_eq!(
            receiver_derived_key.open(&aad, &ct).expect("open"),
            pt,
            "open with the derived key at sequence {seq}"
        );
    }

    for x in v["exports"].as_array().expect("exports") {
        let context = field(x, "exporter_context");
        let expected = field(x, "exported_value");
        let length = usize::try_from(x["L"].as_u64().expect("L")).expect("L fits");
        assert_eq!(sender.export(&context, length).expect("export"), expected);
        assert_eq!(receiver.export(&context, length).expect("export"), expected);
    }
}
