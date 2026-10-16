//! Replays the vector files against the Rust profile. `VECTORS_DIR` points at another
//! generation (the larger fresh run of `run.sh`); by default the committed files are used and
//! must equal a fresh generation with the committed parameters.

use std::{env, fs, path::PathBuf};

use canonical_cbor::{notation, profile, vectors};
use dcbor::CBOR;
use serde_json::Value;

fn vectors_dir() -> PathBuf {
    env::var_os("VECTORS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors"))
}

fn load(name: &str) -> Value {
    let path = vectors_dir().join(name);
    let text =
        fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn items(document: &Value) -> &Vec<Value> {
    document["items"].as_array().expect("items array")
}

fn field<'a>(item: &'a Value, name: &str) -> &'a str {
    item[name]
        .as_str()
        .unwrap_or_else(|| panic!("missing {name} in {item}"))
}

fn bytes_of(item: &Value) -> Vec<u8> {
    hex::decode(field(item, "hex")).expect("hex")
}

#[test]
fn committed_vectors_equal_a_fresh_generation() {
    if env::var_os("VECTORS_DIR").is_some() {
        return;
    }
    let generated = vectors::generate(vectors::COMMITTED).expect("generation");
    let dir = vectors_dir();
    for (name, fresh) in [
        ("corpus.json", generated.corpus),
        ("encode-invalid.json", generated.encode_invalid),
        ("fuzz.json", generated.fuzz),
    ] {
        let committed = fs::read_to_string(dir.join(name)).expect("committed file");
        assert!(
            committed == fresh,
            "{name} differs from a fresh generation; rerun `cargo run --bin gen_vectors -- vectors`"
        );
    }
}

#[test]
fn sha256sums_list_the_vector_files() {
    let dir = vectors_dir();
    let sums = fs::read_to_string(dir.join("SHA256SUMS")).expect("SHA256SUMS");
    let mut listed = 0;
    for line in sums.lines() {
        let (sum, name) = line.split_once("  ").expect("sum and name");
        let content = fs::read(dir.join(name)).expect("listed file");
        assert_eq!(hex::encode(profile::hash(&content)), sum, "{name}");
        listed += 1;
    }
    assert!(listed >= 2);
}

#[test]
fn corpus_header_states_the_profile_constants() {
    // A gate, not a label: the header carries the Unicode version of the pinned NFC tables, so
    // vectors written under other tables fail here instead of being replayed as if equal.
    for name in ["corpus.json", "encode-invalid.json", "fuzz.json"] {
        assert_eq!(load(name)["profile"], vectors::profile_header(), "{name}");
    }
}

#[test]
fn corpus_encodes_hashes_and_round_trips() {
    let corpus = load("corpus.json");
    let mut count = 0;
    for item in items(&corpus) {
        let id = field(item, "id");
        let value =
            notation::to_cbor(&item["value"]).unwrap_or_else(|error| panic!("{id}: {error}"));
        let encoded = profile::encode(&value).unwrap_or_else(|error| panic!("{id}: {error}"));
        assert_eq!(hex::encode(&encoded), field(item, "hex"), "{id}: encoding");
        assert_eq!(
            hex::encode(profile::hash(&encoded)),
            field(item, "sha256"),
            "{id}: hash"
        );
        let decoded = profile::decode(&encoded).unwrap_or_else(|error| panic!("{id}: {error}"));
        assert_eq!(decoded.to_cbor_data(), encoded, "{id}: re-encoding");
        count += 1;
    }
    println!("CHECK INFO rust corpus items {count}");
    assert!(count > 500);
}

#[test]
fn encode_invalid_values_are_all_refused() {
    let invalid = load("encode-invalid.json");
    for item in items(&invalid) {
        let name = field(item, "name");
        let refused = notation::to_cbor(&item["value"])
            .and_then(|value| profile::encode(&value).map_err(|rejection| rejection.to_string()));
        assert!(refused.is_err(), "{name}: encoded");
    }
    println!(
        "CHECK INFO rust encode-invalid items {}",
        items(&invalid).len()
    );
    assert!(!items(&invalid).is_empty());
}

#[test]
fn invalid_inputs_are_all_rejected() {
    let dir = vectors_dir();
    if !dir.join("invalid.json").exists() {
        return;
    }
    let invalid = load("invalid.json");
    let mut raw_accepted = Vec::new();
    for item in items(&invalid) {
        let name = field(item, "name");
        let bytes = bytes_of(item);
        assert!(
            profile::decode(&bytes).is_err(),
            "{name}: accepted by the profile"
        );
        // dcbor alone, for the record of what the profile layer adds. The hand-written inputs
        // are all shallow, so the recursive decoder is safe on them.
        if CBOR::try_from_data(&bytes).is_ok() {
            raw_accepted.push(name);
        }
    }
    println!("CHECK INFO rust invalid items {}", items(&invalid).len());
    println!("CHECK INFO dcbor alone accepts: {}", raw_accepted.join(" "));
}

#[test]
fn fuzz_verdicts_hold() {
    let fuzz = load("fuzz.json");
    let (mut accepted, mut rejected) = (0, 0);
    for item in items(&fuzz) {
        let id = field(item, "id");
        let bytes = bytes_of(item);
        let expected = item["accept"].as_bool().expect("accept");
        let verdict = profile::decode(&bytes);
        assert_eq!(verdict.is_ok(), expected, "{id}: {verdict:?}");
        if item["must_reject"].as_bool().expect("must_reject") {
            assert!(!expected, "{id}: a targeted mutation was accepted");
        }
        match verdict {
            Ok(value) => {
                assert_eq!(value.to_cbor_data(), bytes, "{id}: re-encoding");
                accepted += 1;
            }
            Err(_) => rejected += 1,
        }
    }
    println!("CHECK INFO rust fuzz accepted {accepted} rejected {rejected}");
    assert!(accepted > 0 && rejected > 0);
}
