//! Replays the E19 vector files (D130) against the profile of `vilicus-proto` (Story 2.5, AC5).
//! `VECTORS_DIR` points at another generation, such as a larger one written by
//! `examples/gen_vectors.rs`; by default the committed files under `tests/data/canonical-cbor/`
//! are used and must equal a fresh generation with the committed parameters. Another directory
//! must also hold the hand-written `invalid.json`, which the generator does not write.

mod vectors;

use std::{env, fs, path::PathBuf};

use dcbor::CBOR;
use serde_json::Value;
use vilicus_proto::profile;

use vectors::{hex, notation};

fn vectors_dir() -> PathBuf {
    env::var_os("VECTORS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(vectors::committed_dir)
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
            "{name} differs from a fresh generation; rerun `cargo run -p vilicus-proto --example gen_vectors --config ci/cargo-vendored.toml`"
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
        assert_eq!(hex::encode(&vectors::sha256(&content)), sum, "{name}");
        listed += 1;
    }
    assert!(listed >= 2);
}

#[test]
fn corpus_header_states_the_profile_constants() {
    // A gate, not a label (AC5, AC7): the header carries the Unicode version of the pinned NFC
    // tables, so vectors written under other tables fail here instead of being replayed as if
    // equal.
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
            hex::encode(&vectors::sha256(&encoded)),
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

#[test]
fn every_committed_file_is_listed_in_sha256sums() {
    let dir = vectors::committed_dir();
    let sums = fs::read_to_string(dir.join("SHA256SUMS")).expect("SHA256SUMS");
    let mut listed: Vec<&str> = sums
        .lines()
        .filter_map(|line| line.split_once("  ").map(|(_, name)| name))
        .collect();
    listed.push("SHA256SUMS");
    listed.sort_unstable();
    let mut present: Vec<String> = fs::read_dir(&dir)
        .expect("vector directory")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .into_string()
                .expect("UTF-8 name")
        })
        .collect();
    present.sort_unstable();
    assert_eq!(present, listed);
}

/// AC7: `unicode-normalization` is pinned exactly in the workspace manifest, because its Unicode
/// version is part of the canonical form; a caret requirement would let `cargo update` change it.
#[test]
fn unicode_normalization_is_pinned_exactly() {
    let manifest =
        fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml"))
            .expect("workspace manifest");
    let line = manifest
        .lines()
        .find(|line| line.starts_with("unicode-normalization = "))
        .expect("unicode-normalization in [workspace.dependencies]");
    assert!(line.contains("version = \"=0.1.25\""), "{line}");
    // Unicode 17.0.0 is the version D130 and the Stack table state for 0.1.25; a release of the
    // crate that changed it would fail here even under the same version requirement.
    assert_eq!(profile::UNICODE_VERSION, (17, 0, 0));
    let (major, minor, update) = profile::UNICODE_VERSION;
    let header = vectors::profile_header();
    assert_eq!(
        header["unicode_version"],
        format!("{major}.{minor}.{update}")
    );
}

/// The E19 vector set exists twice: here, where the product regenerates and replays it, and in
/// `spikes/canonical-cbor/vectors/`, which the TypeScript replay reads until Story 10.6 moves it.
/// The two copies must stay byte-equal, file by file.
#[test]
fn the_spike_copy_of_the_vectors_is_byte_equal() {
    let spike =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spikes/canonical-cbor/vectors");
    let names = |dir: &PathBuf| {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .into_string()
                    .expect("UTF-8 name")
            })
            .collect();
        names.sort_unstable();
        names
    };
    let committed = vectors::committed_dir();
    let listed = names(&committed);
    assert_eq!(names(&spike), listed);
    for name in &listed {
        let here = fs::read(committed.join(name)).expect("committed file");
        let there = fs::read(spike.join(name)).expect("spike file");
        assert!(here == there, "{name} differs between the two copies");
    }
}
