//! The E19 vector set of D130, moved from `spikes/canonical-cbor/` (Story 2.5): `corpus.json`,
//! `encode-invalid.json` and `fuzz.json` are generated here, `invalid.json` is written by hand.
//! One item per line, so a change shows as a readable diff. The generator is
//! `examples/gen_vectors.rs`; `tests/canonical_vectors.rs` replays the files and refuses one that
//! differs from a fresh generation.
//!
//! Test data only: this tree is compiled into the integration test and the example, never into
//! the library.

pub mod corpus;
pub mod fuzz;
pub mod hex;
pub mod notation;
pub mod rng;

use std::path::PathBuf;

use serde_json::{Value, json};
use vilicus_proto::profile;

/// The directory of the committed vector files.
pub fn committed_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/canonical-cbor")
}

/// SHA-256, as the Core and every signer compute it; the Core's own goes through
/// `vilicus-crypto`, and this one only writes and checks the vector files.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes);
    digest.as_ref().try_into().expect("SHA-256 has 32 bytes")
}

/// Parameters of a vector generation.
#[derive(Clone, Copy)]
pub struct Parameters {
    pub corpus_seed: u64,
    pub shaped: usize,
    pub random: usize,
    pub fuzz_seed: u64,
    pub fuzz: usize,
    /// Nesting of the deepest hostile inputs in `fuzz.json`.
    pub deep: usize,
}

/// The parameters of the committed vector files.
pub const COMMITTED: Parameters = Parameters {
    corpus_seed: 0x0e19_c0de_0001,
    shaped: 200,
    random: 400,
    fuzz_seed: 0x0e19_f022_0001,
    fuzz: 2_500,
    deep: 10_000,
};

/// Only corpus encodings up to this length are mutated, which keeps `fuzz.json` small.
pub const FUZZ_BASE_MAX_LEN: usize = 128;

pub const CORPUS_FORMAT: &str = "vilicus-e19-corpus/1";
pub const FUZZ_FORMAT: &str = "vilicus-e19-fuzz/1";
pub const ENCODE_INVALID_FORMAT: &str = "vilicus-e19-encode-invalid/1";

/// The profile as the vector files state it, derived from the constants of [`profile`].
pub fn profile_header() -> Value {
    let (major, minor, update) = profile::UNICODE_VERSION;
    json!({
        "max_depth": profile::MAX_DEPTH,
        "listed_tags": profile::LISTED_TAGS,
        "int_min": profile::INT_MIN.to_string(),
        "int_max": profile::INT_MAX.to_string(),
        "floats": false,
        "indefinite_lengths": false,
        "text_normalization": "NFC",
        "unicode_version": format!("{major}.{minor}.{update}"),
        "simple_values": ["false", "true", "null"],
    })
}

/// A corpus item with its canonical encoding.
pub struct Encoded {
    pub item: corpus::Item,
    pub bytes: Vec<u8>,
}

/// Encodes every corpus item with the profile encoder.
pub fn encode_corpus(items: Vec<corpus::Item>) -> Result<Vec<Encoded>, String> {
    items
        .into_iter()
        .map(|item| {
            let value = notation::to_cbor(&item.value)?;
            let bytes = profile::encode(&value).map_err(|error| format!("{}: {error}", item.id))?;
            Ok(Encoded { item, bytes })
        })
        .collect()
}

fn document(header: Value, items: Vec<Value>) -> String {
    let mut header = serde_json::to_string(&header).expect("serializable header");
    // Reopen the header object to append the item array, one item per line.
    header.pop();
    let lines: Vec<String> = items
        .iter()
        .map(|item| serde_json::to_string(item).expect("serializable item"))
        .collect();
    format!("{header},\"items\":[\n{}\n]}}\n", lines.join(",\n"))
}

/// The generated vector files.
pub struct Generated {
    pub corpus: String,
    pub encode_invalid: String,
    pub fuzz: String,
}

/// Generates the vector files for the given parameters.
pub fn generate(parameters: Parameters) -> Result<Generated, String> {
    let encoded = encode_corpus(corpus::generate(
        parameters.corpus_seed,
        parameters.shaped,
        parameters.random,
    ))?;

    let corpus_items = encoded
        .iter()
        .map(|entry| {
            json!({
                "id": entry.item.id,
                "family": entry.item.family,
                "value": entry.item.value,
                "hex": hex::encode(&entry.bytes),
                "sha256": hex::encode(&sha256(&entry.bytes)),
            })
        })
        .collect();
    let corpus_json = document(
        json!({
            "format": CORPUS_FORMAT,
            "description": "Valid values under the AD-13 profile. `value` is the notation (map entries in generation order, text in NFC); `hex` is the canonical encoding produced by dcbor; `sha256` is its hash.",
            "seed": parameters.corpus_seed.to_string(),
            "profile": profile_header(),
        }),
        corpus_items,
    );

    let bases: Vec<(String, Vec<u8>)> = encoded
        .iter()
        .filter(|entry| entry.bytes.len() <= FUZZ_BASE_MAX_LEN)
        .map(|entry| (entry.item.id.clone(), entry.bytes.clone()))
        .collect();
    let fuzz_items = fuzz::generate(
        parameters.fuzz_seed,
        parameters.fuzz,
        parameters.deep,
        &bases,
    )
    .into_iter()
    .map(|case| {
        json!({
            "id": case.id,
            "kind": case.kind,
            "base": case.base,
            "hex": hex::encode(&case.bytes),
            "must_reject": case.must_reject,
            "accept": case.verdict.is_ok(),
            "rust": match &case.verdict {
                Ok(()) => "accept".to_owned(),
                Err(rejection) => rejection.to_string(),
            },
        })
    })
    .collect();
    let fuzz_json = document(
        json!({
            "format": FUZZ_FORMAT,
            "description": "Mutations of corpus encodings. `must_reject` marks a targeted mutation that breaks one profile rule; `accept` is the verdict of the Rust profile decoder, which every other decoder must reach; `rust` is its reason, for information only.",
            "seed": parameters.fuzz_seed.to_string(),
            "profile": profile_header(),
        }),
        fuzz_items,
    );
    let encode_invalid_items = corpus::encode_invalid()
        .into_iter()
        .map(|(name, value)| json!({ "name": name, "value": value }))
        .collect();
    let encode_invalid_json = document(
        json!({
            "format": ENCODE_INVALID_FORMAT,
            "description": "Values every profile encoder must refuse: non-NFC text, map keys equal once normalized, nesting over the bound, an integer below the range. `value` is the notation, text exactly as written.",
            "profile": profile_header(),
        }),
        encode_invalid_items,
    );
    Ok(Generated {
        corpus: corpus_json,
        encode_invalid: encode_invalid_json,
        fuzz: fuzz_json,
    })
}
