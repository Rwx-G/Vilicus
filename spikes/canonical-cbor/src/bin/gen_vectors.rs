//! Writes `corpus.json`, `encode-invalid.json`, `fuzz.json` and `SHA256SUMS` into a directory.
//!
//! Usage: `gen_vectors <out-dir> [corpus-seed shaped random fuzz-seed fuzz deep]`. Without the
//! optional arguments it writes the committed vector set. `SHA256SUMS` also covers the
//! hand-written `invalid.json` when the directory holds one.

use std::{fs, path::Path, process::ExitCode};

use canonical_cbor::{profile, vectors};

fn parse(args: &[String]) -> Result<vectors::Parameters, String> {
    if args.is_empty() {
        return Ok(vectors::COMMITTED);
    }
    let [corpus_seed, shaped, random, fuzz_seed, fuzz, deep] = args else {
        return Err("expected no parameter or all six".to_owned());
    };
    let number = |text: &String| {
        text.parse::<u64>()
            .map_err(|_| format!("not a number: {text}"))
    };
    Ok(vectors::Parameters {
        corpus_seed: number(corpus_seed)?,
        shaped: number(shaped)? as usize,
        random: number(random)? as usize,
        fuzz_seed: number(fuzz_seed)?,
        fuzz: number(fuzz)? as usize,
        deep: number(deep)? as usize,
    })
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (out, rest) = args
        .split_first()
        .ok_or("usage: gen_vectors <out-dir> [...]")?;
    let parameters = parse(rest)?;
    let out = Path::new(out);
    fs::create_dir_all(out).map_err(|error| error.to_string())?;
    let generated = vectors::generate(parameters)?;
    let mut sums = String::new();
    for (name, content) in [
        ("corpus.json", generated.corpus),
        ("encode-invalid.json", generated.encode_invalid),
        ("fuzz.json", generated.fuzz),
    ] {
        fs::write(out.join(name), &content).map_err(|error| error.to_string())?;
    }
    for name in [
        "corpus.json",
        "encode-invalid.json",
        "fuzz.json",
        "invalid.json",
    ] {
        if let Ok(content) = fs::read(out.join(name)) {
            sums.push_str(&format!(
                "{}  {name}\n",
                hex::encode(profile::hash(&content))
            ));
        }
    }
    fs::write(out.join("SHA256SUMS"), sums).map_err(|error| error.to_string())?;
    println!(
        "corpus seed {} ({} shaped, {} random), fuzz seed {} ({} cases, depth {}) written to {}",
        parameters.corpus_seed,
        parameters.shaped,
        parameters.random,
        parameters.fuzz_seed,
        parameters.fuzz,
        parameters.deep,
        out.display()
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("gen_vectors: {error}");
            ExitCode::FAILURE
        }
    }
}
