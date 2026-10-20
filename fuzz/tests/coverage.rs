//! Story 2.7, AC1: every public decoding entry point of `vilicus-proto` has a fuzz target, so a
//! new decoder cannot ship unfuzzed.
//!
//! The entry points are read from the crate's sources, outside their test modules: every public
//! function taking bytes or a reader (`&[u8]`, `Vec<u8>`, `impl Read`), as `module::function`, and
//! every public type with a hand-written `Wire` implementation, macro-generated ones included, by
//! name. Each must be named by the `decoders` of a target, or listed in [`NOT_DECODERS`] with the
//! reason it decodes nothing; each name a target or that list gives must be one of them.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use vilicus_fuzz::TARGETS;

/// Public functions of `vilicus-proto` that take bytes without decoding them.
const NOT_DECODERS: &[(&str, &str)] = &[
    ("frame::write_frame", "writes the message bytes it is given"),
    (
        "canonical::from_stored",
        "wraps stored bytes without decoding them",
    ),
    (
        "canonical::matches_hash",
        "hashes the stored bytes as they are",
    ),
];

const BYTE_PARAMETERS: &[&str] = &["&[u8]", "Vec<u8>", "impl Read"];

fn proto_sources() -> Vec<(String, String)> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/vilicus-proto/src");
    let mut sources: Vec<(String, String)> = std::fs::read_dir(&directory)
        .expect("vilicus-proto sources")
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
        .map(|path: PathBuf| {
            let module = path
                .file_stem()
                .expect("a stem")
                .to_string_lossy()
                .into_owned();
            let code = std::fs::read_to_string(&path).expect("a source file");
            (module, without_test_module(&code))
        })
        .collect();
    sources.sort();
    assert!(
        !sources.is_empty(),
        "no source read from {}",
        directory.display()
    );
    sources
}

/// The code without the file's test module: a `#[cfg(test)]` line opening a `mod tests`, up to
/// the brace that closes it, so that an item written after the module is still read.
fn without_test_module(code: &str) -> String {
    let mut offset = 0;
    let mut lines = code.split_inclusive('\n').peekable();
    while let Some(line) = lines.next() {
        if line.trim_end() == "#[cfg(test)]"
            && lines.peek().is_some_and(|next| next.contains("mod tests"))
        {
            let open = offset + code[offset..].find('{').expect("the module opens");
            let mut depth = 0;
            for (index, c) in code[open..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    _ => {}
                }
                if depth == 0 {
                    return format!("{}{}", &code[..offset], &code[open + index + 1..]);
                }
            }
            panic!("the test module never closes");
        }
        offset += line.len();
    }
    code.to_owned()
}

fn identifier(text: &str) -> &str {
    let end = text
        .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$'))
        .unwrap_or(text.len());
    &text[..end]
}

/// The text between the parenthesis that opens `text` and the one that closes it.
fn parenthesized(text: &str) -> &str {
    let mut depth = 0;
    for (index, c) in text.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return &text[1..index];
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced parameters: {text}")
}

fn byte_reading_functions() -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for (module, code) in proto_sources() {
        for (at, _) in code
            .match_indices("pub fn ")
            .chain(code.match_indices("pub const fn "))
        {
            let after = &code[at..];
            let after = &after[after.find("fn ").expect("fn") + 3..];
            let name = identifier(after);
            let rest = &after[name.len()..];
            let rest = &rest[rest.find('(').expect("parameters")..];
            if BYTE_PARAMETERS
                .iter()
                .any(|kind| parenthesized(rest).contains(kind))
            {
                found.insert(format!("{module}::{name}"));
            }
        }
    }
    found
}

fn public_wire_types() -> BTreeSet<String> {
    let sources = proto_sources();
    let private = |name: &str| {
        sources.iter().any(|(_, code)| {
            code.lines().any(|line| {
                line.starts_with(&format!("struct {name}"))
                    || line.starts_with(&format!("enum {name}"))
            })
        })
    };
    let mut found = BTreeSet::new();
    for (_, code) in &sources {
        for (at, _) in code.match_indices("Wire for ") {
            let name = identifier(&code[at + "Wire for ".len()..]);
            if !name.starts_with('$') && !private(name) {
                found.insert(name.to_owned());
            }
        }
        for (at, _) in code.match_indices("macro_rules! ") {
            let macro_name = identifier(&code[at + "macro_rules! ".len()..]);
            let invocation = format!("{macro_name}!(");
            let Some(called) = code.find(&invocation) else {
                continue;
            };
            if !code[at..called].contains("Wire for $") {
                continue;
            }
            let arguments = parenthesized(&code[called + invocation.len() - 1..]);
            found.extend(
                arguments
                    .split(',')
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .map(str::to_owned),
            );
        }
    }
    found
}

fn declared_decoders() -> BTreeSet<String> {
    TARGETS
        .iter()
        .flat_map(|target| target.decoders.iter().map(|name| (*name).to_owned()))
        .collect()
}

#[test]
fn every_public_function_reading_bytes_has_a_target_or_a_reason() {
    let covered = declared_decoders();
    let excused: BTreeSet<_> = NOT_DECODERS
        .iter()
        .map(|(name, _)| (*name).to_owned())
        .collect();
    let missing: Vec<_> = byte_reading_functions()
        .into_iter()
        .filter(|name| !covered.contains(name) && !excused.contains(name))
        .collect();
    assert!(
        missing.is_empty(),
        "public decoders without a fuzz target: {missing:?}"
    );
}

#[test]
fn every_public_wire_type_is_decoded_by_a_target() {
    let covered = declared_decoders();
    let missing: Vec<_> = public_wire_types()
        .into_iter()
        .filter(|name| !covered.contains(name))
        .collect();
    assert!(
        missing.is_empty(),
        "Wire types without a fuzz target: {missing:?}"
    );
}

#[test]
fn every_declared_decoder_and_reason_names_an_entry_point() {
    let functions = byte_reading_functions();
    let types = public_wire_types();
    for name in declared_decoders() {
        assert!(
            functions.contains(&name) || types.contains(&name),
            "{name} is declared by a target but is no public decoder of vilicus-proto"
        );
    }
    for (name, reason) in NOT_DECODERS {
        assert!(!reason.is_empty());
        assert!(
            functions.contains(*name),
            "{name} is listed as reading bytes, and does not"
        );
    }
}

#[test]
fn every_target_has_its_binary_and_every_binary_a_target() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin");
    let binaries: BTreeSet<String> = std::fs::read_dir(&directory)
        .expect("src/bin")
        .map(|entry| entry.expect("directory entry").path())
        .map(|path| {
            path.file_stem()
                .expect("a stem")
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name != "fuzz-plan")
        .collect();
    let targets: BTreeSet<String> = TARGETS
        .iter()
        .map(|target| target.name.to_owned())
        .collect();
    assert_eq!(binaries, targets);
}
