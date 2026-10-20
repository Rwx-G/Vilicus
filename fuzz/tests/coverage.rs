//! Story 2.7, AC1: every public decoding entry point of `vilicus-proto` has a fuzz target, so a
//! new decoder cannot ship unfuzzed.
//!
//! The entry points are read from every source file under `vilicus-proto/src`, recursively,
//! outside the test modules, with comments removed and whitespace collapsed:
//!
//! - every public function, every method of a public trait (provided or required), whose
//!   generics, parameters or `where` clause mention bytes (a slice or an array of `u8`, or `u8`
//!   as a generic argument, inside any wrapper: `Vec<u8>`, `Box<[u8]>`, `impl AsRef<[u8]>`) or a
//!   trait whose name ends in
//!   `Read` (`impl Read`, `R: Read`, `&mut dyn Read`, `BufRead`), named `module::function` or
//!   `module::Trait::method`;
//! - every public type with a `Wire` implementation, those a `macro_rules!` writes included: every
//!   invocation of such a macro, with any delimiter, names one type per top-level argument.
//!
//! Each must be named by the `decoders` of a target, or listed in `NOT_DECODERS` with the reason
//! it decodes nothing; each name a target or that list gives must be found. This is a scan of the
//! source, not a parse of the language: the authoritative list comes from rustdoc's JSON in the
//! `fuzz` job (`ci/check_fuzz_coverage.py`), and this test is its stable, earlier copy.

use std::collections::BTreeSet;
use std::path::Path;

use vilicus_fuzz::{NOT_DECODERS, TARGETS, input_files};

/// One source file: its module path relative to the crate root, and its scanned text.
struct Source {
    module: String,
    text: String,
}

fn proto_sources() -> Vec<Source> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/vilicus-proto/src");
    let mut files = Vec::new();
    let mut directories = vec![root.clone()];
    while let Some(directory) = directories.pop() {
        for path in std::fs::read_dir(&directory)
            .expect("a source directory")
            .map(|entry| entry.expect("directory entry").path())
        {
            if path.is_dir() {
                directories.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    assert!(!files.is_empty(), "no source under {}", root.display());
    files
        .iter()
        .map(|path| {
            let relative = path.strip_prefix(&root).expect("under the root");
            let mut segments: Vec<String> = relative
                .with_extension("")
                .components()
                .map(|segment| segment.as_os_str().to_string_lossy().into_owned())
                .collect();
            if matches!(segments.last().map(String::as_str), Some("mod" | "lib")) {
                segments.pop();
            }
            let code = std::fs::read_to_string(path).expect("a source file");
            Source {
                module: segments.join("::"),
                text: scanned(&code),
            }
        })
        .collect()
}

/// The code without its test modules and comments, whitespace collapsed to single spaces.
fn scanned(code: &str) -> String {
    let code = without_comments(&without_test_modules(code));
    code.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The code without each `#[cfg(test)]` module, up to the brace that closes it, so that an item
/// written after a test module is still read.
fn without_test_modules(code: &str) -> String {
    let mut rest = code.to_owned();
    while let Some(attribute) = rest.find("#[cfg(test)]") {
        let after = &rest[attribute + "#[cfg(test)]".len()..];
        let item = after.trim_start();
        let is_module = item.starts_with("mod ")
            || item.starts_with("pub(crate) mod ")
            || item.starts_with("pub mod ");
        let Some(open) = after.find('{').filter(|_| is_module) else {
            rest.replace_range(attribute..attribute + "#[cfg(test)]".len(), "");
            continue;
        };
        let start = attribute + "#[cfg(test)]".len() + open;
        let end = start + matching(&rest[start..]).expect("the test module closes");
        rest.replace_range(attribute..end, "");
    }
    rest
}

fn without_comments(code: &str) -> String {
    let mut out = String::with_capacity(code.len());
    let mut chars = code.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, chars.peek()) {
            ('/', Some('/')) => {
                for next in chars.by_ref() {
                    if next == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            ('/', Some('*')) => {
                chars.next();
                let mut previous = ' ';
                for next in chars.by_ref() {
                    if previous == '*' && next == '/' {
                        break;
                    }
                    previous = next;
                }
                out.push(' ');
            }
            _ => out.push(c),
        }
    }
    out
}

/// The length of the bracketed group `text` opens with, up to and including its closing bracket.
fn matching(text: &str) -> Option<usize> {
    let (open, close) = match text.chars().next()? {
        '(' => ('(', ')'),
        '[' => ('[', ']'),
        '{' => ('{', '}'),
        '<' => ('<', '>'),
        _ => return None,
    };
    let mut depth = 0usize;
    let mut previous = ' ';
    for (index, c) in text.char_indices() {
        // `->` inside generics closes nothing.
        if c == close && !(close == '>' && previous == '-') {
            depth -= 1;
            if depth == 0 {
                return Some(index + c.len_utf8());
            }
        } else if c == open {
            depth += 1;
        }
        previous = c;
    }
    None
}

fn is_identifier_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn identifier(text: &str) -> &str {
    let end = text
        .find(|c: char| !(is_identifier_char(c) || c == '$'))
        .unwrap_or(text.len());
    &text[..end]
}

/// Whether the text of a signature's generics, parameters or `where` clause takes bytes or a
/// reader.
fn takes_bytes(signature: &str) -> bool {
    let compact: String = signature.chars().filter(|c| !c.is_whitespace()).collect();
    ["[u8", "<u8>", "<u8,", ",u8>", ",u8,"]
        .iter()
        .any(|form| compact.contains(form))
        || signature
            .match_indices("Read")
            .any(|(at, _)| !signature[at + "Read".len()..].starts_with(is_identifier_char))
}

/// The generics, parameters and `where` clause of the function whose name starts `after`, its
/// return type left out.
fn signature_inputs(after: &str) -> Option<String> {
    let name = identifier(after);
    let mut rest = after[name.len()..].trim_start();
    let mut inputs = String::new();
    if rest.starts_with('<') {
        let end = matching(rest)?;
        inputs.push_str(&rest[..end]);
        rest = rest[end..].trim_start();
    }
    let end = matching(rest)?;
    inputs.push_str(&rest[..end]);
    let tail = &rest[end..];
    let body = tail.find(['{', ';']).unwrap_or(tail.len());
    if let Some(clause) = tail[..body].find(" where ") {
        inputs.push_str(&tail[clause..body]);
    }
    Some(inputs)
}

/// The ranges of the bodies of public traits in `text`, with each trait's name.
fn public_trait_bodies(text: &str) -> Vec<(String, std::ops::Range<usize>)> {
    let mut bodies = Vec::new();
    for (at, _) in text.match_indices("pub trait ") {
        let name = identifier(&text[at + "pub trait ".len()..]).to_owned();
        if let Some(open) = text[at..].find('{').map(|offset| at + offset)
            && let Some(len) = matching(&text[open..])
        {
            bodies.push((name, open..open + len));
        }
    }
    bodies
}

/// Whether the item whose `fn` keyword is at `at` is declared `pub` (not `pub(crate)`), its
/// qualifiers and attributes allowed.
fn declared_pub(text: &str, at: usize) -> bool {
    let start = text[..at]
        .rfind(['{', '}', ';'])
        .map_or(0, |boundary| boundary + 1);
    let mut head = text[start..at].trim();
    while head.starts_with("#[") {
        match matching(&head[1..]) {
            Some(end) => head = head[1 + end..].trim_start(),
            None => return false,
        }
    }
    head.starts_with("pub ") || head == "pub"
}

fn byte_taking_functions_of(source: &Source) -> BTreeSet<String> {
    let text = &source.text;
    let traits = public_trait_bodies(text);
    let mut found = BTreeSet::new();
    for (at, _) in text.match_indices("fn ") {
        if text[..at].ends_with(is_identifier_char) {
            continue;
        }
        let after = &text[at + "fn ".len()..];
        let name = identifier(after);
        let in_trait = traits.iter().find(|(_, body)| body.contains(&at));
        if name.is_empty() || (in_trait.is_none() && !declared_pub(text, at)) {
            continue;
        }
        let Some(inputs) = signature_inputs(after) else {
            continue;
        };
        if takes_bytes(&inputs) {
            let path = match in_trait {
                Some((trait_name, _)) => format!("{trait_name}::{name}"),
                None => name.to_owned(),
            };
            found.insert(qualified(&source.module, &path));
        }
    }
    found
}

fn qualified(module: &str, name: &str) -> String {
    if module.is_empty() {
        name.to_owned()
    } else {
        format!("{module}::{name}")
    }
}

/// Every top-level argument's first identifier, in an invocation's bracketed arguments.
fn argument_names(arguments: &str) -> Vec<String> {
    let inner = &arguments[1..arguments.len() - 1];
    let mut names = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (index, c) in inner.char_indices().chain([(inner.len(), ',')]) {
        match c {
            '(' | '[' | '{' | '<' => depth += 1,
            ')' | ']' | '}' | '>' => depth -= 1,
            ',' if depth == 0 => {
                let item = inner[start..index].trim();
                let item = item.trim_start_matches(|c: char| !is_identifier_char(c));
                let name = identifier(item);
                if !name.is_empty() {
                    names.push(name.to_owned());
                }
                start = index + 1;
            }
            _ => {}
        }
    }
    names
}

fn wire_types_of(sources: &[Source]) -> BTreeSet<String> {
    let private = |name: &str| {
        sources.iter().any(|source| {
            ["struct", "enum", "type", "union"].iter().any(|keyword| {
                source
                    .text
                    .match_indices(&format!("{keyword} {name}"))
                    .any(|(at, _)| {
                        let next = source.text[at + keyword.len() + 1 + name.len()..]
                            .chars()
                            .next();
                        !next.is_some_and(is_identifier_char)
                            && !source.text[..at].ends_with("pub ")
                    })
            })
        })
    };
    let mut found = BTreeSet::new();
    for source in sources {
        let text = &source.text;
        for (at, _) in text.match_indices("Wire for ") {
            let target = &text[at + "Wire for ".len()..];
            let path = target.split(['<', ' ', '{']).next().unwrap_or("");
            let name = path.rsplit("::").next().unwrap_or(path);
            if !name.starts_with('$') && !name.is_empty() && !private(name) {
                found.insert(name.to_owned());
            }
        }
        for (at, _) in text.match_indices("macro_rules! ") {
            let after = &text[at + "macro_rules! ".len()..];
            let macro_name = identifier(after);
            let body_start = after[macro_name.len()..].trim_start();
            let Some(body_len) = matching(body_start) else {
                continue;
            };
            if !body_start[..body_len].contains("Wire for $") {
                continue;
            }
            for searched in sources {
                let calls = &searched.text;
                for (call, _) in calls.match_indices(&format!("{macro_name}!")) {
                    if calls[..call].ends_with(is_identifier_char) {
                        continue;
                    }
                    let arguments = calls[call + macro_name.len() + 1..].trim_start();
                    if let Some(len) = matching(arguments) {
                        found.extend(argument_names(&arguments[..len]));
                    }
                }
            }
        }
    }
    found
}

fn byte_taking_functions(sources: &[Source]) -> BTreeSet<String> {
    sources.iter().flat_map(byte_taking_functions_of).collect()
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
    let missing: Vec<_> = byte_taking_functions(&proto_sources())
        .into_iter()
        .filter(|name| {
            !covered.contains(name) && !NOT_DECODERS.iter().any(|(excused, _)| excused == name)
        })
        .collect();
    assert!(
        missing.is_empty(),
        "public decoders without a fuzz target: {missing:?}"
    );
}

#[test]
fn every_public_wire_type_is_decoded_by_a_target() {
    let covered = declared_decoders();
    let missing: Vec<_> = wire_types_of(&proto_sources())
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
    let sources = proto_sources();
    let functions = byte_taking_functions(&sources);
    let types = wire_types_of(&sources);
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
    let binaries: BTreeSet<String> =
        input_files(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin"))
            .iter()
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

fn scan(module: &str, code: &str) -> (BTreeSet<String>, BTreeSet<String>) {
    let sources = [Source {
        module: module.to_owned(),
        text: scanned(code),
    }];
    (byte_taking_functions(&sources), wire_types_of(&sources))
}

/// Each way of writing a decoder the review of Story 2.7 found the first version of this scan
/// missed, and the forms that must not count.
#[test]
fn the_scan_finds_decoders_however_they_are_written() {
    let decoders = [
        (
            "pub fn read_any<R: Read>(reader: &mut R) -> u8 { 0 }",
            "m::read_any",
        ),
        (
            "pub fn decode_borrowed<'a>(bytes: &'a [u8]) -> &'a [u8] { bytes }",
            "m::decode_borrowed",
        ),
        ("pub fn boxed(bytes: Box<[u8]>) {}", "m::boxed"),
        ("pub fn as_ref(bytes: impl AsRef<[u8]>) {}", "m::as_ref"),
        ("pub fn dynamic(reader: &mut dyn Read) {}", "m::dynamic"),
        (
            "pub fn buffered(reader: impl std::io::BufRead) {}",
            "m::buffered",
        ),
        (
            "pub fn bounded<R>(reader: R) where R: Read {}",
            "m::bounded",
        ),
        ("pub fn array(bytes: &[u8; 4]) {}", "m::array"),
        ("pub fn owned(bytes: Vec<u8>) {}", "m::owned"),
        (
            "pub\n    fn\n    split_lines(\n        bytes: &[ u8 ],\n    ) {}",
            "m::split_lines",
        ),
        ("pub const fn constant(bytes: &[u8]) {}", "m::constant"),
        (
            "#[must_use]\npub fn attributed(bytes: &[u8]) -> bool { true }",
            "m::attributed",
        ),
        (
            "#[cfg(test)]\nmod tests {}\npub fn after_tests(bytes: &[u8]) {}",
            "m::after_tests",
        ),
        (
            "pub trait Wire: Sized { fn from_cbor(v: &C) -> Self; fn from_bytes(b: &[u8]) -> Self { todo() } }",
            "m::Wire::from_bytes",
        ),
        (
            "pub trait Reader { fn required(&mut self, bytes: &[u8]); }",
            "m::Reader::required",
        ),
    ];
    for (code, expected) in decoders {
        let (functions, _) = scan("m", code);
        assert!(
            functions.contains(expected),
            "{expected} not found in {code:?}: {functions:?}"
        );
    }
    let not_decoders = [
        "pub fn as_bytes(&self) -> &[u8] { &self.0 }",
        "pub(crate) fn private(bytes: &[u8]) {}",
        "fn private(bytes: &[u8]) {}",
        "pub fn reads(count: u8) -> Vec<u8> { vec![count] }",
        "pub fn read(request_id: Id, body: B) -> Option<Self> { None }",
        "// pub fn commented(bytes: &[u8]) {}",
        "/* pub fn commented(bytes: &[u8]) {} */",
        "#[cfg(test)]\nmod tests { pub fn in_tests(bytes: &[u8]) {} }",
    ];
    for code in not_decoders {
        let (functions, _) = scan("m", code);
        assert!(
            functions.is_empty(),
            "{code:?} counted as a decoder: {functions:?}"
        );
    }
    let (functions, _) = scan("extra", "pub fn nested(bytes: &[u8]) {}");
    assert!(functions.contains("extra::nested"));
}

#[test]
fn the_scan_finds_every_wire_type_however_it_is_written() {
    let code = "
        pub struct Plain; pub struct Generic<T>(T); struct Hidden;
        impl Wire for Plain {}
        impl<T: Wire> crate::wire::Wire for Generic<T> {}
        impl Wire for Hidden {}
        macro_rules! wired { ($($name:ident),+) => { $(impl Wire for $name {})+ }; }
        macro_rules! other { ($name:ident) => { impl Debug for $name {} }; }
        wired!(First, Second<u8>);
        wired! [Third];
        wired! { Fourth, }
        other!(NotWire);
    ";
    let (_, types) = scan("m", code);
    let expected: BTreeSet<String> = ["Plain", "Generic", "First", "Second", "Third", "Fourth"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    assert_eq!(types, expected);
}
