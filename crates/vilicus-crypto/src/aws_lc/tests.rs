//! Known answers for the aws-lc-rs calls, and the rule that keeps aws-lc-rs key objects to one
//! operation (AC1 and AC7 of Story 4.1).

use std::fs;
use std::path::{Path, PathBuf};

use aws_lc_rs::aead::AES_256_GCM;
use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType};

use super::*;
use crate::test_support::hex;

fn sequence<const N: usize>(start: u8) -> [u8; N] {
    core::array::from_fn(|index| start + u8::try_from(index).expect("short sequence"))
}

#[test]
fn the_suite_lengths_are_those_of_aws_lc_rs() {
    assert_eq!(AES_256_GCM.key_len(), KEY_LEN);
    assert_eq!(AES_256_GCM.nonce_len(), NONCE_LEN);
    assert_eq!(AES_256_GCM.tag_len(), TAG_LEN);
    assert_eq!(NONCE_LEN * 8, 96);
    assert_eq!(KeyType::len(&HKDF_SHA256), KEY_LEN);
}

/// AES-256-GCM against two vectors: the all-zero test case of the GCM specification (McGrew and
/// Viega, test case 14), and a vector with additional data computed with OpenSSL 3.5.7's EVP
/// interface, an implementation independent of aws-lc-rs.
#[test]
fn aes_256_gcm_matches_known_answers_and_opens_what_it_seals() {
    struct Case {
        key: [u8; KEY_LEN],
        nonce: [u8; NONCE_LEN],
        aad: &'static [u8],
        plaintext: Vec<u8>,
        ciphertext: &'static str,
        tag: &'static str,
    }
    let cases = [
        Case {
            key: [0; KEY_LEN],
            nonce: [0; NONCE_LEN],
            aad: b"",
            plaintext: vec![0; 16],
            ciphertext: "cea7403d4d606b6e074ec5d3baf39d18",
            tag: "d0d1c8a799996bf0265b98b5d48ab919",
        },
        Case {
            key: sequence(0x00),
            nonce: sequence(0xa0),
            aad: b"vilicus/v1/test-aad",
            plaintext: sequence::<32>(0x20).to_vec(),
            ciphertext: "c6395e0e61ee24984a4cadf82b57eef1409d6b23a682745ba4371cbd43964b3e",
            tag: "d551e9e8d5f30a180457322ab33223d8",
        },
    ];
    for Case {
        key,
        nonce,
        aad,
        plaintext,
        ciphertext,
        tag,
    } in cases
    {
        let mut in_out = plaintext.clone();
        let sealed_tag = seal_aes_256_gcm(&key, nonce, aad, &mut in_out).expect("seal");
        assert_eq!(in_out, hex(ciphertext));
        assert_eq!(sealed_tag.to_vec(), hex(tag));

        let mut opened = vec![0; in_out.len()];
        open_aes_256_gcm(&key, nonce, aad, &in_out, &sealed_tag, &mut opened).expect("open");
        assert_eq!(opened, plaintext);

        let mut forged = sealed_tag;
        forged[0] ^= 1;
        assert!(open_aes_256_gcm(&key, nonce, aad, &in_out, &forged, &mut opened).is_err());
        assert!(
            open_aes_256_gcm(
                &key,
                nonce,
                b"another aad",
                &in_out,
                &sealed_tag,
                &mut opened
            )
            .is_err()
        );
    }
}

/// HKDF-SHA-256 against RFC 5869 appendix A.3 (no salt, no info; its first 32 bytes), and against
/// a vector whose info is given in parts, computed with Python's `hmac` and `hashlib`, an
/// implementation independent of aws-lc-rs.
#[test]
fn hkdf_sha256_matches_known_answers() {
    let mut out = [0; KEY_LEN];
    hkdf_sha256(&[0x0b; 22], &[], &mut out).expect("derive");
    assert_eq!(
        out.to_vec(),
        hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d")
    );

    let parent: [u8; KEY_LEN] = sequence(0x00);
    let info: [&[u8]; 3] = [b"vilicus/v1/test/", b"member-0001", &7_u32.to_be_bytes()];
    hkdf_sha256(&parent, &info, &mut out).expect("derive");
    assert_eq!(
        out.to_vec(),
        hex("da15a881bac4b0315aef4a7caf83a8b78a13021c50fb972b7ac927e4ea999dca")
    );
}

/// HMAC-SHA-256 against two vectors computed with Python's `hmac` and `hashlib`, an
/// implementation independent of aws-lc-rs: an empty message, and a message given in parts; a
/// tag with one bit flipped, a tag of another message and another key are refused.
#[test]
fn hmac_sha256_matches_known_answers_and_verifies_only_its_tag() {
    let key: [u8; KEY_LEN] = sequence(0x00);
    let empty = hex("d38b42096d80f45f826b44a9d5607de72496a415d3f4a1a8c88e3bb9da8dc1cb");
    assert_eq!(hmac_sha256(&key, &[]).to_vec(), empty);
    let message: [&[u8]; 3] = [b"vilicus/v1/test/", b"member-0001", &7_u32.to_be_bytes()];
    let tag = hmac_sha256(&key, &message);
    assert_eq!(
        tag.to_vec(),
        hex("4146d45e92fc84454ad776b5c8b1684df029dcdfb540f5bdad0df0c9c428d22d")
    );
    assert_eq!(verify_hmac_sha256(&key, &message, &tag), Ok(()));
    let mut flipped = tag;
    flipped[HMAC_SHA256_LEN - 1] ^= 1;
    assert!(verify_hmac_sha256(&key, &message, &flipped).is_err());
    assert!(verify_hmac_sha256(&key, &message[..2], &tag).is_err());
    assert!(verify_hmac_sha256(&sequence(0x01), &message, &tag).is_err());
}

#[test]
fn the_csprng_fills_what_it_is_given() {
    let mut first = [0; 32];
    let mut second = [0; 32];
    fill_random(&mut first).expect("random");
    fill_random(&mut second).expect("random");
    assert_ne!(first, second);
}

/// The aws-lc-rs types that hold a key, an HKDF input, a key schedule or an HMAC state once built
/// (`hmac::Key` and `hmac::Context` are named `Key` and `Context`).
const KEY_OBJECTS: &[&str] = &[
    "LessSafeKey",
    "UnboundKey",
    "RandomizedNonceKey",
    "SealingKey",
    "OpeningKey",
    "TlsRecordSealingKey",
    "TlsRecordOpeningKey",
    "Prk",
    "Okm",
    "Salt",
    "Key",
    "Context",
];

fn names_a_key_object(text: &str) -> Option<&'static str> {
    KEY_OBJECTS.iter().copied().find(|name| {
        text.match_indices(name).any(|(index, _)| {
            let before = text[..index].chars().next_back();
            let after = text[index + name.len()..].chars().next();
            !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
                && !after.is_some_and(|c| c.is_alphanumeric() || c == '_')
        })
    })
}

/// Whether `line` uses the `static` keyword (a `'static` lifetime is not one).
fn declares_a_static(line: &str) -> bool {
    line.match_indices("static").any(|(index, _)| {
        let before = line[..index].chars().next_back();
        let after = line[index + "static".len()..].chars().next();
        !before.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '\'')
            && !after.is_some_and(|c| c.is_alphanumeric() || c == '_')
    })
}

/// What breaks the AC7 shape in the source of `aws_lc.rs`, line by line:
/// - aws-lc-rs is named only in top-level, private `use` declarations that rename nothing, so
///   no item of it is re-exported or reached under another name;
/// - nothing is re-exported, and no `static` or `thread_local!` appears anywhere, function
///   bodies included, so no key object is kept between calls;
/// - outside those `use` declarations and comments, an aws-lc-rs key object is named only inside
///   the body of a function;
/// - every function is `#[inline(never)]`, takes no type parameter, and its signature names no
///   key object, `impl` type or `dyn` type through which one could leave.
///
/// It reads text, not the compiler's view of the code: a heuristic that refuses the ways out it
/// knows, which review backs for the ones it does not.
fn shape_violations(source: &str) -> Vec<String> {
    let mut violations = Vec::new();
    for (number, line) in source.lines().enumerate() {
        let number = number + 1;
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        if declares_a_static(trimmed) || trimmed.contains("thread_local!") {
            violations.push(format!("line {number}: a static"));
        }
        if trimmed.starts_with("pub use")
            || (trimmed.starts_with("pub(") && trimmed.contains(") use "))
        {
            violations.push(format!("line {number}: a re-export"));
        }
    }
    let mut attributes: Vec<&str> = Vec::new();
    let mut lines = source.lines().enumerate();
    while let Some((number, line)) = lines.next() {
        let number = number + 1;
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.is_empty() {
            continue;
        }
        if line.starts_with("#[") {
            attributes.push(line);
            continue;
        }
        if line.starts_with("use ") {
            let mut statement = line.to_string();
            while !statement.trim_end().ends_with(';') {
                match lines.next() {
                    Some((_, next)) => statement.push_str(next),
                    None => break,
                }
            }
            if statement.contains("aws_lc_rs") && statement.contains(" as ") {
                violations.push(format!("line {number}: an aws-lc-rs item renamed"));
            }
            attributes.clear();
            continue;
        }
        let is_function = ["fn ", "pub fn ", "pub(crate) fn "]
            .iter()
            .any(|start| line.starts_with(start));
        if is_function {
            let mut signature = line.to_string();
            while !signature.trim_end().ends_with('{') {
                match lines.next() {
                    Some((_, next)) => signature.push_str(next),
                    None => break,
                }
            }
            if !attributes.contains(&"#[inline(never)]") {
                violations.push(format!(
                    "line {number}: a function that is not #[inline(never)]"
                ));
            }
            if let Some(name) = names_a_key_object(&signature) {
                violations.push(format!("line {number}: a signature names {name}"));
            }
            if signature.contains("impl ") {
                violations.push(format!("line {number}: a signature names an impl type"));
            }
            if signature.contains("dyn ") {
                violations.push(format!("line {number}: a signature names a dyn type"));
            }
            let after_fn = &signature[signature.find("fn ").unwrap_or(0)..];
            let name_and_parameters = &after_fn[..after_fn.find('(').unwrap_or(after_fn.len())];
            if name_and_parameters.contains('<') || signature.contains(" where ") {
                violations.push(format!("line {number}: a generic function"));
            }
            for (body_number, body) in lines.by_ref() {
                if body == "}" {
                    break;
                }
                if !body.trim_start().starts_with("//") && body.contains("aws_lc_rs") {
                    violations.push(format!(
                        "line {}: aws-lc-rs named outside a top-level use",
                        body_number + 1
                    ));
                }
            }
            attributes.clear();
            continue;
        }
        if line.contains("aws_lc_rs") {
            violations.push(format!(
                "line {number}: aws-lc-rs named outside a top-level use"
            ));
        }
        if let Some(name) = names_a_key_object(line) {
            violations.push(format!("line {number}: {name} outside a function body"));
        }
        attributes.clear();
    }
    violations
}

fn rust_files(directory: &Path, found: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).expect("source directory") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            rust_files(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

/// AC7 (D131, Story 1.10's `*-asis-key-object-on-unlocked-heap`): every aws-lc-rs call of the
/// crate is in `aws_lc.rs`, and there an aws-lc-rs key object lives inside one non-inlined
/// function call, built and dropped there; nothing can keep one past the operation.
#[test]
fn key_objects_live_for_one_operation() {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&source_root, &mut files);
    let operations = source_root.join("aws_lc.rs");
    let own_tests = source_root.join("aws_lc").join("tests.rs");
    assert!(
        files.contains(&operations) && files.contains(&own_tests),
        "{files:?}"
    );
    for file in files
        .iter()
        .filter(|file| **file != operations && **file != own_tests)
    {
        let text = fs::read_to_string(file).expect("source file");
        assert!(
            !text.contains("aws_lc_rs"),
            "{} calls aws-lc-rs outside aws_lc.rs",
            file.display()
        );
    }

    let source = fs::read_to_string(&operations).expect("aws_lc.rs");
    assert!(
        names_a_key_object(&source).is_some(),
        "the check reads the file that builds key objects"
    );
    assert_eq!(shape_violations(&source), Vec::<String>::new());
}

/// The shapes the AC7 check refuses, each in a file otherwise like `aws_lc.rs`.
#[test]
fn the_key_object_check_refuses_each_way_out() {
    let base = "use aws_lc_rs::aead::LessSafeKey;\n\n#[inline(never)]\npub(crate) fn seal(key: &[u8; 32]) -> u8 {\n    let key = LessSafeKey::new(todo!());\n    0\n}\n";
    assert_eq!(shape_violations(base), Vec::<String>::new());
    let cases = [
        (
            "inlined",
            base.replace("#[inline(never)]\n", ""),
            "not #[inline(never)]",
        ),
        (
            "returned",
            base.replace("-> u8 {", "-> LessSafeKey {"),
            "a signature names LessSafeKey",
        ),
        (
            "hidden",
            base.replace("-> u8 {", "-> impl Sized {"),
            "an impl type",
        ),
        (
            "kept",
            format!("{base}\nstruct Cached {{\n    key: LessSafeKey,\n}}\n"),
            "LessSafeKey outside a function body",
        ),
        (
            "static",
            format!("{base}\nstatic PRK: std::sync::OnceLock<Prk> = std::sync::OnceLock::new();\n"),
            "Prk outside a function body",
        ),
        // The probes of the review of Story 4.1 (finding 8), and their neighbours.
        (
            "renamed",
            "use aws_lc_rs::aead::LessSafeKey as Kept;\n\n#[inline(never)]\npub(crate) fn make(key: &[u8; 32]) -> Kept {\n    todo!()\n}\n".to_string(),
            "an aws-lc-rs item renamed",
        ),
        (
            "dyn closure",
            base.replace("-> u8 {", "-> Box<dyn Fn(&mut [u8])> {"),
            "a dyn type",
        ),
        (
            "function-local static",
            base.replace(
                "    0\n",
                "    static KEPT: std::sync::OnceLock<LessSafeKey> = std::sync::OnceLock::new();\n    0\n",
            ),
            "a static",
        ),
        (
            "thread-local",
            base.replace("    0\n", "    thread_local! { static KEPT: () = (); }\n    0\n"),
            "a static",
        ),
        (
            "module re-export",
            format!("{base}\npub(crate) use aws_lc_rs::aead;\n"),
            "a re-export",
        ),
        (
            "renamed in a body",
            base.replace("    0\n", "    use aws_lc_rs::aead::LessSafeKey as Kept;\n    0\n"),
            "aws-lc-rs named outside a top-level use",
        ),
        (
            "generic",
            base.replace("fn seal(key", "fn seal<T: From<u8>>(key"),
            "a generic function",
        ),
    ];
    for (case, source, expected) in cases {
        let violations = shape_violations(&source);
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains(expected)),
            "{case}: {violations:?}"
        );
    }
}
