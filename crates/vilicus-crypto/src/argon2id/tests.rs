//! The Argon2id derivation (Story 4.4, AC1, AC5, AC7, AC8) and the usage rules U2 to U8 of
//! `doc/qa/argon2-review.md` that a unit test can hold: the RFC 9106 and reference vectors, the
//! buffer contract of finding F1, the hostile costs of finding F5 and the shape of every call into
//! the crate. The cross-tests against phc-winner-argon2 and OpenSSL, and the derivations at the
//! version 1 cost and at the ceiling, which lock more memory than a test runner's `RLIMIT_MEMLOCK`
//! allows, are `oracles/argon2id`'s. The wipe of the pool during a derivation is tested beside the
//! other wipes, in `memory/tests.rs`.

use std::panic::{AssertUnwindSafe, catch_unwind};

use argon2::{AssociatedData, Block, ParamsBuilder};

use super::limiter::DerivationLimiter;
use super::test_runtime::{block_on, sleep};
use super::*;
use crate::memory::working_memory_wiped;
use crate::test_support::{hex, key_memory};

/// A closure run inside each derivation of this thread, after the passphrase is encoded and
/// before Argon2id runs, so that a test can panic or signal there.
pub(crate) mod hooks {
    use std::cell::RefCell;

    type Hook = Box<dyn FnMut()>;

    thread_local! {
        static DURING: RefCell<Option<Hook>> = const { RefCell::new(None) };
    }

    pub(crate) fn set(hook: impl FnMut() + 'static) {
        DURING.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    pub(crate) fn clear() {
        DURING.with(|slot| *slot.borrow_mut() = None);
    }

    pub(crate) fn during_derivation() {
        let hook = DURING.with(|slot| slot.borrow_mut().take());
        if let Some(mut hook) = hook {
            // Put back before it runs, so that a hook that panics stays set for the test to clear.
            hook();
            DURING.with(|slot| {
                let mut slot = slot.borrow_mut();
                if slot.is_none() {
                    *slot = Some(hook);
                }
            });
        }
    }
}

const fn params(memory_kib: u32, passes: u32, lanes: u32) -> Argon2idParams {
    Argon2idParams {
        memory_kib,
        passes,
        lanes,
    }
}

fn kek_bytes(key: &SymmetricKey) -> [u8; KEY_LEN] {
    key.slot().with_key(|bytes| *bytes).expect("not wiped")
}

/// The product's derivation below the floor: the working memory, the guard and the KEK slot.
fn product(cost: Argon2idParams, passphrase: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    key_memory();
    let cost = CheckedCost::below_the_floor(cost).expect("a cost the crate accepts");
    let kek = derive_into(Slot::new().expect("slot"), &cost, passphrase.chars(), salt)
        .expect("derivation");
    kek_bytes(&kek)
}

/// The crate called directly, as U5 requires it, into an ordinary buffer of exactly its blocks.
fn reference(cost: Argon2idParams, passphrase: &[u8], salt: &[u8]) -> [u8; KEY_LEN] {
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        argon2_params(cost).expect("params"),
    );
    let mut blocks = vec![Block::new(); argon2_params(cost).expect("params").block_count()];
    let mut out = [0; KEY_LEN];
    argon2
        .hash_password_into_with_memory(passphrase, salt, &mut out, &mut blocks)
        .expect("derivation");
    out
}

fn page() -> usize {
    std::fs::read_to_string("/proc/self/smaps")
        .ok()
        .and_then(|smaps| {
            smaps
                .lines()
                .find_map(|line| line.strip_prefix("KernelPageSize:"))
                .and_then(|value| value.split_whitespace().next()?.parse::<usize>().ok())
        })
        .map_or(4096, |kib| kib * 1024)
}

/// U8: the three vectors of RFC 9106 section 5 (Argon2d, Argon2i and Argon2id, version 0x13, with
/// a secret and associated data, m = 32 KiB, t = 3, p = 4), through
/// `hash_password_into_with_memory` with the features of U1 into a locked working memory. The tags
/// are the RFC's (SHA-256 of the RFC 9106 text: 855c06f0...31f31, review section 2).
#[test]
fn the_rfc_9106_vectors_hold() {
    key_memory();
    let cases = [
        (
            Algorithm::Argon2d,
            "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
        ),
        (
            Algorithm::Argon2i,
            "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
        ),
        (
            Algorithm::Argon2id,
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
        ),
    ];
    for (algorithm, tag) in cases {
        let params = ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(AssociatedData::new(&[0x04; 12]).expect("data"))
            .build()
            .expect("params");
        let mut memory = WorkingMemory::new(params.block_count(), 0).expect("working memory");
        let (blocks, _) = memory.split();
        let argon2 =
            Argon2::new_with_secret(&[0x03; 8], algorithm, Version::V0x13, params).expect("ctx");
        let mut out = [0; 32];
        argon2
            .hash_password_into_with_memory(&[0x01; 32], &[0x02; 16], &mut out, blocks)
            .expect("derivation");
        assert_eq!(out.to_vec(), hex(tag), "{algorithm:?}");
    }
}

/// U8, AC8: the eight Argon2id version 0x13 cases of the reference implementation's
/// `src/test.c` (phc-winner-argon2 tag 20190702, which Debian 13's `libargon2-dev` is built
/// from; SHA-256 of the file: 6a8eb32be02dcb8dc9651fd74e5bc2e0e3ce69cf11f7dc6cea78638aaffbeb05),
/// without secret or associated data, "password" and "somesalt" among them. Those that fit a test
/// runner's locked memory go through the product's derivation, the others through the crate into
/// an ordinary buffer.
#[test]
fn the_reference_implementation_vectors_hold() {
    let cases: [(u32, u32, u32, &str, &str, &str); 8] = [
        (
            2,
            16,
            1,
            "password",
            "somesalt",
            "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7",
        ),
        (
            2,
            18,
            1,
            "password",
            "somesalt",
            "78fe1ec91fb3aa5657d72e710854e4c3d9b9198c742f9616c2f085bed95b2e8c",
        ),
        (
            2,
            8,
            1,
            "password",
            "somesalt",
            "9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe",
        ),
        (
            2,
            8,
            2,
            "password",
            "somesalt",
            "6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037",
        ),
        (
            1,
            16,
            1,
            "password",
            "somesalt",
            "f6a5adc1ba723dddef9b5ac1d464e180fcd9dffc9d1cbf76cca2fed795d9ca98",
        ),
        (
            4,
            16,
            1,
            "password",
            "somesalt",
            "9025d48e68ef7395cca9079da4c4ec3affb3c8911fe4f86d1a2520856f63172c",
        ),
        (
            2,
            16,
            1,
            "differentpassword",
            "somesalt",
            "0b84d652cf6b0c4beaef0dfe278ba6a80df6696281d7e0d2891b817d8c458fde",
        ),
        (
            2,
            16,
            1,
            "password",
            "diffsalt",
            "bdf32b05ccc42eb15d58fd19b1f856b113da1e9a5874fdcc544308565aa8141c",
        ),
    ];
    for (passes, log2_memory, lanes, password, salt, tag) in cases {
        let cost = params(1 << log2_memory, passes, lanes);
        let out = if cost.memory_kib <= 1024 {
            product(cost, password, salt.as_bytes())
        } else {
            reference(cost, password.as_bytes(), salt.as_bytes())
        };
        assert_eq!(out.to_vec(), hex(tag), "{cost:?} {password} {salt}");
    }
}

/// U4, U5, U6: the product's derivation is the crate's Argon2id over the UTF-8 bytes of the
/// passphrase, for lane counts the cross-test also covers (3 among them), memory sizes that are
/// not a multiple of 4p, passes from 1 to 4, passphrases that cross BLAKE2b's 128-byte block in H0
/// and non-ASCII text, and salts from 8 to 64 bytes.
#[test]
fn the_derivation_is_the_crates_argon2id_of_the_utf8_passphrase() {
    let passphrases = [
        String::new(),
        "correct horse battery staple".to_string(),
        "é".repeat(48),
        "ж".repeat(112),
        "x".repeat(97),
        "\u{1f511}".repeat(60),
    ];
    let mut index = 0;
    for lanes in [1, 2, 3, 4, 8] {
        for memory_kib in [8 * lanes, 8 * lanes + 5, 4 * lanes * 9 + 3] {
            for passes in 1..=4 {
                let passphrase = &passphrases[index % passphrases.len()];
                let salt = vec![0x5a ^ u8::try_from(index % 256).expect("byte"); 8 + index % 57];
                index += 1;
                let cost = params(memory_kib, passes, lanes);
                assert_eq!(
                    product(cost, passphrase, &salt),
                    reference(cost, passphrase.as_bytes(), &salt),
                    "{cost:?}, {} bytes of passphrase, {} of salt",
                    passphrase.len(),
                    salt.len()
                );
            }
        }
    }
}

/// U2, AC7: the working memory of a derivation holds exactly the cost's blocks then the passphrase
/// buffer, in whole pages, and every byte of it is zero once it is dropped: after a derivation,
/// after a refused one, and while a panic inside one unwinds.
#[test]
fn the_working_memory_is_the_blocks_and_is_zeroes_after_every_derivation() {
    key_memory();
    let cost = CheckedCost::below_the_floor(params(64, 2, 2)).expect("cost");
    let expected_len =
        (cost.block_count() * Block::SIZE + PASSPHRASE_BUFFER_LEN).next_multiple_of(page());
    working_memory_wiped::take();

    let kek = derive_into(
        Slot::new().expect("slot"),
        &cost,
        "passphrase".chars(),
        b"saltsalt",
    );
    assert!(kek.is_ok());
    let derived = working_memory_wiped::take();
    assert_eq!(derived.len(), 1, "one working memory per derivation");
    assert_eq!(derived[0].1, expected_len);
    assert!(derived[0].2, "all zeroes after a derivation");

    let too_long = "\u{10000}".repeat(PASSPHRASE_BUFFER_LEN / 4 + 1);
    let refused = derive_into(
        Slot::new().expect("slot"),
        &cost,
        too_long.chars(),
        b"saltsalt",
    );
    assert!(matches!(refused, Err(CryptoError::PassphraseTooLong)));
    let after_refusal = working_memory_wiped::take();
    assert_eq!(after_refusal.len(), 1);
    assert!(after_refusal[0].2, "all zeroes after a refused derivation");

    hooks::set(|| panic!("a panic inside the derivation"));
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        derive_into(
            Slot::new().expect("slot"),
            &cost,
            "passphrase".chars(),
            b"saltsalt",
        )
    }));
    hooks::clear();
    assert!(unwound.is_err(), "the panic reached the test");
    let after_panic = working_memory_wiped::take();
    assert_eq!(after_panic.len(), 1);
    assert!(after_panic[0].2, "all zeroes after a panic");
}

/// U8, finding F1: the crate writes no block past `block_count`, and what the buffer held before
/// changes nothing, so a reused buffer gives the same output.
#[test]
fn the_crate_writes_only_its_blocks_and_ignores_what_they_held() {
    let cost = params(64, 2, 2);
    let crate_params = argon2_params(cost).expect("params");
    let count = crate_params.block_count();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, crate_params);
    let mut fresh = [0; KEY_LEN];
    let mut blocks = vec![Block::new(); count];
    argon2
        .hash_password_into_with_memory(b"passphrase", b"saltsalt", &mut fresh, &mut blocks)
        .expect("derivation");

    let mut marked = Block::new();
    marked.as_mut().fill(0xa5a5_a5a5_a5a5_a5a5);
    let mut reused = blocks.clone();
    reused.extend(std::iter::repeat_n(marked, 3));
    let mut again = [0; KEY_LEN];
    argon2
        .hash_password_into_with_memory(b"passphrase", b"saltsalt", &mut again, &mut reused)
        .expect("derivation");
    assert_eq!(
        again, fresh,
        "a buffer holding a previous derivation gives the same output"
    );
    for block in &reused[count..] {
        assert!(
            block
                .as_ref()
                .iter()
                .all(|word| *word == 0xa5a5_a5a5_a5a5_a5a5),
            "no write past block_count"
        );
    }

    let mut patterned = vec![marked; count];
    let mut third = [0; KEY_LEN];
    argon2
        .hash_password_into_with_memory(b"passphrase", b"saltsalt", &mut third, &mut patterned)
        .expect("derivation");
    assert_eq!(third, fresh, "prior content does not matter");
}

/// U4, finding F5: hostile costs, as a header could state them, are refused as one error and never
/// a panic, whether below the floor, above the ceiling or outside the crate's bounds; the crate's
/// own refusals of a short salt, a short buffer or another output length touch neither the buffer
/// nor the output.
#[test]
fn hostile_costs_and_inputs_are_refused_never_a_panic() {
    let hostile = [
        params(0, 0, 0),
        params(0, 3, 4),
        params(64 * 1024, 0, 4),
        params(64 * 1024, 3, 0),
        params(64 * 1024, 3, 0x0100_0000),
        params(u32::MAX, u32::MAX, u32::MAX),
        params(u32::MAX, 3, 4),
        params(64 * 1024, u32::MAX, 4),
        params(7, 1, 1),
        params(15, 1, 2),
    ];
    for cost in hostile {
        let checked = catch_unwind(|| CheckedCost::new(cost)).expect("no panic");
        assert!(
            matches!(checked, Err(CryptoError::Argon2idCost { .. })),
            "{cost:?}"
        );
    }
    for cost in [
        params(0, 1, 1),
        params(15, 1, 2),
        params(8, 0, 1),
        params(8, 1, 0),
    ] {
        let checked = catch_unwind(|| CheckedCost::below_the_floor(cost)).expect("no panic");
        assert!(
            matches!(checked, Err(CryptoError::Argon2idCost { .. })),
            "{cost:?}"
        );
    }

    let crate_params = argon2_params(params(64, 1, 1)).expect("params");
    let count = crate_params.block_count();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, crate_params);
    let mut marked = Block::new();
    marked.as_mut().fill(0x3c3c_3c3c_3c3c_3c3c);
    let short_salt: &[u8] = b"7 bytes";
    for (salt, blocks, out_len) in [
        (short_salt, count, KEY_LEN),
        (&b"saltsalt"[..], count - 1, KEY_LEN),
        (&b"saltsalt"[..], count, KEY_LEN - 1),
        (&b"saltsalt"[..], count, KEY_LEN + 1),
    ] {
        let mut buffer = vec![marked; blocks];
        let mut out = vec![0xee; out_len];
        let refused = catch_unwind(AssertUnwindSafe(|| {
            argon2.hash_password_into_with_memory(b"passphrase", salt, &mut out, &mut buffer)
        }))
        .expect("no panic");
        assert!(
            refused.is_err(),
            "{} bytes of salt, {blocks} blocks, {out_len} out",
            salt.len()
        );
        assert!(buffer.iter().all(|block| {
            block
                .as_ref()
                .iter()
                .all(|word| *word == 0x3c3c_3c3c_3c3c_3c3c)
        }));
        assert!(out.iter().all(|byte| *byte == 0xee));
    }
}

/// AC1, AC5: the version 1 cost and both RFC options meet the floor; a KiB or a pass below the
/// smaller option, a KiB, a pass of work or a lane above the ceiling, and a cost the crate refuses
/// are refused; the cost's blocks are m rounded down to a multiple of 4p (finding F7).
#[test]
fn a_cost_outside_the_floor_or_the_ceiling_is_refused() {
    let current = CheckedCost::new(Argon2idParams::PASSPHRASE_V1).expect("the version 1 cost");
    assert_eq!(current.params(), Argon2idParams::PASSPHRASE_V1);
    assert_eq!(
        current.block_count(),
        usize::try_from(vilicus_types::PASSPHRASE_ARGON2ID_MEMORY_KIB).expect("usize")
    );
    let floor = vilicus_types::ARGON2ID_FLOOR_OPTIONS;
    let (memory, passes) = floor[1];
    for (cost, accepted) in [
        (params(memory, passes, 4), true),
        (params(memory - 1, passes, 4), false),
        (params(memory, passes - 1, 4), false),
        (params(vilicus_types::ARGON2ID_MAX_MEMORY_KIB, 4, 8), true),
        (
            params(vilicus_types::ARGON2ID_MAX_MEMORY_KIB + 1, 3, 4),
            false,
        ),
        (params(vilicus_types::ARGON2ID_MAX_MEMORY_KIB, 5, 4), false),
        (
            params(memory, passes, vilicus_types::ARGON2ID_MAX_LANES + 1),
            false,
        ),
        (params(memory, passes, 0), false),
    ] {
        assert_eq!(CheckedCost::new(cost).is_ok(), accepted, "{cost:?}");
    }
    let rounded = CheckedCost::new(params(memory + 13, passes, 3)).expect("cost");
    assert_eq!(
        rounded.block_count(),
        usize::try_from(memory + 13).expect("usize") / 12 * 12
    );
}

/// A derivation needs the permit of its own cost: a permit admitted for another cost, whose
/// memory the limiter did not count, is refused before any working memory is taken.
#[test]
fn a_derivation_needs_the_permit_of_its_cost() {
    key_memory();
    let limiter = DerivationLimiter::new(1, 1 << 20, std::time::Duration::from_secs(4));
    let admitted = CheckedCost::below_the_floor(params(64, 1, 1)).expect("cost");
    let other = CheckedCost::below_the_floor(params(128, 1, 1)).expect("cost");
    let permit = block_on(limiter.admit(&admitted, sleep)).expect("admitted");
    working_memory_wiped::take();
    let refused = derive_passphrase_kek(&permit, &other, "passphrase".chars(), &[7; 16]);
    assert!(matches!(refused, Err(CryptoError::PermitMismatch)));
    assert!(
        working_memory_wiped::take().is_empty(),
        "no working memory was taken"
    );
    let kek = derive_passphrase_kek(&permit, &admitted, "passphrase".chars(), &[7; 16])
        .expect("the permit's own cost");
    assert_eq!(
        kek_bytes(&kek),
        reference(admitted.params(), b"passphrase", &[7; 16])
    );
}

/// U6: each salt is sixteen bytes of the operating system's generator, a new one each call.
#[test]
fn each_salt_is_new() {
    let first = passphrase_salt().expect("salt");
    let second = passphrase_salt().expect("salt");
    assert_eq!(first.len(), vilicus_types::PASSPHRASE_SALT_LEN);
    assert_ne!(first, second);
    assert_ne!(first, [0; vilicus_types::PASSPHRASE_SALT_LEN]);
}

/// The text of `file`, a source file of this crate, without its line comments; a module's tests
/// are files of their own, which [`crate_sources`] leaves out.
fn product_source(file: &str) -> String {
    let path = format!("{}/src/{file}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
    text.lines()
        .map(|line| line.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every source file of the crate, by its path under `src/`, its tests excepted.
fn crate_sources() -> Vec<String> {
    let mut files = Vec::new();
    let mut directories = vec![std::path::PathBuf::from(format!(
        "{}/src",
        env!("CARGO_MANIFEST_DIR")
    ))];
    let root = directories[0].clone();
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(&directory).expect("src") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                directories.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs")
                && !path.ends_with("tests.rs")
            {
                let relative = path.strip_prefix(&root).expect("under src");
                files.push(relative.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    files
}

/// U2, U4, U5, by the text of the product code, tests excepted: the crate is named in this module
/// and the memory module only (whose one use is the block type); the context is built once, as
/// Argon2id version 0x13 with no secret, associated data or key id; the crate's `Params` are built
/// once, from a cost in KiB with a 32-byte output; the one derivation call is
/// `hash_password_into_with_memory`, never `hash_password_into`; no other variant, version or API
/// of the crate appears.
#[test]
fn the_crate_is_called_only_as_the_review_requires() {
    for file in crate_sources() {
        let source = product_source(&file);
        let names_the_crate = source.contains("argon2::");
        match file.as_str() {
            "argon2id.rs" => {}
            "memory.rs" => assert_eq!(
                source.matches("argon2::").count(),
                1,
                "memory.rs names the crate for its block type only"
            ),
            other => assert!(!names_the_crate, "{other} names the argon2 crate"),
        }
    }
    // Without whitespace, so that the formatter's line breaks change nothing.
    let source: String = product_source("argon2id.rs")
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    let count = |pattern: &str| source.matches(pattern).count();
    assert_eq!(count("Argon2::new(Algorithm::Argon2id,Version::V0x13,"), 1);
    assert_eq!(count("Argon2::"), 1, "one context");
    assert_eq!(
        count("Params::new("),
        1,
        "one place builds the crate's parameters"
    );
    assert_eq!(count("Some(PASSPHRASE_KEK_LEN)"), 1);
    assert_eq!(count(".hash_password_into_with_memory("), 1);
    assert_eq!(count("hash_password_into("), 0);
    for forbidden in [
        "new_with_secret",
        "ParamsBuilder",
        "AssociatedData",
        "KeyId",
        "Version::V0x10",
        "Version::try_from",
        "Algorithm::Argon2d",
        "Algorithm::new",
        "fill_memory",
        "Argon2::default",
        "Argon2::from",
        "keyid",
        ".data(",
    ] {
        assert_eq!(count(forbidden), 0, "{forbidden}");
    }
    assert_eq!(
        count("Algorithm::Argon2i"),
        count("Algorithm::Argon2id"),
        "no Argon2i"
    );
}
