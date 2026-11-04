//! The Argon2id oracle of Story 4.4 (D129; `doc/qa/argon2-review.md`, U8): the Core's derivation,
//! through `vilicus-crypto`, against the reference implementation phc-winner-argon2 and against
//! OpenSSL 3.5's `EVP_KDF-ARGON2`, on 10 000 random cases over p in {1, 2, 4, 8} and on the
//! coverage list of U8; the derivations at the floor, at the version 1 cost and at the ceiling
//! through the Core's own entry point and limiter; and a burst at the version 1 cost whose locked
//! memory stays within the budget of D128. One `PASS` or `FAIL` line per check; the exit status is
//! the number of failures, capped at 1.
//!
//! Run by `run.sh`, in a container whose `RLIMIT_MEMLOCK` covers the working memory of D128,
//! which a test runner's does not.

mod openssl;
mod reference;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use unicode_normalization::UnicodeNormalization;
use vilicus_crypto::testing::{self, block_on, sleep};
use vilicus_crypto::{Argon2idParams, CheckedCost, admit_derivation, derive_passphrase_kek};
use vilicus_types::{
    ARGON2ID_CONCURRENCY_LIMIT, ARGON2ID_FLOOR_OPTIONS, ARGON2ID_MAX_LANES,
    ARGON2ID_MAX_MEMORY_KIB, ARGON2ID_MAX_WORK_KIB, ARGON2ID_MEMORY_BUDGET_KIB,
    PASSPHRASE_SALT_LEN,
};

/// The random cases of D129.
const RANDOM_CASES: usize = 10_000;
/// The lane counts of D129's random cases.
const RANDOM_LANES: [u32; 4] = [1, 2, 4, 8];
/// The seed of the random cases, printed with the run so that a failure can be replayed; the
/// environment variable `ORACLE_SEED` replaces it.
const SEED: u64 = 0x5649_4c49_4355_5334;

#[derive(Default)]
struct Report {
    failures: usize,
}

impl Report {
    fn check(&mut self, name: &str, result: Result<String, String>) {
        match result {
            Ok(detail) => println!("PASS {name}: {detail}"),
            Err(detail) => {
                println!("FAIL {name}: {detail}");
                self.failures += 1;
            }
        }
    }
}

/// SplitMix64: the draw of the random cases, not a key's.
struct Draw(u64);

impl Draw {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    fn range(&mut self, low: u32, high: u32) -> u32 {
        low + u32::try_from(self.below(u64::from(high - low) + 1)).expect("in range")
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next().to_le_bytes()[0]).collect()
    }

    /// A passphrase of up to `max_chars` characters, a third of them outside ASCII: precomposed
    /// and decomposed accents, combining marks, Cyrillic, CJK and emoji, so its NFC form differs
    /// from what was drawn.
    fn passphrase(&mut self, max_chars: u64) -> String {
        const OTHERS: [&str; 12] = [
            "\u{e9}",
            "e\u{301}",
            "\u{301}",
            "A\u{30a}",
            "\u{c5}",
            "\u{436}",
            "\u{4e2d}",
            "\u{1f511}",
            "\u{1100}\u{1161}",
            "\u{fb01}",
            "\u{2126}",
            "\u{df}",
        ];
        let count = self.below(max_chars + 1);
        let mut text = String::new();
        for _ in 0..count {
            if self.below(3) == 0 {
                text.push_str(OTHERS[usize::try_from(self.below(12)).expect("index")]);
            } else {
                text.push(char::from(
                    b' ' + u8::try_from(self.below(95)).expect("ascii"),
                ));
            }
        }
        text
    }
}

fn params(memory_kib: u32, passes: u32, lanes: u32) -> Argon2idParams {
    Argon2idParams {
        memory_kib,
        passes,
        lanes,
    }
}

/// The Core's derivation, below the floor allowed: the KEK's bytes, read back from its slot.
fn product(cost: Argon2idParams, passphrase: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let kek = testing::argon2id_below_the_floor(cost, passphrase, salt)
        .map_err(|error| format!("vilicus-crypto: {error}"))?;
    testing::with_key(&kek, |bytes| *bytes).map_err(|error| format!("{error}"))
}

/// The three implementations on one case: `Ok` when they agree, the outputs otherwise.
fn agree(cost: Argon2idParams, passphrase: &str, salt: &[u8]) -> Result<(), String> {
    let Argon2idParams {
        memory_kib,
        passes,
        lanes,
    } = cost;
    let bytes = passphrase.as_bytes();
    let ours = product(cost, passphrase, salt)?;
    let reference = reference::argon2id(memory_kib, passes, lanes, bytes, salt)
        .map_err(|code| format!("libargon2 error {code}"))?;
    let openssl = openssl::argon2id(memory_kib, passes, lanes, bytes, salt)?;
    if ours == reference && ours == openssl {
        Ok(())
    } else {
        Err(format!(
            "{cost:?}, {} bytes of passphrase, {} of salt: vilicus {}, libargon2 {}, openssl {}",
            bytes.len(),
            salt.len(),
            hex(&ours),
            hex(&reference),
            hex(&openssl)
        ))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex"))
        .collect()
}

/// The eight Argon2id version 0x13 cases of the reference implementation's `src/test.c`, which
/// validate both oracles and the binding before they judge anything.
fn reference_vectors() -> Result<String, String> {
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
        let expected = from_hex(tag);
        let memory = 1 << log2_memory;
        let reference =
            reference::argon2id(memory, passes, lanes, password.as_bytes(), salt.as_bytes())
                .map_err(|code| format!("libargon2 error {code}"))?;
        let openssl =
            openssl::argon2id(memory, passes, lanes, password.as_bytes(), salt.as_bytes())?;
        if reference.as_slice() != expected || openssl.as_slice() != expected {
            return Err(format!(
                "m = 2^{log2_memory}, t = {passes}, p = {lanes}, {password}, {salt}"
            ));
        }
        agree(params(memory, passes, lanes), password, salt.as_bytes())?;
    }
    Ok("the eight cases of test.c, by libargon2, OpenSSL and vilicus-crypto".to_string())
}

/// D129: 10 000 random cases over p in {1, 2, 4, 8}, m from 8p to 8p + 2 048 KiB (most of them not
/// a multiple of 4p), t from 1 to 4, passphrases of up to 300 characters in NFC and salts of 8 to
/// 64 bytes.
fn random_cases(seed: u64) -> Result<String, String> {
    let mut draw = Draw(seed);
    let started = Instant::now();
    for case in 0..RANDOM_CASES {
        let lanes = RANDOM_LANES[usize::try_from(draw.below(4)).expect("index")];
        let memory = draw.range(8 * lanes, 8 * lanes + 2048);
        let passes = draw.range(1, 4);
        let passphrase: String = draw.passphrase(300).nfc().collect();
        let salt_len = usize::try_from(draw.range(8, 64)).expect("len");
        let salt = draw.bytes(salt_len);
        agree(params(memory, passes, lanes), &passphrase, &salt)
            .map_err(|error| format!("case {case} of seed {seed:#x}: {error}"))?;
    }
    Ok(format!(
        "{RANDOM_CASES} cases of seed {seed:#x} agree in {:.1} s",
        started.elapsed().as_secs_f64()
    ))
}

/// U8: the cases the review names beyond the random ones, each through the three implementations.
fn coverage_cases() -> Result<String, String> {
    let (floor_memory, floor_passes) = ARGON2ID_FLOOR_OPTIONS[1];
    let mut cases: Vec<(String, Argon2idParams, String, Vec<u8>)> = Vec::new();
    let salt16 = b"coverage-salt-16".to_vec();
    for memory in [24, 25, 26, 27, 100, 1000] {
        cases.push((
            format!("p = 3, m = {memory}"),
            params(memory, 2, 3),
            "three lanes".into(),
            salt16.clone(),
        ));
    }
    for lanes in [1, 2, 4, 8] {
        for extra in [1, 2, 3] {
            let memory = 4 * lanes * 10 + extra;
            cases.push((
                format!("m = {memory} not a multiple of 4p, p = {lanes}"),
                params(memory, 1, lanes),
                "not a multiple".into(),
                salt16.clone(),
            ));
        }
    }
    for passes in 1..=4 {
        cases.push((
            format!("t = {passes}"),
            params(256, passes, 4),
            "passes".into(),
            salt16.clone(),
        ));
    }
    // H0 holds 28 bytes before the passphrase, so its first BLAKE2b block ends 100 bytes in and its
    // second 228 bytes in; lengths around both, and the longest passphrase.
    for len in [
        0, 1, 95, 96, 97, 99, 100, 101, 127, 128, 129, 223, 224, 225, 227, 228, 229, 1024,
    ] {
        let text: String = (0..len)
            .map(|index| char::from(b'a' + u8::try_from(index % 26).expect("letter")))
            .collect();
        cases.push((
            format!("{len} bytes of passphrase"),
            params(64, 1, 1),
            text,
            salt16.clone(),
        ));
    }
    for decomposed in [
        "e\u{301}t\u{e9}",
        "A\u{30a}ngstr\u{f6}m \u{2126}",
        "\u{1100}\u{1161}\u{11a8}",
        "cafe\u{301} cre\u{300}me",
    ] {
        let nfc: String = decomposed.nfc().collect();
        cases.push((
            format!("non-ASCII after NFC ({} bytes)", nfc.len()),
            params(128, 2, 2),
            nfc,
            salt16.clone(),
        ));
    }
    for salt_len in [8, 9, 15, 16, 17, 32, 63, 64] {
        cases.push((
            format!("{salt_len} bytes of salt"),
            params(64, 1, 2),
            "salted".into(),
            vec![0xa5; salt_len],
        ));
    }
    // The backup secret and recovery secret enter as text; their encodings are stories 4.5 and
    // 4.8's, so lengths around what they may take.
    for len in [16, 26, 32, 40, 48, 64] {
        let text: String = (0..len)
            .map(|index| char::from(b"ABCDEFGHJKMNPQRSTVWXYZ0123456789"[index % 32]))
            .collect();
        cases.push((
            format!("a secret of {len} characters"),
            params(256, 3, 4),
            text,
            salt16.clone(),
        ));
    }
    cases.push((
        "m at the floor".into(),
        params(floor_memory, floor_passes, 4),
        "the floor".into(),
        salt16.clone(),
    ));
    let count = cases.len();
    for (label, cost, passphrase, salt) in cases {
        agree(cost, &passphrase, &salt).map_err(|error| format!("{label}: {error}"))?;
    }
    Ok(format!("{count} cases agree"))
}

/// AC1, AC5: the floor, the version 1 cost and the ceiling through the Core's own entry point:
/// `CheckedCost::new`, the process's limiter and `derive_passphrase_kek`, against both oracles.
fn entry_point_costs() -> Result<String, String> {
    let (floor_memory, floor_passes) = ARGON2ID_FLOOR_OPTIONS[1];
    let ceiling_passes =
        u32::try_from(ARGON2ID_MAX_WORK_KIB / u64::from(ARGON2ID_MAX_MEMORY_KIB)).expect("passes");
    let costs = [
        ("the floor", params(floor_memory, floor_passes, 4)),
        ("the version 1 cost", Argon2idParams::PASSPHRASE_V1),
        (
            "the ceiling in memory and lanes",
            params(ARGON2ID_MAX_MEMORY_KIB, floor_passes, ARGON2ID_MAX_LANES),
        ),
        (
            "the ceiling in work",
            params(ARGON2ID_MAX_MEMORY_KIB, ceiling_passes, 4),
        ),
    ];
    let passphrase: String = "\u{e9}t\u{e9} \u{e0} No\u{eb}l, la cl\u{e9} du foyer"
        .nfc()
        .collect();
    let salt = [0x3c; PASSPHRASE_SALT_LEN];
    let mut timings = Vec::new();
    for (label, cost) in costs {
        let checked = CheckedCost::new(cost).map_err(|error| format!("{label}: {error}"))?;
        let started = Instant::now();
        let permit = block_on(admit_derivation(&checked, sleep))
            .map_err(|error| format!("{label}: {error}"))?;
        let kek = derive_passphrase_kek(&permit, &checked, passphrase.chars(), &salt)
            .map_err(|error| format!("{label}: {error}"))?;
        timings.push(format!("{label} {} ms", started.elapsed().as_millis()));
        drop(permit);
        let ours = testing::with_key(&kek, |bytes| *bytes).map_err(|error| format!("{error}"))?;
        let Argon2idParams {
            memory_kib,
            passes,
            lanes,
        } = cost;
        let reference =
            reference::argon2id(memory_kib, passes, lanes, passphrase.as_bytes(), &salt)
                .map_err(|code| format!("{label}: libargon2 error {code}"))?;
        let openssl = openssl::argon2id(memory_kib, passes, lanes, passphrase.as_bytes(), &salt)?;
        if ours != reference || ours != openssl {
            return Err(format!(
                "{label}: vilicus {}, libargon2 {}, openssl {}",
                hex(&ours),
                hex(&reference),
                hex(&openssl)
            ));
        }
    }
    Ok(format!(
        "{} (development host, for information)",
        timings.join(", ")
    ))
}

/// Bytes of locked memory of this process, `VmLck` of `/proc/self/status`.
fn locked_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("VmLck:"))
                .and_then(|value| {
                    value
                        .trim()
                        .trim_end_matches("kB")
                        .trim()
                        .parse::<u64>()
                        .ok()
                })
        })
        .map_or(0, |kib| kib * 1024)
}

/// AC6: a burst of more simultaneous derivations at the version 1 cost than the limit, through
/// the process's limiter: every one served within the wait bound and equal to the reference, and
/// the locked memory, sampled throughout, never above the pool plus the limit's working memory.
fn burst() -> Result<String, String> {
    let current =
        CheckedCost::new(Argon2idParams::PASSPHRASE_V1).map_err(|error| format!("{error}"))?;
    let requests = 3 * ARGON2ID_CONCURRENCY_LIMIT;
    let salt = [0x7e; PASSPHRASE_SALT_LEN];
    let passphrase = "a burst of unlocks";
    let expected = reference::argon2id(
        current.params().memory_kib,
        current.params().passes,
        current.params().lanes,
        passphrase.as_bytes(),
        &salt,
    )
    .map_err(|code| format!("libargon2 error {code}"))?;
    let baseline = locked_bytes();
    let done = Arc::new(AtomicBool::new(false));
    let sampler = {
        let done = Arc::clone(&done);
        thread::spawn(move || {
            let mut peak = 0;
            while !done.load(Ordering::SeqCst) {
                peak = peak.max(locked_bytes());
                thread::sleep(Duration::from_millis(1));
            }
            peak
        })
    };
    let start = Arc::new(Barrier::new(requests));
    let threads: Vec<_> = (0..requests)
        .map(|_| {
            let start = Arc::clone(&start);
            thread::spawn(move || -> Result<[u8; 32], String> {
                start.wait();
                let permit = block_on(admit_derivation(&current, sleep))
                    .map_err(|error| format!("{error}"))?;
                let kek = derive_passphrase_kek(&permit, &current, passphrase.chars(), &salt)
                    .map_err(|error| format!("{error}"))?;
                drop(permit);
                testing::with_key(&kek, |bytes| *bytes).map_err(|error| format!("{error}"))
            })
        })
        .collect();
    let mut outcomes = Vec::new();
    for thread in threads {
        outcomes.push(
            thread
                .join()
                .map_err(|_| "a request panicked".to_string())?,
        );
    }
    done.store(true, Ordering::SeqCst);
    let peak = sampler
        .join()
        .map_err(|_| "the sampler panicked".to_string())?;
    let served = outcomes
        .iter()
        .filter(|outcome| outcome.as_ref().is_ok_and(|kek| *kek == expected))
        .count();
    let page = 4096;
    // Each derivation locks its blocks and a passphrase buffer of three times the longest
    // passphrase, in whole pages.
    let per_derivation = (current.block_count() as u64 * 1024 + 3 * 1024).next_multiple_of(page);
    let bound = baseline + ARGON2ID_CONCURRENCY_LIMIT as u64 * per_derivation;
    let detail = format!(
        "{served} of {requests} served, peak VmLck {} KiB against a bound of {} KiB (pool {} KiB, then {} derivations at once), budget {} KiB",
        peak / 1024,
        bound / 1024,
        baseline / 1024,
        ARGON2ID_CONCURRENCY_LIMIT,
        ARGON2ID_MEMORY_BUDGET_KIB
    );
    if served == requests
        && peak <= bound
        && peak > baseline
        && peak - baseline <= ARGON2ID_MEMORY_BUDGET_KIB * 1024
    {
        Ok(detail)
    } else {
        Err(format!("{detail}; outcomes {outcomes:?}"))
    }
}

fn main() -> std::process::ExitCode {
    let mut report = Report::default();
    if let Err(error) =
        vilicus_crypto::harden_process().and_then(|()| vilicus_crypto::lock_key_memory())
    {
        println!("FAIL key-memory: {error}");
        return std::process::ExitCode::FAILURE;
    }
    let seed = std::env::var("ORACLE_SEED")
        .ok()
        .and_then(|text| u64::from_str_radix(text.trim_start_matches("0x"), 16).ok())
        .unwrap_or(SEED);
    report.check(
        "openssl-version",
        openssl::version().and_then(|version| {
            if version.starts_with("OpenSSL 3.5") {
                Ok(version)
            } else {
                Err(format!("{version}: not OpenSSL 3.5"))
            }
        }),
    );
    report.check("reference-vectors", reference_vectors());
    report.check("random-cross-test", random_cases(seed));
    report.check("coverage-cross-test", coverage_cases());
    report.check("entry-point-costs", entry_point_costs());
    report.check("burst-memory-bound", burst());
    if report.failures == 0 {
        println!("all Argon2id oracle checks passed");
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}
