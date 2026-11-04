//! The unlock benchmark of Story 4.4 (AC3, E12): the Core's own Argon2id derivation at the version
//! 1 cost, through its limiter and its locked working memory, timed alone and as two simultaneous
//! unlocks under the limit of D128, against the 2-second unlock target (PRD assumption, D113).
//!
//! Run on the reference host (4 cores, 8 GB RAM, SSD, no GPU, Debian 13 amd64), idle, by
//! `bash oracles/argon2id/run.sh --bench`, which gives the process an unlimited `RLIMIT_MEMLOCK`
//! and the reference host's limits; the procedure is in Story 4.4's Dev notes. Anywhere else the
//! numbers are for information: the constant m is changed only on the strength of a reference-host
//! run (gate E12-5). One `PASS`, `FAIL` or `INFO` line per measure.

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use vilicus_crypto::testing::{block_on, sleep};
use vilicus_crypto::{Argon2idParams, CheckedCost, admit_derivation, derive_passphrase_kek};
use vilicus_types::{ARGON2ID_CONCURRENCY_LIMIT, PASSPHRASE_SALT_LEN};

/// The unlock target of PRD FR-11 and D113.
const TARGET: Duration = Duration::from_secs(2);
const SINGLE_SAMPLES: usize = 20;
const PAIR_ROUNDS: usize = 15;

/// One unlock's derivation: the admission, then the derivation, as the Core runs them.
fn unlock(cost: &CheckedCost, salt: &[u8; PASSPHRASE_SALT_LEN]) -> Duration {
    let started = Instant::now();
    let permit = block_on(admit_derivation(cost, sleep)).expect("admitted");
    let kek = derive_passphrase_kek(&permit, cost, "a benchmark passphrase".chars(), salt)
        .expect("derived");
    let took = started.elapsed();
    drop((kek, permit));
    took
}

fn milliseconds(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

/// The median, the 95th percentile (nearest rank) and the maximum of `samples`.
fn summary(samples: &mut [Duration]) -> (Duration, Duration, Duration) {
    samples.sort();
    let rank =
        |p: f64| samples[((p * samples.len() as f64).ceil() as usize).clamp(1, samples.len()) - 1];
    (rank(0.5), rank(0.95), samples[samples.len() - 1])
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path)
        .map_or_else(|_| "unknown".to_string(), |text| text.trim().to_string())
}

fn main() {
    vilicus_crypto::harden_process().expect("hardened");
    vilicus_crypto::lock_key_memory().expect("the key pool");
    let cost = CheckedCost::new(Argon2idParams::PASSPHRASE_V1).expect("the version 1 cost");
    let salt = [0x42; PASSPHRASE_SALT_LEN];
    println!(
        "INFO host: E12_HOST={}, available_parallelism={}, cpu.max={}, memory.max={}, cost {:?}, limit {}",
        std::env::var("E12_HOST").unwrap_or_else(|_| "unset".to_string()),
        thread::available_parallelism().map_or(0, usize::from),
        read("/sys/fs/cgroup/cpu.max"),
        read("/sys/fs/cgroup/memory.max"),
        cost.params(),
        ARGON2ID_CONCURRENCY_LIMIT
    );
    unlock(&cost, &salt);

    let mut single: Vec<Duration> = (0..SINGLE_SAMPLES).map(|_| unlock(&cost, &salt)).collect();
    let (median, p95, max) = summary(&mut single);
    let verdict = if p95 <= TARGET { "PASS" } else { "FAIL" };
    println!(
        "{verdict} single-unlock: median {:.1} ms, p95 {:.1} ms, max {:.1} ms over {SINGLE_SAMPLES}, target {} ms",
        milliseconds(median),
        milliseconds(p95),
        milliseconds(max),
        TARGET.as_millis()
    );

    let mut slower = Vec::new();
    for _ in 0..PAIR_ROUNDS {
        let start = Arc::new(Barrier::new(2));
        let pair: Vec<_> = (0..2)
            .map(|_| {
                let start = Arc::clone(&start);
                thread::spawn(move || {
                    start.wait();
                    unlock(&cost, &salt)
                })
            })
            .collect();
        let times: Vec<Duration> = pair
            .into_iter()
            .map(|t| t.join().expect("unlock"))
            .collect();
        slower.push(times.into_iter().max().expect("two"));
    }
    let (median, p95, max) = summary(&mut slower);
    let verdict = if p95 <= TARGET { "PASS" } else { "FAIL" };
    println!(
        "{verdict} concurrent-pair: slower of two simultaneous unlocks, median {:.1} ms, p95 {:.1} ms, max {:.1} ms over {PAIR_ROUNDS} rounds, target {} ms",
        milliseconds(median),
        milliseconds(p95),
        milliseconds(max),
        TARGET.as_millis()
    );
    selection(&salt);
}

/// m of the candidates of D128, in MiB, at t = 3 and p = 4: the run on the reference host picks
/// one of them under the serial, limit-2 model.
const CANDIDATES_MIB: [u32; 3] = [256, 384, 512];
const CANDIDATE_ROUNDS: usize = 7;

/// The median slower latency of two simultaneous unlocks at `cost`, after one warm-up pair.
fn pair_median(cost: &CheckedCost, salt: &[u8; PASSPHRASE_SALT_LEN]) -> Duration {
    let mut slower: Vec<Duration> = (0..=CANDIDATE_ROUNDS)
        .map(|_| {
            let start = Arc::new(Barrier::new(2));
            let pair: Vec<_> = (0..2)
                .map(|_| {
                    let (start, cost, salt) = (Arc::clone(&start), *cost, *salt);
                    thread::spawn(move || {
                        start.wait();
                        unlock(&cost, &salt)
                    })
                })
                .collect();
            pair.into_iter()
                .map(|t| t.join().expect("unlock"))
                .max()
                .expect("two")
        })
        .skip(1)
        .collect();
    summary(&mut slower).0
}

/// AC9, D128: the rule of story 1.8 under the adopted model. Among the candidates whose working
/// memory at the limit stays within the budget, keep those whose median slower-of-pair latency is
/// within the host's margin, the whole target on the reference host and half of it elsewhere, as
/// story 1.8 set it for an emulation; pick the largest. Only a reference-host run judges the
/// constant (gate E12-5): elsewhere the pick is information.
fn selection(salt: &[u8; PASSPHRASE_SALT_LEN]) {
    let reference = std::env::var("E12_HOST").is_ok_and(|host| host == "reference");
    let margin = if reference { TARGET } else { TARGET / 2 };
    let mut picked = None;
    for memory_mib in CANDIDATES_MIB {
        let params = Argon2idParams {
            memory_kib: memory_mib * 1024,
            ..Argon2idParams::PASSPHRASE_V1
        };
        let within_budget = ARGON2ID_CONCURRENCY_LIMIT as u64 * u64::from(params.memory_kib)
            <= vilicus_types::ARGON2ID_MEMORY_BUDGET_KIB;
        let cost = CheckedCost::new(params).expect("a candidate within the floor and the ceiling");
        let median = pair_median(&cost, salt);
        let kept = within_budget && median <= margin;
        if kept {
            picked = Some(params);
        }
        println!(
            "INFO candidate m = {memory_mib} MiB: slower of a pair, median {:.1} ms over {CANDIDATE_ROUNDS} rounds; limit times m within the budget {within_budget}; within the {} ms margin {}",
            milliseconds(median),
            margin.as_millis(),
            median <= margin
        );
    }
    let matches = picked == Some(Argon2idParams::PASSPHRASE_V1);
    let verdict = match (reference, matches) {
        (true, true) => "PASS",
        (true, false) => "FAIL",
        (false, _) => "INFO",
    };
    println!(
        "{verdict} selection-matches-constant: picked {picked:?}, constant {:?} ({})",
        Argon2idParams::PASSPHRASE_V1,
        if reference {
            "reference host: the constant follows the pick"
        } else {
            "not the reference host: the constant is not changed on this run (gate E12-5)"
        }
    );
}
