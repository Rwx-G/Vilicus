//! Runs the E12 measurements and prints one `PASS <name>` or `FAIL <name>` line per check,
//! followed by indented evidence, plus the measured tables. Exits non-zero on any failure.
//!
//! `E12_HOST` says where it runs: `emulation` (default; the selection keeps a margin of half the
//! target) or `reference` (the reference host itself; no margin).
//!
//! `argon2id-params burst <wait_ms>` is the child mode the parent runs in a fresh process, so the
//! peak resident memory it reports belongs to the concurrency-limit test alone.

use std::collections::HashSet;
use std::process::{Command, ExitCode};
use std::sync::{Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use argon2id_params::derive::Pool;
use argon2id_params::guidance::{self, PUBLISHED};
use argon2id_params::limiter::Limiter;
use argon2id_params::stats::{Summary, summarise};
use argon2id_params::{
    Cost, MEMORY_BUDGET_MIB, MIB, UNLOCK_TARGET_MS, UnlockError, peak_rss_kib, recommended, unlock,
};

const SWEEP_MEMORY_MIB: [u32; 6] = [64, 128, 256, 512, 1024, 2048];
const SWEEP_PASSES: [u32; 4] = [1, 2, 3, 4];
const SWEEP_LANES: [u32; 3] = [1, 2, 4];
const SWEEP_SAMPLES: usize = 3;
/// A sweep row slower than this skips the larger memory sizes of the same (t, p).
const SWEEP_CUTOFF_MS: f64 = 5_000.0;
const SINGLE_SAMPLES: usize = 20;
/// Measured rounds of two simultaneous unlocks, after one discarded warm-up round.
const PAIR_ROUNDS: usize = 15;
/// Parameter sets compared under the recommended pool and limit, all at p = 4 (one lane per core of
/// the reference host, as in both RFC 9106 options) and all inside [floor, ceiling].
const CANDIDATES: [Cost; 6] = [
    Cost::new(256, 3, 4),
    Cost::new(256, 4, 4),
    Cost::new(384, 3, 4),
    Cost::new(512, 3, 4),
    Cost::new(768, 3, 4),
    Cost::new(1024, 3, 4),
];
/// Requests fired at once in the burst test: every member of a large household at the same time.
const BURST_REQUESTS: usize = 8;
/// Allowance over `limit * m` for the process itself in the burst child (binary, pools, stacks).
const RSS_ALLOWANCE_MIB: u64 = 64;
const PASSPHRASE: &[u8] = b"correct horse battery staple";
const SALT: [u8; 16] = [0x5a; 16];

struct Checks {
    failures: usize,
    names: HashSet<String>,
}

impl Checks {
    fn record(&mut self, name: &str, passed: bool, evidence: &[String]) {
        assert!(
            self.names.insert(name.to_owned()),
            "check {name} recorded twice"
        );
        println!("{} {name}", if passed { "PASS" } else { "FAIL" });
        evidence.iter().for_each(|line| println!("  {line}"));
        if !passed {
            self.failures += 1;
        }
    }
}

/// Where the run happens, which sets the selection margin.
struct Host {
    name: &'static str,
    /// Fraction of the target the slower of two simultaneous unlocks may take in the selection.
    margin: f64,
}

fn host() -> Result<Host, String> {
    match std::env::var("E12_HOST").as_deref() {
        Ok("emulation") | Err(std::env::VarError::NotPresent) => Ok(Host {
            name: "emulation",
            margin: 0.5,
        }),
        Ok("reference") => Ok(Host {
            name: "reference",
            margin: 1.0,
        }),
        Ok(other) => Err(format!("E12_HOST={other}: expected emulation or reference")),
        Err(e) => Err(format!("E12_HOST: {e}")),
    }
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some("burst") {
        return match args.next().and_then(|ms| ms.parse().ok()) {
            Some(wait_ms) => burst_child(wait_ms),
            None => ExitCode::FAILURE,
        };
    }
    environment();
    let mut checks = Checks {
        failures: 0,
        names: HashSet::new(),
    };
    match run(&mut checks) {
        Ok(()) if checks.failures == 0 => ExitCode::SUCCESS,
        Ok(()) => ExitCode::FAILURE,
        Err(error) => {
            println!("FAIL harness");
            println!("  {error}");
            ExitCode::FAILURE
        }
    }
}

fn environment() {
    let cores = thread::available_parallelism().map_or(0, |n| n.get());
    println!("INFO available_parallelism={cores}");
    for (label, path) in [
        ("cgroup cpu.max", "/sys/fs/cgroup/cpu.max"),
        ("cgroup memory.max", "/sys/fs/cgroup/memory.max"),
    ] {
        let value = std::fs::read_to_string(path).unwrap_or_else(|_| "unavailable".into());
        println!("INFO {label}={}", value.trim());
    }
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|info| {
            info.lines()
                .find_map(|l| l.strip_prefix("model name"))
                .map(|rest| rest.trim_start_matches([' ', '\t', ':']).to_owned())
        })
        .unwrap_or_else(|| "unavailable".into());
    println!("INFO cpu={cpu}");
}

fn run(checks: &mut Checks) -> Result<(), String> {
    let host = host()?;
    println!(
        "INFO host profile={} selection margin={} of the target ({} ms)",
        host.name,
        host.margin,
        host.margin * UNLOCK_TARGET_MS
    );
    published_floor(checks);
    sweep()?;
    let single = single(checks)?;
    pairs(checks)?;
    candidates(checks, &host)?;
    burst(checks, &single)?;
    Ok(())
}

fn print_summary(label: &str, s: &Summary) {
    println!(
        "  {label:<34} n={:<3} median={:>7.1} ms  p95={:>7.1} ms  max={:>7.1} ms",
        s.samples, s.median_ms, s.p95_ms, s.max_ms
    );
}

/// Times `samples` derivations after one discarded warm-up derivation.
fn timed(pool: &Pool, cost: Cost, samples: usize) -> Result<Summary, String> {
    pool.time(cost)?;
    let durations = (0..samples)
        .map(|_| pool.time(cost))
        .collect::<Result<Vec<_>, _>>()?;
    summarise(&durations).ok_or_else(|| "no samples".into())
}

fn published_floor(checks: &mut Checks) {
    let mut evidence: Vec<String> = PUBLISHED
        .iter()
        .map(|set| {
            let verdict = guidance::floor_violation(set.cost).unwrap_or_else(|| "meets".into());
            format!("{:<22} {}  -> {verdict}", set.source, set.cost)
        })
        .collect();
    let violation = guidance::header_violation(recommended::COST);
    evidence.push(
        "floor (project rule): at least one RFC 9106 option in both memory and passes".into(),
    );
    evidence.push(format!(
        "ceiling (project rule): m <= {} MiB, m*t <= {} MiB, p <= {}",
        guidance::CEILING_M_KIB / MIB,
        guidance::CEILING_WORK_MIB,
        guidance::CEILING_P
    ));
    evidence.push(format!(
        "recommended {}: {}",
        recommended::COST,
        violation.as_deref().unwrap_or("inside [floor, ceiling]")
    ));
    checks.record(
        "recommended_meets_published_floor",
        violation.is_none(),
        &evidence,
    );
}

fn sweep() -> Result<(), String> {
    let pool = Pool::new(4)?;
    println!(
        "TABLE sweep (single derivation, 4-thread pool, {SWEEP_SAMPLES} samples after a warm-up)"
    );
    println!("  m_MiB  t  p  floor  median_ms  p95_ms");
    for &p in &SWEEP_LANES {
        for &t in &SWEEP_PASSES {
            for &m in &SWEEP_MEMORY_MIB {
                let cost = Cost::new(m, t, p);
                let s = timed(&pool, cost, SWEEP_SAMPLES)?;
                let floor = if guidance::floor_violation(cost).is_none() {
                    "yes"
                } else {
                    "no"
                };
                println!(
                    "  {m:>5} {t:>2} {p:>2}  {floor:<5} {:>9.1} {:>7.1}",
                    s.median_ms, s.p95_ms
                );
                if s.median_ms > SWEEP_CUTOFF_MS {
                    break;
                }
            }
        }
    }
    Ok(())
}

fn single(checks: &mut Checks) -> Result<Summary, String> {
    let cost = recommended::COST;
    println!(
        "TABLE recommended {cost}, single derivation by pool size (allocation and wipe included)"
    );
    for threads in [1, 2, 4] {
        let s = timed(&Pool::new(threads)?, cost, SINGLE_SAMPLES)?;
        print_summary(&format!("{threads}-thread pool"), &s);
    }
    let pool = Pool::new(recommended::POOL_THREADS)?;
    let s = timed(&pool, cost, SINGLE_SAMPLES)?;
    let passed = s.median_ms < UNLOCK_TARGET_MS && s.p95_ms < UNLOCK_TARGET_MS;
    checks.record(
        "single_unlock_under_target",
        passed,
        &[format!(
            "{cost}, {}-thread pool, n={}: median {:.1} ms, p95 {:.1} ms, max {:.1} ms (target {UNLOCK_TARGET_MS} ms)",
            recommended::POOL_THREADS, s.samples, s.median_ms, s.p95_ms, s.max_ms
        )],
    );
    Ok(s)
}

/// Fast and slow latencies of two unlocks requested at the same instant.
struct Pairs {
    fast: Summary,
    slow: Summary,
}

/// `PAIR_ROUNDS` rounds of two unlocks requested at the same instant, after one discarded warm-up
/// round. Each latency runs from the request to the derived KEK, so time queued behind the limit
/// counts.
fn pair_latencies(pool: &Pool, cost: Cost, limit: usize) -> Result<Pairs, String> {
    let limiter = Limiter::new(limit, Duration::from_secs(60));
    let mut fast = Vec::with_capacity(PAIR_ROUNDS);
    let mut slow = Vec::with_capacity(PAIR_ROUNDS);
    for round in 0..=PAIR_ROUNDS {
        let barrier = Barrier::new(2);
        let results: Vec<Result<Duration, String>> = thread::scope(|scope| {
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        let started = Instant::now();
                        unlock(&limiter, pool, cost, PASSPHRASE, &SALT)
                            .map_err(|e| format!("{e:?}"))?;
                        Ok(started.elapsed())
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap_or_else(|_| Err("thread panicked".into())))
                .collect()
        });
        let mut pair = results.into_iter().collect::<Result<Vec<_>, _>>()?;
        pair.sort();
        if round > 0 {
            fast.push(pair[0]);
            slow.push(pair[1]);
        }
    }
    if limiter.peak() > limit {
        return Err(format!("limit {limit} let {} run at once", limiter.peak()));
    }
    Ok(Pairs {
        fast: summarise(&fast).ok_or("no samples")?,
        slow: summarise(&slow).ok_or("no samples")?,
    })
}

fn pairs(checks: &mut Checks) -> Result<(), String> {
    let pool = Pool::new(recommended::POOL_THREADS)?;
    println!(
        "TABLE two simultaneous unlocks, {}, {}-thread pool, {PAIR_ROUNDS} rounds after a warm-up",
        recommended::COST,
        recommended::POOL_THREADS
    );
    let mut chosen = None;
    for limit in [1, 2] {
        let pairs = pair_latencies(&pool, recommended::COST, limit)?;
        print_summary(&format!("limit {limit}, faster of the pair"), &pairs.fast);
        print_summary(&format!("limit {limit}, slower of the pair"), &pairs.slow);
        if limit == recommended::CONCURRENT_DERIVATIONS {
            chosen = Some(pairs);
        }
    }
    let p = chosen.ok_or("the recommended limit was not measured")?;
    checks.record(
        "concurrent_pair_under_target",
        p.slow.max_ms < UNLOCK_TARGET_MS,
        &[
            format!(
                "limit {}, n={} pairs; faster: median {:.1} ms, p95 {:.1} ms, max {:.1} ms",
                recommended::CONCURRENT_DERIVATIONS,
                p.fast.samples,
                p.fast.median_ms,
                p.fast.p95_ms,
                p.fast.max_ms
            ),
            format!(
                "slower: median {:.1} ms, p95 {:.1} ms, max {:.1} ms (target {UNLOCK_TARGET_MS} ms)",
                p.slow.median_ms, p.slow.p95_ms, p.slow.max_ms
            ),
        ],
    );
    Ok(())
}

/// Measures each candidate under the recommended pool and limit and applies the selection rule:
/// among candidates whose median slower-of-pair latency is within the host's margin, the most
/// work (m times t), then the most memory. Every candidate is inside [floor, ceiling] and fits the
/// memory budget under the limit.
fn candidates(checks: &mut Checks, host: &Host) -> Result<(), String> {
    let pool = Pool::new(recommended::POOL_THREADS)?;
    let margin_ms = host.margin * UNLOCK_TARGET_MS;
    println!(
        "TABLE candidates, slower of two simultaneous unlocks, limit {}, {}-thread pool, {PAIR_ROUNDS} rounds",
        recommended::CONCURRENT_DERIVATIONS,
        recommended::POOL_THREADS
    );
    let mut selected: Option<Cost> = None;
    for cost in CANDIDATES {
        if let Some(violation) = guidance::header_violation(cost) {
            return Err(format!("candidate outside [floor, ceiling]: {violation}"));
        }
        if recommended::CONCURRENT_DERIVATIONS as u32 * cost.m_mib() > MEMORY_BUDGET_MIB {
            return Err(format!("candidate {cost} exceeds the memory budget"));
        }
        let pairs = pair_latencies(&pool, cost, recommended::CONCURRENT_DERIVATIONS)?;
        print_summary(&cost.to_string(), &pairs.slow);
        let better = selected
            .is_none_or(|best| (cost.work_mib(), cost.m_kib) > (best.work_mib(), best.m_kib));
        if pairs.slow.median_ms <= margin_ms && better {
            selected = Some(cost);
        }
    }
    let evidence = [
        format!(
            "rule: median slower-of-pair <= {margin_ms} ms ({} profile), then most m*t, then most m",
            host.name
        ),
        format!(
            "picked {}, constant {}",
            selected.map_or_else(|| "nothing".to_owned(), |c| c.to_string()),
            recommended::COST
        ),
    ];
    checks.record(
        "selection_matches_constant",
        selected == Some(recommended::COST),
        &evidence,
    );
    Ok(())
}

/// Child mode: fires `BURST_REQUESTS` unlocks at once under the recommended limit with the given
/// queue wait bound and prints one machine-readable `BURST` line for the parent.
fn burst_child(wait_ms: u64) -> ExitCode {
    let Ok(pool) = Pool::new(recommended::POOL_THREADS) else {
        return ExitCode::FAILURE;
    };
    let baseline = peak_rss_kib().unwrap_or(0);
    let limiter = Limiter::new(
        recommended::CONCURRENT_DERIVATIONS,
        Duration::from_millis(wait_ms),
    );
    let barrier = Barrier::new(BURST_REQUESTS);
    let min_refused_wait = Mutex::new(u128::MAX);
    let outcomes: Vec<bool> = thread::scope(|scope| {
        let handles: Vec<_> = (0..BURST_REQUESTS)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    match unlock(&limiter, &pool, recommended::COST, PASSPHRASE, &SALT) {
                        Ok(_) => true,
                        Err(UnlockError::Refused(refused)) => {
                            let mut min =
                                min_refused_wait.lock().unwrap_or_else(|p| p.into_inner());
                            *min = (*min).min(refused.waited.as_millis());
                            false
                        }
                        Err(_) => false,
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or(false))
            .collect()
    });
    let served = outcomes.iter().filter(|&&ok| ok).count();
    let min_refused = *min_refused_wait.lock().unwrap_or_else(|p| p.into_inner());
    println!(
        "BURST served={served} refused={} peak={} min_refused_wait_ms={} baseline_kib={baseline} rss_kib={}",
        outcomes.len() - served,
        limiter.peak(),
        if min_refused == u128::MAX {
            0
        } else {
            min_refused
        },
        peak_rss_kib().unwrap_or(0)
    );
    ExitCode::SUCCESS
}

fn burst_field(line: &str, key: &str) -> Result<u64, String> {
    line.split_whitespace()
        .find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
        .ok_or_else(|| format!("no {key} in {line:?}"))?
        .parse()
        .map_err(|e| format!("{key}: {e}"))
}

fn run_burst(wait_ms: u64) -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let output = Command::new(exe)
        .args(["burst", &wait_ms.to_string()])
        .output()
        .map_err(|e| format!("burst child: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find(|l| l.starts_with("BURST "))
        .map(str::to_owned)
        .ok_or_else(|| format!("burst child printed no result: {stdout}"))
}

/// Two bursts. Under limit 1 the k-th request (from 0) starts after k derivations, so with a wait
/// bound `w` it is served when those k derivations finish within `w`. From the single-derivation
/// measurement, the served count lies between `1 + w / max` and `1 + w / (0.8 * median)`, capped
/// at the burst size. The second burst uses a bound of half a median derivation: exactly the
/// first request is served and the other seven are refused.
fn burst(checks: &mut Checks, single: &Summary) -> Result<(), String> {
    let limit = recommended::CONCURRENT_DERIVATIONS as u64;
    let rss_bound_mib = limit * u64::from(recommended::COST.m_mib()) + RSS_ALLOWANCE_MIB;
    let requests = BURST_REQUESTS as u64;
    let bound = recommended::MAX_QUEUE_WAIT_MS as f64;
    let served_range = |slowest: f64, fastest: f64| {
        let low = (1 + (bound / slowest).floor() as u64).min(requests);
        let high = (1 + (bound / fastest).floor() as u64).min(requests);
        (low, high)
    };
    let short_wait_ms = (single.median_ms / 2.0) as u64;
    let mut passed = true;
    let mut evidence = Vec::new();
    for (wait_ms, (low, high)) in [
        (
            recommended::MAX_QUEUE_WAIT_MS,
            served_range(single.max_ms, 0.8 * single.median_ms),
        ),
        (short_wait_ms, (limit, limit)),
    ] {
        let line = run_burst(wait_ms)?;
        let served = burst_field(&line, "served")?;
        let refused = burst_field(&line, "refused")?;
        let peak = burst_field(&line, "peak")?;
        let min_refused = burst_field(&line, "min_refused_wait_ms")?;
        let rss_mib = burst_field(&line, "rss_kib")? / u64::from(MIB);
        let ok = (low..=high).contains(&served)
            && refused == requests - served
            && peak == limit
            && (refused == 0 || min_refused >= wait_ms)
            && rss_mib <= rss_bound_mib;
        passed &= ok;
        evidence.push(format!(
            "wait bound {wait_ms} ms: served {served} (expected {low} to {high}), refused {refused}, most at once {peak}, shortest refused wait {min_refused} ms, peak RSS {rss_mib} MiB (bound {rss_bound_mib} MiB)",
        ));
    }
    checks.record("concurrency_limit_holds", passed, &evidence);
    Ok(())
}
