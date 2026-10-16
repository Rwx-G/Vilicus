//! E32 runner.
//!
//! - `core-execution run --name <name> [--pool <permits>] [--unlockers <loops>]
//!   [--duration <seconds>] [--throttle <bytes per second>] [--informational]` runs one
//!   configuration and prints one `PASS <check>` or `FAIL <check>` line per check and the
//!   measured table; with `--informational` the D116 lines are printed as `INFO` (a
//!   sensitivity run, not the gate).
//! - `core-execution pause-bound [--sizes <MiB,...>] [--updates <commits>]` measures an AD-31
//!   writer pause against file size with a WAL left unchecked for `--updates` commits.
//! - `core-execution fsync-bench [--iterations <n>]` times a 4 KiB write and `fdatasync` in
//!   the temporary directory the runs use.
//! - `core-execution audit-writer <append socket> <admin socket> <db>` is the audit writer
//!   process a run starts.

use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use core_execution::experiments;
use core_execution::load::{
    self, ALL_ACTIONS_LABEL, AuditMode, Config, PROBE_LABEL, RULE_WAKE_TO_DISPATCH_LABEL,
    SOCKET_PROBE_LABEL,
};
use core_execution::stats;

/// D116: p99 under 100 ms for one action through the full pipeline.
const D116_P99: Duration = Duration::from_millis(100);
/// The rule loop ticks at least every 100 ms; this allows 50 ms of scheduling slack.
const WATCHDOG_GAP_LIMIT: Duration = Duration::from_millis(150);

struct Args {
    name: String,
    pool: usize,
    unlockers: usize,
    duration: u64,
    throttle: Option<u64>,
    informational: bool,
    sizes: Vec<u64>,
    updates: u32,
    iterations: u32,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut parsed = Args {
        name: "ad9".into(),
        pool: 3,
        unlockers: 2,
        duration: 600,
        throttle: None,
        informational: false,
        sizes: vec![64, 256, 512],
        updates: 20_000,
        iterations: 2_000,
    };
    fn number<T: std::str::FromStr>(flag: &str, value: &str) -> Result<T, String> {
        value.parse().map_err(|_| format!("{flag}: not a number"))
    }
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or(format!("{flag} needs a value"));
        match flag.as_str() {
            "--name" => parsed.name = value()?,
            "--pool" => parsed.pool = number(&flag, &value()?)?,
            "--unlockers" => parsed.unlockers = number(&flag, &value()?)?,
            "--duration" => parsed.duration = number(&flag, &value()?)?,
            "--throttle" => parsed.throttle = Some(number(&flag, &value()?)?),
            "--informational" => parsed.informational = true,
            "--sizes" => {
                parsed.sizes = value()?
                    .split(',')
                    .map(|size| number(&flag, size))
                    .collect::<Result<_, _>>()?;
            }
            "--updates" => parsed.updates = number(&flag, &value()?)?,
            "--iterations" => parsed.iterations = number(&flag, &value()?)?,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(parsed)
}

/// `nr_periods`, `nr_throttled` and `throttled_usec` of the container's cgroup, if readable.
fn cpu_throttling() -> Option<[u64; 3]> {
    let stat = std::fs::read_to_string("/sys/fs/cgroup/cpu.stat").ok()?;
    let field = |name: &str| {
        stat.lines()
            .find_map(|line| line.strip_prefix(name)?.trim().parse::<u64>().ok())
    };
    Some([
        field("nr_periods ")?,
        field("nr_throttled ")?,
        field("throttled_usec ")?,
    ])
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let command = args.next();
    if command.as_deref() == Some("audit-writer") {
        let (Some(append), Some(admin), Some(db)) = (args.next(), args.next(), args.next()) else {
            eprintln!("usage: audit-writer <append socket> <admin socket> <db>");
            return ExitCode::FAILURE;
        };
        return match load::audit_writer_main(Path::new(&append), Path::new(&admin), Path::new(&db))
        {
            Ok(_) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("audit writer: {error}");
                ExitCode::FAILURE
            }
        };
    }
    let parsed = match parse_args(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    match command.as_deref() {
        Some("run") => run(&parsed),
        Some("pause-bound") => pause_bound(&parsed),
        Some("fsync-bench") => fsync_bench(&parsed),
        _ => {
            eprintln!("usage: core-execution run | pause-bound | fsync-bench | audit-writer");
            ExitCode::FAILURE
        }
    }
}

fn pause_bound(args: &Args) -> ExitCode {
    let workdir = std::env::temp_dir().join(format!("e32-pause-bound-{}", std::process::id()));
    println!(
        "INFO pause_bound: one writer pause per file size, WAL holding {} single-row commits \
         with automatic checkpoints off",
        args.updates
    );
    println!("| file MiB | WAL MiB | checkpoint ms | copy ms | pause ms | copy MiB/s |");
    println!("|---|---|---|---|---|---|");
    let mut failed = false;
    let mut points = Vec::new();
    let mut wal_rates = Vec::new();
    for size in &args.sizes {
        match experiments::pause_bound(&workdir, *size, args.updates) {
            Ok(row) => {
                println!(
                    "| {:.0} | {:.1} | {:.1} | {:.1} | {:.1} | {:.0} |",
                    row.file_mib,
                    row.wal_mib,
                    ms(row.checkpoint),
                    ms(row.copy),
                    ms(row.pause),
                    row.file_mib / row.copy.as_secs_f64()
                );
                points.push((row.file_mib, ms(row.copy)));
                wal_rates.push(ms(row.checkpoint) / row.wal_mib.max(f64::EPSILON));
                println!("PASS pause_bound.{size}_mib");
            }
            Err(error) => {
                println!("FAIL pause_bound.{size}_mib ({error})");
                failed = true;
            }
        }
    }
    // The pause is the checkpoint (driven by the WAL) plus the copy (driven by the file): each
    // part is reported against its own driver.
    if points.len() >= 2 {
        // Least-squares line through (file size, copy time): copy = a + b * size.
        let n = points.len() as f64;
        let (sx, sy) = points
            .iter()
            .fold((0.0, 0.0), |(sx, sy), (x, y)| (sx + x, sy + y));
        let (sxx, sxy) = points
            .iter()
            .fold((0.0, 0.0), |(sxx, sxy), (x, y)| (sxx + x * x, sxy + x * y));
        let slope = (n * sxy - sx * sy) / (n * sxx - sx * sx);
        let intercept = (sy - slope * sx) / n;
        println!(
            "INFO pause_bound copy fit: copy ~ {intercept:.1} ms + {slope:.2} ms per MiB of \
             file; the copy alone reaches 100 ms at about {:.0} MiB",
            (100.0 - intercept) / slope
        );
        println!(
            "INFO pause_bound checkpoint: {:.2} to {:.2} ms per MiB of WAL",
            wal_rates.iter().copied().fold(f64::INFINITY, f64::min),
            wal_rates.iter().copied().fold(0.0, f64::max)
        );
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn fsync_bench(args: &Args) -> ExitCode {
    let dir = std::env::temp_dir().join(format!("e32-fsync-{}", std::process::id()));
    match experiments::fsync_bench(&dir, args.iterations) {
        Ok(summary) => {
            println!(
                "INFO fsync_bench in {} ({}): p50 {:.3} ms, p99 {:.3} ms, max {:.3} ms over {} \
                 samples",
                std::env::temp_dir().display(),
                summary.label,
                ms(summary.p50),
                ms(summary.p99),
                ms(summary.max),
                summary.count
            );
            println!("PASS fsync_bench");
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!("FAIL fsync_bench ({error})");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> ExitCode {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(error) => {
            eprintln!("current executable: {error}");
            return ExitCode::FAILURE;
        }
    };
    let workdir = std::env::temp_dir().join(format!("e32-{}-{}", args.name, std::process::id()));
    let mut cfg = Config::household(&args.name, workdir, AuditMode::Process(exe));
    cfg.pool_permits = args.pool;
    cfg.unlockers = args.unlockers;
    cfg.duration = Duration::from_secs(args.duration);
    cfg.backup_throttle = args.throttle;
    println!("INFO config {}", cfg.describe());
    println!(
        "INFO cpus available_parallelism={}",
        std::thread::available_parallelism().map_or(0, |n| n.get())
    );
    let throttling_before = cpu_throttling();
    let wall = Instant::now();
    let report = match load::run(&cfg) {
        Ok(report) => report,
        Err(error) => {
            println!("FAIL {}.run ({error})", cfg.name);
            return ExitCode::FAILURE;
        }
    };
    println!(
        "INFO {} wall {} s, module files {} MiB at the end",
        cfg.name,
        wall.elapsed().as_secs(),
        report.file_bytes / (1 << 20)
    );
    if let (Some(before), Some(after)) = (throttling_before, cpu_throttling()) {
        println!(
            "INFO {} cgroup CPU throttling: {} of {} periods throttled, {} ms throttled in total",
            cfg.name,
            after[1] - before[1],
            after[0] - before[0],
            (after[2] - before[2]) / 1_000
        );
    }
    println!("INFO {} measured table ({}):", cfg.name, cfg.name);
    print!("{}", stats::table(&report.summaries));
    println!(
        "INFO {} slowest pipeline actions (all labels pooled):",
        cfg.name
    );
    for (_, detail) in &report.slowest {
        println!("INFO   {detail}");
    }

    let mut failed = false;
    let mut check = |name: &str, ok: bool, detail: String, gate: bool| {
        let verdict = match (gate, ok) {
            (false, _) => "INFO",
            (true, true) => "PASS",
            (true, false) => "FAIL",
        };
        println!("{verdict} {}.{name} ({detail})", cfg.name);
        failed |= gate && !ok;
    };
    let error_count: usize = report.errors.values().map(Vec::len).sum();
    let first_errors: Vec<String> = report
        .errors
        .iter()
        .flat_map(|(label, errors)| errors.iter().take(3).map(move |e| format!("{label}: {e}")))
        .take(5)
        .collect();
    check(
        "no_pipeline_or_background_errors",
        error_count == 0,
        format!("{error_count} errors {first_errors:?}"),
        true,
    );
    check(
        "load_shape",
        report.max_concurrent_unlocks >= 2
            && report.backups > 0
            && report.copies_during_unlock > 0
            && report.rule_dispatches > 0
            && report.home_interleaved_jobs > 0
            && report.retention_deleted > 0
            && report.audit_copies > 0
            && report.long_reads > 0,
        format!(
            "{} unlocks, at most {} at once; {} backup cycles, each flushing the audit writer \
             and copying audit.db ({} copies), {} file copies started while an unlock ran; {} \
             jobs ran between home online backup steps; {} pause attempts retried behind a \
             reader; {} long reads; {} expired home journal entries deleted; {} rule \
             dispatches",
            report.unlocks,
            report.max_concurrent_unlocks,
            report.backups,
            report.audit_copies,
            report.copies_during_unlock,
            report.home_interleaved_jobs,
            report.pause_retries,
            report.long_reads,
            report.retention_deleted,
            report.rule_dispatches
        ),
        true,
    );
    check(
        "pool_permits_respected",
        report.max_permits_held <= cfg.pool_permits,
        format!(
            "at most {} permits held, pool of {}",
            report.max_permits_held, cfg.pool_permits
        ),
        true,
    );
    check(
        "watchdog_gap",
        report.watchdog_ticks > 0 && report.watchdog_max_gap <= WATCHDOG_GAP_LIMIT,
        format!(
            "{} ticks, longest gap {:.1} ms, limit {} ms",
            report.watchdog_ticks,
            ms(report.watchdog_max_gap),
            WATCHDOG_GAP_LIMIT.as_millis()
        ),
        true,
    );
    check(
        "audit_chain_verifies",
        report.audit_verified.as_ref().ok() == Some(&report.audit_appends),
        format!(
            "{} entries appended, verification {:?}",
            report.audit_appends, report.audit_verified
        ),
        true,
    );
    let expected = cfg.expected_probes();
    for (name, label) in [
        ("probe_count", PROBE_LABEL),
        ("socket_probe_count", SOCKET_PROBE_LABEL),
    ] {
        let count = report.summary(label).map_or(0, |summary| summary.count) as u64;
        check(
            name,
            count.abs_diff(expected) <= 1,
            format!("{count} samples, {expected} ticks scheduled in the window"),
            true,
        );
    }
    for (name, label) in [
        ("d116_probe_p99", PROBE_LABEL),
        ("d116_socket_probe_p99", SOCKET_PROBE_LABEL),
        ("d116_all_actions_p99", ALL_ACTIONS_LABEL),
    ] {
        match report.summary(label) {
            Some(summary) => check(
                name,
                summary.p99 < D116_P99,
                format!(
                    "p99 {:.2} ms, max {:.2} ms over {} samples, criterion p99 under {} ms",
                    ms(summary.p99),
                    ms(summary.max),
                    summary.count,
                    D116_P99.as_millis()
                ),
                !args.informational,
            ),
            None => check(name, false, "no samples".into(), true),
        }
    }
    if let Some(rule) = report.summary(RULE_WAKE_TO_DISPATCH_LABEL) {
        println!(
            "INFO {}.rule_wake_to_dispatch (p50 {:.3} ms, p99 {:.3} ms, max {:.3} ms over {} samples)",
            cfg.name,
            ms(rule.p50),
            ms(rule.p99),
            ms(rule.max),
            rule.count
        );
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
