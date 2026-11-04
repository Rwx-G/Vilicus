//! The harness: writes the material, starts subject processes, reads their memory at each phase
//! and prints one `PASS`, `FAIL`, `SKIP` or `INFO` line per check.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};

use vilicus_crypto::{PLANNED_SLOTS, STACK_SCRUB_LEN, STACK_SCRUB_MARGIN, testing};

use crate::material::{self, DEK, Field, KEK, KEY, MARKER, Material, PARENT, Pattern, pattern};
use crate::scan::{self, Findings, RegionKind};
use crate::subject::EXIT_REFUSED;

/// The groups of checks, one container each.
pub const GROUPS: [&str; 5] = ["main", "noptrace", "nomemlock", "ipclock", "swap"];

/// Counts failures while printing the report.
#[derive(Default)]
pub struct Report {
    failures: usize,
}

impl Report {
    fn check(&mut self, name: &str, ok: bool, detail: &str) {
        if ok {
            println!("PASS {name}: {detail}");
        } else {
            println!("FAIL {name}: {detail}");
            self.failures += 1;
        }
    }

    fn fail(&mut self, name: &str, detail: &str) {
        self.check(name, false, detail);
    }

    fn info(&mut self, name: &str, detail: &str) {
        println!("INFO {name}: {detail}");
    }

    fn skip(&mut self, name: &str, reason: &str) {
        println!("SKIP {name}: {reason}");
    }

    pub fn failures(&self) -> usize {
        self.failures
    }
}

/// A guarded operation and the stack depth it reported.
type StackDepth = (String, Option<usize>);

struct Subject {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    pool: (usize, usize),
    /// `PR_GET_DUMPABLE` as the subject reported it once set up.
    dumpable: Option<i32>,
    /// The planted input copies of the default shape, by pattern and address (`PLANTED` lines).
    planted: Vec<(String, usize)>,
}

/// A subject that ended before it was set up: its exit status and its last line.
type Started = Result<Subject, (ExitStatus, String)>;

impl Subject {
    fn start(scenario: &str, variant: &str, material: &Path) -> io::Result<Started> {
        let cwd = material.parent().unwrap_or(Path::new("/tmp"));
        Subject::start_in(scenario, variant, material, cwd)
    }

    fn start_in(scenario: &str, variant: &str, material: &Path, cwd: &Path) -> io::Result<Started> {
        let mut child = Command::new(std::env::current_exe()?)
            .args(["subject", scenario, variant])
            .arg(material)
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let stdin = child.stdin.take().expect("piped stdin");
        let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        let mut line = String::new();
        stdout.read_line(&mut line)?;
        let Some(pool) = parse_pool(&line) else {
            let status = child.wait()?;
            return Ok(Err((status, line.trim().to_string())));
        };
        let mut status_line = String::new();
        stdout.read_line(&mut status_line)?;
        let dumpable = status_line
            .trim()
            .strip_prefix("STATUS dumpable=")
            .and_then(|d| d.parse().ok());
        Ok(Ok(Subject {
            child,
            stdin,
            stdout,
            pool,
            dumpable,
            planted: Vec::new(),
        }))
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Reads lines until one starts with `tag`, and returns it.
    fn expect(&mut self, tag: &str) -> io::Result<String> {
        loop {
            let mut line = String::new();
            if self.stdout.read_line(&mut line)? == 0 {
                return Err(io::Error::other(format!("subject ended before {tag}")));
            }
            if line.starts_with("ERROR") {
                return Err(io::Error::other(line.trim().to_string()));
            }
            if let Some((name, address)) = line
                .trim()
                .strip_prefix("PLANTED ")
                .and_then(|rest| rest.split_once(' '))
                && let Ok(address) = usize::from_str_radix(address, 16)
            {
                self.planted.push((name.to_string(), address));
            }
            if line.starts_with(tag) {
                return Ok(line.trim().to_string());
            }
        }
    }

    /// Reads the `STACK` lines up to the next `tag` line, which it returns with them.
    fn expect_with_stacks(&mut self, tag: &str) -> io::Result<(String, Vec<StackDepth>)> {
        let mut stacks = Vec::new();
        loop {
            let line = self.expect("")?;
            if let Some(rest) = line.strip_prefix("STACK ") {
                let (name, depth) = rest.split_once(' ').unwrap_or((rest, ""));
                stacks.push((name.to_string(), depth.parse().ok()));
            } else if line.starts_with(tag) {
                return Ok((line, stacks));
            }
        }
    }

    fn answer(&mut self, text: &str) -> io::Result<()> {
        self.stdin.write_all(format!("{text}\n").as_bytes())?;
        self.stdin.flush()
    }

    fn proceed(&mut self) -> io::Result<()> {
        self.answer("")
    }

    fn scan(&self, patterns: &[Pattern]) -> io::Result<Findings> {
        scan::scan(self.pid(), self.pool, patterns)
    }

    fn signal(&self, signal: i32) -> io::Result<()> {
        testing::signal(self.pid(), signal)
    }

    fn finish(mut self) -> io::Result<ExitStatus> {
        drop(self.stdin);
        self.child.wait()
    }
}

fn parse_pool(line: &str) -> Option<(usize, usize)> {
    let mut fields = line.trim().strip_prefix("POOL ")?.split(' ');
    let start = usize::from_str_radix(fields.next()?, 16).ok()?;
    let len = fields.next()?.parse().ok()?;
    Some((start, len))
}

fn material_path() -> io::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("key-memory-{}", std::process::id()));
    fs::create_dir_all(&dir)?;
    Ok(dir.join("material.bin"))
}

fn started(
    report: &mut Report,
    name: &str,
    scenario: &str,
    variant: &str,
    path: &Path,
) -> io::Result<Option<Subject>> {
    match Subject::start(scenario, variant, path)? {
        Ok(subject) => Ok(Some(subject)),
        Err((status, line)) => {
            report.fail(
                name,
                &format!("subject stopped at start ({status}): {line}"),
            );
            Ok(None)
        }
    }
}

pub fn run(group: &str, report: &mut Report) -> io::Result<()> {
    let path = material_path()?;
    let material = Material::generate(&path)?;
    match group {
        "main" => main_group(&material, &path, report),
        "noptrace" => noptrace_group(&material, &path, report),
        "nomemlock" => refused(
            "mlock-refused-fails-closed",
            "core",
            "LimitMEMLOCK",
            "RLIMIT_MEMLOCK below the pool, no CAP_IPC_LOCK",
            &path,
            report,
        ),
        "ipclock" => refused(
            "cap-ipc-lock-refused",
            "core",
            "CapIpcLock",
            "CAP_IPC_LOCK held",
            &path,
            report,
        ),
        "swap" => swap_group(&path, report),
        other => Err(io::Error::other(format!("unknown group {other}"))),
    }
}

/// The patterns of a path: the keys it holds in the pool while live, every pattern searched, and
/// those without a positive control, each with the reason.
struct PathPatterns {
    held: Vec<&'static str>,
    all: Vec<Pattern>,
    /// Patterns asserted absent after the drop for which the default shape leaves no copy but its
    /// planted input: their absence alone shows nothing. The check fails when this list and the
    /// run disagree, either way.
    no_control: &'static [(&'static str, &'static str)],
}

fn secret_pattern(m: &Material, name: &str, field: Field) -> Pattern {
    pattern(name, m.get(field))
}

fn wrap_patterns(m: &Material) -> io::Result<Vec<Pattern>> {
    let mut all = material::aead_key("kek", &m.get(KEK))?;
    all.push(secret_pattern(m, "dek", DEK));
    Ok(all)
}

/// Why aws-lc-rs's raw GHASH key has no control: its GCM code keeps the key only in the POLYVAL
/// form, the `kek-gcm-h-polyval` pattern, which has one.
const RAW_GHASH: (&str, &str) = (
    "kek-gcm-h",
    "aws-lc keeps the GHASH key only in its POLYVAL form, which has its own control",
);

/// The HKDF intermediates of aws-lc-rs: computed in an HMAC context on the stack of its C code,
/// which it cleanses before returning, so no shape leaves them (Story 1.10 found the PRK in no
/// scan either).
const HKDF_INTERMEDIATES: [(&str, &str); 4] = [
    (
        "parent-hkdf-prk",
        "aws-lc-rs's HKDF keeps the PRK in a context it cleanses",
    ),
    (
        "prk-hmac-ipad",
        "aws-lc-rs's HMAC keeps its states in a context it cleanses",
    ),
    (
        "prk-hmac-opad",
        "aws-lc-rs's HMAC keeps its states in a context it cleanses",
    ),
    (
        "extract-inner",
        "aws-lc-rs's HMAC keeps its inner digest in a context it cleanses",
    ),
];

const NO_CONTROL_COPIES: &[(&str, &str)] = &[];
const NO_CONTROL_DERIVE: &[(&str, &str)] = &HKDF_INTERMEDIATES;
const NO_CONTROL_WRAP: &[(&str, &str)] = &[
    RAW_GHASH,
    (
        "dek",
        "the default shape seals its planted copy of the key in place and makes no other",
    ),
];
const NO_CONTROL_UNWRAP: &[(&str, &str)] = &[RAW_GHASH];
const NO_CONTROL_UNWRAP_WRONG: &[(&str, &str)] = &[
    RAW_GHASH,
    (
        "dek",
        "the key is sealed in place before the refused open, which writes no plaintext",
    ),
];
const NO_CONTROL_KEY_TEXT: &[(&str, &str)] = &[(
    "key",
    "the default shape reads the key only from its planted copy; the copies path has the control",
)];
const NO_CONTROL_THREAD: &[(&str, &str)] = &[
    RAW_GHASH,
    (
        "kek",
        "on the worker thread no copy of the KEK but the planted one is left after the drop; the wrap path, on the main thread, has the control",
    ),
];

fn path_patterns(name: &str, m: &Material, path: &Path) -> io::Result<PathPatterns> {
    let parent = m.get(PARENT);
    let prk = material::hkdf_prk(&parent);
    let (ipad, opad) = material::hmac_states(&prk);
    Ok(match name {
        "copies" => PathPatterns {
            held: vec!["key"],
            all: vec![secret_pattern(m, "key", KEY)],
            no_control: NO_CONTROL_COPIES,
        },
        "derive" => PathPatterns {
            held: vec!["parent", "child"],
            all: vec![
                secret_pattern(m, "parent", PARENT),
                pattern("child", m.derived(path)?),
                pattern("parent-hkdf-prk", &prk),
                pattern("prk-hmac-ipad", ipad),
                pattern("prk-hmac-opad", opad),
                pattern("extract-inner", material::extract_inner(&parent)),
            ],
            no_control: NO_CONTROL_DERIVE,
        },
        "wrap" => PathPatterns {
            held: vec!["kek", "dek"],
            all: wrap_patterns(m)?,
            no_control: NO_CONTROL_WRAP,
        },
        "unwrap" => PathPatterns {
            held: vec!["kek", "dek"],
            all: wrap_patterns(m)?,
            no_control: NO_CONTROL_UNWRAP,
        },
        "unwrap-wrong" => PathPatterns {
            held: vec!["kek"],
            all: wrap_patterns(m)?,
            no_control: NO_CONTROL_UNWRAP_WRONG,
        },
        "key-text" => PathPatterns {
            held: vec!["key"],
            all: [
                vec![secret_pattern(m, "key", KEY)],
                material::key_text(&m.get(KEY)),
            ]
            .concat(),
            no_control: NO_CONTROL_KEY_TEXT,
        },
        "thread" => PathPatterns {
            held: vec![],
            all: wrap_patterns(m)?,
            no_control: NO_CONTROL_THREAD,
        },
        other => return Err(io::Error::other(format!("no patterns for {other}"))),
    })
}

/// The patterns the default shape left a copy of outside its planted input: a hit outside the
/// pool at an address the subject did not report as planted for that pattern.
fn controlled(scans: &[&Findings], planted: &[(String, usize)]) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for scan in scans {
        for (name, hits) in &scan.hits {
            let made_by_the_operation = hits.iter().any(|(address, kind)| {
                *kind != RegionKind::Pool
                    && !planted
                        .iter()
                        .any(|(planted_name, at)| planted_name == name && at == address)
            });
            if made_by_the_operation {
                found.insert(name.clone());
            }
        }
    }
    found
}

/// Review finding 2: every pattern the product shape is asserted not to leave is paired with a
/// copy of that same pattern the default shape left on the same path, its planted input excluded,
/// or is listed, with its reason, among the patterns without a control.
fn control_check(
    name: &str,
    patterns: &PathPatterns,
    controlled: &BTreeSet<String>,
    report: &mut Report,
) {
    let listed: BTreeSet<&str> = patterns
        .no_control
        .iter()
        .map(|(pattern, _)| *pattern)
        .collect();
    let without: BTreeSet<&str> = patterns
        .all
        .iter()
        .map(|p| p.name.as_str())
        .filter(|p| !controlled.contains(*p))
        .collect();
    let unlisted: Vec<&&str> = without.difference(&listed).collect();
    let stale: Vec<&&str> = listed.difference(&without).collect();
    let with: Vec<&String> = controlled.iter().collect();
    report.check(
        &format!("{name}-controls"),
        unlisted.is_empty() && stale.is_empty(),
        &format!(
            "with a copy in the default shape, the planted input excluded: {with:?}; without, as listed: {:?}; without a control and not listed: {unlisted:?}; listed but controlled: {stale:?}",
            listed.intersection(&without).collect::<Vec<_>>()
        ),
    );
    for (pattern, reason) in patterns.no_control {
        report.info(&format!("{name}-no-control-{pattern}"), reason);
    }
}

fn main_group(m: &Material, path: &Path, report: &mut Report) -> io::Result<()> {
    report.check(
        "pattern-recomputation",
        material::sha256_compression_agrees_with_aws_lc(),
        "the scanner's SHA-256 compression, which recomputes the HMAC states, agrees with aws-lc-rs's SHA-256",
    );
    // The harness derives the child key of the derive path with the crate, in a pool of its own.
    vilicus_crypto::harden_process().map_err(io::Error::other)?;
    vilicus_crypto::lock_key_memory().map_err(io::Error::other)?;
    hygiene(m, path, report)?;
    capacity(path, report)?;
    unhardened(path, report)?;
    for name in [
        "copies",
        "derive",
        "wrap",
        "unwrap",
        "unwrap-wrong",
        "key-text",
    ] {
        code_path(name, m, path, report)?;
    }
    thread(m, path, report)?;
    panic_hook(m, path, report)?;
    sigterm(m, path, report)?;
    killed(m, path, report)?;
    fork(path, report)
}

/// AC1, AC6, AC7: the state a `core` subject starts in and the guard pages around its pool.
fn hygiene(m: &Material, path: &Path, report: &mut Report) -> io::Result<()> {
    let Some(mut subject) = started(report, "process-hygiene", "hold", "core", path)? else {
        return Ok(());
    };
    let pid = subject.pid();
    let (start, len) = subject.pool;
    let limits = fs::read_to_string(format!("/proc/{pid}/limits"))?;
    let core_limit = limits
        .lines()
        .find(|line| line.starts_with("Max core file size"))
        .map(|line| {
            line.split_whitespace()
                .skip(4)
                .take(2)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(|value| value.trim().to_string())
            .unwrap_or_default()
    };
    let vmlck_kb: usize = field("VmLck:").trim_end_matches(" kB").parse().unwrap_or(0);
    let cap_ipc_lock = ["CapEff:", "CapPrm:", "CapAmb:"]
        .iter()
        .any(|set| u64::from_str_radix(&field(set), 16).map_or(true, |caps| caps & (1 << 14) != 0));
    let smaps = fs::read_to_string(format!("/proc/{pid}/smaps"))?;
    let mut flags = BTreeSet::new();
    let mut lines = smaps.lines();
    while let Some(line) = lines.next() {
        if scan::parse_range(line).is_some_and(|(s, e)| (s..e).contains(&start)) {
            if let Some(found) = lines.find_map(|line| line.strip_prefix("VmFlags:")) {
                flags = found.split_whitespace().map(str::to_string).collect();
            }
            break;
        }
    }
    // The subject reports its own PR_GET_DUMPABLE; the harness reads the rest from /proc.
    let ok = subject.dumpable == Some(0)
        && core_limit == "0 0"
        && vmlck_kb * 1024 >= len
        && !cap_ipc_lock
        && ["lo", "dd", "wf"].iter().all(|flag| flags.contains(*flag));
    report.check(
        "process-hygiene",
        ok,
        &format!(
            "PR_GET_DUMPABLE {:?}, RLIMIT_CORE {core_limit}, VmLck {vmlck_kb} kB for a pool of {len} bytes, CAP_IPC_LOCK held {cap_ipc_lock}, pool VmFlags {:?} (expected 0, 0 0, VmLck covering the pool, no CAP_IPC_LOCK, lo dd wf)",
            subject.dumpable, flags
        ),
    );
    let maps = fs::read_to_string(format!("/proc/{pid}/maps"))?;
    let guard = |matches: &dyn Fn(usize, usize) -> bool| {
        maps.lines().any(|line| {
            scan::parse_range(line).is_some_and(|(s, e)| matches(s, e))
                && line.split_whitespace().nth(1) == Some("---p")
        })
    };
    report.check(
        "pool-guard-pages",
        guard(&|_, end| end == start) && guard(&|begin, _| begin == start + len),
        "the pages just below and just above the pool are mapped ---p (PROT_NONE)",
    );
    subject.expect("LIVE")?;
    let live = subject.scan(&[secret_pattern(m, "key", KEY)])?;
    report.check(
        "planted-key-in-pool",
        live.count_in("key", RegionKind::Pool) == 1 && live.outside_pool() == 0,
        &format!(
            "the planted key is in the pool and nowhere else ({}); {} bytes read from the subject, every mapping read, non-readable ones included",
            live.summary(),
            live.bytes_read
        ),
    );
    subject.proceed()?;
    subject.expect("DROPPED")?;
    subject.proceed()?;
    subject.finish()?;
    Ok(())
}

/// AC6: the pool holds exactly the planned slot count and refuses one more.
fn capacity(path: &Path, report: &mut Report) -> io::Result<()> {
    let Some(mut subject) = started(report, "key-pool-capacity", "capacity", "core", path)? else {
        return Ok(());
    };
    let line = subject.expect("CAPACITY")?;
    subject.proceed()?;
    subject.expect("DROPPED")?;
    subject.proceed()?;
    subject.finish()?;
    report.check(
        "key-pool-capacity",
        line == format!("CAPACITY {PLANNED_SLOTS} true"),
        &format!("{line} (expected {PLANNED_SLOTS} keys, then Exhausted)"),
    );
    Ok(())
}

/// AC1, AC7: a pool asked for before the process is hardened is refused, and no key is created.
fn unhardened(path: &Path, report: &mut Report) -> io::Result<()> {
    refused(
        "unhardened-process-refused",
        "unhardened",
        "NotHardened",
        "lock_key_memory before harden_process",
        path,
        report,
    )
}

fn depth_checks(name: &str, stacks: &[StackDepth], report: &mut Report) {
    if stacks.is_empty() {
        report.fail(
            &format!("{name}-stack-depth"),
            "no guarded key operation reported its depth",
        );
    }
    for (operation, depth) in stacks {
        report.check(
            &format!("{name}-stack-depth"),
            depth.is_some_and(|depth| depth + STACK_SCRUB_MARGIN <= STACK_SCRUB_LEN),
            &format!(
                "{operation}: deepest stack use {depth:?} bytes, scrub {STACK_SCRUB_LEN} bytes, margin {STACK_SCRUB_MARGIN}"
            ),
        );
    }
}

/// One path, product shape then default shape: the held keys found in the pool while live and
/// nowhere else, nothing after the drop, and each absent pattern paired with the default shape's
/// copy of it (`control_check`).
fn code_path(name: &str, m: &Material, path: &Path, report: &mut Report) -> io::Result<()> {
    let patterns = path_patterns(name, m, path)?;
    let mut asis_controls = BTreeSet::new();
    for variant in ["core", "asis"] {
        let prefix = format!("{name}-{variant}");
        let Some(mut subject) = started(report, &format!("{prefix}-live"), name, variant, path)?
        else {
            continue;
        };
        let (_, stacks) = subject.expect_with_stacks("LIVE")?;
        let live = subject.scan(&patterns.all)?;
        if variant == "core" {
            depth_checks(&prefix, &stacks, report);
            let missing: Vec<&&str> = patterns
                .held
                .iter()
                .filter(|held| live.count_in(held, RegionKind::Pool) == 0)
                .collect();
            report.check(
                &format!("{prefix}-live-control"),
                missing.is_empty(),
                &format!(
                    "held keys found in the pool: {}; missing: {missing:?}",
                    patterns.held.join(",")
                ),
            );
            report.check(
                &format!("{prefix}-live-only-in-pool"),
                live.outside_pool() == 0 && (name != "unwrap-wrong" || live.count("dek") == 0),
                &format!("while live, outside the pool: {}", live.summary()),
            );
        } else {
            report.info(&format!("{prefix}-live-scan"), &live.summary());
        }
        subject.proceed()?;
        subject.expect("DROPPED")?;
        let dropped = subject.scan(&patterns.all)?;
        if variant == "core" {
            report.check(
                &format!("{prefix}-dropped"),
                dropped.hits.is_empty(),
                &format!(
                    "{} patterns searched after the drop, found: {}",
                    patterns.all.len(),
                    dropped.summary()
                ),
            );
        } else {
            report.info(&format!("{prefix}-dropped-scan"), &dropped.summary());
            asis_controls = controlled(&[&live, &dropped], &subject.planted);
        }
        subject.proceed()?;
        let status = subject.finish()?;
        if !status.success() {
            report.fail(&format!("{prefix}-exit"), &format!("{status}"));
        }
    }
    control_check(name, &patterns, &asis_controls, report);
    Ok(())
}

/// A wrap and an unwrap on a spawned thread: nothing anywhere in the product shape; in the
/// default shape, residue in that thread's stack mapping, and each pattern paired with the
/// default shape's copy of it.
fn thread(m: &Material, path: &Path, report: &mut Report) -> io::Result<()> {
    let patterns = path_patterns("thread", m, path)?;
    let mut asis_controls = BTreeSet::new();
    for variant in ["core", "asis"] {
        let prefix = format!("thread-{variant}");
        let Some(mut subject) = started(report, &prefix, "thread", variant, path)? else {
            continue;
        };
        let line = subject.expect("THREADSTACK")?;
        let marker = line
            .strip_prefix("THREADSTACK ")
            .and_then(|a| usize::from_str_radix(a, 16).ok())
            .unwrap_or(0);
        let (_, stacks) = subject.expect_with_stacks("DROPPED")?;
        if variant == "core" {
            depth_checks(&prefix, &stacks, report);
        }
        let dropped = subject.scan(&patterns.all)?;
        let mapping = scan::regions(subject.pid(), subject.pool)?
            .into_iter()
            .find(|r| (r.start..r.end).contains(&marker));
        let in_thread = mapping.as_ref().map_or(0, |r| {
            dropped
                .hits
                .values()
                .flat_map(|hits| hits.keys())
                .filter(|a| (r.start..r.end).contains(*a))
                .count()
        });
        let (name, ok) = if variant == "core" {
            (
                format!("{prefix}-dropped"),
                mapping.is_some() && dropped.hits.is_empty(),
            )
        } else {
            asis_controls = controlled(&[&dropped], &subject.planted);
            (format!("{prefix}-residue-in-thread-stack"), in_thread > 0)
        };
        report.check(
            &name,
            ok,
            &format!(
                "after the thread ended and was joined: {in_thread} hit(s) in its stack mapping; all hits: {}",
                dropped.summary()
            ),
        );
        subject.proceed()?;
        subject.finish()?;
    }
    control_check("thread", &patterns, &asis_controls, report);
    Ok(())
}

/// AC9: a panic inside a handler's boundary keeps the keys; outside one, the hook wipes the pool
/// and aborts with no dump.
fn panic_hook(m: &Material, path: &Path, report: &mut Report) -> io::Result<()> {
    let patterns = [secret_pattern(m, "key", KEY), secret_pattern(m, "dek", DEK)];
    let Some(mut subject) = started(
        report,
        "panic-inside-boundary-keeps-keys",
        "panic-hook",
        "core",
        path,
    )?
    else {
        return Ok(());
    };
    subject.expect("LIVE")?;
    let live = subject.scan(&patterns)?;
    subject.proceed()?;
    // A hook that took the panic inside the boundary for one outside it stops at PANICKED.
    let phase = subject.expect("")?;
    if phase.starts_with("PANICKED") {
        report.fail(
            "panic-inside-boundary-keeps-keys",
            "the panic hook wiped the pool for a panic inside a handler's boundary",
        );
        subject.proceed()?;
        subject.finish()?;
        return Ok(());
    }
    if !phase.starts_with("CAUGHT") {
        return Err(io::Error::other(format!("expected CAUGHT, read {phase}")));
    }
    let caught = subject.scan(&patterns)?;
    let both = |f: &Findings| {
        f.count_in("key", RegionKind::Pool) == 1 && f.count_in("dek", RegionKind::Pool) == 1
    };
    report.check(
        "panic-inside-boundary-keeps-keys",
        both(&live) && both(&caught),
        &format!(
            "before: {}; after a panic caught at the boundary: {}",
            live.summary(),
            caught.summary()
        ),
    );
    subject.proceed()?;
    subject.expect("PANICKED")?;
    let after = subject.scan(&patterns)?;
    report.check(
        "panic-outside-boundary-wipes",
        after.hits.is_empty(),
        &format!(
            "in the hook, after the wipe and before the abort: {}",
            after.summary()
        ),
    );
    subject.proceed()?;
    let status = subject.finish()?;
    report.check(
        "panic-abort-no-core-dump",
        status.signal() == Some(libc::SIGABRT) && !status.core_dumped(),
        &format!("{status}, core dumped: {}", status.core_dumped()),
    );
    Ok(())
}

/// AC9: SIGTERM is taken on its own thread, which wipes the pool before the shutdown.
fn sigterm(m: &Material, path: &Path, report: &mut Report) -> io::Result<()> {
    let patterns = [secret_pattern(m, "key", KEY)];
    let Some(mut subject) = started(report, "sigterm-wipes-pool", "sigterm", "core", path)? else {
        return Ok(());
    };
    subject.expect("LIVE")?;
    let live = subject.scan(&patterns)?;
    subject.signal(libc::SIGTERM)?;
    subject.expect("TERMWIPED")?;
    let after = subject.scan(&patterns)?;
    subject.proceed()?;
    let status = subject.finish()?;
    report.check(
        "sigterm-wipes-pool",
        live.count_in("key", RegionKind::Pool) == 1 && after.hits.is_empty() && status.success(),
        &format!(
            "live: {}; after SIGTERM, before the exit: {}; {status}",
            live.summary(),
            after.summary()
        ),
    );
    Ok(())
}

/// SIGKILL while a key is held: no code runs and no dump is written. Informational only (review
/// finding 4): a zombie's memory reads as 0 bytes whether its pool was wiped or not, so the read
/// shows nothing about the keys, and the absence of a dump is the `no-core-dump-*` checks' to
/// show.
fn killed(m: &Material, path: &Path, report: &mut Report) -> io::Result<()> {
    let Some(mut subject) = started(report, "kill-while-held", "hold", "core", path)? else {
        return Ok(());
    };
    subject.expect("LIVE")?;
    let live = subject.scan(&[secret_pattern(m, "key", KEY)])?;
    subject.signal(libc::SIGKILL)?;
    let status = subject.finish()?;
    report.info(
        "kill-while-held",
        &format!(
            "live: {}; {status}, core dumped: {} (no code runs on SIGKILL: the keys stay until the kernel frees the pages)",
            live.summary(),
            status.core_dumped()
        ),
    );
    Ok(())
}

/// AC9: a forked child reads the pool as zeroes, and a heap copy as it was.
fn fork(path: &Path, report: &mut Report) -> io::Result<()> {
    let Some(mut subject) = started(report, "fork-wipes-pool", "fork", "core", path)? else {
        return Ok(());
    };
    let line = subject.expect("FORK")?;
    subject.finish()?;
    report.check(
        "fork-wipes-pool",
        line == "FORK slot_zero=true control_kept=true",
        &format!("{line} (the heap copy is the control: fork copies unadvised memory)"),
    );
    Ok(())
}

/// A subject whose key memory must be refused at start: it exits with [`EXIT_REFUSED`], its
/// error is `expected`, and no key can be created after the refusal.
fn refused(
    name: &str,
    variant: &str,
    expected: &str,
    setting: &str,
    path: &Path,
    report: &mut Report,
) -> io::Result<()> {
    match Subject::start("hold", variant, path)? {
        Ok(subject) => {
            let status = subject.finish()?;
            report.fail(name, &format!("the pool was locked ({setting}); {status}"));
        }
        Err((status, line)) => report.check(
            name,
            status.code() == Some(EXIT_REFUSED)
                && line.starts_with("REFUSED ")
                && line.contains(expected)
                && line.ends_with("a key: refused (no key pool is locked)"),
            &format!("{setting}: {line}; {status}"),
        ),
    }
    Ok(())
}

/// Without `CAP_SYS_PTRACE`: a hardened subject cannot be read by a same-user process, and no
/// crash of it writes a core dump, while a dumpable control does.
fn noptrace_group(m: &Material, path: &Path, report: &mut Report) -> io::Result<()> {
    let marker = [pattern("marker", m.get(MARKER))];
    if let Some(mut subject) = started(
        report,
        "same-user-reads-dumpable-process",
        "dump",
        "control",
        path,
    )? {
        subject.expect("LIVE")?;
        let result = subject.scan(&marker);
        report.check(
            "same-user-reads-dumpable-process",
            matches!(&result, Ok(f) if f.count("marker") >= 1),
            &format!(
                "control, a process left dumpable: {}",
                match &result {
                    Ok(f) => f.summary(),
                    Err(e) => format!("error {e}"),
                }
            ),
        );
        subject.proceed()?;
        subject.expect("DROPPED")?;
        subject.proceed()?;
        subject.finish()?;
    }
    if let Some(mut subject) = started(
        report,
        "dumpable-off-blocks-same-user-reader",
        "hold",
        "core",
        path,
    )? {
        subject.expect("LIVE")?;
        let result = scan::open_memory(subject.pid());
        let errno = result.as_ref().err().and_then(io::Error::raw_os_error);
        report.check(
            "dumpable-off-blocks-same-user-reader",
            matches!(errno, Some(libc::EACCES | libc::EPERM)),
            &match result {
                Ok(_) => "/proc/<pid>/mem opened".to_string(),
                Err(e) => format!("/proc/<pid>/mem: {e}"),
            },
        );
        subject.proceed()?;
        subject.expect("DROPPED")?;
        subject.proceed()?;
        subject.finish()?;
    }
    core_dumps(path, report)
}

#[derive(Clone, Copy)]
enum Ending {
    Signal(i32),
    Fault,
}

/// AC2, AC7: crashes of a hardened subject write no dump; the dumpable control does. Under a pipe
/// `core_pattern` the kernel hands the control's image to the pipe and the subject's status says
/// so; `ci/key_memory.py` then compares the host's `coredumpctl` entries with the
/// `dumpable-crashes` count printed here.
fn core_dumps(path: &Path, report: &mut Report) -> io::Result<()> {
    let core_pattern = fs::read_to_string("/proc/sys/kernel/core_pattern").unwrap_or_default();
    report.info("core-pattern", &format!("{:?}", core_pattern.trim()));
    let control = crash("control", Ending::Signal(libc::SIGABRT), path, 0)?;
    report.check(
        "core-dump-control",
        control.as_ref().is_some_and(ExitStatus::core_dumped),
        &format!(
            "a dumpable process, SIGABRT: {} (shows a dump is produced and observable here)",
            describe(control.as_ref())
        ),
    );
    report.info(
        "dumpable-crashes",
        &usize::from(control.is_some()).to_string(),
    );
    for (index, (ending, signal, name)) in [
        (Ending::Signal(libc::SIGABRT), libc::SIGABRT, "SIGABRT"),
        (Ending::Fault, libc::SIGSEGV, "SIGSEGV-fault"),
        (Ending::Signal(libc::SIGQUIT), libc::SIGQUIT, "SIGQUIT"),
    ]
    .into_iter()
    .enumerate()
    {
        let result = crash("core", ending, path, index + 1)?;
        report.check(
            &format!("no-core-dump-{name}"),
            result
                .as_ref()
                .is_some_and(|s| s.signal() == Some(signal) && !s.core_dumped()),
            &format!(
                "hardened process, a key held: {}",
                describe(result.as_ref())
            ),
        );
    }
    Ok(())
}

fn describe(status: Option<&ExitStatus>) -> String {
    status.map_or_else(
        || "subject did not start".to_string(),
        |s| format!("{s}, core dumped: {}", s.core_dumped()),
    )
}

/// Starts a `dump` subject of `variant` in a fresh working directory, ends it while it holds its
/// key, and returns how it ended.
fn crash(
    variant: &str,
    ending: Ending,
    path: &Path,
    index: usize,
) -> io::Result<Option<ExitStatus>> {
    let cwd = path
        .parent()
        .unwrap_or(Path::new("/tmp"))
        .join(format!("crash-{index}"));
    fs::create_dir_all(&cwd)?;
    let Ok(mut subject) = Subject::start_in("dump", variant, path, &cwd)? else {
        return Ok(None);
    };
    subject.expect("LIVE")?;
    match ending {
        Ending::Signal(signal) => subject.signal(signal)?,
        Ending::Fault => subject.answer("fault")?,
    }
    Ok(Some(subject.finish()?))
}

/// The host's swap, from `/proc/meminfo`, which a container reads from its host.
fn swap_total_kb() -> u64 {
    fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|meminfo| {
            meminfo.lines().find_map(|line| {
                line.strip_prefix("SwapTotal:")
                    .and_then(|value| value.split_whitespace().next()?.parse().ok())
            })
        })
        .unwrap_or(0)
}

/// Under a cgroup memory limit with swap: the locked pool stays resident while an unlocked page
/// holding the same key goes to swap. Without swap there is nothing to push pages out to, so the
/// group reports `SKIP` with that reason (Story 1.10, gate E16-5).
fn swap_group(path: &Path, report: &mut Report) -> io::Result<()> {
    let swap = swap_total_kb();
    if swap == 0 {
        report.skip(
            "swap",
            "the host has no swap (SwapTotal 0 kB), so no page can be pushed out",
        );
        return Ok(());
    }
    let Some(mut subject) = started(report, "swap", "swap", "core", path)? else {
        return Ok(());
    };
    let line = subject.expect("SWAP")?;
    subject.finish()?;
    let field = |key: &str| {
        line.split_whitespace()
            .find_map(|f| f.strip_prefix(key))
            .unwrap_or_default()
            .to_string()
    };
    report.check(
        "swap-control-unlocked-page-swapped",
        field("plain_swapped=") == "true",
        &format!("{line} (SwapTotal {swap} kB; the unlocked copy's page went to swap: the limit does push pages out)"),
    );
    report.check(
        "swap-locked-pool-resident",
        field("pool_present=") == "true" && field("pool_swapped=") == "false",
        &line,
    );
    Ok(())
}
