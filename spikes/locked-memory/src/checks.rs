//! The harness: writes the material, starts subject processes, reads their memory at each
//! phase and prints one `PASS`, `FAIL` or `INFO` line per check.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::FileExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::time::Instant;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

use crate::material::{DEK, EPH_IKM, KEY, Material, RECORD_NONCE};
use crate::patterns::{self, CodePath, Pattern};
use crate::pool::{self, STACK_SCRUB_LEN};
use crate::scan::{self, Findings, RegionKind};
use crate::subject::{EXIT_MLOCK_REFUSED, hex};

/// Bytes of stack the scrub must reach beyond the deepest measured use of a key operation.
const STACK_MARGIN: usize = 8 * 1024;

/// Counts failures while printing the report.
#[derive(Default)]
pub struct Report {
    failures: usize,
}

impl Report {
    fn pass(&mut self, name: &str, detail: &str) {
        println!("PASS {name}: {detail}");
    }

    fn fail(&mut self, name: &str, detail: &str) {
        println!("FAIL {name}: {detail}");
        self.failures += 1;
    }

    fn check(&mut self, name: &str, ok: bool, detail: &str) {
        if ok {
            self.pass(name, detail);
        } else {
            self.fail(name, detail);
        }
    }

    fn info(&mut self, name: &str, detail: &str) {
        println!("INFO {name}: {detail}");
    }

    /// Number of failed checks.
    pub fn failures(&self) -> usize {
        self.failures
    }
}

struct Subject {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    pool: (usize, usize),
    status: String,
    preopened: Option<File>,
}

type Started = Result<Subject, (ExitStatus, String)>;

impl Subject {
    /// Starts a subject and reads its `POOL` and `STATUS` lines; `Err` carries the exit status
    /// and the last line when it stops before them.
    fn start(scenario: &str, variant: &str, material: &Path) -> io::Result<Started> {
        let cwd = material.parent().unwrap_or(Path::new("/tmp"));
        Subject::start_in(scenario, variant, material, cwd)
    }

    /// As `start`, with the subject's working directory (where a `core` file would land). A
    /// `preopen` subject stops before hardening itself; its memory is opened at that point and
    /// the descriptor kept in `preopened`.
    fn start_in(scenario: &str, variant: &str, material: &Path, cwd: &Path) -> io::Result<Started> {
        let mut child = Command::new(std::env::current_exe()?)
            .args(["subject", scenario, variant])
            .arg(material)
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let mut stdin = child.stdin.take().expect("piped stdin");
        let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        let mut line = String::new();
        stdout.read_line(&mut line)?;
        let mut preopened = None;
        if line.trim() == "PREHARDEN" {
            preopened = Some(scan::open_memory(child.id())?);
            stdin.write_all(b"\n")?;
            stdin.flush()?;
            line.clear();
            stdout.read_line(&mut line)?;
        }
        let Some(pool) = parse_pool(&line) else {
            let status = child.wait()?;
            return Ok(Err((status, line.trim().to_string())));
        };
        let mut status = String::new();
        stdout.read_line(&mut status)?;
        Ok(Ok(Subject {
            child,
            stdin,
            stdout,
            pool,
            status: status.trim().to_string(),
            preopened,
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
            if line.starts_with(tag) {
                return Ok(line.trim().to_string());
            }
        }
    }

    fn proceed(&mut self) -> io::Result<()> {
        self.answer("")
    }

    fn answer(&mut self, text: &str) -> io::Result<()> {
        self.stdin.write_all(format!("{text}\n").as_bytes())?;
        self.stdin.flush()
    }

    fn scan(&self, patterns: &[Pattern]) -> io::Result<Findings> {
        scan::scan(self.pid(), self.pool, patterns)
    }

    fn signal(&self, signal: i32) -> io::Result<()> {
        let pid = i32::try_from(self.pid()).map_err(io::Error::other)?;
        // SAFETY: plain kill(2) on our own child.
        if unsafe { libc::kill(pid, signal) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
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
    let dir = std::env::temp_dir().join(format!("locked-memory-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("material.bin"))
}

fn names(patterns: &[Pattern]) -> BTreeSet<String> {
    patterns.iter().map(|p| p.name.clone()).collect()
}

fn pattern(name: &str, bytes: &[u8]) -> Pattern {
    Pattern {
        name: name.to_string(),
        bytes: bytes.to_vec(),
    }
}

fn key_and_dek(m: &Material) -> Vec<Pattern> {
    vec![pattern("key", m.get(KEY)), pattern("dek", m.get(DEK))]
}

/// Runs the checks of `group`.
pub fn run(group: &str, report: &mut Report) -> io::Result<()> {
    let path = material_path()?;
    let material = Material::generate(&path)?;
    match group {
        "main" => main_group(&material, &path, report),
        "noptrace" => noptrace_group(&material, &path, report),
        "nomemlock" => nomemlock_group(&path, report),
        "swap" => swap_group(&path, report),
        other => Err(io::Error::other(format!("unknown group {other}"))),
    }
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

fn main_group(m: &Material, path: &Path, report: &mut Report) -> io::Result<()> {
    hygiene(m, path, report)?;
    for code_path in CodePath::ALL {
        code_path_checks(code_path, m, path, report)?;
    }
    passphrase_wrong(m, path, report)?;
    hpke_open_thread(m, path, report)?;
    panic_hook(m, path, report)?;
    panic_unwind(m, path, report)?;
    sigterm(m, path, report)?;
    killed(m, path, report)?;
    fork(path, report)?;
    mlock_over_limit(path, report)?;
    scrub_cost(m, report)
}

/// The process state a `core` subject starts with, and the guard pages around its pool.
fn hygiene(m: &Material, path: &Path, report: &mut Report) -> io::Result<()> {
    let name = "process-hygiene";
    let Some(mut subject) = started(report, name, "hold", "core", path)? else {
        return Ok(());
    };
    let status = subject.status.clone();
    let field = |key: &str| {
        status
            .split_whitespace()
            .find_map(|f| f.strip_prefix(key).map(str::to_string))
            .unwrap_or_default()
    };
    let flags: BTreeSet<String> = field("vmflags=").split(',').map(str::to_string).collect();
    let vmlck: usize = field("vmlck_kb=").parse().unwrap_or(0);
    let ok = field("dumpable=") == "0"
        && field("core_limit=") == "0"
        && vmlck * 1024 >= subject.pool.1
        && ["lo", "dd", "wf"].iter().all(|f| flags.contains(*f));
    report.check(
        name,
        ok,
        &format!(
            "{status} (expected dumpable=0, core_limit=0, VmLck covering the {} pool bytes, VmFlags lo dd wf)",
            subject.pool.1
        ),
    );

    let maps = std::fs::read_to_string(format!("/proc/{}/maps", subject.pid()))?;
    let (start, len) = subject.pool;
    let guard = |range_end: usize, range_start: usize| {
        maps.lines().any(|line| {
            pool::parse_range(line).is_some_and(|(s, e)| {
                (e == range_end || s == range_start)
                    && line.split_whitespace().nth(1) == Some("---p")
            })
        })
    };
    report.check(
        "pool-guard-pages",
        guard(start, usize::MAX) && guard(usize::MAX, start + len),
        "the pages just below and just above the pool are mapped ---p (PROT_NONE)",
    );

    subject.expect("LIVE")?;
    let live = subject.scan(&[pattern("key", m.get(KEY))])?;
    report.info(
        "scan-coverage",
        &format!(
            "{} bytes read from the subject; every mapping read, non-readable ones included (a scan fails on any unreadable mapping)",
            live.bytes_read
        ),
    );
    subject.proceed()?;
    subject.expect("DROPPED")?;
    subject.proceed()?;
    subject.finish()?;
    Ok(())
}

/// Reads the `STACK <depth>` line a guarded key operation prints and checks it against the
/// scrub length.
fn stack_depth(subject: &mut Subject, name: &str, report: &mut Report) -> io::Result<()> {
    let line = subject.expect("STACK")?;
    let depth: usize = line
        .strip_prefix("STACK ")
        .and_then(|d| d.parse().ok())
        .unwrap_or(usize::MAX);
    report.check(
        name,
        depth.saturating_add(STACK_MARGIN) <= STACK_SCRUB_LEN,
        &format!(
            "deepest stack use of the key operation {depth} bytes, scrub {STACK_SCRUB_LEN} bytes, margin required {STACK_MARGIN}"
        ),
    );
    Ok(())
}

/// One code path, `core` then `asis`: held keys found while live, what is left after drop,
/// and the default-shape residue as the control of each absence.
fn code_path_checks(
    code_path: CodePath,
    m: &Material,
    path: &Path,
    report: &mut Report,
) -> io::Result<()> {
    let held = names(&code_path.held(m));
    let all = code_path.all(m);
    let mut seen = BTreeSet::new();
    for variant in ["core", "asis"] {
        let prefix = format!("{}-{variant}", code_path.name());
        let Some(mut subject) = started(
            report,
            &format!("{prefix}-live"),
            code_path.name(),
            variant,
            path,
        )?
        else {
            continue;
        };
        if variant == "core" && code_path != CodePath::Copies {
            stack_depth(&mut subject, &format!("{prefix}-stack-depth"), report)?;
        }
        if code_path == CodePath::HpkeSeal {
            let line = subject.expect("ENC")?;
            let expected = hex(&patterns::expected_enc(&m.get32(EPH_IKM)));
            report.check(
                &format!("{prefix}-ephemeral-from-known-seed"),
                line == format!("ENC {expected}"),
                "the encapsulated key matches the one recomputed from the planted seed, so the ephemeral patterns are the ones in use",
            );
        }
        subject.expect("LIVE")?;
        let live = subject.scan(&all)?;
        let missing: Vec<&String> = held
            .iter()
            .filter(|n| live.count_in(n, RegionKind::Pool) == 0)
            .collect();
        report.check(
            &format!("{prefix}-live-control"),
            missing.is_empty(),
            &format!(
                "held keys found in the locked pool: {}; missing: {missing:?}",
                held.iter().cloned().collect::<Vec<_>>().join(",")
            ),
        );
        report.info(&format!("{prefix}-live-scan"), &live.summary());
        seen.extend(live.names());
        live_extras(code_path, variant, &subject, &live, report)?;

        subject.proceed()?;
        if code_path == CodePath::Passphrase {
            subject.expect("WIPED")?;
            if variant == "core" {
                let wiped = subject.scan(&all)?;
                let before = live.count_in("argon2-first-block", RegionKind::Anonymous)
                    + live.count_in("argon2-last-block", RegionKind::Anonymous);
                let after = wiped.count_in("argon2-first-block", RegionKind::Anonymous)
                    + wiped.count_in("argon2-last-block", RegionKind::Anonymous);
                report.check(
                    "passphrase-core-argon2-wipe",
                    before > 0 && after == 0,
                    &format!(
                        "Argon2id blocks in anonymous memory before the wipe (control): {before}; after the wipe, buffer still allocated: {after}"
                    ),
                );
            }
            subject.proceed()?;
        }
        subject.expect("DROPPED")?;
        let dropped = subject.scan(&all)?;
        seen.extend(dropped.names());
        if variant == "core" {
            report.check(
                &format!("{prefix}-dropped"),
                dropped.hits.is_empty(),
                &format!(
                    "{} patterns searched after drop, found: {}",
                    all.len(),
                    dropped.summary()
                ),
            );
        } else {
            let in_stack_or_heap = dropped.hits.values().any(|hits| {
                hits.values()
                    .any(|k| matches!(k, RegionKind::Stack | RegionKind::Heap))
            });
            report.check(
                &format!("{prefix}-residue-control"),
                in_stack_or_heap,
                &format!(
                    "the default shape leaves patterns on the stack or heap, so the scan does see such residue on this path: {}",
                    dropped.summary()
                ),
            );
        }
        subject.proceed()?;
        let status = subject.finish()?;
        if !status.success() {
            report.fail(&format!("{prefix}-exit"), &format!("{status}"));
        }
    }
    let unseen: Vec<String> = all
        .iter()
        .map(|p| p.name.clone())
        .filter(|n| !seen.contains(n))
        .collect();
    report.info(
        &format!("{}-patterns-never-seen", code_path.name()),
        &if unseen.is_empty() {
            "none: every pattern was found in at least one scan, so each absence is paired with a sighting".to_string()
        } else {
            format!(
                "{} (no scan of either variant found them, so their absence after drop has no positive control)",
                unseen.join(",")
            )
        },
    );
    Ok(())
}

/// Live checks specific to one path: the stack copy of `copies`, and where the aws-lc-rs key
/// objects keep the key (unlocked heap by default, nowhere outside the pool in the Core shape).
fn live_extras(
    code_path: CodePath,
    variant: &str,
    subject: &Subject,
    live: &Findings,
    report: &mut Report,
) -> io::Result<()> {
    let key_name = match code_path {
        CodePath::Copies => {
            report.check(
                &format!("copies-{variant}-live-stack-control"),
                live.count_in("key", RegionKind::Stack) > 0,
                &format!(
                    "the planted stack copy is found while live: {}",
                    live.summary()
                ),
            );
            return Ok(());
        }
        CodePath::Passphrase => "kek",
        CodePath::Hkdf => "file-key",
        CodePath::HpkeOpen | CodePath::HpkeSeal => return Ok(()),
    };
    if variant == "core" {
        report.check(
            &format!("{}-core-no-key-object-at-rest", code_path.name()),
            live.count(key_name) == live.count_in(key_name, RegionKind::Pool),
            &format!(
                "AEAD and HKDF objects built per operation and dropped: {key_name} found only in the pool while live ({})",
                live.summary()
            ),
        );
        return Ok(());
    }
    let heap: Vec<usize> = live
        .hits
        .get(key_name)
        .map(|hits| {
            hits.iter()
                .filter(|(_, k)| **k == RegionKind::Heap)
                .map(|(a, _)| *a)
                .collect()
        })
        .unwrap_or_default();
    let mut unlocked = 0;
    for address in &heap {
        let info = pool::mapping_info(&subject.pid().to_string(), *address)?;
        if info.is_some_and(|i| !i.vm_flags.split_whitespace().any(|f| f == "lo")) {
            unlocked += 1;
        }
    }
    report.check(
        &format!("{}-asis-key-object-on-unlocked-heap", code_path.name()),
        !heap.is_empty() && unlocked == heap.len(),
        &format!(
            "a live aws-lc-rs key object keeps {key_name} in {} heap copy(ies), {unlocked} of them in a mapping without the lo (locked) flag: swappable unless swap is off or encrypted",
            heap.len()
        ),
    );
    Ok(())
}

/// A wrong wrapped DEK: the open fails after Argon2id; the error path still wipes the Argon2id
/// memory and scrubs the stack.
fn passphrase_wrong(m: &Material, path: &Path, report: &mut Report) -> io::Result<()> {
    let all = CodePath::Passphrase.all(m);
    let Some(mut subject) = started(
        report,
        "passphrase-wrong-core",
        "passphrase-wrong",
        "core",
        path,
    )?
    else {
        return Ok(());
    };
    stack_depth(&mut subject, "passphrase-wrong-core-stack-depth", report)?;
    let failed = subject.expect("FAILED")?;
    report.info("passphrase-wrong-core-failure", &failed);
    subject.expect("LIVE")?;
    let live = subject.scan(&all)?;
    report.check(
        "passphrase-wrong-core-live-control",
        live.count_in("passphrase", RegionKind::Pool) == 1
            && live.count_in("kek", RegionKind::Pool) == 1,
        &format!("after the failed open: {}", live.summary()),
    );
    subject.proceed()?;
    subject.expect("WIPED")?;
    subject.proceed()?;
    subject.expect("DROPPED")?;
    let dropped = subject.scan(&all)?;
    report.check(
        "passphrase-wrong-core-dropped",
        dropped.hits.is_empty(),
        &format!(
            "{} patterns searched after the failure and drop, found: {}",
            all.len(),
            dropped.summary()
        ),
    );
    subject.proceed()?;
    subject.finish()?;
    Ok(())
}

/// HPKE open on a spawned thread: residue in that thread's stack mapping by default, none in
/// the Core shape.
fn hpke_open_thread(m: &Material, path: &Path, report: &mut Report) -> io::Result<()> {
    let all = CodePath::HpkeOpen.all(m);
    for variant in ["core", "asis"] {
        let prefix = format!("hpke-open-thread-{variant}");
        let Some(mut subject) = started(report, &prefix, "hpke-open-thread", variant, path)? else {
            continue;
        };
        let line = subject.expect("THREADSTACK")?;
        let marker = line
            .strip_prefix("THREADSTACK ")
            .and_then(|a| usize::from_str_radix(a, 16).ok())
            .unwrap_or(0);
        if variant == "core" {
            stack_depth(&mut subject, &format!("{prefix}-stack-depth"), report)?;
        }
        subject.expect("DROPPED")?;
        let dropped = subject.scan(&all)?;
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
        let ok = mapping.is_some()
            && if variant == "core" {
                dropped.hits.is_empty()
            } else {
                in_thread > 0
            };
        report.check(
            &format!("{prefix}-residue"),
            ok,
            &format!(
                "after the thread ended and was joined: {} hit(s) in its stack mapping{}; all hits: {}",
                in_thread,
                if variant == "core" {
                    ""
                } else {
                    " (control: the default shape leaves residue there)"
                },
                dropped.summary()
            ),
        );
        subject.proceed()?;
        subject.finish()?;
    }
    Ok(())
}

fn core_dumped(status: &ExitStatus) -> bool {
    status.core_dumped()
}

/// Both panic cases in one process: inside an AD-9 boundary the panic is caught and the keys
/// stay; outside it the hook wipes the pool and aborts without a dump.
fn panic_hook(m: &Material, path: &Path, report: &mut Report) -> io::Result<()> {
    let patterns = key_and_dek(m);
    let Some(mut subject) = started(report, "panic-hook", "panic-hook", "core", path)? else {
        return Ok(());
    };
    subject.expect("LIVE")?;
    let live = subject.scan(&patterns)?;
    subject.proceed()?;
    subject.expect("CAUGHT")?;
    let caught = subject.scan(&patterns)?;
    let both_in_pool = |f: &Findings| {
        f.count_in("key", RegionKind::Pool) == 1 && f.count_in("dek", RegionKind::Pool) == 1
    };
    report.check(
        "panic-inside-boundary-keeps-keys",
        both_in_pool(&live) && both_in_pool(&caught),
        &format!(
            "before: {}; after a panic caught by the handler boundary: {}",
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
            "in the hook after the wipe, before the abort: {}",
            after.summary()
        ),
    );
    subject.proceed()?;
    let status = subject.finish()?;
    report.check(
        "panic-abort-no-core-dump",
        status.signal() == Some(libc::SIGABRT) && !core_dumped(&status),
        &format!("{status}, core dumped: {}", core_dumped(&status)),
    );
    Ok(())
}

/// Unwinding a panicking thread drops the slots it owns.
fn panic_unwind(m: &Material, path: &Path, report: &mut Report) -> io::Result<()> {
    let patterns = key_and_dek(m);
    let Some(mut subject) = started(report, "panic-unwind-drops", "panic-unwind", "core", path)?
    else {
        return Ok(());
    };
    subject.expect("LIVE")?;
    let live = subject.scan(&patterns)?;
    subject.proceed()?;
    subject.expect("DROPPED")?;
    let after = subject.scan(&patterns)?;
    report.check(
        "panic-unwind-drops",
        live.count_in("key", RegionKind::Pool) == 1
            && live.count_in("dek", RegionKind::Pool) == 1
            && after.hits.is_empty(),
        &format!(
            "while the worker holds the keys: {}; after it panicked and unwound: {}",
            live.summary(),
            after.summary()
        ),
    );
    subject.proceed()?;
    subject.finish()?;
    Ok(())
}

/// SIGTERM is taken on a signalfd thread, which wipes the pool before the process exits.
fn sigterm(m: &Material, path: &Path, report: &mut Report) -> io::Result<()> {
    let patterns = [pattern("key", m.get(KEY))];
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
            "live: {}; after SIGTERM, before exit: {}; {status}",
            live.summary(),
            after.summary()
        ),
    );
    Ok(())
}

/// SIGKILL while keys are held: no code runs, no dump, and the memory is gone with the process.
fn killed(m: &Material, path: &Path, report: &mut Report) -> io::Result<()> {
    let Some(mut subject) = started(report, "kill-while-held", "hold", "core", path)? else {
        return Ok(());
    };
    subject.expect("LIVE")?;
    let live = subject.scan(&[pattern("key", m.get(KEY))])?;
    let memory = scan::open_memory(subject.pid())?;
    subject.signal(libc::SIGKILL)?;
    let pid = i32::try_from(subject.pid()).map_err(io::Error::other)?;
    // SAFETY: an all-zero siginfo_t is a valid out-buffer for waitid.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: waitid on our own child with WNOWAIT leaves it a zombie, not reaped, so the pid
    // still names it while its memory is read; `info` is a valid out-pointer.
    let waited = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOWAIT,
        )
    };
    if waited != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buffer = [0u8; 32];
    let read = memory.read_at(&mut buffer, subject.pool.0 as u64);
    let status = subject.finish()?;
    report.check(
        "kill-while-held",
        live.count_in("key", RegionKind::Pool) == 1
            && matches!(read, Ok(0))
            && status.signal() == Some(libc::SIGKILL)
            && !core_dumped(&status),
        &format!(
            "live: {}; read of the pool after SIGKILL, before reaping: {}; {status}, core dumped: {}",
            live.summary(),
            match read {
                Ok(n) => format!("{n} bytes"),
                Err(e) => format!("error {e}"),
            },
            core_dumped(&status)
        ),
    );
    Ok(())
}

fn fork(path: &Path, report: &mut Report) -> io::Result<()> {
    let Some(mut subject) = started(report, "fork-wipes-pool", "fork", "core", path)? else {
        return Ok(());
    };
    let line = subject.expect("FORK")?;
    subject.finish()?;
    report.check(
        "fork-wipes-pool",
        line == "FORK slot_zero=true heap_copy_kept=true",
        &format!("{line} (the heap copy is the control: fork copies unadvised memory)"),
    );
    Ok(())
}

fn mlock_over_limit(path: &Path, report: &mut Report) -> io::Result<()> {
    refused(
        "mlock-over-limit-fails-closed",
        "mlock-over-limit",
        "RLIMIT_MEMLOCK lowered to 4096 bytes below a 4-page pool",
        path,
        report,
    )
}

fn refused(
    name: &str,
    scenario: &str,
    setting: &str,
    path: &Path,
    report: &mut Report,
) -> io::Result<()> {
    match Subject::start(scenario, "core", path)? {
        Ok(subject) => {
            let status = subject.finish()?;
            report.fail(name, &format!("the pool was locked ({setting}); {status}"));
        }
        Err((status, line)) => report.check(
            name,
            status.code() == Some(EXIT_MLOCK_REFUSED)
                && line.starts_with("ERROR mlock refused")
                && line.ends_with("keys_read=0"),
            &format!("{setting}: {line}; {status}"),
        ),
    }
    Ok(())
}

/// Cost of the stack scrub next to one record operation (AES-256-GCM seal and open of a
/// 256-byte record with a key object built from 32 bytes), measured in the harness process.
fn scrub_cost(m: &Material, report: &mut Report) -> io::Result<()> {
    const ROUNDS: u32 = 10_000;
    let started = Instant::now();
    for _ in 0..ROUNDS {
        pool::scrub_stack();
    }
    let scrub = started.elapsed() / ROUNDS;
    let started = Instant::now();
    for _ in 0..ROUNDS {
        let key = LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM, m.get(DEK)).map_err(crate::material::other)?,
        );
        let mut record = vec![0x5a_u8; 256];
        let tag = key
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(RECORD_NONCE),
                Aad::empty(),
                &mut record,
            )
            .map_err(crate::material::other)?;
        record.extend_from_slice(tag.as_ref());
        key.open_in_place(
            Nonce::assume_unique_for_key(RECORD_NONCE),
            Aad::empty(),
            &mut record,
        )
        .map_err(crate::material::other)?;
    }
    let record = started.elapsed() / ROUNDS;
    report.info(
        "scrub-cost",
        &format!(
            "stack scrub of {STACK_SCRUB_LEN} bytes plus vzeroall: {scrub:?} per call; record seal and open with a per-operation key object: {record:?} per record ({ROUNDS} rounds each, release build)"
        ),
    );
    Ok(())
}

/// Without `CAP_SYS_PTRACE`: a non-dumpable subject cannot be opened by a same-user process,
/// except through a descriptor opened before it hardened itself; no signal produces a dump.
fn noptrace_group(m: &Material, path: &Path, report: &mut Report) -> io::Result<()> {
    let key = [pattern("key", m.get(KEY))];
    if let Some(mut subject) = started(report, "ptrace-control", "hold", "control", path)? {
        subject.expect("LIVE")?;
        let result = subject.scan(&key);
        report.check(
            "same-user-reads-dumpable-process",
            matches!(&result, Ok(f) if f.count_in("key", RegionKind::Pool) == 1),
            &format!(
                "control, process left dumpable: {}",
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
    if let Some(mut subject) = started(report, "dumpable-off", "hold", "core", path)? {
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
    preopened(m, path, report)?;
    core_dumps(m, path, report)
}

/// A descriptor on `/proc/<pid>/mem` opened before `PR_SET_DUMPABLE` 0 keeps reading the
/// memory afterwards: the limit that makes a dedicated user, running nothing else, part of
/// the design.
fn preopened(m: &Material, path: &Path, report: &mut Report) -> io::Result<()> {
    let Some(mut subject) = started(report, "preopened-descriptor", "hold", "preopen", path)?
    else {
        return Ok(());
    };
    subject.expect("LIVE")?;
    let fresh = scan::open_memory(subject.pid());
    let mut slot = [0u8; 32];
    let read = subject
        .preopened
        .as_ref()
        .map(|fd| fd.read_exact_at(&mut slot, subject.pool.0 as u64));
    let read_ok = matches!(read, Some(Ok(())));
    report.check(
        "preopened-descriptor-survives-hardening",
        read_ok && slot == m.get(KEY) && fresh.is_err(),
        &format!(
            "descriptor opened before hardening reads the key from the pool: {}; a new open after hardening: {} (documents the limit: hardening does not revoke earlier access)",
            read_ok && slot == m.get(KEY),
            match fresh {
                Ok(_) => "succeeded".to_string(),
                Err(e) => format!("refused, {e}"),
            }
        ),
    );
    subject.proceed()?;
    subject.expect("DROPPED")?;
    subject.proceed()?;
    subject.finish()?;
    Ok(())
}

fn core_dumps(m: &Material, path: &Path, report: &mut Report) -> io::Result<()> {
    let core_pattern = std::fs::read_to_string("/proc/sys/kernel/core_pattern")
        .unwrap_or_default()
        .trim()
        .to_string();
    report.info("core-pattern", &format!("{core_pattern:?}"));

    let control = crash("control", Ending::Signal(libc::SIGABRT), path, 0)?;
    report.check(
        "core-dump-control",
        control.as_ref().is_some_and(|c| core_dumped(&c.status)),
        &format!(
            "dumpable process, RLIMIT_CORE at its hard limit, SIGABRT: {} (proves a dump is produced and observable here)",
            describe(&control)
        ),
    );
    match control.as_ref().and_then(|c| c.core_files.first()) {
        Some(core_file) => {
            let bytes = std::fs::read(core_file)?;
            let mut findings = Findings::default();
            scan::Index::new(&key_and_dek(m)).search(&bytes, 0, RegionKind::File, &mut findings);
            report.check(
                "core-file-excludes-locked-pool",
                findings.count("dek") > 0 && findings.count("key") == 0,
                &format!(
                    "{} bytes of core file; DEK copy on the unlocked heap (control) found {} time(s), key in the MADV_DONTDUMP pool found {} time(s)",
                    bytes.len(),
                    findings.count("dek"),
                    findings.count("key")
                ),
            );
        }
        None => report.info(
            "core-file-excludes-locked-pool",
            &format!(
                "not run here: no core file reached the working directory (core_pattern {core_pattern:?})"
            ),
        ),
    }
    let limit_only = crash("limit-only", Ending::Signal(libc::SIGABRT), path, 1)?;
    report.info(
        "core-dump-with-rlimit-core-0-only",
        &format!(
            "dumpable process, RLIMIT_CORE 0, SIGABRT: {}",
            describe(&limit_only)
        ),
    );
    for (index, (ending, signal, name)) in [
        (Ending::Signal(libc::SIGABRT), libc::SIGABRT, "SIGABRT"),
        (Ending::Fault, libc::SIGSEGV, "SIGSEGV-fault"),
        (Ending::Signal(libc::SIGQUIT), libc::SIGQUIT, "SIGQUIT"),
    ]
    .into_iter()
    .enumerate()
    {
        let result = crash("core", ending, path, index + 2)?;
        report.check(
            &format!("no-core-dump-{name}"),
            result.as_ref().is_some_and(|c| {
                c.status.signal() == Some(signal)
                    && !core_dumped(&c.status)
                    && c.core_files.is_empty()
            }),
            &format!("hardened process, keys held: {}", describe(&result)),
        );
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Ending {
    /// The harness sends this signal.
    Signal(i32),
    /// The subject writes to a `PROT_NONE` page: a real memory fault.
    Fault,
}

struct Crash {
    status: ExitStatus,
    core_files: Vec<PathBuf>,
}

fn describe(crash: &Option<Crash>) -> String {
    match crash {
        Some(c) => format!(
            "{}, core dumped: {}, core files in the working directory: {}",
            c.status,
            core_dumped(&c.status),
            c.core_files.len()
        ),
        None => "subject did not start".to_string(),
    }
}

/// Starts a `dump` subject in `variant` in a fresh working directory, ends it while the keys
/// are held, and returns how it ended and the core files it left there.
fn crash(variant: &str, ending: Ending, path: &Path, index: usize) -> io::Result<Option<Crash>> {
    let cwd = path
        .parent()
        .unwrap_or(Path::new("/tmp"))
        .join(format!("crash-{index}"));
    std::fs::create_dir_all(&cwd)?;
    let Ok(mut subject) = Subject::start_in("dump", variant, path, &cwd)? else {
        return Ok(None);
    };
    subject.expect("LIVE")?;
    match ending {
        Ending::Signal(signal) => subject.signal(signal)?,
        Ending::Fault => subject.answer("fault")?,
    }
    let status = subject.finish()?;
    let mut core_files = Vec::new();
    for entry in std::fs::read_dir(&cwd)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with("core") {
            core_files.push(entry.path());
        }
    }
    Ok(Some(Crash { status, core_files }))
}

/// With `RLIMIT_MEMLOCK` 0 from the container: the pool is refused and nothing is loaded.
fn nomemlock_group(path: &Path, report: &mut Report) -> io::Result<()> {
    let limit = pool::get_limit(libc::RLIMIT_MEMLOCK)?;
    refused(
        "mlock-refused-fails-closed",
        "hold",
        &format!(
            "RLIMIT_MEMLOCK {}:{} from the container, no CAP_IPC_LOCK",
            limit.0, limit.1
        ),
        path,
        report,
    )
}

/// Under a cgroup memory limit with swap: the locked pool stays resident, an unlocked page
/// holding the same key goes to swap.
fn swap_group(path: &Path, report: &mut Report) -> io::Result<()> {
    let Some(mut subject) = started(report, "swap", "swap", "core", path)? else {
        return Ok(());
    };
    let line = subject.expect("SWAP")?;
    subject.finish()?;
    let field = |key: &str| -> String {
        line.split_whitespace()
            .find_map(|f| f.strip_prefix(key))
            .unwrap_or_default()
            .to_string()
    };
    report.check(
        "swap-control-unlocked-page-swapped",
        field("plain_page_swapped=") == "true",
        &format!(
            "{line} (the page of the unlocked copy went to swap: the limit does push pages out)"
        ),
    );
    report.check(
        "swap-locked-pool-resident",
        field("pool_page_present=") == "true"
            && field("pool_page_swapped=") == "false"
            && field("pool_swap_kb=") == "0"
            && field("pool_locked_kb=") != "0",
        &line,
    );
    Ok(())
}
