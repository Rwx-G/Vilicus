//! The simulated household of D116 and the run that measures it.
//!
//! Load, all at once for the whole measured window:
//! - a member probe: one member action through the full pipeline at a fixed interval, the
//!   action D116 measures, timed from its scheduled instant so runtime delay is counted;
//! - a token probe: an assistant action with a capability token, sent as a request over a Unix
//!   socket to an in-process listener (the peer-socket ingress) and timed from its scheduled
//!   instant to the response read by the client;
//! - two active adults: member actions on their personal and the household files;
//! - each adult's assistant: token-principal tool calls (capability token, budget, expiry);
//! - the testbed (D102), simulated because Story 2.6 comes later: a reference-module plugin
//!   writing with a token, and a device adapter double reporting state and feeding the rules;
//! - the dedicated rule thread: a synthetic rule loop that turns adapter events into rule
//!   actions through the pipeline;
//! - two unlocks in a loop, one per adult, concurrently, on the bounded blocking pool;
//! - a backup in a loop: writer pause with a TRUNCATE checkpoint and a copy of every file but
//!   the home file, the home file through the online backup API in bounded steps, the audit
//!   writer flushed on its admin socket and `audit.db` copied, SHA-256 of every copy and the
//!   keys sealed to the backup public key (spine AD-31);
//! - the home partition's journal retention: expired entries deleted in batches (AD-26);
//! - a long reader: a 300 ms read transaction on the household tasks file, so a backup pause
//!   sometimes meets a reader that holds the WAL.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use aws_lc_rs::agreement::{PrivateKey, X25519};
use aws_lc_rs::digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Handle;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::MissedTickBehavior;

use crate::audit::{self, AuditClient, AuditKeys};
use crate::crypto::{self, Argon2Cost, MemberWrappers};
use crate::pipeline::{
    Call, Core, FileId, Outcome, PartitionKind, Principal, TOKEN_BUDGET, TOKEN_TTL, Tool,
};
use crate::stats::{Recorder, Summary};
use crate::storage::{self, FileKey};
use crate::writer::Writer;

/// Label of the member action D116 measures.
pub const PROBE_LABEL: &str = "probe: member tasks.update household";
/// Label of the token-principal action sent through the socket ingress.
pub const SOCKET_PROBE_LABEL: &str = "probe: assistant tasks.update household via socket";
/// Label pooling every pipeline action of the load, both probes included.
pub const ALL_ACTIONS_LABEL: &str = "all pipeline actions (pooled)";
/// From the rule thread's wake on an event to the dispatch of the rule action.
pub const RULE_WAKE_TO_DISPATCH_LABEL: &str = "rule thread: wake to dispatch";
const RULE_EVENT_TO_DISPATCH_LABEL: &str = "rule thread: event to dispatch";
const RULE_WAKE_LABEL: &str = "rule thread: event to wake";
const RULE_EVENT_TO_DONE_LABEL: &str = "rule: event to action done";
const UNLOCK_LABEL: &str = "background: unlock";
const BACKUP_CYCLE_LABEL: &str = "background: backup cycle";
const BACKUP_PAUSE_LABEL: &str = "background: writer pause per file";
const HOME_ONLINE_BACKUP_LABEL: &str = "background: home online backup";
const AUDIT_FLUSH_LABEL: &str = "background: audit flush and copy";
const RETENTION_LABEL: &str = "background: home journal retention batch";
const LONG_READER_LABEL: &str = "background: long reader";

const DEVICES: u16 = 64;
const RULES: u16 = 200;
const ADAPTER: u8 = 1;
/// Home journal retention period (AD-26, `[ASSUMPTION]` 24 hours).
const HOME_RETENTION_SECS: i64 = 86_400;
const RETENTION_BATCH: u32 = 500;

/// Where the audit writer runs.
#[derive(Clone, Debug)]
pub enum AuditMode {
    /// A separate process: this executable started with `audit-writer`.
    Process(PathBuf),
    /// A thread of this process (tests).
    Thread,
}

/// One run's parameters.
#[derive(Clone, Debug)]
pub struct Config {
    pub name: String,
    pub workdir: PathBuf,
    pub duration: Duration,
    pub warmup: Duration,
    /// Permits of the bounded blocking pool.
    pub pool_permits: usize,
    pub argon2: Argon2Cost,
    pub rows_personal: u32,
    pub rows_household: u32,
    pub rows_reference: u32,
    pub rows_home: u32,
    /// Home journal entries older than the retention period at the start.
    pub expired_home_journal: u32,
    pub body_bytes: usize,
    pub probe_interval: Duration,
    /// Mean gap between two actions of one adult (exponential).
    pub adult_gap: Duration,
    pub assistant_gap: Duration,
    pub plugin_gap: Duration,
    pub adapter_gap: Duration,
    /// Unlock loops running at once, alternating between the two adults; D116 needs two.
    pub unlockers: usize,
    /// Pause between two unlocks of one unlock loop.
    pub unlock_gap: Duration,
    /// Pause between two backup cycles.
    pub backup_gap: Duration,
    /// Copy rate limit in bytes per second; `None` copies at full speed.
    pub backup_throttle: Option<u64>,
    pub home_backup_pages: i32,
    pub retention_gap: Duration,
    pub long_reader_gap: Duration,
    pub long_reader_hold: Duration,
    /// A writer pause of this length on the household tasks file a third into the window
    /// (tests: checks that the probes are timed from their scheduled start).
    pub injected_pause: Option<Duration>,
    pub audit: AuditMode,
}

impl Config {
    /// The D116 household on the reference host.
    pub fn household(name: &str, workdir: PathBuf, audit: AuditMode) -> Self {
        Self {
            name: name.to_owned(),
            workdir,
            duration: Duration::from_secs(600),
            warmup: Duration::from_secs(15),
            pool_permits: 3,
            argon2: Argon2Cost {
                m_kib: 256 * 1024,
                t: 3,
                p: 4,
            },
            rows_personal: 20_000,
            rows_household: 50_000,
            rows_reference: 10_000,
            rows_home: 20_000,
            expired_home_journal: 20_000,
            body_bytes: 400,
            probe_interval: Duration::from_millis(100),
            adult_gap: Duration::from_secs(2),
            assistant_gap: Duration::from_secs(3),
            plugin_gap: Duration::from_secs(1),
            adapter_gap: Duration::from_millis(250),
            unlockers: 2,
            unlock_gap: Duration::from_millis(500),
            backup_gap: Duration::from_secs(2),
            backup_throttle: None,
            home_backup_pages: 64,
            retention_gap: Duration::from_secs(10),
            long_reader_gap: Duration::from_secs(5),
            long_reader_hold: Duration::from_millis(300),
            injected_pause: None,
            audit,
        }
    }

    /// A few seconds of the same load at a small scale, for tests.
    pub fn smoke(workdir: PathBuf) -> Self {
        Self {
            duration: Duration::from_secs(3),
            warmup: Duration::from_millis(500),
            argon2: Argon2Cost {
                m_kib: 8 * 1024,
                t: 1,
                p: 1,
            },
            rows_personal: 200,
            rows_household: 300,
            rows_reference: 100,
            rows_home: 100,
            expired_home_journal: 2_000,
            probe_interval: Duration::from_millis(20),
            adult_gap: Duration::from_millis(100),
            assistant_gap: Duration::from_millis(100),
            plugin_gap: Duration::from_millis(100),
            adapter_gap: Duration::from_millis(30),
            unlock_gap: Duration::from_millis(50),
            backup_gap: Duration::from_millis(200),
            home_backup_pages: 4,
            retention_gap: Duration::from_millis(300),
            long_reader_gap: Duration::from_millis(400),
            long_reader_hold: Duration::from_millis(100),
            ..Self::household("smoke", workdir, AuditMode::Thread)
        }
    }

    /// Probe ticks scheduled inside the window.
    pub fn expected_probes(&self) -> u64 {
        (self.duration.as_nanos() / self.probe_interval.as_nanos()) as u64
    }

    pub fn describe(&self) -> String {
        format!(
            "{}: {} s measured after {} s warm-up; blocking pool {} permits; Argon2id {}; \
             rows personal {}, household {}, reference {}, home {} (+{} expired journal \
             entries); probes every {} ms; mean gaps adult {} ms, assistant {} ms, plugin {} ms, \
             adapter {} ms; {} unlock loops, unlock gap {} ms; backup gap {} ms; backup throttle \
             {}; retention batch every {} ms; long reader {} ms every {} ms",
            self.name,
            self.duration.as_secs(),
            self.warmup.as_secs(),
            self.pool_permits,
            self.argon2,
            self.rows_personal,
            self.rows_household,
            self.rows_reference,
            self.rows_home,
            self.expired_home_journal,
            self.probe_interval.as_millis(),
            self.adult_gap.as_millis(),
            self.assistant_gap.as_millis(),
            self.plugin_gap.as_millis(),
            self.adapter_gap.as_millis(),
            self.unlockers,
            self.unlock_gap.as_millis(),
            self.backup_gap.as_millis(),
            self.backup_throttle
                .map_or_else(|| "none".to_owned(), |rate| format!("{rate} B/s")),
            self.retention_gap.as_millis(),
            self.long_reader_hold.as_millis(),
            self.long_reader_gap.as_millis(),
        )
    }
}

/// What a run measured.
#[derive(Debug)]
pub struct RunReport {
    pub summaries: Vec<Summary>,
    pub errors: BTreeMap<String, Vec<String>>,
    /// The slowest pipeline actions with their stage times and backup activity.
    pub slowest: Vec<(Duration, String)>,
    pub unlocks: u64,
    pub max_concurrent_unlocks: usize,
    pub max_permits_held: usize,
    pub backups: u64,
    pub copies_during_unlock: u64,
    pub home_interleaved_jobs: u64,
    pub pause_retries: u64,
    pub retention_deleted: u64,
    pub long_reads: u64,
    pub rule_dispatches: u64,
    pub watchdog_ticks: u64,
    pub watchdog_max_gap: Duration,
    pub audit_appends: u64,
    pub audit_verified: Result<u64, String>,
    pub audit_copies: u64,
    pub file_bytes: u64,
}

impl RunReport {
    pub fn summary(&self, label: &str) -> Option<&Summary> {
        self.summaries.iter().find(|summary| summary.label == label)
    }
}

/// SplitMix64: enough for load jitter, never for keys.
struct Rng(u64);

impl Rng {
    fn seeded() -> Self {
        Self(u64::from_be_bytes(crypto::random()))
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1_u64 << 53) as f64
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    /// An exponential gap of mean `mean` (a Poisson arrival process).
    fn gap(&mut self, mean: Duration) -> Duration {
        mean.mul_f64(-(1.0 - self.unit()).ln())
    }

    fn record(&mut self, rows: u32) -> i64 {
        self.below(u64::from(rows)) as i64 + 1
    }
}

struct Shared {
    core: Arc<Core>,
    recorder: Arc<Recorder>,
    stop: AtomicBool,
    in_flight: AtomicUsize,
    pool: Arc<Semaphore>,
    permits_held: AtomicUsize,
    max_permits_held: AtomicUsize,
    unlocks_in_flight: AtomicUsize,
    max_concurrent_unlocks: AtomicUsize,
    unlocks: AtomicU64,
    backups: AtomicU64,
    copies_during_unlock: AtomicU64,
    home_interleaved_jobs: AtomicU64,
    retention_deleted: AtomicU64,
    long_reads: AtomicU64,
    audit_copies: AtomicU64,
    rule_dispatches: AtomicU64,
    watchdog_ticks: AtomicU64,
    watchdog_max_gap_us: AtomicU64,
    socket_probe_done: AtomicBool,
}

impl Shared {
    fn stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// Takes a pool permit and counts it; [`Shared::give_back`] uncounts it before release,
    /// so the count never exceeds the permits really held.
    async fn take_permit(&self) -> Option<OwnedSemaphorePermit> {
        let permit = Arc::clone(&self.pool).acquire_owned().await.ok()?;
        let held = self.permits_held.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_permits_held.fetch_max(held, Ordering::SeqCst);
        Some(permit)
    }

    fn give_back(&self, permit: OwnedSemaphorePermit) {
        self.permits_held.fetch_sub(1, Ordering::SeqCst);
        drop(permit);
    }
}

/// Sleeps `duration` in slices so a loop notices the stop flag within 100 ms.
async fn pause_for(shared: &Shared, duration: Duration) {
    let until = Instant::now() + duration;
    while !shared.stopping() {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return;
        }
        tokio::time::sleep(left.min(Duration::from_millis(100))).await;
    }
}

fn partition_label(file: FileId) -> &'static str {
    match file.partition() {
        PartitionKind::Personal(_) => "personal",
        PartitionKind::Household => "household",
        PartitionKind::Home => "home",
    }
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

/// Records one completed action: its total under `label` and the pooled label, its stage
/// times under `label`, the pooled total split by backup activity on the file, and a detail
/// line kept if it is among the slowest.
fn record_outcome(recorder: &Recorder, label: &str, started: Instant, outcome: &Outcome) {
    let elapsed = started.elapsed();
    let timings = outcome.timings;
    recorder.record(label, started, elapsed);
    recorder.record(&format!("{label} | stage policy"), started, timings.policy);
    recorder.record(&format!("{label} | stage write"), started, timings.write);
    recorder.record(&format!("{label} | stage audit"), started, timings.audit);
    recorder.record(
        &format!("{ALL_ACTIONS_LABEL} | {}", outcome.backup.label()),
        started,
        elapsed,
    );
    let detail = format!(
        "{label}: total {:.2} ms (before the pipeline {:.2}, policy {:.2}, write {:.2}, audit \
         {:.2}), {}",
        ms(elapsed),
        ms(elapsed.saturating_sub(timings.policy + timings.write + timings.audit)),
        ms(timings.policy),
        ms(timings.write),
        ms(timings.audit),
        outcome.backup.label()
    );
    recorder.record_detailed(ALL_ACTIONS_LABEL, started, elapsed, detail);
}

/// Runs `call` on the runtime and records it from `started` under `label`.
fn spawn_call(
    handle: &Handle,
    shared: &Arc<Shared>,
    label: String,
    call: Call,
    started: Instant,
    event_at: Option<Instant>,
) {
    shared.in_flight.fetch_add(1, Ordering::SeqCst);
    let shared = Arc::clone(shared);
    handle.spawn(async move {
        match shared.core.execute(call).await {
            Ok(outcome) => {
                record_outcome(&shared.recorder, &label, started, &outcome);
                if let Some(event_at) = event_at {
                    shared
                        .recorder
                        .record(RULE_EVENT_TO_DONE_LABEL, event_at, event_at.elapsed());
                }
            }
            Err(refusal) => shared.recorder.error(&label, format!("{refusal:?}")),
        }
        shared.in_flight.fetch_sub(1, Ordering::SeqCst);
    });
}

struct Household {
    cost: Argon2Cost,
    members: [(Vec<u8>, MemberWrappers); 2],
    file_keys: HashMap<FileId, FileKey>,
    instance_key: [u8; 32],
    backup_public: Vec<u8>,
}

fn file_info(file: FileId) -> String {
    let (module, partition) = file.name().split_once('.').unwrap_or((file.name(), ""));
    format!("vilicus/v1/db/{module}/{partition}/1")
}

fn file_path(workdir: &Path, file: FileId) -> PathBuf {
    workdir.join(format!("{}.db", file.name()))
}

struct Paths {
    audit_db: PathBuf,
    audit_append: PathBuf,
    audit_admin: PathBuf,
    ingress: PathBuf,
}

impl Paths {
    fn new(workdir: &Path) -> Self {
        Self {
            audit_db: workdir.join("audit.db"),
            audit_append: workdir.join("audit-append.sock"),
            audit_admin: workdir.join("audit-admin.sock"),
            ingress: workdir.join("core-peer.sock"),
        }
    }
}

fn set_up(cfg: &Config) -> Result<Household, String> {
    std::fs::create_dir_all(cfg.workdir.join("backup")).map_err(|e| e.to_string())?;
    let household_key = crypto::random::<32>();
    let home_root = crypto::random::<32>();
    let mut members = Vec::new();
    let mut deks = Vec::new();
    for member in 1..=2_u8 {
        let passphrase = format!("passphrase of adult {member}").into_bytes();
        let (wrappers, dek) = crypto::enroll(cfg.argon2, &passphrase, &household_key)?;
        members.push((passphrase, wrappers));
        deks.push(dek);
    }
    let mut file_keys = HashMap::new();
    for file in FileId::ALL {
        let root = match file.partition() {
            PartitionKind::Personal(member) => deks[usize::from(member) - 1],
            PartitionKind::Household => household_key,
            PartitionKind::Home => home_root,
        };
        let key = crypto::hkdf(&root, &file_info(file));
        let (rows, expired) = match file {
            FileId::TasksAdult1 | FileId::TasksAdult2 => (cfg.rows_personal, 0),
            FileId::TasksHousehold | FileId::CalendarHousehold => (cfg.rows_household, 0),
            FileId::ReferenceHousehold => (cfg.rows_reference, 0),
            FileId::Home => (cfg.rows_home, cfg.expired_home_journal),
        };
        storage::create_module_file(
            &file_path(&cfg.workdir, file),
            &key,
            rows,
            cfg.body_bytes,
            expired,
        )
        .map_err(|e| format!("creating {}: {e}", file.name()))?;
        file_keys.insert(file, key);
    }
    let backup_private = PrivateKey::generate(&X25519).map_err(|_| "backup key pair")?;
    let backup_public = backup_private
        .compute_public_key()
        .map_err(|_| "backup public key")?
        .as_ref()
        .to_vec();
    let members: [(Vec<u8>, MemberWrappers); 2] =
        members.try_into().map_err(|_| "two members".to_owned())?;
    Ok(Household {
        cost: cfg.argon2,
        members,
        file_keys,
        instance_key: crypto::random(),
        backup_public,
    })
}

enum AuditWriter {
    Process(Child),
    Thread(JoinHandle<Result<u64, String>>),
}

fn start_audit_writer(
    cfg: &Config,
    paths: &Paths,
    keys: &AuditKeys,
) -> Result<AuditWriter, String> {
    match &cfg.audit {
        AuditMode::Process(exe) => {
            let mut child = Command::new(exe)
                .arg("audit-writer")
                .arg(&paths.audit_append)
                .arg(&paths.audit_admin)
                .arg(&paths.audit_db)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .map_err(|e| format!("starting the audit writer: {e}"))?;
            let mut stdin = child.stdin.take().ok_or("audit writer stdin")?;
            stdin
                .write_all(&keys.to_bytes())
                .map_err(|e| e.to_string())?;
            drop(stdin);
            let stdout = child.stdout.take().ok_or("audit writer stdout")?;
            let mut line = String::new();
            BufReader::new(stdout)
                .read_line(&mut line)
                .map_err(|e| e.to_string())?;
            if line.trim() != "ready" {
                return Err(format!("audit writer said {line:?}"));
            }
            Ok(AuditWriter::Process(child))
        }
        AuditMode::Thread => {
            let append = UnixListener::bind(&paths.audit_append).map_err(|e| e.to_string())?;
            let admin = UnixListener::bind(&paths.audit_admin).map_err(|e| e.to_string())?;
            let db = paths.audit_db.clone();
            let keys = keys.clone();
            Ok(AuditWriter::Thread(std::thread::spawn(move || {
                audit::serve(&append, Some(&admin), &db, &keys, Duration::ZERO)
            })))
        }
    }
}

/// The `audit-writer` entry point of the executable: keys on stdin, "ready" on stdout once
/// both sockets listen, then [`audit::serve`].
pub fn audit_writer_main(append: &Path, admin: &Path, db: &Path) -> Result<u64, String> {
    let mut bytes = [0; 64];
    std::io::stdin()
        .read_exact(&mut bytes)
        .map_err(|e| e.to_string())?;
    let keys = AuditKeys::from_bytes(&bytes);
    let append = UnixListener::bind(append).map_err(|e| e.to_string())?;
    let admin = UnixListener::bind(admin).map_err(|e| e.to_string())?;
    let mut stdout = std::io::stdout();
    writeln!(stdout, "ready").map_err(|e| e.to_string())?;
    stdout.flush().map_err(|e| e.to_string())?;
    audit::serve(&append, Some(&admin), db, &keys, Duration::ZERO)
}

/// Runs one configuration end to end and verifies the audit chain afterwards.
pub fn run(cfg: &Config) -> Result<RunReport, String> {
    let household = Arc::new(set_up(cfg)?);
    let audit_keys = AuditKeys {
        db_key: crypto::random(),
        mac_key: crypto::random(),
    };
    let paths = Paths::new(&cfg.workdir);
    audit::create_audit_db(&paths.audit_db, &audit_keys).map_err(|e| e.to_string())?;
    let audit_writer = start_audit_writer(cfg, &paths, &audit_keys)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let measured = runtime.block_on(drive(cfg, &household, &paths));
    drop(runtime);
    match audit_writer {
        AuditWriter::Process(mut child) => {
            child.wait().map_err(|e| e.to_string())?;
        }
        AuditWriter::Thread(thread) => {
            thread.join().map_err(|_| "audit writer panicked")??;
        }
    }
    let mut report = measured?;
    report.audit_verified = audit::verify_chain(&paths.audit_db, &audit_keys);
    report.file_bytes = FileId::ALL
        .iter()
        .filter_map(|file| std::fs::metadata(file_path(&cfg.workdir, *file)).ok())
        .map(|metadata| metadata.len())
        .sum();
    Ok(report)
}

async fn drive(
    cfg: &Config,
    household: &Arc<Household>,
    paths: &Paths,
) -> Result<RunReport, String> {
    let mut writers = HashMap::new();
    for file in FileId::ALL {
        let conn =
            storage::open_writer(&file_path(&cfg.workdir, file), &household.file_keys[&file])
                .map_err(|e| e.to_string())?;
        writers.insert(
            file,
            Writer::spawn(file.name(), conn).map_err(|e| e.to_string())?,
        );
    }
    let audit = AuditClient::connect(&paths.audit_append)
        .await
        .map_err(|e| format!("connecting to the audit writer: {e}"))?;
    let core = Arc::new(Core::new(
        writers,
        audit,
        (0..RULES).collect::<HashSet<_>>(),
        HashSet::from([ADAPTER]),
    ));
    let recorder = Arc::new(Recorder::default());
    let shared = Arc::new(Shared {
        core: Arc::clone(&core),
        recorder: Arc::clone(&recorder),
        stop: AtomicBool::new(false),
        in_flight: AtomicUsize::new(0),
        pool: Arc::new(Semaphore::new(cfg.pool_permits)),
        permits_held: AtomicUsize::new(0),
        max_permits_held: AtomicUsize::new(0),
        unlocks_in_flight: AtomicUsize::new(0),
        max_concurrent_unlocks: AtomicUsize::new(0),
        unlocks: AtomicU64::new(0),
        backups: AtomicU64::new(0),
        copies_during_unlock: AtomicU64::new(0),
        home_interleaved_jobs: AtomicU64::new(0),
        retention_deleted: AtomicU64::new(0),
        long_reads: AtomicU64::new(0),
        audit_copies: AtomicU64::new(0),
        rule_dispatches: AtomicU64::new(0),
        watchdog_ticks: AtomicU64::new(0),
        watchdog_max_gap_us: AtomicU64::new(0),
        socket_probe_done: AtomicBool::new(false),
    });
    let handle = Handle::current();
    let ingress = tokio::net::UnixListener::bind(&paths.ingress).map_err(|e| e.to_string())?;
    let mut tasks = vec![
        tokio::spawn(probe(cfg.clone(), Arc::clone(&shared))),
        tokio::spawn(ingress_server(ingress, Arc::clone(&shared))),
        tokio::spawn(socket_probe(
            cfg.clone(),
            Arc::clone(&shared),
            paths.ingress.clone(),
        )),
    ];
    for member in 1..=2 {
        tasks.push(tokio::spawn(adult(
            cfg.clone(),
            Arc::clone(&shared),
            member,
        )));
        tasks.push(tokio::spawn(assistant(
            cfg.clone(),
            Arc::clone(&shared),
            member,
        )));
    }
    for unlocker in 0..cfg.unlockers {
        let member = if unlocker % 2 == 0 { 1 } else { 2 };
        tasks.push(tokio::spawn(unlock_loop(
            cfg.clone(),
            Arc::clone(&shared),
            Arc::clone(household),
            member,
        )));
    }
    tasks.push(tokio::spawn(plugin(cfg.clone(), Arc::clone(&shared))));
    tasks.push(tokio::spawn(backup_loop(
        cfg.clone(),
        Arc::clone(&shared),
        Arc::clone(household),
        paths.audit_admin.clone(),
        paths.audit_db.clone(),
    )));
    tasks.push(tokio::spawn(retention_loop(
        cfg.clone(),
        Arc::clone(&shared),
    )));
    tasks.push(tokio::spawn(long_reader_loop(
        cfg.clone(),
        Arc::clone(&shared),
        household.file_keys[&FileId::TasksHousehold],
    )));
    if let Some(length) = cfg.injected_pause {
        let shared = Arc::clone(&shared);
        let at = cfg.warmup + cfg.duration / 3;
        tasks.push(tokio::spawn(async move {
            tokio::time::sleep(at).await;
            if let Some(writer) = shared.core.writer(FileId::TasksHousehold)
                && let Ok(guard) = writer.pause().await
            {
                tokio::time::sleep(length).await;
                drop(guard);
            }
        }));
    }
    let (event_sender, events) = mpsc::channel();
    let (dispatch_sender, mut dispatches) = tokio::sync::mpsc::unbounded_channel::<Dispatch>();
    let rule_thread = {
        let shared = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("home-rules".into())
            .spawn(move || rule_loop(&events, &dispatch_sender, &shared))
            .map_err(|e| e.to_string())?
    };
    let adapter_thread = {
        let shared = Arc::clone(&shared);
        let handle = handle.clone();
        let cfg = cfg.clone();
        std::thread::Builder::new()
            .name("adapter-double".into())
            .spawn(move || adapter_double(&cfg, &shared, &handle, &event_sender))
            .map_err(|e| e.to_string())?
    };
    let dispatcher = {
        let shared = Arc::clone(&shared);
        let handle = handle.clone();
        tokio::spawn(async move {
            while let Some(dispatch) = dispatches.recv().await {
                let call = Call::new(
                    Principal::Rule(dispatch.rule),
                    Tool::HomeSetState,
                    FileId::Home,
                    Some(i64::from(dispatch.device) + 1),
                );
                spawn_call(
                    &handle,
                    &shared,
                    "rule: home.set_state".to_owned(),
                    call,
                    dispatch.dispatched_at,
                    Some(dispatch.event_at),
                );
            }
        })
    };

    tokio::time::sleep(cfg.warmup).await;
    recorder.start();
    tokio::time::sleep(cfg.duration).await;
    recorder.stop();
    shared.stop.store(true, Ordering::SeqCst);
    for task in tasks {
        task.await.map_err(|e| e.to_string())?;
    }
    tokio::task::spawn_blocking(move || {
        let adapter = adapter_thread.join();
        let rules = rule_thread.join();
        adapter.and(rules)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|_| "a load thread panicked".to_owned())?;
    dispatcher.await.map_err(|e| e.to_string())?;
    let drain_deadline = Instant::now() + Duration::from_secs(60);
    while shared.in_flight.load(Ordering::SeqCst) > 0 {
        if Instant::now() > drain_deadline {
            return Err("calls still in flight 60 s after the stop".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let report = RunReport {
        summaries: recorder.summaries(),
        errors: recorder.errors(),
        slowest: recorder.slowest(),
        unlocks: shared.unlocks.load(Ordering::SeqCst),
        max_concurrent_unlocks: shared.max_concurrent_unlocks.load(Ordering::SeqCst),
        max_permits_held: shared.max_permits_held.load(Ordering::SeqCst),
        backups: shared.backups.load(Ordering::SeqCst),
        copies_during_unlock: shared.copies_during_unlock.load(Ordering::SeqCst),
        home_interleaved_jobs: shared.home_interleaved_jobs.load(Ordering::SeqCst),
        pause_retries: FileId::ALL
            .iter()
            .filter_map(|file| core.writer(*file))
            .map(Writer::pause_retries)
            .sum(),
        retention_deleted: shared.retention_deleted.load(Ordering::SeqCst),
        long_reads: shared.long_reads.load(Ordering::SeqCst),
        rule_dispatches: shared.rule_dispatches.load(Ordering::SeqCst),
        watchdog_ticks: shared.watchdog_ticks.load(Ordering::SeqCst),
        watchdog_max_gap: Duration::from_micros(shared.watchdog_max_gap_us.load(Ordering::SeqCst)),
        audit_appends: core.audit_appends(),
        audit_verified: Err("not verified yet".into()),
        audit_copies: shared.audit_copies.load(Ordering::SeqCst),
        file_bytes: 0,
    };
    drop(shared);
    // The last reference: dropping it joins the writer threads and closes the audit
    // connection, which ends the audit writer.
    drop(core);
    Ok(report)
}

async fn probe(cfg: Config, shared: Arc<Shared>) {
    let handle = Handle::current();
    let mut rng = Rng::seeded();
    let mut interval = tokio::time::interval(cfg.probe_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Burst);
    let mut member = 1;
    while !shared.stopping() {
        let scheduled = interval.tick().await.into_std();
        let call = Call::new(
            Principal::Member(member),
            Tool::TasksUpdate,
            FileId::TasksHousehold,
            Some(rng.record(cfg.rows_household)),
        );
        spawn_call(
            &handle,
            &shared,
            PROBE_LABEL.to_owned(),
            call,
            scheduled,
            None,
        );
        member = 3 - member;
    }
}

/// Request on the ingress socket: token (16 bytes), call id (16), record id (8).
const INGRESS_REQUEST: usize = 40;
const INGRESS_OK: u8 = 0;
const INGRESS_REFUSED: u8 = 1;

/// The Core side of a peer socket, reduced to one request shape: parses the request, runs the
/// call as an `AiTask` principal through the pipeline and answers with the audit sequence.
async fn ingress_server(listener: tokio::net::UnixListener, shared: Arc<Shared>) {
    loop {
        if shared.socket_probe_done.load(Ordering::SeqCst)
            && shared.in_flight.load(Ordering::SeqCst) == 0
        {
            return;
        }
        let Ok(Ok((mut stream, _))) =
            tokio::time::timeout(Duration::from_millis(50), listener.accept()).await
        else {
            continue;
        };
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let mut request = [0; INGRESS_REQUEST];
            if stream.read_exact(&mut request).await.is_err() {
                return;
            }
            let received = Instant::now();
            let mut token = [0; 16];
            token.copy_from_slice(&request[..16]);
            let mut record = [0; 8];
            record.copy_from_slice(&request[32..]);
            let mut call = Call::new(
                Principal::AiTask(u128::from_be_bytes(token)),
                Tool::TasksUpdate,
                FileId::TasksHousehold,
                Some(i64::from_be_bytes(record)),
            );
            call.call_id.copy_from_slice(&request[16..32]);
            call.inputs = vec![i64::from_be_bytes(record)];
            let mut response = [INGRESS_REFUSED; 9];
            if let Ok(outcome) = shared.core.execute(call).await {
                response[0] = INGRESS_OK;
                response[1..].copy_from_slice(&outcome.audit_seq.to_be_bytes());
                record_outcome(
                    &shared.recorder,
                    "ingress server side: assistant tasks.update household",
                    received,
                    &outcome,
                );
            }
            // The client sees a closed connection as an error.
            let _ = stream.write_all(&response).await;
        });
    }
}

/// The token probe: a capability token renewed every [`TOKEN_BUDGET`] calls, one request per
/// tick over a fresh connection, timed from the tick to the response.
async fn socket_probe(cfg: Config, shared: Arc<Shared>, socket: PathBuf) {
    let mut rng = Rng::seeded();
    let mut interval = tokio::time::interval(cfg.probe_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Burst);
    let mut token = 0;
    let mut sent = TOKEN_BUDGET;
    while !shared.stopping() {
        let scheduled = interval.tick().await.into_std();
        if sent == TOKEN_BUDGET {
            token = shared.core.issue_token(
                1,
                &[Tool::TasksUpdate],
                &[FileId::TasksHousehold],
                TOKEN_BUDGET,
                TOKEN_TTL,
            );
            sent = 0;
        }
        sent += 1;
        let record = rng.record(cfg.rows_household);
        shared.in_flight.fetch_add(1, Ordering::SeqCst);
        let shared = Arc::clone(&shared);
        let socket = socket.clone();
        tokio::spawn(async move {
            let mut request = [0; INGRESS_REQUEST];
            request[..16].copy_from_slice(&token.to_be_bytes());
            request[16..32].copy_from_slice(&crypto::random::<16>());
            request[32..].copy_from_slice(&record.to_be_bytes());
            let answer = async {
                let mut stream = tokio::net::UnixStream::connect(&socket).await?;
                stream.write_all(&request).await?;
                let mut response = [0; 9];
                stream.read_exact(&mut response).await?;
                Ok::<_, std::io::Error>(response)
            }
            .await;
            let elapsed = scheduled.elapsed();
            match answer {
                Ok(response) if response[0] == INGRESS_OK => {
                    shared
                        .recorder
                        .record(SOCKET_PROBE_LABEL, scheduled, elapsed);
                    shared
                        .recorder
                        .record(ALL_ACTIONS_LABEL, scheduled, elapsed);
                }
                Ok(_) => shared
                    .recorder
                    .error(SOCKET_PROBE_LABEL, "refused by the pipeline".into()),
                Err(error) => shared.recorder.error(SOCKET_PROBE_LABEL, error.to_string()),
            }
            shared.in_flight.fetch_sub(1, Ordering::SeqCst);
        });
    }
    // Every request this probe will send is counted in `in_flight` by now; the ingress server
    // waits for this flag so it never closes its socket under a request still to come.
    shared.socket_probe_done.store(true, Ordering::SeqCst);
}

async fn adult(cfg: Config, shared: Arc<Shared>, member: u8) {
    let handle = Handle::current();
    let mut rng = Rng::seeded();
    let personal = FileId::personal_tasks(member);
    loop {
        pause_for(&shared, rng.gap(cfg.adult_gap)).await;
        if shared.stopping() {
            return;
        }
        let (tool, file, record) = match rng.below(10) {
            0..=2 => (Tool::TasksCreate, personal, None),
            3..=5 => (
                Tool::TasksUpdate,
                personal,
                Some(rng.record(cfg.rows_personal)),
            ),
            6 | 7 => (
                Tool::TasksUpdate,
                FileId::TasksHousehold,
                Some(rng.record(cfg.rows_household)),
            ),
            _ => (
                Tool::CalendarUpdate,
                FileId::CalendarHousehold,
                Some(rng.record(cfg.rows_household)),
            ),
        };
        let label = format!("member {} {}", tool.name(), partition_label(file));
        let call = Call::new(Principal::Member(member), tool, file, record);
        spawn_call(&handle, &shared, label, call, Instant::now(), None);
    }
}

/// Tool calls of one adult's assistant, under a capability token renewed when its budget is
/// spent or it is close to expiry.
async fn assistant(cfg: Config, shared: Arc<Shared>, member: u8) {
    token_principal_loop(
        &shared,
        cfg.assistant_gap,
        member,
        Tool::TasksUpdate,
        FileId::personal_tasks(member),
        cfg.rows_personal,
        Principal::AiTask,
        "assistant tasks.update personal",
    )
    .await;
}

/// The testbed's reference module, as a plugin with its own token (D102, simulated).
async fn plugin(cfg: Config, shared: Arc<Shared>) {
    token_principal_loop(
        &shared,
        cfg.plugin_gap,
        1,
        Tool::ReferenceWrite,
        FileId::ReferenceHousehold,
        cfg.rows_reference,
        Principal::Plugin,
        "testbed plugin reference.write household",
    )
    .await;
}

#[allow(clippy::too_many_arguments)] // Two call sites; a struct would only rename the list.
async fn token_principal_loop(
    shared: &Arc<Shared>,
    gap: Duration,
    member: u8,
    tool: Tool,
    file: FileId,
    rows: u32,
    principal: fn(u128) -> Principal,
    label: &str,
) {
    let handle = Handle::current();
    let mut rng = Rng::seeded();
    let mut token = None;
    let mut remaining = 0;
    let mut issued = Instant::now();
    loop {
        pause_for(shared, rng.gap(gap)).await;
        if shared.stopping() {
            return;
        }
        if token.is_none()
            || remaining == 0
            || issued.elapsed() > TOKEN_TTL - Duration::from_secs(30)
        {
            token =
                Some(
                    shared
                        .core
                        .issue_token(member, &[tool], &[file], TOKEN_BUDGET, TOKEN_TTL),
                );
            remaining = TOKEN_BUDGET;
            issued = Instant::now();
        }
        remaining -= 1;
        let Some(id) = token else { return };
        let mut call = Call::new(principal(id), tool, file, Some(rng.record(rows)));
        call.inputs = (0..3).map(|_| rng.record(rows)).collect();
        spawn_call(
            &handle,
            shared,
            label.to_owned(),
            call,
            Instant::now(),
            None,
        );
    }
}

async fn unlock_loop(cfg: Config, shared: Arc<Shared>, household: Arc<Household>, member: u8) {
    while !shared.stopping() {
        let Some(permit) = shared.take_permit().await else {
            return;
        };
        let started = Instant::now();
        let work_shared = Arc::clone(&shared);
        let work_household = Arc::clone(&household);
        let workdir = cfg.workdir.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            let now = work_shared.unlocks_in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            work_shared
                .max_concurrent_unlocks
                .fetch_max(now, Ordering::SeqCst);
            let result = unlock_member(&work_household, &workdir, member);
            work_shared.unlocks_in_flight.fetch_sub(1, Ordering::SeqCst);
            work_shared.give_back(permit);
            result
        })
        .await
        .map_err(|e| e.to_string())
        .and_then(|result| result);
        match outcome {
            Ok(()) => {
                shared.unlocks.fetch_add(1, Ordering::SeqCst);
                shared
                    .recorder
                    .record(UNLOCK_LABEL, started, started.elapsed());
            }
            Err(error) => shared.recorder.error(UNLOCK_LABEL, error),
        }
        pause_for(&shared, cfg.unlock_gap).await;
    }
}

/// The unlock: Argon2id and unwrapping (crypto), then each file the member can now open is
/// keyed from the recovered roots and checked against its `_meta`.
fn unlock_member(household: &Household, workdir: &Path, member: u8) -> Result<(), String> {
    let (passphrase, wrappers) = &household.members[usize::from(member) - 1];
    let keys = crypto::unlock(household.cost, passphrase, wrappers)?;
    for file in FileId::ALL {
        let root = match file.partition() {
            PartitionKind::Personal(owner) if owner == member => keys.dek,
            PartitionKind::Household => keys.household_key,
            PartitionKind::Personal(_) | PartitionKind::Home => continue,
        };
        let key = crypto::hkdf(&root, &file_info(file));
        if key != household.file_keys[&file] {
            return Err(format!("{} key mismatch after unlock", file.name()));
        }
        let conn = storage::open_reader(&file_path(workdir, file), &key)
            .map_err(|e| format!("opening {}: {e}", file.name()))?;
        conn.query_row(
            "SELECT value FROM _meta WHERE key = 'generation'",
            [],
            |row| row.get::<_, String>(0),
        )
        .map_err(|e| format!("reading {} _meta: {e}", file.name()))?;
    }
    Ok(())
}

async fn backup_loop(
    cfg: Config,
    shared: Arc<Shared>,
    household: Arc<Household>,
    audit_admin: PathBuf,
    audit_db: PathBuf,
) {
    while !shared.stopping() {
        let Some(permit) = shared.take_permit().await else {
            return;
        };
        let started = Instant::now();
        match backup_cycle(&cfg, &shared, &household, &audit_admin, &audit_db).await {
            Ok(()) => {
                shared.backups.fetch_add(1, Ordering::SeqCst);
                shared
                    .recorder
                    .record(BACKUP_CYCLE_LABEL, started, started.elapsed());
            }
            Err(error) => shared.recorder.error(BACKUP_CYCLE_LABEL, error),
        }
        shared.give_back(permit);
        pause_for(&shared, cfg.backup_gap).await;
    }
}

async fn backup_cycle(
    cfg: &Config,
    shared: &Shared,
    household: &Household,
    audit_admin: &Path,
    audit_db: &Path,
) -> Result<(), String> {
    let backup_dir = cfg.workdir.join("backup");
    let mut manifest = Vec::new();
    for file in FileId::ALL.into_iter().filter(|file| *file != FileId::Home) {
        let writer = shared.core.writer(file).ok_or("writer missing")?;
        if shared.unlocks_in_flight.load(Ordering::SeqCst) > 0 {
            shared.copies_during_unlock.fetch_add(1, Ordering::SeqCst);
        }
        let paused_at = Instant::now();
        let guard = writer.pause().await?;
        let source = file_path(&cfg.workdir, file);
        let target = backup_dir.join(format!("{}.db", file.name()));
        let throttle = cfg.backup_throttle;
        let copied = tokio::task::spawn_blocking(move || copy_and_hash(&source, &target, throttle))
            .await
            .map_err(|e| e.to_string())?;
        drop(guard);
        shared
            .recorder
            .record(BACKUP_PAUSE_LABEL, paused_at, paused_at.elapsed());
        manifest.push((file.name(), copied?));
    }
    let home_started = Instant::now();
    let home_target = backup_dir.join("home.home.db");
    let home_key = household.file_keys[&FileId::Home];
    let target_path = home_target.clone();
    let target = tokio::task::spawn_blocking(move || {
        match std::fs::remove_file(&target_path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(error.to_string());
            }
            _ => {}
        }
        storage::open_backup_target(&target_path, &home_key).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())??;
    let steps = shared
        .core
        .writer(FileId::Home)
        .ok_or("home writer missing")?
        .online_backup(target, cfg.home_backup_pages)
        .await?;
    shared
        .home_interleaved_jobs
        .fetch_add(u64::from(steps.interleaved_jobs), Ordering::SeqCst);
    shared.recorder.record(
        HOME_ONLINE_BACKUP_LABEL,
        home_started,
        home_started.elapsed(),
    );
    let home_hash = tokio::task::spawn_blocking(move || hash_file(&home_target))
        .await
        .map_err(|e| e.to_string())??;
    manifest.push(("home.home", home_hash));
    let audit_started = Instant::now();
    let flushed = audit::flush(audit_admin)
        .await
        .map_err(|e| format!("audit flush: {e}"))?;
    let audit_source = audit_db.to_owned();
    let audit_target = backup_dir.join("audit.db");
    let audit_hash =
        tokio::task::spawn_blocking(move || copy_and_hash(&audit_source, &audit_target, None))
            .await
            .map_err(|e| e.to_string())?;
    drop(flushed);
    shared
        .recorder
        .record(AUDIT_FLUSH_LABEL, audit_started, audit_started.elapsed());
    manifest.push(("audit", audit_hash?));
    shared.audit_copies.fetch_add(1, Ordering::SeqCst);
    let instance_key = household.instance_key;
    let backup_public = household.backup_public.clone();
    let sealed =
        tokio::task::spawn_blocking(move || crypto::seal_to(&backup_public, &instance_key))
            .await
            .map_err(|e| e.to_string())?;
    if sealed.is_empty() || manifest.len() != FileId::ALL.len() + 1 {
        return Err("incomplete backup manifest".into());
    }
    Ok(())
}

/// The home partition's journal retention (AD-26): one batch of expired entries deleted under
/// `secure_delete`, as a job on the home writer.
async fn retention_loop(cfg: Config, shared: Arc<Shared>) {
    while !shared.stopping() {
        pause_for(&shared, cfg.retention_gap).await;
        if shared.stopping() {
            return;
        }
        let Some(writer) = shared.core.writer(FileId::Home) else {
            return;
        };
        let started = Instant::now();
        let cutoff = storage::unix_now() - HOME_RETENTION_SECS;
        let deleted = writer
            .run(move |conn| {
                conn.execute(
                    "DELETE FROM _journal WHERE id IN
                         (SELECT id FROM _journal WHERE created_at < ?1 LIMIT ?2)",
                    rusqlite::params![cutoff, RETENTION_BATCH],
                )
            })
            .await;
        match deleted {
            Ok(Ok(rows)) => {
                shared
                    .retention_deleted
                    .fetch_add(rows as u64, Ordering::SeqCst);
                shared
                    .recorder
                    .record(RETENTION_LABEL, started, started.elapsed());
            }
            Ok(Err(error)) => shared.recorder.error(RETENTION_LABEL, error.to_string()),
            Err(error) => shared.recorder.error(RETENTION_LABEL, error),
        }
    }
}

/// A reader that holds a read transaction on the household tasks file, as a digest render
/// would, so that some backup pauses meet a reader holding the WAL.
async fn long_reader_loop(cfg: Config, shared: Arc<Shared>, key: FileKey) {
    let path = file_path(&cfg.workdir, FileId::TasksHousehold);
    while !shared.stopping() {
        pause_for(&shared, cfg.long_reader_gap).await;
        if shared.stopping() {
            return;
        }
        let started = Instant::now();
        let path = path.clone();
        let hold = cfg.long_reader_hold;
        let read = tokio::task::spawn_blocking(move || {
            let conn = storage::open_reader(&path, &key).map_err(|e| e.to_string())?;
            let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
            storage::record_count(&tx).map_err(|e| e.to_string())?;
            std::thread::sleep(hold);
            tx.commit().map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| e.to_string())
        .and_then(|result| result);
        match read {
            Ok(()) => {
                shared.long_reads.fetch_add(1, Ordering::SeqCst);
                shared
                    .recorder
                    .record(LONG_READER_LABEL, started, started.elapsed());
            }
            Err(error) => shared.recorder.error(LONG_READER_LABEL, error),
        }
    }
}

/// Copies `source` to `target` in 1 MiB chunks, hashing with SHA-256 and syncing the copy;
/// `throttle` limits the rate in bytes per second.
pub(crate) fn copy_and_hash(
    source: &Path,
    target: &Path,
    throttle: Option<u64>,
) -> Result<Vec<u8>, String> {
    let mut input = std::fs::File::open(source).map_err(|e| e.to_string())?;
    let mut output = std::fs::File::create(target).map_err(|e| e.to_string())?;
    let mut context = digest::Context::new(&digest::SHA256);
    let mut buffer = vec![0; 1 << 20];
    let started = Instant::now();
    let mut copied = 0_u64;
    loop {
        let read = input.read(&mut buffer).map_err(|e| e.to_string())?;
        if read == 0 {
            break;
        }
        context.update(&buffer[..read]);
        output
            .write_all(&buffer[..read])
            .map_err(|e| e.to_string())?;
        copied += read as u64;
        if let Some(rate) = throttle {
            let due = Duration::from_secs_f64(copied as f64 / rate as f64);
            if let Some(ahead) = due.checked_sub(started.elapsed()) {
                std::thread::sleep(ahead);
            }
        }
    }
    output.sync_all().map_err(|e| e.to_string())?;
    Ok(context.finish().as_ref().to_vec())
}

fn hash_file(path: &Path) -> Result<Vec<u8>, String> {
    let mut input = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut context = digest::Context::new(&digest::SHA256);
    let mut buffer = vec![0; 1 << 20];
    loop {
        let read = input.read(&mut buffer).map_err(|e| e.to_string())?;
        if read == 0 {
            return Ok(context.finish().as_ref().to_vec());
        }
        context.update(&buffer[..read]);
    }
}

struct Event {
    device: u16,
    value: u16,
    sent_at: Instant,
}

struct Dispatch {
    rule: u16,
    device: u16,
    event_at: Instant,
    dispatched_at: Instant,
}

struct SyntheticRule {
    id: u16,
    device: u16,
    threshold: u16,
}

/// The dedicated rule thread: wakes on each adapter event, evaluates every rule, dispatches
/// the first matching rule's action to the runtime, and ticks a watchdog counter on every
/// pass, at least every 100 ms (the `WatchdogSec=` keep-alive of AD-9). The longest gap
/// between two ticks is recorded.
fn rule_loop(
    events: &mpsc::Receiver<Event>,
    dispatch: &tokio::sync::mpsc::UnboundedSender<Dispatch>,
    shared: &Shared,
) {
    let mut rng = Rng::seeded();
    let rules: Vec<SyntheticRule> = (0..RULES)
        .map(|id| SyntheticRule {
            id,
            device: id % DEVICES,
            threshold: rng.below(1_000) as u16,
        })
        .collect();
    let mut last_tick = Instant::now();
    loop {
        match events.recv_timeout(Duration::from_millis(100)) {
            Ok(event) => {
                let woke = Instant::now();
                shared
                    .recorder
                    .record(RULE_WAKE_LABEL, event.sent_at, woke - event.sent_at);
                let matched = rules
                    .iter()
                    .filter(|rule| rule.device == event.device && event.value > rule.threshold)
                    .min_by_key(|rule| rule.threshold);
                if let Some(rule) = matched {
                    let dispatched_at = Instant::now();
                    if dispatch
                        .send(Dispatch {
                            rule: rule.id,
                            device: event.device,
                            event_at: event.sent_at,
                            dispatched_at,
                        })
                        .is_err()
                    {
                        return;
                    }
                    let sent = Instant::now();
                    shared.rule_dispatches.fetch_add(1, Ordering::SeqCst);
                    shared
                        .recorder
                        .record(RULE_WAKE_TO_DISPATCH_LABEL, event.sent_at, sent - woke);
                    shared.recorder.record(
                        RULE_EVENT_TO_DISPATCH_LABEL,
                        event.sent_at,
                        sent - event.sent_at,
                    );
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
        let now = Instant::now();
        let gap = u64::try_from((now - last_tick).as_micros()).unwrap_or(u64::MAX);
        shared.watchdog_max_gap_us.fetch_max(gap, Ordering::SeqCst);
        last_tick = now;
        shared.watchdog_ticks.fetch_add(1, Ordering::SeqCst);
    }
}

/// The testbed's device adapter double: Poisson device events, each one sent to the rule
/// thread and reported as an adapter state write through the pipeline.
fn adapter_double(
    cfg: &Config,
    shared: &Arc<Shared>,
    handle: &Handle,
    events: &mpsc::Sender<Event>,
) {
    let mut rng = Rng::seeded();
    while !shared.stopping() {
        std::thread::sleep(rng.gap(cfg.adapter_gap));
        let device = rng.below(u64::from(DEVICES)) as u16;
        let sent_at = Instant::now();
        if events
            .send(Event {
                device,
                value: rng.below(1_000) as u16,
                sent_at,
            })
            .is_err()
        {
            return;
        }
        let call = Call::new(
            Principal::Adapter(ADAPTER),
            Tool::HomeReport,
            FileId::Home,
            Some(i64::from(device) + 1),
        );
        spawn_call(
            handle,
            shared,
            "testbed adapter home.report".to_owned(),
            call,
            sent_at,
            None,
        );
    }
}
