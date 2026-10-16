//! The pieces the measurement relies on: the pipeline refuses what it must, the write leaves
//! its journal and outbox rows atomically, a panicking job rolls back, the writer thread's
//! backup commands behave as AD-31 needs (a pause does not wait on a long reader), the
//! durability settings are what they claim, the audit chain detects tampering and its
//! acknowledgement is inside the measured audit stage, the unlock recovers the keys, and a
//! short run of the whole load is clean and times its probes from their scheduled start.

use std::collections::{HashMap, HashSet};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::time::Duration;

use core_execution::audit::{self, AuditClient, AuditKeys};
use core_execution::crypto::{self, Argon2Cost};
use core_execution::load::{self, ALL_ACTIONS_LABEL, Config, PROBE_LABEL, SOCKET_PROBE_LABEL};
use core_execution::pipeline::{Call, Core, FileId, Principal, Refusal, Tool};
use core_execution::storage::{self, FileKey};
use core_execution::writer::Writer;

const ROWS: u32 = 50;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("e32-test-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

struct TestCore {
    core: Core,
    dir: PathBuf,
    keys: HashMap<FileId, FileKey>,
    audit_keys: AuditKeys,
    audit_thread: std::thread::JoinHandle<Result<u64, String>>,
}

async fn test_core(name: &str) -> TestCore {
    test_core_with_audit_delay(name, Duration::ZERO).await
}

async fn test_core_with_audit_delay(name: &str, commit_delay: Duration) -> TestCore {
    let dir = scratch(name);
    let mut writers = HashMap::new();
    let mut keys = HashMap::new();
    for file in FileId::ALL {
        let key = crypto::random::<32>();
        let path = dir.join(format!("{}.db", file.name()));
        storage::create_module_file(&path, &key, ROWS, 100, 0).expect("module file");
        let conn = storage::open_writer(&path, &key).expect("writer connection");
        writers.insert(
            file,
            Writer::spawn(file.name(), conn).expect("writer thread"),
        );
        keys.insert(file, key);
    }
    let audit_keys = AuditKeys {
        db_key: crypto::random(),
        mac_key: crypto::random(),
    };
    let audit_db = dir.join("audit.db");
    audit::create_audit_db(&audit_db, &audit_keys).expect("audit db");
    let socket = dir.join("append.sock");
    let listener = UnixListener::bind(&socket).expect("audit socket");
    let thread_keys = audit_keys.clone();
    let audit_thread = std::thread::spawn(move || {
        audit::serve(&listener, None, &audit_db, &thread_keys, commit_delay)
    });
    let client = AuditClient::connect(&socket).await.expect("audit client");
    TestCore {
        core: Core::new(writers, client, HashSet::from([7]), HashSet::from([1])),
        dir,
        keys,
        audit_keys,
        audit_thread,
    }
}

impl TestCore {
    fn finish(self) -> u64 {
        let appended = self.core.audit_appends();
        drop(self.core);
        let served = self
            .audit_thread
            .join()
            .expect("audit thread")
            .expect("audit serve");
        assert_eq!(served, appended);
        let verified =
            audit::verify_chain(&self.dir.join("audit.db"), &self.audit_keys).expect("chain");
        let _ = std::fs::remove_dir_all(&self.dir);
        verified
    }

    fn reader(&self, file: FileId) -> rusqlite::Connection {
        storage::open_reader(
            &self.dir.join(format!("{}.db", file.name())),
            &self.keys[&file],
        )
        .expect("reader")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipeline_refuses_out_of_scope_calls_and_audits_every_call() {
    let t = test_core("refusals").await;
    let core = &t.core;
    let update = |principal, tool, file| Call::new(principal, tool, file, Some(1));

    let expired = core.issue_token(
        1,
        &[Tool::TasksUpdate],
        &[FileId::TasksAdult1],
        5,
        Duration::ZERO,
    );
    let refused = core
        .execute(update(
            Principal::AiTask(expired),
            Tool::TasksUpdate,
            FileId::TasksAdult1,
        ))
        .await;
    assert_eq!(refused.unwrap_err(), Refusal::Token("expired"));

    let narrow = core.issue_token(
        1,
        &[Tool::TasksUpdate],
        &[FileId::TasksAdult1],
        1,
        Duration::from_secs(60),
    );
    let out_of_scope = core
        .execute(update(
            Principal::AiTask(narrow),
            Tool::TasksUpdate,
            FileId::TasksHousehold,
        ))
        .await;
    assert_eq!(out_of_scope.unwrap_err(), Refusal::Token("out of scope"));
    core.execute(update(
        Principal::AiTask(narrow),
        Tool::TasksUpdate,
        FileId::TasksAdult1,
    ))
    .await
    .expect("within scope and budget");
    let spent = core
        .execute(update(
            Principal::AiTask(narrow),
            Tool::TasksUpdate,
            FileId::TasksAdult1,
        ))
        .await;
    assert_eq!(spent.unwrap_err(), Refusal::Token("budget spent"));

    let other_member = core
        .execute(update(
            Principal::Member(2),
            Tool::TasksUpdate,
            FileId::TasksAdult1,
        ))
        .await;
    assert!(matches!(other_member, Err(Refusal::Principal(_))));
    let unvalidated_rule = core
        .execute(update(Principal::Rule(8), Tool::HomeSetState, FileId::Home))
        .await;
    assert!(matches!(unvalidated_rule, Err(Refusal::Principal(_))));
    core.execute(update(Principal::Rule(7), Tool::HomeSetState, FileId::Home))
        .await
        .expect("validated rule");

    let mut tainted = update(
        Principal::AiTask(core.issue_token(
            1,
            &[Tool::TasksUpdate],
            &[FileId::TasksAdult1],
            5,
            Duration::from_secs(60),
        )),
        Tool::TasksUpdate,
        FileId::TasksAdult1,
    );
    tainted.session_tainted = true;
    assert_eq!(core.execute(tainted).await.unwrap_err(), Refusal::Elevated);

    let mut bad_schema = update(Principal::Member(1), Tool::TasksUpdate, FileId::TasksAdult1);
    bad_schema.body = "line\nbreak".into();
    assert!(matches!(
        core.execute(bad_schema).await,
        Err(Refusal::Schema(_))
    ));

    assert_eq!(
        t.finish(),
        9,
        "every call, refused or not, has one audit entry"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_bumps_rev_journals_images_and_refuses_a_replayed_call_id() {
    let t = test_core("journal").await;
    let call = Call::new(
        Principal::Member(1),
        Tool::TasksUpdate,
        FileId::TasksHousehold,
        Some(3),
    );
    let outcome = t.core.execute(call.clone()).await.expect("update");
    assert_eq!((outcome.record_id, outcome.rev), (3, 2));
    assert_eq!(
        t.core.execute(call.clone()).await.unwrap_err(),
        Refusal::Duplicate
    );
    let (rev_after_replay, journal_rows, outbox_rows): (i64, i64, i64) = t
        .reader(FileId::TasksHousehold)
        .query_row(
            "SELECT (SELECT rev FROM records WHERE id = 3),
                    (SELECT count(*) FROM _journal WHERE call_id = ?1),
                    (SELECT count(*) FROM _outbox)",
            [call.call_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("state after replay");
    assert_eq!(
        (rev_after_replay, journal_rows, outbox_rows),
        (2, 1, 1),
        "the replay rolled back its record update and wrote no journal or outbox row"
    );

    let created = t
        .core
        .execute(Call::new(
            Principal::Member(1),
            Tool::TasksCreate,
            FileId::TasksAdult1,
            None,
        ))
        .await
        .expect("create");
    assert_eq!((created.record_id, created.rev), (i64::from(ROWS) + 1, 1));

    let report = t
        .core
        .execute(Call::new(
            Principal::Adapter(1),
            Tool::HomeReport,
            FileId::Home,
            Some(1),
        ))
        .await
        .expect("adapter report");
    assert_eq!(report.rev, 2);

    let household = t.reader(FileId::TasksHousehold);
    let (rev, author, taint): (i64, String, String) = household
        .query_row(
            "SELECT rev, author, taint FROM records WHERE id = 3",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("record");
    assert_eq!(
        (rev, author.as_str(), taint.as_str()),
        (2, "member:1", "trusted")
    );
    let (before, after): (Option<Vec<u8>>, Vec<u8>) = household
        .query_row(
            "SELECT before_image, after_image FROM _journal WHERE record_id = 3",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("journal row");
    assert!(before.is_some_and(|image| image.starts_with(b"seed record")));
    assert!(!after.is_empty());
    let home_journal: i64 = t
        .reader(FileId::Home)
        .query_row("SELECT count(*) FROM _journal", [], |row| row.get(0))
        .expect("home journal");
    assert_eq!(
        home_journal, 0,
        "adapter reports are observations, not journaled"
    );
    t.finish();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn writer_connection_keeps_the_story_1_7_authorizer() {
    let t = test_core("authorizer").await;
    let writer = t.core.writer(FileId::Home).expect("home writer");
    let attach = writer
        .run(|conn| conn.execute_batch("ATTACH DATABASE '/tmp/e32-other.db' AS other"))
        .await
        .expect("job ran");
    assert!(
        attach
            .as_ref()
            .is_err_and(sqlite_authorizer::is_authorizer_denial)
    );
    let pragma = writer
        .run(|conn| conn.execute_batch("PRAGMA secure_delete = OFF"))
        .await
        .expect("job ran");
    assert!(
        pragma
            .as_ref()
            .is_err_and(sqlite_authorizer::is_authorizer_denial)
    );
    let panicked = writer.run(|_| panic!("handler fault")).await;
    assert!(
        panicked.is_err(),
        "a panicking job is caught on the writer thread"
    );
    let alive = writer
        .run(storage::record_count)
        .await
        .expect("writer alive");
    assert_eq!(alive.expect("count"), i64::from(ROWS));
    t.finish();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paused_writer_holds_writes_until_resumed_and_leaves_an_empty_wal() {
    let t = test_core("pause").await;
    let writer = t.core.writer(FileId::TasksHousehold).expect("writer");
    writer
        .run(|conn| conn.execute("UPDATE records SET title = 'x' WHERE id = 1", []))
        .await
        .expect("job")
        .expect("update");
    let guard = writer.pause().await.expect("pause");
    let wal = t.dir.join("tasks.household.db-wal");
    assert_eq!(std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0), 0);
    let pending =
        writer.run(|conn| conn.execute("UPDATE records SET title = 'y' WHERE id = 1", []));
    let held = tokio::time::timeout(Duration::from_millis(200), pending).await;
    assert!(held.is_err(), "a write waits while the writer is paused");
    drop(guard);
    writer
        .run(|conn| conn.execute("UPDATE records SET title = 'z' WHERE id = 1", []))
        .await
        .expect("job")
        .expect("update after resume");
    t.finish();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panicking_job_rolls_back_its_transaction_and_the_next_write_commits() {
    let t = test_core("rollback").await;
    let writer = t.core.writer(FileId::TasksAdult1).expect("writer");
    let panicked = writer
        .run(|conn| {
            let tx = conn.unchecked_transaction().expect("transaction");
            tx.execute("UPDATE records SET title = 'half done' WHERE id = 1", [])
                .expect("update");
            panic!("handler fault inside a transaction");
        })
        .await;
    assert!(panicked.is_err());
    let title_after_panic: String = writer
        .run(|conn| conn.query_row("SELECT title FROM records WHERE id = 1", [], |r| r.get(0)))
        .await
        .expect("job")
        .expect("title");
    assert_eq!(title_after_panic, "seed record 0");
    t.core
        .execute(Call::new(
            Principal::Member(1),
            Tool::TasksUpdate,
            FileId::TasksAdult1,
            Some(1),
        ))
        .await
        .expect("next write commits");
    let rev: i64 = t
        .reader(FileId::TasksAdult1)
        .query_row("SELECT rev FROM records WHERE id = 1", [], |r| r.get(0))
        .expect("rev");
    assert_eq!(rev, 2);
    t.finish();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pause_retries_behind_a_long_reader_without_blocking_writes() {
    let t = test_core("long-reader").await;
    let writer = t.core.writer(FileId::TasksHousehold).expect("writer");
    writer
        .run(|conn| conn.execute("UPDATE records SET title = 'in the wal' WHERE id = 1", []))
        .await
        .expect("job")
        .expect("update");
    let path = t.dir.join("tasks.household.db");
    let key = t.keys[&FileId::TasksHousehold];
    let (reading, read_started) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let conn = storage::open_reader(&path, &key).expect("reader");
        let tx = conn.unchecked_transaction().expect("read transaction");
        storage::record_count(&tx).expect("read");
        reading.send(()).expect("signal");
        std::thread::sleep(Duration::from_millis(400));
        tx.commit().expect("end read");
    });
    read_started.recv().expect("reader started");
    let started = std::time::Instant::now();
    let pause = writer.pause();
    let write_during = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let asked = std::time::Instant::now();
        writer
            .run(|conn| conn.execute("UPDATE records SET title = 'meanwhile' WHERE id = 2", []))
            .await
            .expect("job")
            .expect("update");
        asked.elapsed()
    };
    let (guard, write_wait) = tokio::join!(pause, write_during);
    let guard = guard.expect("pause after the reader ends");
    let paused_after = started.elapsed();
    drop(guard);
    reader.join().expect("reader thread");
    assert!(
        writer.pause_retries() > 0,
        "the reader made the pause retry"
    );
    assert!(
        write_wait < Duration::from_millis(100),
        "a write during the retries waited {write_wait:?}"
    );
    assert!(
        paused_after >= Duration::from_millis(250),
        "{paused_after:?}"
    );
    t.finish();
}

#[test]
fn writer_connections_have_the_durability_settings_they_claim() {
    let dir = scratch("durability");
    let path = dir.join("file.db");
    let key = crypto::random::<32>();
    storage::create_module_file(&path, &key, 1, 10, 0).expect("module file");
    let conn = storage::open_writer(&path, &key).expect("writer");
    conn.authorizer(None::<fn(rusqlite::hooks::AuthContext<'_>) -> rusqlite::hooks::Authorization>)
        .expect("lift authorizer");
    let read = |pragma: &str| {
        conn.query_row(&format!("PRAGMA {pragma}"), [], |row| {
            row.get::<_, rusqlite::types::Value>(0)
        })
        .expect(pragma)
    };
    assert_eq!(read("synchronous"), rusqlite::types::Value::Integer(2));
    assert_eq!(read("secure_delete"), rusqlite::types::Value::Integer(1));
    assert_eq!(
        read("journal_mode"),
        rusqlite::types::Value::Text("wal".into())
    );
    storage::check_durability(&conn).expect("writer settings");
    let audit_keys = AuditKeys {
        db_key: crypto::random(),
        mac_key: crypto::random(),
    };
    let audit_db = dir.join("audit.db");
    audit::create_audit_db(&audit_db, &audit_keys).expect("audit db");
    storage::open_writer(&audit_db, &audit_keys.db_key).expect("audit writer settings");
    let plain = storage::open_backup_target(&dir.join("plain.db"), &key).expect("plain");
    assert!(
        storage::check_durability(&plain).is_err(),
        "a connection without the setup is refused"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_sequence_advances_by_one_per_call_and_matches_the_chain() {
    let t = test_core("sequence").await;
    let mut seqs = Vec::new();
    for record in 1..=8 {
        let outcome = t
            .core
            .execute(Call::new(
                Principal::Member(1),
                Tool::TasksUpdate,
                FileId::TasksAdult1,
                Some(record),
            ))
            .await
            .expect("update");
        seqs.push(outcome.audit_seq);
    }
    assert_eq!(seqs, (1..=8).collect::<Vec<u64>>());
    assert_eq!(t.finish(), 8);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_audit_commit_is_inside_the_measured_audit_stage() {
    let delay = Duration::from_millis(60);
    let t = test_core_with_audit_delay("audit-delay", delay).await;
    let outcome = t
        .core
        .execute(Call::new(
            Principal::Member(1),
            Tool::TasksUpdate,
            FileId::TasksAdult1,
            Some(1),
        ))
        .await
        .expect("update");
    assert!(outcome.timings.audit >= delay, "{:?}", outcome.timings);
    t.finish();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn online_backup_runs_queued_writes_between_steps_and_copies_them() {
    let t = test_core("online").await;
    let writer = t.core.writer(FileId::Home).expect("home writer");
    let target_path = t.dir.join("home-copy.db");
    let target = storage::open_backup_target(&target_path, &t.keys[&FileId::Home]).expect("target");
    let backup = writer.online_backup(target, 1);
    let writes: Vec<_> = (0..20)
        .map(|_| {
            writer.run(|conn| {
                conn.execute(
                    "INSERT INTO records (source, taint, data_types, author, created_at,
                         updated_at, rev, title, body)
                     VALUES ('adapter', 'trusted', 'home_state', 'adapter:1', 0, 0, 1, 't', 'b')",
                    [],
                )
            })
        })
        .collect();
    let (steps, written) = tokio::join!(backup, futures_join(writes));
    let steps = steps.expect("online backup");
    assert!(steps.steps > 1);
    assert_eq!(written, 20);
    let copy = storage::open_reader(&target_path, &t.keys[&FileId::Home]).expect("copy opens");
    let copied = storage::record_count(&copy).expect("count");
    assert!(copied >= i64::from(ROWS) + i64::from(steps.interleaved_jobs));
    t.finish();
}

async fn futures_join<F, T>(futures: Vec<F>) -> usize
where
    F: std::future::Future<Output = Result<rusqlite::Result<T>, String>>,
{
    let mut done = 0;
    for future in futures {
        if matches!(future.await, Ok(Ok(_))) {
            done += 1;
        }
    }
    done
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_chain_verifies_and_detects_a_rewritten_entry() {
    let t = test_core("chain").await;
    for record in 1..=10 {
        t.core
            .execute(Call::new(
                Principal::Member(1),
                Tool::TasksUpdate,
                FileId::TasksAdult1,
                Some(record),
            ))
            .await
            .expect("update");
    }
    let dir = t.dir.clone();
    let keys = t.audit_keys.clone();
    let appended = t.core.audit_appends();
    drop(t.core);
    t.audit_thread.join().expect("thread").expect("serve");
    let db = dir.join("audit.db");
    assert_eq!(audit::verify_chain(&db, &keys), Ok(appended));
    let tamper = storage::open_backup_target(&db, &keys.db_key).expect("raw connection");
    tamper
        .execute("UPDATE entries SET entry = x'00' WHERE seq = 4", [])
        .expect("tamper");
    drop(tamper);
    assert_eq!(
        audit::verify_chain(&db, &keys),
        Err("audit chain broken at entry 4".to_owned())
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unlock_recovers_the_keys_and_refuses_a_wrong_passphrase() {
    let cost = Argon2Cost {
        m_kib: 8 * 1024,
        t: 1,
        p: 2,
    };
    let household_key = crypto::random::<32>();
    let (wrappers, dek) = crypto::enroll(cost, b"right", &household_key).expect("enroll");
    let keys = crypto::unlock(cost, b"right", &wrappers).expect("unlock");
    assert_eq!((keys.dek, keys.household_key), (dek, household_key));
    assert!(crypto::unlock(cost, b"wrong", &wrappers).is_err());
}

#[test]
fn a_short_run_of_the_whole_load_is_clean_and_times_probes_from_their_schedule() {
    let dir = scratch("smoke");
    let injected = Duration::from_millis(300);
    let cfg = Config {
        injected_pause: Some(injected),
        ..Config::smoke(dir.clone())
    };
    let report = load::run(&cfg).expect("run");
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert_eq!(report.audit_verified, Ok(report.audit_appends));
    assert_eq!(report.max_concurrent_unlocks, 2);
    assert!(report.max_permits_held <= cfg.pool_permits);
    assert!(report.backups > 0 && report.rule_dispatches > 0);
    assert!(report.audit_copies > 0 && report.retention_deleted > 0);
    assert!(report.watchdog_max_gap <= Duration::from_millis(150));
    assert!(
        report
            .summary(ALL_ACTIONS_LABEL)
            .is_some_and(|s| s.count > 0)
    );
    let expected = cfg.expected_probes();
    for label in [PROBE_LABEL, SOCKET_PROBE_LABEL] {
        let summary = report.summary(label).expect(label);
        assert!(
            (summary.count as u64).abs_diff(expected) <= 1,
            "{label}: {} samples, {expected} ticks",
            summary.count
        );
    }
    let member_probe = report.summary(PROBE_LABEL).expect("probe");
    assert!(
        member_probe.max >= injected,
        "a probe scheduled at the start of the injected pause waited it out: max {:?}",
        member_probe.max
    );
    let _ = std::fs::remove_dir_all(&dir);
}
