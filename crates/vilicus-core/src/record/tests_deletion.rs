//! Story 3.6, deletions that must be real (FR-29, D113, D132, E17): the journal retention purge
//! (AC6), the destruction of a wrapped record key (AC7) and the purge's checkpoint behind a reader
//! (AC8), each checked by the file inspection of Story 1.11 on the product build: every page of
//! the file and every frame of the WAL decrypted, the shm read as it is, and searched for runs of
//! 16 and of 8 bytes of the deleted values, with values that must remain as the control.

use std::sync::mpsc;
use std::thread;

use vilicus_module_api::{DataType, Field, FieldKind, ModuleDeclaration, Structured, Table, Value};
use vilicus_storage::{Handle, MigrationTrack, ModuleFile, Partition, Read, Write};
use vilicus_types::{HOME_JOURNAL_RETENTION, Id, ModuleName, UNDO_JOURNAL_RETENTION, UtcMillis};

use super::inspect::{Inspected, Needles, Rng, inspect};
use super::journal::encode_row;
use super::tests::{KEY, module, noon, raw_connection, registry_of, scratch_dir};
use super::tests_call::{ella, own_action};
use super::{CallResult, Invocation, Stamper, journal_retention, purge_expired_journal, run_call};

const DAY: i64 = 24 * 60 * 60 * 1000;

const SECRET_FIELDS: &[Field] = &[
    Field {
        name: "body",
        kind: FieldKind::FreeText { max_len: 8000 },
        optional: false,
    },
    Field {
        name: "status",
        kind: FieldKind::Structured(Structured::Enumeration(&["open", "done"])),
        optional: false,
    },
];

fn vault() -> &'static ModuleDeclaration {
    module(
        "vault",
        vec![Table {
            name: "secrets",
            data_types: &[DataType::Meals],
            fields: SECRET_FIELDS,
            elevation_exempt: false,
        }],
        None,
    )
}

/// `module`'s file in `partition`, its Core track at the Core's version and its module's
/// migrations applied, opened as the Core opens a file.
fn open_in(
    module: &'static ModuleDeclaration,
    partition: Partition,
    label: &str,
) -> (ModuleFile, Handle<Write>) {
    let file = ModuleFile::new(
        scratch_dir(label),
        ModuleName::from_static(module.name),
        partition,
    );
    let epoch = vilicus_storage::KeyEpoch {
        partition_root_version: 1,
        generation: 0,
    };
    vilicus_storage::create(&file, &KEY, epoch)
        .expect("create")
        .close()
        .expect("close");
    let mut migration =
        vilicus_storage::open::<vilicus_storage::Migration>(&file, &KEY).expect("open");
    migration
        .apply_module_migrations(
            &crate::registry::frozen_migrations(module).expect("frozen migrations"),
        )
        .expect("migrate");
    migration.close().expect("close");
    let handle = registry_of(vec![module])
        .open::<Write>(&file, &KEY)
        .expect("open");
    assert_eq!(
        handle
            .schema_version(MigrationTrack::Module)
            .expect("version"),
        1
    );
    (file, handle)
}

/// A clock a test sets, and random bits for new ids from a fixed seed.
struct Clock {
    now: UtcMillis,
    rng: Rng,
}

impl Clock {
    fn at(now: UtcMillis) -> Self {
        Self {
            now,
            rng: Rng::new(0x5eed),
        }
    }

    fn set(&mut self, start: UtcMillis, millis: i64) {
        self.now = UtcMillis::from_millis(start.as_millis() + millis).expect("in range");
    }

    fn call_id(&mut self) -> Id {
        Id::new_v7(self.now, self.rng.random_10()).expect("after the epoch")
    }
}

impl Stamper for Clock {
    fn now(&mut self) -> UtcMillis {
        self.now
    }

    fn id_random(&mut self) -> [u8; 10] {
        self.rng.random_10()
    }
}

fn secret(body: &str, status: &str) -> Vec<(&'static str, Value)> {
    vec![
        ("body", Value::Text(body.to_owned())),
        ("status", Value::Text(status.to_owned())),
    ]
}

/// Runs one own-action call of Ella's under `call_id`, which must commit, and returns its value.
fn commit<T>(
    handle: &Handle<Write>,
    module: &'static ModuleDeclaration,
    clock: &mut Clock,
    call_id: Id,
    body: impl FnOnce(&mut dyn vilicus_module_api::Records) -> Result<T, vilicus_module_api::WriteError>,
) -> T {
    let invocation = Invocation {
        call_id: call_id.into(),
        request_hash: None,
        delivery: None,
    };
    match run_call(
        handle,
        module,
        &own_action(ella()),
        &invocation,
        clock,
        body,
    ) {
        Ok(CallResult::Committed(outcome)) => outcome.value,
        _ => panic!("the call commits"),
    }
}

/// The values a workload wrote: those of expired journal entries only, which the purge must
/// remove, and those of live entries and live records, which must remain.
#[derive(Default)]
struct Workload {
    expired: Needles,
    live: Needles,
}

/// Interleaves, so they share pages: calls dated `old` that insert, update and delete records
/// (every value of those records lives in expired journal entries only), and calls dated
/// `recent` that insert and update records (their values live in live entries and live rows).
/// One record in three carries text long enough to spill into overflow pages.
fn write_workload(
    handle: &Handle<Write>,
    module: &'static ModuleDeclaration,
    clock: &mut Clock,
    rounds: usize,
    old: UtcMillis,
    recent: UtcMillis,
) -> Workload {
    let mut rng = Rng::new(0xe17);
    let mut workload = Workload::default();
    for round in 0..rounds {
        let length = if round % 3 == 0 { 3000 } else { 48 };
        let offset = i64::try_from(round).expect("small");
        let [x, y, p, q] = [0; 4].map(|_| rng.text(length));

        clock.set(old, offset);
        let first_call = clock.call_id();
        let expired = commit(handle, module, clock, first_call, |records| {
            records.insert("secrets", &secret(&x, "open"), &[])
        });
        clock.set(recent, offset);
        let live_call = clock.call_id();
        let live = commit(handle, module, clock, live_call, |records| {
            records.insert("secrets", &secret(&p, "open"), &[])
        });
        clock.set(old, offset + 1);
        let update_call = clock.call_id();
        commit(handle, module, clock, update_call, |records| {
            records.update("secrets", expired.id, expired.rev, &secret(&y, "done"), &[])
        });
        clock.set(recent, offset + 1);
        let live_update = clock.call_id();
        commit(handle, module, clock, live_update, |records| {
            records.update("secrets", live.id, live.rev, &secret(&q, "done"), &[])
        });
        clock.set(old, offset + 2);
        let delete_call = clock.call_id();
        commit(handle, module, clock, delete_call, |records| {
            records.delete("secrets", expired.id)
        });

        for value in [x.as_bytes(), y.as_bytes()] {
            workload.expired.add(value);
        }
        for id in [first_call, update_call, delete_call] {
            workload.expired.add(&id.to_bytes());
        }
        for value in [p.as_bytes(), q.as_bytes()] {
            workload.live.add(value);
        }
        for id in [live_call, live_update] {
            workload.live.add(&id.to_bytes());
        }
    }
    workload
}

/// No run of 16, nor of 8, bytes of any expired value anywhere: the file, the WAL, the shm.
fn assert_gone(needles: &Needles, inspected: &Inspected, what: &str) {
    for (part, bytes) in inspected.parts() {
        assert_eq!(
            (needles.found_in(bytes), needles.found_in_short(bytes)),
            (0, 0),
            "{what}: a run of 16 or 8 bytes of a deleted value in the {part}"
        );
    }
}

fn file_and_wal(inspected: &Inspected) -> Vec<u8> {
    [inspected.file.as_slice(), inspected.wal.as_slice()].concat()
}

/// AC6 (FR-29, D113, D132, E17): in a personal and in the household partition, the retention
/// purge deletes every journal entry older than 30 days in one `DELETE`, then checkpoints in
/// TRUNCATE mode in the same step: the WAL is empty, and no run of 8 bytes or more of any deleted
/// before-image, after-image or call id remains in the file, the WAL or the shm, while every live
/// value is found in the file. Before the purge, every expired value is found: the scan sees them.
#[test]
fn the_retention_purge_leaves_no_run_of_an_expired_entry() {
    let module = vault();
    for partition in [Partition::Member(ella()), Partition::Household] {
        assert_eq!(journal_retention(partition), UNDO_JOURNAL_RETENTION);
        let (file, handle) = open_in(module, partition, "retention");
        let start = noon();
        let mut clock = Clock::at(start);
        let recent = UtcMillis::from_millis(start.as_millis() + 29 * DAY).expect("in range");
        let workload = write_workload(&handle, module, &mut clock, 12, start, recent);

        let before = inspect(&file, &KEY);
        let everywhere = file_and_wal(&before);
        assert_eq!(
            workload.expired.found_in(&everywhere),
            workload.expired.len(),
            "{partition}: the scan finds every expired value before the purge"
        );
        assert!(before.wal_frames > 0, "the workload is still in the WAL");

        let now = UtcMillis::from_millis(start.as_millis() + 31 * DAY).expect("in range");
        let purge = purge_expired_journal(&handle, now).expect("purge");
        assert_eq!(
            purge.deleted, 36,
            "{partition}: three expired entries a round"
        );
        assert_eq!(purge.checkpoint_attempts, 1);

        let after = inspect(&file, &KEY);
        assert_eq!(
            (after.wal_frames, after.wal.len()),
            (0, 0),
            "{partition}: the WAL is empty"
        );
        assert_gone(&workload.expired, &after, &partition.to_string());
        assert_eq!(
            workload.live.found_in(&after.file),
            workload.live.len(),
            "{partition}: every live value is in the file"
        );
        handle.close().expect("close");
    }
}

/// AD-26: the home partition keeps its journal 24 hours, the other partitions 30 days.
#[test]
fn the_home_partition_keeps_its_journal_a_day() {
    assert_eq!(journal_retention(Partition::Home), HOME_JOURNAL_RETENTION);
    let module = vault();
    let (file, handle) = open_in(module, Partition::Home, "retention-home");
    let start = noon();
    let mut clock = Clock::at(start);
    let recent = UtcMillis::from_millis(start.as_millis() + 2 * DAY).expect("in range");
    let workload = write_workload(&handle, module, &mut clock, 3, start, recent);
    let now = UtcMillis::from_millis(start.as_millis() + 2 * DAY + 60_000).expect("in range");
    let purge = purge_expired_journal(&handle, now).expect("purge");
    assert_eq!(purge.deleted, 9);
    let after = inspect(&file, &KEY);
    assert_gone(&workload.expired, &after, "home");
    assert_eq!(workload.live.found_in(&after.file), workload.live.len());
}

/// AC8 (E17, gate E17-2): a reader holding an old snapshot keeps the purge's TRUNCATE checkpoint
/// busy; the purge retries it, and once the reader ends the WAL is empty and no deleted value
/// remains. A reader that outlasts every attempt makes the purge fail, its deleted values still
/// in the WAL, until the next checkpoint after the reader ends. The reader ends once the purge
/// reports a busy attempt, or once the purge returned, never on a timer.
#[test]
fn the_purge_checkpoint_waits_for_a_reader_and_completes_once_it_ends() {
    let module = vault();
    for completes in [true, false] {
        let (file, mut handle) = open_in(module, Partition::Household, "retention-reader");
        let (end, ended) = mpsc::channel::<()>();
        if completes {
            let busy = end.clone();
            handle.observe_checkpoint_retries(Box::new(move |_| {
                // The reader waits for the first; later sends find no receiver.
                let _ = busy.send(());
            }));
        }
        let start = noon();
        let mut clock = Clock::at(start);
        let recent = UtcMillis::from_millis(start.as_millis() + 29 * DAY).expect("in range");
        let workload = write_workload(&handle, module, &mut clock, 6, start, recent);

        let (ready, started) = mpsc::channel();
        let reader_file = file.clone();
        let reader = thread::spawn(move || {
            let reader = vilicus_storage::open::<Read>(&reader_file, &KEY).expect("open reader");
            reader.execute_batch("BEGIN").expect("begin");
            let _: i64 = reader
                .query_row("SELECT count(*) FROM secrets", [], |row| row.get(0))
                .expect("take a snapshot");
            ready.send(()).expect("signal");
            ended.recv().expect("released");
            reader.execute_batch("COMMIT").expect("end the snapshot");
            reader.close().expect("close the reader");
        });
        started.recv().expect("the reader holds its snapshot");
        let now = UtcMillis::from_millis(start.as_millis() + 31 * DAY).expect("in range");
        let purge = purge_expired_journal(&handle, now);
        if completes {
            let purge = purge.expect("the purge completes once the reader ends");
            assert!(
                purge.checkpoint_attempts > 1,
                "the checkpoint was busy: {purge:?}"
            );
            reader.join().expect("reader");
        } else {
            assert!(
                matches!(
                    purge,
                    Err(super::RecordError::Storage(
                        vilicus_storage::Error::DeletedNotCheckpointed { deleted: 18, .. }
                    ))
                ),
                "{purge:?}"
            );
            let still = inspect(&file, &KEY);
            assert!(
                workload.expired.found_in(&still.wal) > 0,
                "while the reader holds its snapshot, deleted values stay in the WAL"
            );
            end.send(()).expect("the reader waits");
            reader.join().expect("reader");
            handle
                .checkpoint_truncate()
                .expect("the next checkpoint completes");
        }
        let after = inspect(&file, &KEY);
        assert_eq!(after.wal_frames, 0);
        assert_gone(&workload.expired, &after, "after the reader");
        assert_eq!(workload.live.found_in(&after.file), workload.live.len());
    }
}

/// Twenty records, each with a wrapped record key in `_record_keys` and a journaled update, and
/// their ciphertext stand-ins, keys and ids.
struct Shreddable {
    records: Vec<Id>,
    keys: Vec<Vec<u8>>,
    ciphertexts: Vec<String>,
}

fn shreddable(
    handle: &Handle<Write>,
    module: &'static ModuleDeclaration,
    clock: &mut Clock,
) -> Shreddable {
    let mut rng = Rng::new(0x5bed);
    let mut made = Shreddable {
        records: Vec::new(),
        keys: Vec::new(),
        ciphertexts: Vec::new(),
    };
    for _ in 0..20 {
        let ciphertext = rng.text(96);
        let key = rng.bytes(48);
        let call_id = clock.call_id();
        let written = commit(handle, module, clock, call_id, |records| {
            records.insert("secrets", &secret(&ciphertext, "open"), &[])
        });
        handle
            .store_wrapped_record_key(written.id, &key)
            .expect("store the wrapped key");
        let update = clock.call_id();
        commit(handle, module, clock, update, |records| {
            records.update(
                "secrets",
                written.id,
                written.rev,
                &secret(&ciphertext, "done"),
                &[],
            )
        });
        made.records.push(written.id);
        made.keys.push(key);
        made.ciphertexts.push(ciphertext);
    }
    made
}

fn needles<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> Needles {
    let mut needles = Needles::default();
    for value in values {
        needles.add(value);
    }
    needles
}

/// AC7 (D132, E17): shredding a record deletes its wrapped key under `secure_delete` = ON and
/// checkpoints in TRUNCATE mode: no run of 8 bytes or more of a destroyed key remains in the file,
/// the WAL or the shm, `_journal` included, since no journal image holds a key, while the
/// shredded records' ciphertext and the kept keys remain in the file.
#[test]
fn shredding_leaves_no_run_of_the_destroyed_key() {
    let module = vault();
    let (file, handle) = open_in(module, Partition::Household, "shredding");
    let mut clock = Clock::at(noon());
    let made = shreddable(&handle, module, &mut clock);
    let destroyed = needles(made.keys[..10].iter().map(Vec::as_slice));
    let kept = needles(made.keys[10..].iter().map(Vec::as_slice));
    let ciphertexts = needles(made.ciphertexts[..10].iter().map(String::as_bytes));

    let before = inspect(&file, &KEY);
    assert_eq!(
        destroyed.found_in(&file_and_wal(&before)),
        10,
        "the scan sees the keys"
    );
    for record in &made.records[..10] {
        let shredded = handle.destroy_wrapped_record_key(*record).expect("shred");
        assert_eq!(
            (shredded.key_deleted, shredded.checkpoint_attempts),
            (true, 1)
        );
    }
    let after = inspect(&file, &KEY);
    assert_eq!(after.wal_frames, 0);
    assert_gone(&destroyed, &after, "destroyed keys");
    assert_eq!(kept.found_in(&after.file), 10, "the kept keys remain");
    assert_eq!(
        ciphertexts.found_in(&after.file),
        10,
        "the shredded records remain"
    );
    for record in &made.records[..10] {
        assert_eq!(handle.wrapped_record_key(*record).expect("read"), None);
    }
}

/// AC7, the negative control of Story 1.11 (`journaled_shredding_keeps_keys_until_journal_rows_go`):
/// had the journal imaged the key row, as the alternative of D132 would, the destroyed keys
/// would stay readable in `_journal` after the shredding and its checkpoint, until those journal
/// rows go, here by the retention purge.
#[test]
fn a_journaled_shredding_keeps_the_keys_until_the_journal_rows_go() {
    let module = vault();
    let (file, handle) = open_in(module, Partition::Household, "shredding-journaled");
    let start = noon();
    let mut clock = Clock::at(start);
    clock.set(start, 40 * DAY);
    let made = shreddable(&handle, module, &mut clock);
    let destroyed = needles(made.keys[..10].iter().map(Vec::as_slice));
    let kept = needles(made.keys[10..].iter().map(Vec::as_slice));

    let raw = raw_connection(&file);
    for (record, key) in made.records[..10].iter().zip(&made.keys) {
        let columns = [
            Value::Blob(record.to_bytes().to_vec()),
            Value::Blob(key.clone()),
        ];
        let image = encode_row(["record_id", "wrapped_key"].into_iter().zip(columns.iter()));
        raw.execute(
            "INSERT INTO _journal (call_id, principal, source, authority, member, change_index, \
             record_table, record_id, rev_before, rev_after, image_before, image_after, inputs, \
             created_at) VALUES (?1, 'Member', 'member(x)', 'own_action', NULL, 0, \
             '_record_keys', ?2, NULL, NULL, ?3, NULL, x'010000', ?4)",
            rusqlite::params![
                clock.call_id().to_bytes(),
                record.to_bytes(),
                image,
                start.as_millis()
            ],
        )
        .expect("journal the key row as the alternative would");
    }
    drop(raw);
    for record in &made.records[..10] {
        handle.destroy_wrapped_record_key(*record).expect("shred");
    }
    let kept_in_journal = inspect(&file, &KEY);
    assert_eq!(kept_in_journal.wal_frames, 0);
    assert_eq!(
        destroyed.found_in(&kept_in_journal.file),
        10,
        "the journal still holds every destroyed key"
    );

    let now = UtcMillis::from_millis(start.as_millis() + 31 * DAY).expect("in range");
    let purge = purge_expired_journal(&handle, now).expect("purge");
    assert_eq!(
        purge.deleted, 10,
        "only the rows that imaged the keys are expired"
    );
    let after = inspect(&file, &KEY);
    assert_gone(&destroyed, &after, "once the journal rows go");
    assert_eq!(kept.found_in(&after.file), 10);
}
