//! Story 3.6: the Core tables the Core migration track makes (AD-26). Module SQL, in a migration,
//! on a write or read handle or in a trigger body, can neither write, reshape nor read the
//! private ones (journal, outbox, consumed events, dead letters, record keys); the Core's own
//! statements write them: journal rows and their purge, effect intents and their outcomes,
//! consumed events and wrapped record keys.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use vilicus_types::{EffectOutcome, Id, Principal, Rev, Source, UtcMillis};

use super::{EPOCH, KEY, create_module_file, raw_connection, scratch_dir};
use crate::error::Error;
use crate::{
    AuthorityKind, CHECKPOINT_ATTEMPTS, CORE_PRIVATE_TABLES, CORE_TABLES, CallKey, EffectIntent,
    EffectState, JournalEntry, Migration, ModuleFile, Read, Write, create, open,
};

/// The statements module SQL might run against the Core table `table`, whose first column is
/// `column`: reads, row writes and schema changes.
fn hostile(table: &str, column: &str) -> Vec<(String, String)> {
    [
        ("read", format!("SELECT * FROM {table}")),
        (
            "read_qualified",
            format!("SELECT {column} FROM main.{table}"),
        ),
        (
            "read_other_case",
            format!("SELECT count({column}) FROM {}", table.to_ascii_uppercase()),
        ),
        ("delete", format!("DELETE FROM {table}")),
        ("update", format!("UPDATE {table} SET {column} = {column}")),
        ("drop", format!("DROP TABLE {table}")),
        ("rename", format!("ALTER TABLE {table} RENAME TO gone")),
        (
            "add_column",
            format!("ALTER TABLE {table} ADD COLUMN extra TEXT"),
        ),
        ("index", format!("CREATE INDEX probe ON {table} ({column})")),
        (
            "trigger",
            format!("CREATE TRIGGER probe AFTER DELETE ON {table} BEGIN SELECT 1; END"),
        ),
    ]
    .into_iter()
    .map(|(name, sql)| (format!("{table}_{name}"), sql))
    .collect()
}

fn first_column(file: &ModuleFile, table: &str) -> String {
    raw_connection(&file.path())
        .query_row(
            &format!("SELECT name FROM pragma_table_info('{table}') ORDER BY cid LIMIT 1"),
            [],
            |row| row.get(0),
        )
        .expect("a Core table has columns")
}

fn every_hostile_statement(file: &ModuleFile) -> Vec<(String, String)> {
    CORE_PRIVATE_TABLES
        .iter()
        .flat_map(|table| hostile(table, &first_column(file, table)))
        .collect()
}

/// The schema entries of the Core tables, read without the authorizer.
fn core_schema(file: &ModuleFile) -> Vec<String> {
    super::schema(file)
        .into_iter()
        .filter(|entry| CORE_TABLES.iter().any(|table| entry.contains(table)))
        .collect()
}

#[test]
fn without_the_authorizer_every_core_table_statement_runs() {
    let reference = create_module_file(&scratch_dir("core-rows-reference"));
    let mut failures = Vec::new();
    for (name, sql) in every_hostile_statement(&reference) {
        let file = create_module_file(&scratch_dir(&format!("core-rows-control-{name}")));
        if let Err(error) = raw_connection(&file.path()).execute_batch(&sql) {
            failures.push(format!("{name}: {error}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn every_core_table_statement_is_refused_in_a_migration() {
    let file = create_module_file(&scratch_dir("core-rows-migration"));
    let before = core_schema(&file);
    let mut failures = Vec::new();
    for (name, sql) in every_hostile_statement(&file) {
        let mut handle = open::<Migration>(&file, &KEY).expect("open");
        let outcome = handle.apply_migration(&format!("CREATE TABLE added (x INTEGER);\n{sql};"));
        handle.close().expect("close");
        if !outcome.as_ref().is_err_and(Error::is_refusal) {
            failures.push(format!("{name}: {outcome:?}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    assert_eq!(core_schema(&file), before);
}

#[test]
fn every_core_table_statement_is_refused_on_write_and_read_handles() {
    let file = create_module_file(&scratch_dir("core-rows-handles"));
    let statements = every_hostile_statement(&file);
    let writer = open::<Write>(&file, &KEY).expect("open");
    let reader = open::<Read>(&file, &KEY).expect("open");
    let mut failures = Vec::new();
    for (name, sql) in &statements {
        for (role, outcome) in [
            ("write", writer.execute_batch(sql)),
            ("read", reader.execute_batch(sql)),
        ] {
            if !outcome.as_ref().is_err_and(Error::is_refusal) {
                failures.push(format!("{role} {name}: {outcome:?}"));
            }
        }
    }
    writer.close().expect("close");
    reader.close().expect("close");
    assert!(failures.is_empty(), "{failures:#?}");
}

/// A trigger body is authorized when it fires: a trigger on a module table that writes a private
/// Core table, or copies from it into a module table, makes the write that fires it fail.
#[test]
fn a_trigger_that_reaches_a_core_table_is_refused_when_it_fires() {
    for table in CORE_PRIVATE_TABLES {
        for body in [
            format!("DELETE FROM {table};"),
            format!("INSERT INTO items (label) SELECT count(*) FROM {table};"),
        ] {
            let file = create_module_file(&scratch_dir("core-rows-trigger"));
            raw_connection(&file.path())
                .execute_batch(&format!(
                    "CREATE TRIGGER items_reach AFTER INSERT ON items WHEN NEW.label = 'fire' \
                     BEGIN {body} END"
                ))
                .expect("plant the trigger");
            let writer = open::<Write>(&file, &KEY).expect("open");
            let fired = writer.execute_batch("INSERT INTO items (label) VALUES ('fire')");
            writer.close().expect("close");
            assert!(
                fired.as_ref().is_err_and(Error::is_refusal),
                "{table} {body}: {fired:?}"
            );
        }
    }
}

fn id(last: u8) -> Id {
    let mut bytes = [0x11; 16];
    bytes[6] = 0x70;
    bytes[8] = 0x80;
    bytes[15] = last;
    Id::from_bytes(bytes).expect("a UUIDv7")
}

fn at(millis: i64) -> UtcMillis {
    UtcMillis::from_millis(1_790_000_000_000 + millis).expect("in range")
}

fn new_writer(label: &str) -> crate::Handle<Write> {
    let file = super::module_file(&scratch_dir(label));
    create(&file, &KEY, EPOCH).expect("create")
}

fn entry<'a>(call: CallKey<'a>, change_index: u32, record: Id, at: UtcMillis) -> JournalEntry<'a> {
    JournalEntry {
        call,
        authority: AuthorityKind::OwnAction,
        member: Some(id(1)),
        change_index,
        table: "items",
        record,
        rev_before: None,
        rev_after: Some(Rev::FIRST),
        image_before: None,
        image_after: Some(b"after image"),
        inputs: b"inputs",
        created_at: at,
    }
}

#[test]
fn a_journal_row_joins_the_callers_transaction_and_is_read_back_by_its_call() {
    let writer = new_writer("journal-rows");
    let source = Source::Member(id(1));
    let call = CallKey {
        principal: Principal::Member,
        source: &source,
        call_id: id(9),
    };
    assert!(matches!(
        writer.append_journal(&entry(call, 0, id(20), at(0))),
        Err(Error::NoTransaction)
    ));
    writer.execute_batch("BEGIN IMMEDIATE").expect("begin");
    writer
        .append_journal(&entry(call, 1, id(21), at(0)))
        .expect("second change");
    writer
        .append_journal(&entry(call, 0, id(20), at(0)))
        .expect("first change");
    assert!(
        writer
            .append_journal(&entry(call, 0, id(22), at(0)))
            .is_err(),
        "a call has one row per change"
    );
    writer.execute_batch("COMMIT").expect("commit");

    let rows = writer.journaled_call(&call).expect("read");
    let records: Vec<(u32, Id)> = rows
        .iter()
        .map(|row| (row.change_index, row.record))
        .collect();
    assert_eq!(records, [(0, id(20)), (1, id(21))]);
    assert_eq!(rows[0].authority, AuthorityKind::OwnAction);
    assert_eq!(rows[0].member, Some(id(1)));
    assert_eq!(rows[0].image_after.as_deref(), Some(&b"after image"[..]));
    assert_eq!(rows[0].created_at, at(0));
    let other = Source::Member(id(2));
    for key in [
        CallKey {
            principal: Principal::Cli,
            ..call
        },
        CallKey {
            source: &other,
            ..call
        },
        CallKey {
            call_id: id(8),
            ..call
        },
    ] {
        assert!(
            writer.journaled_call(&key).expect("read").is_empty(),
            "{key:?}"
        );
    }

    writer.execute_batch("BEGIN IMMEDIATE").expect("begin");
    writer
        .append_journal(&entry(call, 2, id(23), at(0)))
        .expect("third change");
    writer.execute_batch("ROLLBACK").expect("rollback");
    assert_eq!(writer.journaled_call(&call).expect("read").len(), 2);
}

#[test]
fn the_purge_deletes_the_rows_before_the_cutoff_and_empties_the_wal() {
    let writer = new_writer("journal-purge");
    let source = Source::Member(id(1));
    for (call_id, time) in [(id(1), at(0)), (id(2), at(10)), (id(3), at(20))] {
        let call = CallKey {
            principal: Principal::Member,
            source: &source,
            call_id,
        };
        writer.execute_batch("BEGIN IMMEDIATE").expect("begin");
        writer
            .append_journal(&entry(call, 0, id(30), time))
            .expect("journal");
        writer.execute_batch("COMMIT").expect("commit");
    }
    let purge = writer.purge_journal(at(10)).expect("purge");
    assert_eq!(purge.deleted, 1);
    assert_eq!(purge.checkpoint_attempts, 1);
    let remaining = |call_id| {
        writer
            .journaled_call(&CallKey {
                principal: Principal::Member,
                source: &source,
                call_id,
            })
            .expect("read")
            .len()
    };
    assert_eq!(
        [remaining(id(1)), remaining(id(2)), remaining(id(3))],
        [0, 1, 1]
    );
    assert_eq!(
        std::fs::metadata(writer.file().wal_path()).map_or(0, |metadata| metadata.len()),
        0
    );
}

/// AC8 of Story 3.6, at the storage layer: a reader holding a snapshot keeps the purge's TRUNCATE
/// checkpoint busy; the purge retries, and completes once the reader ends within the attempts.
/// A reader that outlasts them makes the purge fail rather than claim the rows are gone.
#[test]
fn the_purge_retries_its_checkpoint_until_a_reader_ends() {
    let writer = new_writer("journal-purge-reader");
    let source = Source::Member(id(1));
    let call = CallKey {
        principal: Principal::Member,
        source: &source,
        call_id: id(1),
    };
    let file = writer.file().clone();
    for (index, created_at) in [(0, at(0)), (1, at(0))] {
        writer.execute_batch("BEGIN IMMEDIATE").expect("begin");
        writer
            .append_journal(&entry(
                CallKey {
                    call_id: id(index + 1),
                    ..call
                },
                0,
                id(40),
                created_at,
            ))
            .expect("journal");
        writer.execute_batch("COMMIT").expect("commit");
    }

    let hold_reader = |hold: Duration| {
        let file = file.clone();
        let (ready, started) = mpsc::channel();
        let reader = thread::spawn(move || {
            let reader = open::<Read>(&file, &KEY).expect("open reader");
            reader.execute_batch("BEGIN").expect("begin");
            let _: i64 = reader
                .query_row("SELECT count(*) FROM _meta", [], |row| row.get(0))
                .expect("take a snapshot");
            ready.send(()).expect("signal");
            thread::sleep(hold);
            reader.execute_batch("COMMIT").expect("end the snapshot");
            reader.close().expect("close");
        });
        started.recv().expect("the reader holds its snapshot");
        reader
    };

    let reader = hold_reader(Duration::from_millis(250));
    let purge = writer
        .purge_journal(at(1))
        .expect("completes once the reader ends");
    reader.join().expect("reader");
    assert_eq!(purge.deleted, 2);
    assert!(purge.checkpoint_attempts > 1, "{purge:?}");

    writer.execute_batch("BEGIN IMMEDIATE").expect("begin");
    writer
        .append_journal(&entry(
            CallKey {
                call_id: id(5),
                ..call
            },
            0,
            id(41),
            at(0),
        ))
        .expect("journal");
    writer.execute_batch("COMMIT").expect("commit");
    let reader = hold_reader(Duration::from_millis(u64::from(CHECKPOINT_ATTEMPTS) * 400));
    let outlasted = writer.purge_journal(at(1));
    reader.join().expect("reader");
    assert!(
        matches!(outlasted, Err(Error::CheckpointIncomplete { .. })),
        "{outlasted:?}"
    );
    writer
        .checkpoint_truncate()
        .expect("the next checkpoint completes once the reader ended");
}

fn intent<'a>(call: CallKey<'a>, intent_id: Id, key: &'a [u8]) -> EffectIntent<'a> {
    EffectIntent {
        call,
        member: Some(id(1)),
        id: intent_id,
        effect: "send_message",
        idempotency_key: key,
        payload: b"parameters",
        created_at: at(0),
    }
}

#[test]
fn an_effect_intent_commits_with_its_call_once_per_key() {
    let writer = new_writer("effects");
    let source = Source::AiTask(id(7));
    let call = CallKey {
        principal: Principal::AiTask,
        source: &source,
        call_id: id(9),
    };
    assert!(matches!(
        writer.append_effect(&intent(call, id(50), b"key-1")),
        Err(Error::NoTransaction)
    ));
    writer.execute_batch("BEGIN IMMEDIATE").expect("begin");
    for refused in [
        intent(call, id(50), b""),
        EffectIntent {
            effect: "",
            ..intent(call, id(50), b"k")
        },
    ] {
        assert!(matches!(
            writer.append_effect(&refused),
            Err(Error::InvalidEffectIntent)
        ));
    }
    let first = writer
        .append_effect(&intent(call, id(50), b"key-1"))
        .expect("intent");
    assert_eq!(
        (first.id, first.state, first.attempts),
        (id(50), EffectState::Pending, 0)
    );
    let again = writer
        .append_effect(&intent(call, id(51), b"key-1"))
        .expect("same key");
    assert_eq!(again, first, "an intent of the same key is the earlier one");
    writer.execute_batch("ROLLBACK").expect("rollback");
    assert!(writer.effects_of_call(&call).expect("read").is_empty());

    writer.execute_batch("BEGIN IMMEDIATE").expect("begin");
    writer
        .append_effect(&intent(call, id(50), b"key-1"))
        .expect("intent");
    writer
        .append_effect(&intent(call, id(52), b"key-2"))
        .expect("intent");
    writer.execute_batch("COMMIT").expect("commit");
    let ids: Vec<Id> = writer
        .effects_of_call(&call)
        .expect("read")
        .into_iter()
        .map(|row| row.id)
        .collect();
    assert_eq!(ids, [id(50), id(52)]);
    assert_eq!(
        writer
            .effects_in_state(EffectState::Pending)
            .expect("read")
            .len(),
        2
    );
}

/// AC4 of Story 3.6: an outcome is recorded once per attempt; only a failed intent is retried,
/// with its id and its key; an unknown one is never retried.
#[test]
fn outcomes_are_recorded_and_only_a_failed_intent_is_retried() {
    let writer = new_writer("effect-outcomes");
    let source = Source::AiTask(id(7));
    let call = CallKey {
        principal: Principal::AiTask,
        source: &source,
        call_id: id(9),
    };
    writer.execute_batch("BEGIN IMMEDIATE").expect("begin");
    for (intent_id, key) in [
        (id(60), &b"done"[..]),
        (id(61), &b"failed"[..]),
        (id(62), &b"unknown"[..]),
    ] {
        writer
            .append_effect(&intent(call, intent_id, key))
            .expect("intent");
    }
    writer.execute_batch("COMMIT").expect("commit");

    for (intent_id, outcome) in [
        (id(60), EffectOutcome::Done),
        (id(61), EffectOutcome::Failed),
        (id(62), EffectOutcome::Unknown),
    ] {
        let row = writer
            .record_effect_outcome(intent_id, outcome, at(5))
            .expect("record");
        assert_eq!(
            (row.state, row.attempts, row.updated_at),
            (EffectState::from(outcome), 1, at(5))
        );
        assert!(
            matches!(
                writer.record_effect_outcome(intent_id, EffectOutcome::Done, at(6)),
                Err(Error::EffectNotPending { state }) if state == EffectState::from(outcome)
            ),
            "{outcome}"
        );
    }
    for (intent_id, state) in [(id(60), EffectState::Done), (id(62), EffectState::Unknown)] {
        assert!(
            matches!(writer.retry_effect(intent_id, at(7)), Err(Error::EffectNotRetryable { state: found }) if found == state),
            "{state}"
        );
    }
    let retried = writer.retry_effect(id(61), at(7)).expect("retry");
    assert_eq!(
        (
            retried.id,
            retried.idempotency_key.as_slice(),
            retried.state,
            retried.attempts
        ),
        (id(61), &b"failed"[..], EffectState::Pending, 1)
    );
    assert!(matches!(
        writer.retry_effect(id(61), at(8)),
        Err(Error::EffectNotRetryable {
            state: EffectState::Pending
        })
    ));
    let unknown: Vec<(Id, Option<Id>)> = writer
        .effects_in_state(EffectState::Unknown)
        .expect("read")
        .into_iter()
        .map(|row| (row.id, row.member))
        .collect();
    assert_eq!(unknown, [(id(62), Some(id(1)))]);
    assert!(matches!(
        writer.record_effect_outcome(id(63), EffectOutcome::Done, at(9)),
        Err(Error::EffectNotFound)
    ));
}

#[test]
fn a_consumed_event_is_recorded_in_the_transaction_of_its_effect() {
    let writer = new_writer("consumed");
    assert!(matches!(
        writer.record_consumed(id(70), "notes", at(0)),
        Err(Error::NoTransaction)
    ));
    writer.execute_batch("BEGIN IMMEDIATE").expect("begin");
    writer
        .record_consumed(id(70), "notes", at(0))
        .expect("record");
    writer.execute_batch("ROLLBACK").expect("rollback");
    assert!(!writer.is_consumed(id(70), "notes").expect("read"));
    writer.execute_batch("BEGIN IMMEDIATE").expect("begin");
    writer
        .record_consumed(id(70), "notes", at(0))
        .expect("record");
    assert!(
        writer.record_consumed(id(70), "notes", at(1)).is_err(),
        "once per consumer"
    );
    writer.execute_batch("COMMIT").expect("commit");
    assert!(writer.is_consumed(id(70), "notes").expect("read"));
    assert!(!writer.is_consumed(id(70), "meals").expect("read"));
    assert!(!writer.is_consumed(id(71), "notes").expect("read"));
}

#[test]
fn a_wrapped_record_key_is_stored_once_and_destroyed_with_a_checkpoint() {
    let writer = new_writer("record-keys");
    assert!(matches!(
        writer.store_wrapped_record_key(id(80), b""),
        Err(Error::InvalidWrappedKey)
    ));
    writer
        .store_wrapped_record_key(id(80), b"wrapped key bytes")
        .expect("store");
    assert!(
        writer.store_wrapped_record_key(id(80), b"another").is_err(),
        "a record's key is never replaced"
    );
    assert_eq!(
        writer.wrapped_record_key(id(80)).expect("read").as_deref(),
        Some(&b"wrapped key bytes"[..])
    );
    let shredded = writer.destroy_wrapped_record_key(id(80)).expect("destroy");
    assert_eq!(shredded.checkpoint_attempts, 1);
    assert_eq!(writer.wrapped_record_key(id(80)).expect("read"), None);
    assert_eq!(
        std::fs::metadata(writer.file().wal_path()).map_or(0, |metadata| metadata.len()),
        0
    );
    assert!(matches!(
        writer.destroy_wrapped_record_key(id(80)),
        Err(Error::RecordKeyNotFound)
    ));
}
