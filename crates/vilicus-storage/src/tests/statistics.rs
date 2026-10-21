//! Story 3.6 review, M1: `ANALYZE` samples index keys into SQLite's statistics tables, those of
//! the Core's private indexes included (call ids, idempotency keys, wrapped record keys), into
//! rows every role could read and that outlive the rows they were sampled from. No policy runs
//! it, and module SQL neither creates, writes nor reads a statistics table. The two experiments
//! of the review are kept as regression tests.

use vilicus_types::{CallId, Id, Principal, Rev, Source, UtcMillis};

use super::{KEY, create_module_file, frozen, raw_connection, scratch_dir};
use crate::error::Error;
use crate::{
    AuthorityKind, CallKey, EffectIntent, JournalEntry, Migration, ModuleFile, Read, Write, open,
};

fn id(last: u8) -> Id {
    let mut bytes = [0x11; 16];
    bytes[6] = 0x70;
    bytes[8] = 0x80;
    bytes[15] = last;
    Id::from_bytes(bytes).expect("a UUIDv7")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The statistics tables of the file, read without the storage layer.
fn statistics_tables(file: &ModuleFile) -> Vec<String> {
    raw_connection(&file.path())
        .prepare("SELECT name FROM sqlite_master WHERE name LIKE 'sqlite_stat%' ORDER BY name")
        .expect("prepare")
        .query_map([], |row| row.get(0))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("read")
}

/// A file whose private Core tables hold known secrets: 30 effect intents with idempotency keys,
/// 30 wrapped record keys and 30 journal rows with marked call ids.
fn file_with_secrets(label: &str) -> ModuleFile {
    let file = create_module_file(&scratch_dir(label));
    let writer = open::<Write>(&file, &KEY).expect("open");
    let source = Source::Member(id(1));
    for n in 0..30u8 {
        let mut marked = *b"CALLIDMARKER\x00\x00\x00\x00";
        marked[6] = 0x70;
        marked[8] = 0x80;
        marked[15] = n;
        let call = CallKey {
            principal: Principal::Member,
            source: &source,
            call_id: CallId::from_bytes(marked).expect("a call id"),
        };
        let key = format!("SECRET-IDEMPOTENCY-KEY-{n:02}");
        writer.execute_batch("BEGIN IMMEDIATE").expect("begin");
        writer
            .append_effect(&EffectIntent {
                call,
                request_hash: None,
                member: Some(id(1)),
                first_adult: None,
                id: id(100 + n),
                effect: "send_mail",
                idempotency_key: key.as_bytes(),
                payload: b"payload",
                created_at: UtcMillis::from_millis(1_790_000_000_000).expect("in range"),
            })
            .expect("intent");
        writer
            .append_journal(&JournalEntry {
                call,
                request_hash: None,
                authority: AuthorityKind::OwnAction,
                member: Some(id(1)),
                change_index: 0,
                table: "items",
                record: id(50 + n),
                rev_before: None,
                rev_after: Some(Rev::FIRST),
                image_before: None,
                image_after: Some(b"img"),
                inputs: b"in",
                created_at: UtcMillis::from_millis(1_790_000_000_000).expect("in range"),
            })
            .expect("journal");
        writer.execute_batch("COMMIT").expect("commit");
        writer
            .store_wrapped_record_key(id(200 + n), format!("WRAPPED-KEY-BYTES-{n:02}").as_bytes())
            .expect("key");
    }
    writer.close().expect("close");
    file
}

/// The statements a migration might use to sample, plant or read statistics.
const HOSTILE: &[&str] = &[
    "ANALYZE",
    "ANALYZE main",
    "ANALYZE _journal",
    "ANALYZE main._outbox",
    "ANALYZE _record_keys",
    "ANALYZE items",
    "PRAGMA optimize",
    "PRAGMA analysis_limit = 1",
    "ANALYZE; CREATE TABLE leak (sample BLOB); \
     INSERT INTO leak SELECT sample FROM sqlite_stat4 WHERE tbl = '_journal'",
];

/// The first experiment of the review: `ANALYZE` in a module migration sampled 82 keys of the
/// outbox, its indexes and `_record_keys`. Every form is refused, nothing is written, and no
/// statistics table exists afterwards.
#[test]
fn a_migration_cannot_sample_the_core_indexes() {
    let file = file_with_secrets("statistics-hostile");
    let mut failures = Vec::new();
    for sql in HOSTILE {
        let mut migration = open::<Migration>(&file, &KEY).expect("open");
        let outcome = migration.apply_module_migrations(&[frozen(sql)]);
        migration.close().expect("close");
        if !outcome.as_ref().is_err_and(Error::is_refusal) {
            failures.push(format!("{sql}: {outcome:?}"));
        }
        if !statistics_tables(&file).is_empty() {
            failures.push(format!("{sql}: left {:?}", statistics_tables(&file)));
        }
    }
    // SQLite itself refuses these names before the authorizer sees them; the authorizer refuses
    // them too (`no_policy_analyzes_or_reaches_the_statistics_tables`).
    for sql in [
        "CREATE TABLE sqlite_stat1 (tbl, idx, stat)",
        "CREATE TABLE sqlite_stat4 (tbl, idx, neq, nlt, ndlt, sample)",
    ] {
        let mut migration = open::<Migration>(&file, &KEY).expect("open");
        let outcome = migration.apply_module_migrations(&[frozen(sql)]);
        migration.close().expect("close");
        if outcome.is_ok() || !statistics_tables(&file).is_empty() {
            failures.push(format!("{sql}: {outcome:?}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    let mut migration = open::<Migration>(&file, &KEY).expect("open");
    migration
        .apply_module_migrations(&[frozen(
            "CREATE TABLE notes (x INTEGER); CREATE INDEX notes_x ON notes (x);",
        )])
        .expect("an ordinary migration with an index applies");
    migration.close().expect("close");
    assert!(
        statistics_tables(&file).is_empty(),
        "no migration made statistics"
    );
}

/// Statistics planted outside the storage layer, by root, are read and written by no role, so a
/// module cannot copy what they sampled; the control shows they hold the private keys.
#[test]
fn planted_statistics_are_read_by_no_role() {
    let file = file_with_secrets("statistics-planted");
    raw_connection(&file.path())
        .execute_batch("ANALYZE")
        .expect("plant the statistics without the authorizer");
    let samples: Vec<Vec<u8>> = raw_connection(&file.path())
        .prepare("SELECT sample FROM sqlite_stat4")
        .expect("prepare")
        .query_map([], |row| row.get(0))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("read");
    assert!(
        samples
            .iter()
            .any(|sample| contains(sample, b"SECRET-IDEMPOTENCY-KEY")),
        "the control: ANALYZE samples the private keys"
    );
    let reads = [
        "SELECT tbl, idx, sample FROM sqlite_stat4",
        "SELECT tbl, idx, stat FROM sqlite_stat1",
        "SELECT count(*) FROM main.SQLITE_STAT4",
    ];
    let reader = open::<Read>(&file, &KEY).expect("open");
    let writer = open::<Write>(&file, &KEY).expect("open");
    let mut failures = Vec::new();
    for sql in reads {
        for (role, outcome) in [
            ("read", reader.query_values(sql, &[]).map(drop)),
            ("write", writer.query_values(sql, &[]).map(drop)),
        ] {
            if !outcome.as_ref().is_err_and(Error::is_refusal) {
                failures.push(format!("{role} {sql}: {outcome:?}"));
            }
        }
    }
    for sql in [
        "DELETE FROM sqlite_stat1",
        "UPDATE sqlite_stat4 SET sample = x'00'",
    ] {
        let outcome = writer.execute_batch(sql);
        if !outcome.as_ref().is_err_and(Error::is_refusal) {
            failures.push(format!("write {sql}: {outcome:?}"));
        }
    }
    reader.close().expect("close");
    writer.close().expect("close");
    for sql in [
        "CREATE TABLE leak AS SELECT sample FROM sqlite_stat4",
        "DROP TABLE sqlite_stat4",
        "DELETE FROM sqlite_stat1",
    ] {
        let mut migration = open::<Migration>(&file, &KEY).expect("open");
        let outcome = migration.apply_module_migrations(&[frozen(sql)]);
        migration.close().expect("close");
        if !outcome.as_ref().is_err_and(Error::is_refusal) {
            failures.push(format!("migration {sql}: {outcome:?}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The second experiment of the review: a migration that ran `ANALYZE` and copied the samples of
/// `_journal` kept expired call ids past the retention purge. The migration is refused, so after
/// the purge no statistics row and no copy of one holds a call id.
#[test]
fn no_statistics_outlive_the_retention_purge() {
    let file = file_with_secrets("statistics-purge");
    let mut migration = open::<Migration>(&file, &KEY).expect("open");
    let outcome = migration.apply_module_migrations(&[frozen(
        "ANALYZE; CREATE TABLE leak (sample BLOB); \
         INSERT INTO leak SELECT sample FROM sqlite_stat4 WHERE tbl = '_journal';",
    )]);
    migration.close().expect("close");
    assert!(
        outcome.as_ref().is_err_and(Error::is_refusal),
        "{outcome:?}"
    );
    let writer = open::<Write>(&file, &KEY).expect("open");
    let purge = writer
        .purge_journal(UtcMillis::from_millis(1_800_000_000_000).expect("in range"))
        .expect("purge");
    assert_eq!(purge.deleted, 30);
    writer.close().expect("close");
    assert!(statistics_tables(&file).is_empty());
    let leak: i64 = raw_connection(&file.path())
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE name = 'leak'",
            [],
            |row| row.get(0),
        )
        .expect("read");
    assert_eq!(leak, 0);
}
