//! The Core migration track of a module file (AD-26): the Core tables beside `_meta`, created and
//! changed by the Core's own migrations, embedded here, never by module SQL.
//!
//! A module file has two migration tracks, Core first then module, each with its schema version
//! in `_meta` (AD-23, AD-26). `_meta` itself is written by `create` before either track runs,
//! since it holds both versions and the key epoch every open checks. Each Core migration runs
//! through the migration runner under [`Policy::CoreMigration`](crate::authorizer::Policy), which
//! changes the schema of the Core tables only, and a module migration is refused until the Core
//! track is at [`CORE_SCHEMA_VERSION`].
//!
//! The tables of version 1:
//! - `_vocabulary`, the labels an adult confirmed for the file's reviewed vocabularies (D104,
//!   D146);
//! - `_journal`, one row per record a call changed: the call's key (principal, `source`,
//!   `call_id`), the hash of its request when the pipeline gives one, its authority and member,
//!   the record's table, id and revisions, its before and after images and the provenance of the
//!   write's inputs, written in the transaction of the write (AD-26, AD-28, FR-29). The unique
//!   index on the call's key and the change's position holds every call to one set of rows;
//! - `_outbox`, the event rows and effect intents a call commits with its writes (AD-10, AD-28),
//!   with the call's key and request hash, the member to report an `unknown` outcome to, or the
//!   adult to report it to first when no member is named; an effect intent is unique by its
//!   effect's name and its business idempotency key;
//! - `_consumed`, the event ids a consumer recorded in the transaction of its effect (AD-10);
//! - `_dead_letter`, the events a consumer kept failing (AD-29);
//! - `_record_keys`, the wrapped record key of each record that has one (`doc/architecture.md`
//!   section 5.1): a Core table that module SQL can neither read nor copy, and that no journal
//!   image holds, so destroying a key row shreds the record (D132).
//!
//! The `_journal` and `_outbox` tables keep the rowid, as `seq`, which orders their rows by
//! commit; the others are `WITHOUT ROWID` tables keyed by their natural key. Every table is
//! `STRICT`.

/// The Core track's migrations, in order: migration `n` brings the track to version `n`. A
/// migration once released is never edited; a change is a new migration (AD-23).
pub(crate) const CORE_MIGRATIONS: &[&str] = &["CREATE TABLE _vocabulary (
        vocabulary TEXT NOT NULL,
        label TEXT NOT NULL,
        confirmed_by BLOB NOT NULL,
        confirmed_at INTEGER NOT NULL,
        PRIMARY KEY (vocabulary, label)
    ) STRICT, WITHOUT ROWID;
    CREATE TABLE _journal (
        seq INTEGER PRIMARY KEY,
        call_id BLOB NOT NULL,
        request_hash BLOB,
        principal TEXT NOT NULL,
        source TEXT NOT NULL,
        authority TEXT NOT NULL,
        member BLOB,
        change_index INTEGER NOT NULL,
        record_table TEXT NOT NULL,
        record_id BLOB NOT NULL,
        rev_before INTEGER,
        rev_after INTEGER,
        image_before BLOB,
        image_after BLOB,
        inputs BLOB NOT NULL,
        created_at INTEGER NOT NULL
    ) STRICT;
    CREATE UNIQUE INDEX _journal_call ON _journal (principal, source, call_id, change_index);
    CREATE TABLE _outbox (
        seq INTEGER PRIMARY KEY,
        id BLOB NOT NULL UNIQUE,
        kind TEXT NOT NULL,
        call_id BLOB NOT NULL,
        request_hash BLOB,
        principal TEXT NOT NULL,
        source TEXT NOT NULL,
        member BLOB,
        first_adult BLOB,
        name TEXT NOT NULL,
        idempotency_key BLOB,
        payload BLOB NOT NULL,
        state TEXT NOT NULL,
        attempts INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    ) STRICT;
    CREATE INDEX _outbox_call ON _outbox (principal, source, call_id);
    CREATE UNIQUE INDEX _outbox_effect ON _outbox (name, idempotency_key);
    CREATE TABLE _consumed (
        event_id BLOB NOT NULL,
        consumer TEXT NOT NULL,
        consumed_at INTEGER NOT NULL,
        PRIMARY KEY (event_id, consumer)
    ) STRICT, WITHOUT ROWID;
    CREATE TABLE _dead_letter (
        id BLOB NOT NULL PRIMARY KEY,
        event_id BLOB NOT NULL,
        consumer TEXT NOT NULL,
        attempts INTEGER NOT NULL,
        failed_at INTEGER NOT NULL
    ) STRICT, WITHOUT ROWID;
    CREATE TABLE _record_keys (
        record_id BLOB NOT NULL PRIMARY KEY,
        wrapped_key BLOB NOT NULL
    ) STRICT, WITHOUT ROWID;"];

/// The Core track's schema version once every Core migration ran: the version the Core's code
/// expects of every file it opens.
pub const CORE_SCHEMA_VERSION: u32 = {
    assert!(CORE_MIGRATIONS.len() <= u32::MAX as usize);
    CORE_MIGRATIONS.len() as u32
};
