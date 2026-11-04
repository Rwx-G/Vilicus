//! Tests of the storage layer that need its internals: the Story 1.7 hostile replay, the setup
//! order, the key, the epoch, the checkpoints and the build of SQLCipher itself. Fixtures here.

mod core_rows;
mod core_tables;
mod engine;
mod fts5;
mod hostile;
mod maintenance;
mod migration_copy;
mod outbox_events;
mod replay;
mod schema;
mod setup;
mod statistics;
mod vocabulary;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use rusqlite::Connection;
use vilicus_types::ModuleName;

use crate::authorizer::{self, Policy};
use crate::{
    FrozenMigration, Handle, KEY_TEXT_LEN, KeyEpoch, ModuleFile, Partition, Role, RoleKind, create,
};

/// The bytes of the test key only; the Core derives one key per file (`doc/key-management.md`
/// section 2).
pub(crate) const KEY_BYTES: [u8; 32] = [0x5a; 32];

/// SQLCipher's raw key text of [`KEY_BYTES`], which keys the test files as the text the Core lends
/// from a file key does.
pub(crate) const KEY: [u8; KEY_TEXT_LEN] = key_text(KEY_BYTES);

/// SQLCipher's raw key text of `key`, `x'`, its lowercase hex digits, then `'`: test code only,
/// where the product's text is written by `vilicus-crypto` in its locked pool.
pub(crate) const fn key_text(key: [u8; 32]) -> [u8; KEY_TEXT_LEN] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = [b'\''; KEY_TEXT_LEN];
    text[0] = b'x';
    let mut index = 0;
    while index < key.len() {
        text[2 + 2 * index] = HEX[(key[index] >> 4) as usize];
        text[3 + 2 * index] = HEX[(key[index] & 0x0f) as usize];
        index += 1;
    }
    text
}

pub(crate) const EPOCH: KeyEpoch = KeyEpoch {
    partition_root_version: 1,
    generation: 0,
};

static NEXT_DIR: AtomicU32 = AtomicU32::new(0);

/// A new empty directory under the system temporary directory.
pub(crate) fn scratch_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "vilicus-storage-{}-{}-{label}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).expect("create scratch directory");
    dir
}

pub(crate) fn module_file(dir: &Path) -> ModuleFile {
    ModuleFile::new(
        dir,
        ModuleName::from_static("fixture"),
        Partition::Household,
    )
}

/// `PRAGMA key` with the key text `text`, for connections the tests open outside the storage
/// layer. Test code only: the product keys through `ffi::key` from the text the Core lends.
pub(crate) fn raw_key_pragma(text: &[u8]) -> String {
    let text = std::str::from_utf8(text).expect("a key text is ASCII");
    format!("PRAGMA key = \"{text}\";")
}

/// A connection keyed with [`KEY`] and nothing else: no setup, no authorizer.
pub(crate) fn raw_connection(path: &Path) -> Connection {
    raw_connection_keyed(path, &KEY)
}

/// A connection keyed with the key text `text` and nothing else: no setup, no authorizer.
pub(crate) fn raw_connection_keyed(path: &Path, text: &[u8]) -> Connection {
    let connection = Connection::open(path).expect("open without the storage layer");
    connection
        .execute_batch(&raw_key_pragma(text))
        .expect("key");
    connection
}

/// Creates the module file through [`create`], then, without any authorizer as the registry
/// would, a table with one row and an `AUTOINCREMENT` table, so `sqlite_sequence` exists.
pub(crate) fn create_module_file(dir: &Path) -> ModuleFile {
    let file = module_file(dir);
    create(&file, &KEY, EPOCH)
        .expect("create module file")
        .close()
        .expect("close new file");
    let connection = raw_connection(&file.path());
    connection
        .execute_batch(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT NOT NULL);
             INSERT INTO items (label) VALUES ('first');
             CREATE TABLE counters (id INTEGER PRIMARY KEY AUTOINCREMENT, n INTEGER);
             INSERT INTO counters (n) VALUES (1);",
        )
        .expect("create schema");
    connection.close().expect("close schema connection");
    file
}

/// `sql` as the runner takes it, with a stand-in for its frozen hash: the storage layer computes
/// no digest, it records and compares the one it is given, so any value that differs between two
/// texts of these tests serves. The Core's tests use the SHA-256 of `vilicus-crypto`.
pub(crate) fn frozen(sql: &str) -> FrozenMigration<'_> {
    let mut sha256 = [0; 32];
    for (index, chunk) in (0_u64..).zip(sha256.chunks_mut(8)) {
        let fold = sql
            .bytes()
            .fold(0xcbf2_9ce4_8422_2325 ^ index, |hash, byte| {
                (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
            });
        chunk.copy_from_slice(&fold.to_le_bytes());
    }
    FrozenMigration { sql, sha256 }
}

/// Each of `sqls`, as [`frozen`] makes it: a module's migrations, the first being version 1.
pub(crate) fn frozen_all<'a>(sqls: &[&'a str]) -> Vec<FrozenMigration<'a>> {
    sqls.iter().map(|sql| frozen(sql)).collect()
}

pub(crate) fn opening_policy(kind: RoleKind) -> Policy {
    match kind {
        RoleKind::Migration => Policy::Closed,
        RoleKind::Write => Policy::Write,
        RoleKind::Read => Policy::Read,
    }
}

/// Runs `inspect` on the handle's connection with the authorizer removed, then reinstalls the
/// role's opening policy.
pub(crate) fn without_authorizer<R: Role, T>(
    handle: &Handle<R>,
    inspect: impl FnOnce(&Connection) -> T,
) -> T {
    authorizer::remove(handle.raw()).expect("remove authorizer");
    let value = inspect(handle.raw());
    authorizer::install(handle.raw(), opening_policy(R::KIND)).expect("reinstall authorizer");
    value
}

/// The bytes of a database file and the names in its directory. SQLite's shared-memory sidecar
/// is left out, and the WAL is listed only when it holds frames.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DiskState {
    pub(crate) file_bytes: Vec<u8>,
    pub(crate) directory: Vec<String>,
}

/// Records the disk state; call it with every connection to the file closed.
pub(crate) fn disk_state(file: &ModuleFile) -> DiskState {
    let name = file.file_name();
    let shm = format!("{name}-shm");
    let wal = format!("{name}-wal");
    let mut directory: Vec<String> = fs::read_dir(file.directory())
        .expect("list directory")
        .map(|entry| entry.expect("directory entry"))
        .filter_map(|entry| {
            let entry_name = entry.file_name().to_string_lossy().into_owned();
            let empty = entry.metadata().expect("entry metadata").len() == 0;
            (entry_name != shm && !(entry_name == wal && empty)).then_some(entry_name)
        })
        .collect();
    directory.sort();
    DiskState {
        file_bytes: fs::read(file.path()).expect("read database file"),
        directory,
    }
}

/// The schema entries of the file, read without an authorizer.
pub(crate) fn schema(file: &ModuleFile) -> Vec<String> {
    raw_connection(&file.path())
        .prepare(
            "SELECT type || ' ' || name || ' ' || ifnull(sql, '') FROM sqlite_master ORDER BY name",
        )
        .expect("prepare schema query")
        .query_map([], |row| row.get(0))
        .expect("query schema")
        .collect::<Result<_, _>>()
        .expect("read schema")
}

/// The schema and the `items` rows, read without an authorizer.
pub(crate) fn logical_state(file: &ModuleFile) -> (Vec<String>, Vec<String>) {
    let rows = raw_connection(&file.path())
        .prepare("SELECT label FROM items ORDER BY id")
        .expect("prepare rows query")
        .query_map([], |row| row.get(0))
        .expect("query rows")
        .collect::<Result<_, _>>()
        .expect("read rows");
    (schema(file), rows)
}

/// True when SQLite refused `error` because the function does not exist in this build.
pub(crate) fn no_such_function(error: &crate::Error) -> bool {
    match error {
        crate::Error::Sqlite(rusqlite::Error::SqlInputError { msg, .. }) => {
            msg.starts_with("no such function: ")
        }
        crate::Error::Sqlite(rusqlite::Error::SqliteFailure(_, Some(msg))) => {
            msg.starts_with("no such function: ")
        }
        _ => false,
    }
}
