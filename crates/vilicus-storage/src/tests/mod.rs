//! Tests of the storage layer that need its internals: the Story 1.7 hostile replay, the setup
//! order, the key, the epoch, the checkpoints and the build of SQLCipher itself. Fixtures here.

mod core_rows;
mod core_tables;
mod engine;
mod hostile;
mod maintenance;
mod replay;
mod schema;
mod setup;
mod vocabulary;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use rusqlite::Connection;
use vilicus_types::ModuleName;

use crate::authorizer::{self, Policy};
use crate::{Handle, KeyEpoch, ModuleFile, Partition, Role, RoleKind, create};

/// Test key only; the Core derives one key per file (`doc/key-management.md` section 2).
pub(crate) const KEY: [u8; 32] = [0x5a; 32];

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

/// The SQLCipher `x'...'` form of [`KEY`], for connections the tests open outside the storage
/// layer. Test code only: the product keys through `ffi::key` from a wiped buffer.
pub(crate) fn raw_key_pragma(key: &[u8; 32]) -> String {
    let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("PRAGMA key = \"x'{hex}'\";")
}

/// A connection keyed with [`KEY`] and nothing else: no setup, no authorizer.
pub(crate) fn raw_connection(path: &Path) -> Connection {
    let connection = Connection::open(path).expect("open without the storage layer");
    connection
        .execute_batch(&raw_key_pragma(&KEY))
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
