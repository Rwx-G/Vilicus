//! Shared fixtures: scratch directories, a keyed module file, and a record of what a file and
//! its directory hold, so a test can assert that nothing was written.

#![allow(dead_code)] // Each integration test binary uses a different subset of these helpers.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use rusqlite::Connection;
use rusqlite::hooks::{AuthContext, Authorization};
use sqlite_authorizer::{Policy, Role, apply_raw_key, install_authorizer, open, sqlite_code};

/// Test key only; the product derives one key per file (`doc/key-management.md` section 2).
pub const KEY: [u8; 32] = [0x5a; 32];

static NEXT_DIR: AtomicU32 = AtomicU32::new(0);

/// A new empty directory under the system temporary directory.
pub fn scratch_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "vilicus-e11-{}-{}-{label}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).expect("create scratch directory");
    dir
}

/// Creates `module.db` in `dir`: SQLCipher with [`KEY`], WAL, a table with one row and an
/// `AUTOINCREMENT` table (so `sqlite_sequence` exists), no trigger. Built without any
/// authorizer, as the registry would build it.
pub fn create_module_file(dir: &Path) -> PathBuf {
    let path = dir.join("module.db");
    let connection = Connection::open(&path).expect("open new module file");
    apply_raw_key(&connection, &KEY).expect("key new module file");
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .expect("set WAL");
    connection
        .execute_batch(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT NOT NULL);
             INSERT INTO items (label) VALUES ('first');
             CREATE TABLE counters (id INTEGER PRIMARY KEY AUTOINCREMENT, n INTEGER);
             INSERT INTO counters (n) VALUES (1);",
        )
        .expect("create schema");
    connection.close().expect("close new module file");
    path
}

/// Opens `path` for `role` with an in-memory database attached as `other` before the
/// authorizer goes on, so `DETACH other` and `sqlcipher_export('other')` have a target.
pub fn open_with_other_attached(path: &Path, role: Role) -> Connection {
    let connection = open(path, &KEY, role).expect("open module file");
    connection
        .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
        .expect("remove authorizer for setup");
    connection
        .execute_batch("ATTACH DATABASE ':memory:' AS other")
        .expect("attach setup database");
    install_authorizer(&connection, role.opening_policy()).expect("reinstall authorizer");
    connection
}

/// Runs `inspect` with the authorizer removed, then reinstalls `policy`.
pub fn without_authorizer<T>(
    connection: &Connection,
    policy: Policy,
    inspect: impl FnOnce(&Connection) -> T,
) -> T {
    connection
        .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
        .expect("remove authorizer");
    let value = inspect(connection);
    install_authorizer(connection, policy).expect("reinstall authorizer");
    value
}

/// The bytes of a database file and the names in its directory. SQLite's own shared-memory
/// sidecar is left out, and the WAL sidecar is listed only when it holds frames: a read-only
/// connection cannot remove either on close, and neither is a write.
#[derive(Debug, PartialEq, Eq)]
pub struct DiskState {
    pub file_bytes: Vec<u8>,
    pub directory: Vec<String>,
}

/// Records the disk state; call it with every connection to the file closed.
pub fn disk_state(path: &Path) -> DiskState {
    let file_name = path
        .file_name()
        .expect("database file name")
        .to_string_lossy()
        .into_owned();
    let shm = format!("{file_name}-shm");
    let wal = format!("{file_name}-wal");
    let mut directory: Vec<String> = fs::read_dir(path.parent().expect("file has a directory"))
        .expect("list directory")
        .map(|entry| entry.expect("directory entry"))
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let empty = entry.metadata().expect("entry metadata").len() == 0;
            (name != shm && !(name == wal && empty)).then_some(name)
        })
        .collect();
    directory.sort();
    DiskState {
        file_bytes: fs::read(path).expect("read database file"),
        directory,
    }
}

fn inspect(path: &Path) -> Connection {
    let connection = Connection::open(path).expect("open for inspection");
    apply_raw_key(&connection, &KEY).expect("key for inspection");
    connection
}

/// The schema entries of the file, read without an authorizer.
pub fn schema(path: &Path) -> Vec<String> {
    inspect(path)
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
pub fn logical_state(path: &Path) -> (Vec<String>, Vec<String>) {
    let rows = inspect(path)
        .prepare("SELECT label FROM items ORDER BY id")
        .expect("prepare rows query")
        .query_map([], |row| row.get(0))
        .expect("query rows")
        .collect::<Result<_, _>>()
        .expect("read rows");
    (schema(path), rows)
}

/// Prints one check line that `run.sh` collects, and returns whether it passed.
pub fn report(passed: bool, check: &str, detail: &str) -> bool {
    let verdict = if passed { "PASS" } else { "FAIL" };
    if detail.is_empty() {
        println!("CHECK {verdict} {check}");
    } else {
        println!("CHECK {verdict} {check} ({detail})");
    }
    passed
}

/// A short description of a statement outcome for check lines.
pub fn describe(outcome: &rusqlite::Result<()>) -> String {
    match outcome {
        Ok(()) => "succeeded".to_owned(),
        Err(error) => match sqlite_code(error) {
            Some(code) => format!("{code:?}: {error}"),
            None => format!("{error}"),
        },
    }
}
