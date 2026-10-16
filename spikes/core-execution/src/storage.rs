//! Module files as the pipeline writes them: SQLCipher in WAL mode with `secure_delete` on, the
//! record envelope of spine AD-6 and the Core tables of AD-26, opened through the story 1.7
//! connection setup and authorizer (`spikes/sqlite-authorizer`).

use std::ffi::c_int;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::hooks::{AuthContext, Authorization};
use rusqlite::{Connection, ffi, params};
use sqlite_authorizer::{Policy, Role};

/// A raw 256-bit SQLCipher key (no SQLCipher KDF; the Core derives file keys with HKDF).
pub type FileKey = [u8; 32];

/// rusqlite's default busy timeout, restored after a short-timeout checkpoint.
pub const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// The schema the registry would create in every module file: the module's one record table
/// with the full envelope, and the Core tables the pipeline writes (`_journal` with the input
/// record ids of the call, `_outbox` for the change event, AD-10 and AD-26).
pub const MODULE_SCHEMA: &str = "
CREATE TABLE _meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE records (
    id INTEGER PRIMARY KEY,
    source TEXT NOT NULL,
    taint TEXT NOT NULL,
    data_types TEXT NOT NULL,
    author TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    rev INTEGER NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL
);
CREATE TABLE _journal (
    id INTEGER PRIMARY KEY,
    principal TEXT NOT NULL,
    call_id BLOB NOT NULL,
    record_id INTEGER NOT NULL,
    rev_before INTEGER,
    rev_after INTEGER NOT NULL,
    before_image BLOB,
    after_image BLOB NOT NULL,
    inputs TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX _journal_call ON _journal (principal, call_id);
CREATE INDEX _journal_created_at ON _journal (created_at);
CREATE TABLE _outbox (
    id INTEGER PRIMARY KEY,
    event_id BLOB NOT NULL UNIQUE,
    topic TEXT NOT NULL,
    payload BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    delivered_at INTEGER
);
INSERT INTO _meta (key, value) VALUES ('core_schema', '1'), ('generation', '1');
";

/// Seconds since the Unix epoch.
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or_default()
}

/// Creates a module file through the story 1.7 migration runner, seeds `rows` records of
/// about `body_bytes` bytes each and `expired_journal_rows` journal entries two days old (for
/// the home partition's 24-hour retention), and leaves the WAL empty.
pub fn create_module_file(
    path: &Path,
    key: &FileKey,
    rows: u32,
    body_bytes: usize,
    expired_journal_rows: u32,
) -> rusqlite::Result<()> {
    let mut migration = sqlite_authorizer::open(path, key, Role::Migration)?;
    sqlite_authorizer::apply_migration(&mut migration, MODULE_SCHEMA)?;
    drop(migration);
    let conn = open_writer(path, key)?;
    let tx = conn.unchecked_transaction()?;
    {
        let mut insert = tx.prepare(
            "INSERT INTO records
                 (source, taint, data_types, author, created_at, updated_at, rev, title, body)
             VALUES ('member', 'trusted', 'household_other', 'member:1', ?1, ?1, 1, ?2, ?3)",
        )?;
        let body = seed_body(body_bytes);
        for row in 0..rows {
            insert.execute(params![
                1_790_000_000_i64,
                format!("seed record {row}"),
                body
            ])?;
        }
        let mut journal = tx.prepare(
            "INSERT INTO _journal (principal, call_id, record_id, rev_before, rev_after,
                 before_image, after_image, inputs, created_at)
             VALUES ('adapter:1', ?1, 1, 1, 2, ?2, ?2, '', ?3)",
        )?;
        let image = seed_body(body_bytes).into_bytes();
        let two_days_ago = unix_now() - 2 * 86_400;
        for row in 0..expired_journal_rows {
            journal.execute(params![row.to_be_bytes().as_slice(), image, two_days_ago])?;
        }
    }
    tx.commit()?;
    checkpoint_truncate(&conn).map_err(|code| {
        rusqlite::Error::SqliteFailure(ffi::Error::new(code), Some("checkpoint".into()))
    })?;
    Ok(())
}

fn seed_body(bytes: usize) -> String {
    "household record body text ".repeat(bytes / 27 + 1)[..bytes].to_owned()
}

/// A writer connection: the story 1.7 setup and [`Policy::Write`], plus `synchronous = FULL`,
/// so a reported write is durable. The setup pragma runs with the authorizer lifted, as the
/// story 1.7 setup pragmas do; the durability settings are read back ([`check_durability`])
/// before the write policy is installed again.
pub fn open_writer(path: &Path, key: &FileKey) -> rusqlite::Result<Connection> {
    let conn = sqlite_authorizer::open(path, key, Role::Write)?;
    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    check_durability(&conn).map_err(|message| {
        rusqlite::Error::SqliteFailure(ffi::Error::new(ffi::SQLITE_MISUSE), Some(message))
    })?;
    sqlite_authorizer::install_authorizer(&conn, Policy::Write)?;
    Ok(conn)
}

/// Reads back `synchronous`, `secure_delete` and `journal_mode`; any value other than FULL
/// (2), ON (1) and `wal` is an error. Needs a connection without the write policy, which
/// refuses these pragmas.
pub fn check_durability(conn: &Connection) -> Result<(), String> {
    let read = |pragma: &str| -> Result<String, String> {
        conn.query_row(&format!("PRAGMA {pragma}"), [], |row| {
            row.get::<_, rusqlite::types::Value>(0)
        })
        .map(|value| match value {
            rusqlite::types::Value::Integer(number) => number.to_string(),
            rusqlite::types::Value::Text(text) => text.to_lowercase(),
            other => format!("{other:?}"),
        })
        .map_err(|e| format!("reading {pragma}: {e}"))
    };
    for (pragma, wanted) in [
        ("synchronous", "2"),
        ("secure_delete", "1"),
        ("journal_mode", "wal"),
    ] {
        let value = read(pragma)?;
        if value != wanted {
            return Err(format!("{pragma} is {value}, wanted {wanted}"));
        }
    }
    Ok(())
}

/// A read connection under [`Policy::Read`] (story 1.7).
pub fn open_reader(path: &Path, key: &FileKey) -> rusqlite::Result<Connection> {
    sqlite_authorizer::open(path, key, Role::Read)
}

/// The destination of an online backup: a new file under the same key, so SQLCipher accepts
/// the page copy. Not a runtime connection, so no authorizer; the backup API prepares no SQL.
pub fn open_backup_target(path: &Path, key: &FileKey) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    sqlite_authorizer::disable_extension_loading_api(&conn)?;
    sqlite_authorizer::apply_raw_key(&conn, key)?;
    Ok(conn)
}

/// `sqlite3_wal_checkpoint_v2` in TRUNCATE mode, as story 1.11 does it: no SQL statement, so
/// the write policy (which refuses `PRAGMA wal_checkpoint`) does not apply. Returns the frames
/// in the log and the frames checkpointed, or the SQLite result code (`SQLITE_BUSY` when a
/// reader still uses the WAL once the busy timeout has run out).
#[allow(unsafe_code)] // FFI to SQLite's checkpoint API; rusqlite exposes no safe wrapper.
pub fn checkpoint_truncate(conn: &Connection) -> Result<(c_int, c_int), c_int> {
    let mut log: c_int = 0;
    let mut checkpointed: c_int = 0;
    // SAFETY: the handle is valid while `conn` is borrowed and is used on this thread only; the
    // database name is a NUL-terminated literal; both out pointers are live locals.
    let code = unsafe {
        ffi::sqlite3_wal_checkpoint_v2(
            conn.handle(),
            c"main".as_ptr(),
            ffi::SQLITE_CHECKPOINT_TRUNCATE,
            &mut log,
            &mut checkpointed,
        )
    };
    if code == ffi::SQLITE_OK {
        Ok((log, checkpointed))
    } else {
        Err(code)
    }
}

/// [`checkpoint_truncate`] with the busy timeout lowered to `timeout`, so a long reader makes
/// it fail fast with `SQLITE_BUSY` instead of holding the writer for the default 5 s.
pub fn checkpoint_truncate_within(
    conn: &Connection,
    timeout: Duration,
) -> Result<(c_int, c_int), c_int> {
    conn.busy_timeout(timeout).map_err(|_| ffi::SQLITE_ERROR)?;
    let outcome = checkpoint_truncate(conn);
    conn.busy_timeout(DEFAULT_BUSY_TIMEOUT)
        .map_err(|_| ffi::SQLITE_ERROR)?;
    outcome
}

/// Number of rows in `records`, through a read connection.
pub fn record_count(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT count(*) FROM records", [], |row| row.get(0))
}
