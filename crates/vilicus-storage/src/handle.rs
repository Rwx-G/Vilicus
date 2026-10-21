//! Connections to a module file, one type per role (AD-5, AD-9, AD-23).
//!
//! Every connection is set up in the order of D126, D127, D132 and D136, before its authorizer
//! is installed, because SQLCipher pragmas go through the authorizer: the extension loading C
//! API is turned off, the file is keyed with its raw key, the setup pragmas run,
//! `SQLITE_DBCONFIG_DEFENSIVE` is enabled, every value is read back, and the key epoch of the
//! sidecar is compared with the file's `_meta`; only then is the role's policy installed.
//!
//! A handle never gives out its `rusqlite::Connection`, whose `authorizer` and `set_db_config`
//! methods would undo that setup.
//!
//! Read handles are opened read-write with `PRAGMA query_only` on, under the read policy, rather
//! than with `SQLITE_OPEN_READONLY`: a read-only connection cannot checkpoint, so when it was the
//! last one to close a file the WAL content would stay (AD-23, AD-5). Two guards remain against a
//! write through a read handle, the authorizer and `query_only`, which the authorizer keeps
//! anyone from turning off.

use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use rusqlite::config::DbConfig;
use rusqlite::{Connection, ErrorCode, OpenFlags, Params, Row, Statement};
use zeroize::Zeroizing;

use crate::authorizer::{self, Policy};
use crate::error::{Error, Result};
use crate::ffi;
use crate::file::{
    self, KeyEpoch, META_CORE_SCHEMA_VERSION, META_GENERATION, META_MODULE_SCHEMA_VERSION,
    META_PARTITION_ROOT_VERSION, ModuleFile,
};

/// `PRAGMA journal_size_limit` on every connection: after a WAL restart, the first commit cuts
/// the WAL to what it wrote, so stale frames do not outlive the restart even when a TRUNCATE
/// checkpoint is missed (E17, D132). Defence in depth only; deletions still checkpoint.
pub const JOURNAL_SIZE_LIMIT: i64 = 0;

/// `PRAGMA synchronous` value of `FULL`, set on every connection (D136).
const SYNCHRONOUS_FULL: i64 = 2;

/// How long a statement or a checkpoint waits for a lock held by another connection to the file
/// before it reports busy. Short, so a checkpoint that meets a reader fails fast and is retried
/// rather than holding its writer (D136); `[ASSUMPTION]`, in place of rusqlite's 5 seconds.
pub const BUSY_TIMEOUT: Duration = Duration::from_millis(100);

/// Attempts of a TRUNCATE checkpoint before it is reported incomplete, and the pause between
/// them; each attempt also waits up to [`BUSY_TIMEOUT`] (D132).
const CHECKPOINT_ATTEMPTS: u32 = 10;
const CHECKPOINT_PAUSE: Duration = Duration::from_millis(20);

/// What a connection is opened for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoleKind {
    /// Applies migrations through [`Handle::apply_migration`] and nothing else.
    Migration,
    /// Writes rows in the file's tables, never its schema.
    Write,
    /// Runs `SELECT` only.
    Read,
}

mod sealed {
    pub trait Sealed {}
}

/// The role of a [`Handle`], one marker type per [`RoleKind`].
pub trait Role: sealed::Sealed {
    /// The role this marker stands for.
    const KIND: RoleKind;
}

/// Marker of a migration handle: closed to every statement outside the runner.
#[derive(Debug)]
pub enum Migration {}
/// Marker of a write handle.
#[derive(Debug)]
pub enum Write {}
/// Marker of a read handle.
#[derive(Debug)]
pub enum Read {}

impl sealed::Sealed for Migration {}
impl sealed::Sealed for Write {}
impl sealed::Sealed for Read {}
impl Role for Migration {
    const KIND: RoleKind = RoleKind::Migration;
}
impl Role for Write {
    const KIND: RoleKind = RoleKind::Write;
}
impl Role for Read {
    const KIND: RoleKind = RoleKind::Read;
}

/// The roles whose handles read the file's schema and schema versions: [`Read`] and [`Write`].
/// A [`Migration`] handle is closed to every statement outside its runner, so it has none of these
/// methods:
///
/// ```compile_fail,E0599
/// fn read(handle: &vilicus_storage::Handle<vilicus_storage::Migration>) {
///     let _ = handle.schema();
/// }
/// ```
pub trait Inspect: Role {}
impl Inspect for Read {}
impl Inspect for Write {}

/// One of the two migration tracks of a module file (AD-26): the Core's tables first, then the
/// module's. Each track has its own schema version in `_meta`, which only the runner writes, in
/// the transaction of the migration, under the Core policy that module SQL never runs under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MigrationTrack {
    /// The Core tables of the file (`_meta`, `_journal`, `_outbox`, `_consumed`, `_dead_letter`).
    Core,
    /// The module's own tables.
    Module,
}

impl MigrationTrack {
    fn meta_key(self) -> &'static str {
        match self {
            Self::Core => META_CORE_SCHEMA_VERSION,
            Self::Module => META_MODULE_SCHEMA_VERSION,
        }
    }
}

impl core::fmt::Display for MigrationTrack {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Core => "Core",
            Self::Module => "module",
        })
    }
}

/// The setups of the storage layer: the three roles, and the Core maintenance connection, which
/// is set up like a writer and gets no authorizer (D126, D132).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Setup {
    Role(RoleKind),
    Maintenance,
}

impl Setup {
    fn writes(self) -> bool {
        self != Self::Role(RoleKind::Read)
    }

    /// The policy installed at open; `None` for the maintenance connection.
    fn opening_policy(self) -> Option<Policy> {
        match self {
            Self::Role(RoleKind::Migration) => Some(Policy::Closed),
            Self::Role(RoleKind::Write) => Some(Policy::Write),
            Self::Role(RoleKind::Read) => Some(Policy::Read),
            Self::Maintenance => None,
        }
    }
}

/// The connection settings read back after the setup, before the authorizer went on. An open
/// fails unless each holds the value the setup requires.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Settings {
    /// `PRAGMA secure_delete`: 1 is ON, 2 would be FAST (D132).
    pub secure_delete: i64,
    /// `PRAGMA trusted_schema`.
    pub trusted_schema: bool,
    /// `PRAGMA journal_size_limit`.
    pub journal_size_limit: i64,
    /// `PRAGMA journal_mode`.
    pub journal_mode: String,
    /// `PRAGMA synchronous`: 2 is FULL.
    pub synchronous: i64,
    /// `PRAGMA query_only`, on for read handles.
    pub query_only: bool,
    /// `PRAGMA foreign_keys`.
    pub foreign_keys: bool,
    /// `PRAGMA temp_store`: 0 uses the build's `SQLITE_TEMP_STORE=2`, memory (D132).
    pub temp_store: i64,
    /// `SQLITE_DBCONFIG_DEFENSIVE` (D127).
    pub defensive: bool,
    /// `SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION`, the switch of the extension loading C API (D126).
    pub extension_loading_api: bool,
}

impl Settings {
    fn read(connection: &Connection) -> Result<Self> {
        let int = |name: &str| -> Result<i64> {
            Ok(connection.pragma_query_value(None, name, |row| row.get(0))?)
        };
        Ok(Self {
            secure_delete: int("secure_delete")?,
            trusted_schema: int("trusted_schema")? != 0,
            journal_size_limit: int("journal_size_limit")?,
            journal_mode: connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?,
            synchronous: int("synchronous")?,
            query_only: int("query_only")? != 0,
            foreign_keys: int("foreign_keys")? != 0,
            temp_store: int("temp_store")?,
            defensive: connection.db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)?,
            extension_loading_api: ffi::extension_loading_api(connection)?,
        })
    }

    pub(crate) fn require(self, setup: Setup) -> Result<Self> {
        let reading = setup == Setup::Role(RoleKind::Read);
        let checks: [(&'static str, String, String); 10] = [
            ("secure_delete", "1".into(), self.secure_delete.to_string()),
            (
                "trusted_schema",
                "false".into(),
                self.trusted_schema.to_string(),
            ),
            (
                "journal_size_limit",
                JOURNAL_SIZE_LIMIT.to_string(),
                self.journal_size_limit.to_string(),
            ),
            ("journal_mode", "wal".into(), self.journal_mode.clone()),
            (
                "synchronous",
                SYNCHRONOUS_FULL.to_string(),
                self.synchronous.to_string(),
            ),
            (
                "query_only",
                reading.to_string(),
                self.query_only.to_string(),
            ),
            ("foreign_keys", "true".into(), self.foreign_keys.to_string()),
            ("temp_store", "0".into(), self.temp_store.to_string()),
            (
                "SQLITE_DBCONFIG_DEFENSIVE",
                "true".into(),
                self.defensive.to_string(),
            ),
            (
                "SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION",
                "false".into(),
                self.extension_loading_api.to_string(),
            ),
        ];
        for (setting, expected, found) in checks {
            if expected != found {
                return Err(Error::SetupMismatch {
                    setting,
                    expected,
                    found,
                });
            }
        }
        Ok(self)
    }
}

/// Keys `connection` with the raw 256-bit `key`, in SQLCipher's `x'<64 hex digits>'` form, which
/// skips SQLCipher's passphrase KDF (D2, AD-5), then reads the schema so a wrong key fails here.
/// The hex form lives in one buffer allocated at its final size and wiped on drop (AD-4, AC11).
pub(crate) fn key_connection(connection: &Connection, key: &[u8; 32]) -> Result<()> {
    ffi::key(connection, &raw_key_text(key))?;
    match connection.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    }) {
        Ok(_) => Ok(()),
        Err(error) if error.sqlite_error_code() == Some(ErrorCode::NotADatabase) => {
            Err(Error::WrongKey)
        }
        Err(error) => Err(error.into()),
    }
}

/// The `x'<64 hex digits>'` form of `key`, built in place in a buffer of its final size, so no
/// reallocation leaves an unwiped copy, and wiped when dropped.
pub(crate) fn raw_key_text(key: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = Zeroizing::new(Vec::with_capacity(2 + 2 * key.len() + 1));
    text.extend_from_slice(b"x'");
    for byte in key {
        text.push(HEX[usize::from(byte >> 4)]);
        text.push(HEX[usize::from(byte & 0x0f)]);
    }
    text.push(b'\'');
    text
}

/// Opens and sets up a connection to `file` in the order of the module documentation, without
/// its authorizer.
pub(crate) fn connect(
    file: &ModuleFile,
    key: &[u8; 32],
    setup: Setup,
    create: bool,
) -> Result<(Connection, Settings)> {
    connect_path(&file.path(), key, setup, create)
}

/// [`connect`] on any database path: a module file, the staging file of `create`, or the target
/// of a backup. No `SQLITE_OPEN_URI`, so a path is never read as a URI.
pub(crate) fn connect_path(
    path: &Path,
    key: &[u8; 32],
    setup: Setup,
    create: bool,
) -> Result<(Connection, Settings)> {
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    if create {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    let connection = Connection::open_with_flags(path, flags)?;
    connection.busy_timeout(BUSY_TIMEOUT)?;
    ffi::set_extension_loading_api(&connection, false)?;
    key_connection(&connection, key)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "secure_delete", true)?;
    connection.pragma_update(None, "journal_size_limit", JOURNAL_SIZE_LIMIT)?;
    if setup.writes() {
        connection.pragma_update(None, "journal_mode", "WAL")?;
    }
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "query_only", !setup.writes())?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    let settings = Settings::read(&connection)?.require(setup)?;
    Ok((connection, settings))
}

/// The key epoch the file's `_meta` table holds.
pub(crate) fn meta_epoch(file: &ModuleFile, connection: &Connection) -> Result<KeyEpoch> {
    let tables: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = '_meta'",
        [],
        |row| row.get(0),
    )?;
    if tables == 0 {
        return Err(Error::MissingEpoch);
    }
    let value = |key: &str| -> Result<u32> {
        let stored: i64 = connection
            .query_row("SELECT value FROM _meta WHERE key = ?1", [key], |row| {
                row.get(0)
            })
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => Error::MissingEpoch,
                other => other.into(),
            })?;
        u32::try_from(stored).map_err(|_| Error::MalformedEpoch(file.path()))
    };
    Ok(KeyEpoch {
        partition_root_version: value(META_PARTITION_ROOT_VERSION)?,
        generation: value(META_GENERATION)?,
    })
}

/// The epoch of the sidecar, checked against `_meta` (AD-5).
pub(crate) fn checked_epoch(file: &ModuleFile, connection: &Connection) -> Result<KeyEpoch> {
    let sidecar = file::read_epoch(file)?;
    let in_file = meta_epoch(file, connection)?;
    if sidecar == in_file {
        Ok(sidecar)
    } else {
        Err(Error::EpochMismatch {
            sidecar,
            file: in_file,
        })
    }
}

fn wal_is_empty(file: &ModuleFile) -> Result<bool> {
    wal_of_is_empty(&file.wal_path())
}

pub(crate) fn wal_of_is_empty(wal: &Path) -> Result<bool> {
    match std::fs::metadata(wal) {
        Ok(metadata) => Ok(metadata.len() == 0),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
    }
}

/// TRUNCATE checkpoints through the C API until one reports not busy and the WAL is empty
/// (D132, E17), at most [`CHECKPOINT_ATTEMPTS`] times.
pub(crate) fn checkpoint_until_empty(file: &ModuleFile, connection: &Connection) -> Result<()> {
    let mut last = None;
    for attempt in 0..CHECKPOINT_ATTEMPTS {
        if attempt > 0 {
            thread::sleep(CHECKPOINT_PAUSE);
        }
        let frames = ffi::checkpoint_truncate(connection)?;
        if !frames.busy && wal_is_empty(file)? {
            return Ok(());
        }
        last = Some(frames);
    }
    let frames = last.map_or((-1, -1), |frames| (frames.log, frames.checkpointed));
    Err(Error::CheckpointIncomplete {
        log: frames.0,
        checkpointed: frames.1,
    })
}

/// One TRUNCATE checkpoint, then the close. A busy checkpoint means another connection to the
/// file is still open, so this one is not the last; the last close then checkpoints instead.
pub(crate) fn checkpoint_and_close(connection: Connection) -> Result<()> {
    let checkpoint = ffi::checkpoint_truncate(&connection);
    connection
        .close()
        .map_err(|(_, error)| Error::from(error))?;
    checkpoint.map(drop).map_err(Error::from)
}

/// An open connection to a module file in role `R`, under that role's authorizer.
pub struct Handle<R: Role> {
    connection: Option<Connection>,
    file: ModuleFile,
    epoch: KeyEpoch,
    settings: Settings,
    role: PhantomData<R>,
}

impl<R: Role> core::fmt::Debug for Handle<R> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Handle")
            .field("role", &R::KIND)
            .field("file", &self.file.file_name())
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

/// Opens `file` in role `R` with its raw 256-bit `key` (AD-5, D2): never a passphrase through
/// SQLCipher's KDF. Fails with [`Error::WrongKey`] when the key does not open the file, with
/// [`Error::SetupMismatch`] when a setting does not read back as set, and with
/// [`Error::EpochMismatch`] when the sidecar and `_meta` disagree.
pub fn open<R: Role>(file: &ModuleFile, key: &[u8; 32]) -> Result<Handle<R>> {
    let setup = Setup::Role(R::KIND);
    let (connection, settings) = connect(file, key, setup, false)?;
    let epoch = checked_epoch(file, &connection)?;
    Handle::guarded(connection, file, epoch, settings)
}

/// Creates `file` with its raw `key` and key epoch, and returns its write handle.
///
/// The file is built under [`ModuleFile::staging_path`] with its `_meta` table and closed, then
/// its sidecar is written, then it is renamed into place, so the final name exists only once the
/// file and its sidecar are durable. A crash leaves a staging file, alone or with a sidecar: that
/// is an interrupted `create`, which never held module data, and the next `create` discards it.
/// A sidecar with neither a file nor a staging file is not explained by `create`, and fails with
/// [`Error::EpochSidecarWithoutFile`].
pub fn create(file: &ModuleFile, key: &[u8; 32], epoch: KeyEpoch) -> Result<Handle<Write>> {
    let path = file.path();
    if path.exists() {
        return Err(Error::AlreadyExists(path));
    }
    let staging = file.staging_path();
    let sidecar = file.epoch_path();
    let interrupted = staging.exists();
    if sidecar.exists() && !interrupted {
        return Err(Error::EpochSidecarWithoutFile(sidecar));
    }
    if interrupted {
        for leftover in [
            staging.clone(),
            suffixed(&staging, "-wal"),
            suffixed(&staging, "-shm"),
            sidecar.clone(),
        ] {
            remove_if_present(&leftover)?;
        }
    }
    build_new_file(&staging, key, epoch)?;
    file::write_sidecar(&sidecar, epoch)?;
    std::fs::rename(&staging, &path)?;
    file::sync_parent(&path)?;
    open::<Write>(file, key)
}

/// The staging file of `create`: keyed, set up like a writer, holding `_meta`, closed after a
/// TRUNCATE checkpoint so the database file alone holds it.
fn build_new_file(staging: &Path, key: &[u8; 32], epoch: KeyEpoch) -> Result<()> {
    let (connection, _) = connect_path(staging, key, Setup::Role(RoleKind::Write), true)?;
    let built = connection
        .execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE _meta (key TEXT PRIMARY KEY NOT NULL, value INTEGER NOT NULL) STRICT, WITHOUT ROWID;",
        )
        .and_then(|()| {
            [
                (META_PARTITION_ROOT_VERSION, epoch.partition_root_version),
                (META_GENERATION, epoch.generation),
            ]
            .into_iter()
            .try_for_each(|(key, value)| {
                connection
                    .execute(
                        "INSERT INTO _meta (key, value) VALUES (?1, ?2)",
                        rusqlite::params![key, value],
                    )
                    .map(drop)
            })
        })
        .and_then(|()| connection.execute_batch("COMMIT"))
        .map_err(Error::from);
    let closed = checkpoint_and_close(connection);
    built.and(closed)?;
    let wal = suffixed(staging, "-wal");
    if !wal_of_is_empty(&wal)? {
        return Err(Error::WalNotEmpty(wal));
    }
    std::fs::File::open(staging)?.sync_all()?;
    Ok(())
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

pub(crate) fn remove_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

impl<R: Role> Handle<R> {
    fn guarded(
        connection: Connection,
        file: &ModuleFile,
        epoch: KeyEpoch,
        settings: Settings,
    ) -> Result<Self> {
        let policy = Setup::Role(R::KIND)
            .opening_policy()
            .unwrap_or(Policy::Closed);
        authorizer::install(&connection, policy)?;
        Ok(Self {
            connection: Some(connection),
            file: file.clone(),
            epoch,
            settings,
            role: PhantomData,
        })
    }

    pub(crate) fn connection(&self) -> &Connection {
        self.connection
            .as_ref()
            .expect("a handle holds its connection until it is closed or dropped")
    }

    /// The file this handle is open on.
    pub fn file(&self) -> &ModuleFile {
        &self.file
    }

    /// The file's key epoch, as checked at open.
    pub fn epoch(&self) -> KeyEpoch {
        self.epoch
    }

    /// The settings read back at open.
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Prepares `sql` under the authorizer; a refusal is [`Error::Refused`].
    pub fn prepare(&self, sql: &str) -> Result<Statement<'_>> {
        Ok(self.connection().prepare(sql)?)
    }

    /// Runs one statement with `params` and returns the number of rows it changed.
    pub fn execute(&self, sql: &str, params: impl Params) -> Result<usize> {
        Ok(self.connection().execute(sql, params)?)
    }

    /// Runs `sql`, one or more statements without parameters.
    pub fn execute_batch(&self, sql: &str) -> Result<()> {
        Ok(self.connection().execute_batch(sql)?)
    }

    /// Runs a query and maps its first row with `map`.
    pub fn query_row<T>(
        &self,
        sql: &str,
        params: impl Params,
        map: impl FnOnce(&Row<'_>) -> rusqlite::Result<T>,
    ) -> Result<T> {
        Ok(self.connection().query_row(sql, params, map)?)
    }

    /// Closes the handle after a TRUNCATE checkpoint (AD-23). When other connections to the file
    /// are still open the checkpoint may be busy; the last connection to close then leaves no WAL
    /// content, since every handle checkpoints at close and SQLite removes the WAL at the last
    /// close of a file.
    pub fn close(mut self) -> Result<()> {
        let connection = self.connection.take().expect("a handle is closed once");
        checkpoint_and_close(connection)
    }

    #[cfg(test)]
    pub(crate) fn raw(&self) -> &Connection {
        self.connection()
    }
}

impl<R: Role> Drop for Handle<R> {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            // A handle dropped without `close` still checkpoints; there is no caller to report to.
            let _ = checkpoint_and_close(connection);
        }
    }
}

impl Handle<Write> {
    /// Checkpoints the WAL into the file with `sqlite3_wal_checkpoint_v2` in TRUNCATE mode, which
    /// the authorizer does not see, retried until it reports not busy and the WAL is empty
    /// (D132): the step after a deletion that must be real. `PRAGMA wal_checkpoint` is refused
    /// on every handle. A reader that holds a snapshot keeps the deleted rows in the WAL until it
    /// ends, so a deletion that must be real needs short-lived readers; while one is open this
    /// returns [`Error::CheckpointIncomplete`] rather than claim the rows are gone.
    pub fn checkpoint_truncate(&self) -> Result<()> {
        checkpoint_until_empty(&self.file, self.connection())
    }

    /// Writes a new key epoch (AD-5), in three durable steps: the pending sidecar
    /// `<file>.epoch.next`, then `_meta` in one transaction, then the pending sidecar renamed over
    /// `<file>.epoch`. `_meta` is written under the Core policy, which writes nothing but the Core
    /// tables; module SQL never can. A failure before the rename removes the pending
    /// sidecar again; a crash leaves it in place, and every later open fails with
    /// [`Error::EpochTransitionPending`] until the Core resolves it (Story 3.1, Implementation
    /// Notes, the recovery rule).
    pub fn write_epoch(&mut self, epoch: KeyEpoch) -> Result<()> {
        let pending = self.file.pending_epoch_path();
        file::write_sidecar(&pending, epoch)?;
        if let Err(error) = self.update_meta(epoch) {
            return Err(remove_if_present(&pending).err().unwrap_or(error));
        }
        std::fs::rename(&pending, self.file.epoch_path())?;
        file::sync_parent(&self.file.epoch_path())?;
        self.epoch = epoch;
        Ok(())
    }

    fn update_meta(&self, epoch: KeyEpoch) -> Result<()> {
        let connection = self.connection();
        authorizer::install(connection, Policy::Core)?;
        let outcome = write_meta(connection, epoch);
        let restored = authorizer::install(connection, Policy::Write).map_err(Error::from);
        outcome.and(restored)
    }
}

/// The epoch rows of `_meta` in one transaction; on any failure the transaction is rolled back
/// and the original error returned, even if the rollback fails too.
fn write_meta(connection: &Connection, epoch: KeyEpoch) -> Result<()> {
    connection.execute_batch("BEGIN IMMEDIATE")?;
    let updated = [
        (META_PARTITION_ROOT_VERSION, epoch.partition_root_version),
        (META_GENERATION, epoch.generation),
    ]
    .into_iter()
    .try_fold(0, |total, (key, value)| {
        connection
            .execute(
                "UPDATE _meta SET value = ?2 WHERE key = ?1",
                rusqlite::params![key, value],
            )
            .map(|changed| total + changed)
    });
    let failure = match updated {
        Ok(2) => return connection.execute_batch("COMMIT").map_err(Error::from),
        Ok(_) => Error::MissingEpoch,
        Err(error) => Error::from(error),
    };
    // The rollback's own failure is not reported: the original error says why the epoch was not
    // written, and SQLite ends the transaction with the connection either way.
    let _ = connection.execute_batch("ROLLBACK");
    Err(failure)
}

impl Handle<Migration> {
    /// Applies one migration without a version, for the replay of the Story 1.7 hostile
    /// statements, which test the runner itself. Product code has only
    /// [`apply_versioned_migration`](Self::apply_versioned_migration), so every schema change
    /// moves a track's version.
    #[cfg(test)]
    pub(crate) fn apply_migration(&mut self, sql: &str) -> Result<()> {
        self.run(sql, None)
    }

    /// Applies migration `version` of `track` atomically (AD-23, D126) and records `version` as the
    /// track's schema version in `_meta`, in the same transaction, so the schema and its version
    /// never disagree (AD-26).
    ///
    /// The runner opens the transaction with `BEGIN IMMEDIATE`, with the authorizer removed, so
    /// the order check reads the version under the write lock and a concurrent writer makes the
    /// call fail as busy rather than race it. Forward only and in order: `version` must follow
    /// the recorded one by exactly one, the first migration being 1, or the call fails with
    /// [`Error::MigrationOutOfOrder`] before the SQL runs. The migration SQL runs under the
    /// migration policy, which refuses transaction control; the version is written under the Core
    /// policy, never by the migration SQL, which cannot reach `_meta`. On any error the
    /// transaction is rolled back and nothing is written; on every exit the connection is left
    /// closed to every statement.
    pub fn apply_versioned_migration(
        &mut self,
        track: MigrationTrack,
        version: u32,
        sql: &str,
    ) -> Result<()> {
        self.run(sql, Some((track, version)))
    }

    fn run(&mut self, sql: &str, version: Option<(MigrationTrack, u32)>) -> Result<()> {
        let connection = self
            .connection
            .as_mut()
            .expect("a handle holds its connection until it is closed or dropped");
        let outcome = run_migration(connection, sql, version);
        let closed = authorizer::install(connection, Policy::Closed).map_err(Error::from);
        outcome.and(closed)
    }
}

impl<R: Inspect> Handle<R> {
    /// The schema version `_meta` records for `track`; 0 before the track's first migration.
    pub fn schema_version(&self, track: MigrationTrack) -> Result<u32> {
        read_schema_version(self.connection(), track)
    }
}

fn read_schema_version(connection: &Connection, track: MigrationTrack) -> Result<u32> {
    match connection.query_row(
        "SELECT value FROM _meta WHERE key = ?1",
        [track.meta_key()],
        |row| row.get::<_, rusqlite::types::Value>(0),
    ) {
        Ok(rusqlite::types::Value::Integer(stored)) => {
            u32::try_from(stored).map_err(|_| Error::MalformedSchemaVersion(track))
        }
        Ok(_) => Err(Error::MalformedSchemaVersion(track)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
        Err(error) => Err(error.into()),
    }
}

fn run_migration(
    connection: &mut Connection,
    sql: &str,
    version: Option<(MigrationTrack, u32)>,
) -> Result<()> {
    authorizer::remove(connection)?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let applied = migrate_in_transaction(&transaction, sql, version);
    authorizer::remove(&transaction)?;
    match applied {
        Ok(()) => Ok(transaction.commit()?),
        Err(error) => {
            transaction.rollback()?;
            Err(error)
        }
    }
}

/// The body of the runner's transaction: the order check with no authorizer (a Core statement),
/// the migration SQL under the migration policy, then the version row under the Core policy.
fn migrate_in_transaction(
    transaction: &Connection,
    sql: &str,
    version: Option<(MigrationTrack, u32)>,
) -> Result<()> {
    if let Some((track, version)) = version {
        let current = read_schema_version(transaction, track)?;
        if current.checked_add(1) != Some(version) {
            return Err(Error::MigrationOutOfOrder {
                track,
                current,
                version,
            });
        }
    }
    authorizer::install(transaction, Policy::Migration)?;
    transaction.execute_batch(sql)?;
    if let Some((track, version)) = version {
        authorizer::install(transaction, Policy::Core)?;
        transaction.execute(
            "INSERT INTO _meta (key, value) VALUES (?1, ?2) \
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            rusqlite::params![track.meta_key(), version],
        )?;
    }
    Ok(())
}
