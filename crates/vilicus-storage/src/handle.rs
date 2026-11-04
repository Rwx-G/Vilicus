//! Connections to a module file, one type per role (AD-5, AD-9, AD-23).
//!
//! Every connection is set up in the order of D126, D127, D132 and D136, before its authorizer
//! is installed, because SQLCipher pragmas go through the authorizer: the extension loading C
//! API is turned off, the file is keyed with its raw key's text, lent for that call, the setup
//! pragmas run, `SQLITE_DBCONFIG_DEFENSIVE` is enabled, every value is read back, and the key
//! epoch of the sidecar is compared with the file's `_meta`; only then is the role's policy
//! installed.
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
use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, ErrorCode, OpenFlags, Params, Row, Statement};
use vilicus_types::{Id, UtcMillis, is_vocabulary_label};

use crate::authorizer::{self, Policy};
use crate::core_schema::{CORE_MIGRATIONS, CORE_SCHEMA_VERSION};
use crate::error::{Error, Result};
use crate::ffi;
use crate::file::{
    self, KeyEpoch, META_CORE_SCHEMA_VERSION, META_GENERATION, META_MODULE_SCHEMA_VERSION,
    META_PARTITION_ROOT_VERSION, ModuleFile,
};
use crate::migration::{self, FrozenMigration};

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
/// them; each attempt also waits up to [`BUSY_TIMEOUT`] for the readers to end (D132).
pub const CHECKPOINT_ATTEMPTS: u32 = 10;
const CHECKPOINT_PAUSE: Duration = Duration::from_millis(20);

/// What a connection is opened for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoleKind {
    /// Applies migrations through [`Handle::apply_module_migrations`] and
    /// [`Handle::apply_core_migrations`], and nothing else.
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
/// module's. Each track has its own schema version in `_meta` and its record of frozen hashes in
/// `_migrations`, which only the runner writes, in the transaction of the migration, under the
/// Core policy that module SQL never runs under. The Core track's migrations are the Core's own,
/// embedded in this crate ([`Handle::apply_core_migrations`]); a module's are given to
/// [`Handle::apply_module_migrations`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MigrationTrack {
    /// The Core tables of the file ([`CORE_TABLES`](crate::CORE_TABLES)) other than `_meta`.
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

/// Bytes of SQLCipher's raw key text of a 256-bit key: `x'`, its 64 lowercase hex digits, `'`.
pub const KEY_TEXT_LEN: usize = 2 + 2 * 32 + 1;

/// What keys a connection to a file: SQLCipher's raw key text of the file's 256-bit key, `x'`, its
/// 64 lowercase hex digits, then `'` ([`KEY_TEXT_LEN`] bytes), which skips SQLCipher's passphrase
/// KDF (D2, AD-5). The text is lent for the one call that keys a connection and never kept: the
/// Core lends the text `vilicus_crypto` writes from a file key in its locked pool (spine AD-4,
/// D154), so this crate holds no key text of its own. Test code implements it over a fixed text,
/// with a type of its own; the product implements it for the Core's file keys only.
pub trait FileKeying {
    /// Lends the key text to `key_with`, which keys a connection with it, and returns what
    /// `key_with` returned; [`Error::KeyUnavailable`] when the text cannot be lent.
    fn lend_key_text(&self, key_with: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()>;
}

/// Refuses a key text that is not `x'`, 64 lowercase hex digits, then `'`, which SQLCipher would
/// otherwise take for a passphrase and stretch into another key ([`Error::MalformedKeyText`]).
/// The digits are checked without a branch on any of them, since they are the key.
fn check_key_text(text: &[u8]) -> Result<()> {
    let [b'x', b'\'', digits @ .., b'\''] = text else {
        return Err(Error::MalformedKeyText);
    };
    if digits.len() != KEY_TEXT_LEN - 3 {
        return Err(Error::MalformedKeyText);
    }
    let mut outside = 0_i16;
    for byte in digits {
        let digit = i16::from(*byte) - i16::from(b'0');
        let letter = i16::from(*byte) - i16::from(b'a');
        // Each term is -1 when the byte is outside its range and 0 inside it.
        let not_digit = (digit | (9 - digit)) >> 15;
        let not_letter = (letter | (5 - letter)) >> 15;
        outside |= not_digit & not_letter;
    }
    if outside == 0 {
        Ok(())
    } else {
        Err(Error::MalformedKeyText)
    }
}

/// Keys `connection` with the key text `key` lends, through `sqlite3_key_v2` so that no SQL text
/// holds it (AC11 of Story 3.1), then reads the schema so a wrong key fails here.
pub(crate) fn key_connection(connection: &Connection, key: &dyn FileKeying) -> Result<()> {
    key.lend_key_text(&mut |text| {
        check_key_text(text)?;
        Ok(ffi::key(connection, text)?)
    })?;
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

/// Opens and sets up a connection to `file` in the order of the module documentation, without
/// its authorizer.
pub(crate) fn connect(
    file: &ModuleFile,
    key: &dyn FileKeying,
    setup: Setup,
    create: bool,
) -> Result<(Connection, Settings)> {
    connect_path(&file.path(), key, setup, create)
}

/// [`connect`] on any database path: a module file, the staging file of `create`, or the target
/// of a backup. No `SQLITE_OPEN_URI`, so a path is never read as a URI.
pub(crate) fn connect_path(
    path: &Path,
    key: &dyn FileKeying,
    setup: Setup,
    create: bool,
) -> Result<(Connection, Settings)> {
    let connection = open_path(path, create)?;
    key_connection(&connection, key)?;
    let settings = set_up(&connection, setup)?;
    Ok((connection, settings))
}

/// A new connection to `path`, read-write, created when `create`, with no URI, its busy timeout
/// and the extension loading C API off: the first steps of every setup, before the key.
pub(crate) fn open_path(path: &Path, create: bool) -> Result<Connection> {
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    if create {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    let connection = Connection::open_with_flags(path, flags)?;
    connection.busy_timeout(BUSY_TIMEOUT)?;
    ffi::set_extension_loading_api(&connection, false)?;
    Ok(connection)
}

/// The setup pragmas of `setup` and `SQLITE_DBCONFIG_DEFENSIVE` on a connection already keyed,
/// every value read back: the steps after the key and before the authorizer.
pub(crate) fn set_up(connection: &Connection, setup: Setup) -> Result<Settings> {
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "secure_delete", true)?;
    connection.pragma_update(None, "journal_size_limit", JOURNAL_SIZE_LIMIT)?;
    if setup.writes() {
        connection.pragma_update(None, "journal_mode", "WAL")?;
    }
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "query_only", !setup.writes())?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    Settings::read(connection)?.require(setup)
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

pub(crate) fn wal_of_is_empty(wal: &Path) -> Result<bool> {
    match std::fs::metadata(wal) {
        Ok(metadata) => Ok(metadata.len() == 0),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
    }
}

/// What a handle calls after each TRUNCATE checkpoint attempt that stayed busy or left WAL
/// content, with the attempt's number from 1, before it pauses and tries again.
pub type CheckpointRetryObserver = Box<dyn Fn(u32) + Send>;

/// TRUNCATE checkpoints through the C API until one reports not busy and the WAL is empty
/// (D132, E17), at most [`CHECKPOINT_ATTEMPTS`] times; returns the number of attempts made.
/// `observer` hears of each attempt that must be retried.
pub(crate) fn checkpoint_until_empty(
    file: &ModuleFile,
    connection: &Connection,
    observer: Option<&CheckpointRetryObserver>,
) -> Result<u32> {
    checkpoint_wal_until_empty(&file.wal_path(), connection, observer)
}

/// [`checkpoint_until_empty`] on the connection of any database whose WAL is `wal`.
pub(crate) fn checkpoint_wal_until_empty(
    wal: &Path,
    connection: &Connection,
    observer: Option<&CheckpointRetryObserver>,
) -> Result<u32> {
    let mut last = None;
    for attempt in 0..CHECKPOINT_ATTEMPTS {
        if attempt > 0 {
            thread::sleep(CHECKPOINT_PAUSE);
        }
        let frames = ffi::checkpoint_truncate(connection)?;
        if !frames.busy && wal_of_is_empty(wal)? {
            return Ok(attempt + 1);
        }
        if let Some(observer) = observer {
            observer(attempt + 1);
        }
        last = Some(frames);
    }
    let frames = last.map_or((-1, -1), |frames| (frames.log, frames.checkpointed));
    Err(Error::CheckpointIncomplete {
        log: frames.0,
        checkpointed: frames.1,
    })
}

/// The checkpoint after a deletion that must be real (D132): [`checkpoint_until_empty`], whose
/// failure after every attempt carries the `deleted` rows the caller committed, since they are
/// gone from the tables yet maybe still in the WAL.
pub(crate) fn checkpoint_after_delete(handle: &Handle<Write>, deleted: usize) -> Result<u32> {
    checkpoint_until_empty(
        handle.file(),
        handle.connection(),
        handle.checkpoint_retries.as_ref(),
    )
    .map_err(|error| match error {
        Error::CheckpointIncomplete { log, checkpointed } => Error::DeletedNotCheckpointed {
            deleted,
            log,
            checkpointed,
        },
        other => other,
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

/// The role's policy, put back on its connection when the Core's own statements end, or when a
/// panic unwinds through them.
struct RolePolicy<'c> {
    connection: &'c Connection,
    policy: Policy,
    restored: bool,
}

impl RolePolicy<'_> {
    fn restore(mut self) -> Result<()> {
        self.restored = true;
        authorizer::install(self.connection, self.policy).map_err(Error::from)
    }
}

impl Drop for RolePolicy<'_> {
    fn drop(&mut self) {
        if !self.restored {
            // Only while a panic unwinds: no caller to report a failure to, and the connection
            // has no policy wider than the role's once this runs.
            let _ = authorizer::install(self.connection, self.policy);
        }
    }
}

/// An open connection to a module file in role `R`, under that role's authorizer.
pub struct Handle<R: Role> {
    connection: Option<Connection>,
    file: ModuleFile,
    epoch: KeyEpoch,
    settings: Settings,
    checkpoint_retries: Option<CheckpointRetryObserver>,
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

/// Opens `file` in role `R`, keyed by `key` (AD-5, D2): its raw key's text, never a passphrase
/// through SQLCipher's KDF; [`Error::MalformedKeyText`] for a text of another shape. Fails with [`Error::WrongKey`] when the key does not open the file, with
/// [`Error::SetupMismatch`] when a setting does not read back as set, and with
/// [`Error::EpochMismatch`] when the sidecar and `_meta` disagree.
pub fn open<R: Role>(file: &ModuleFile, key: &dyn FileKeying) -> Result<Handle<R>> {
    let setup = Setup::Role(R::KIND);
    let (connection, settings) = connect(file, key, setup, false)?;
    let epoch = checked_epoch(file, &connection)?;
    Handle::guarded(connection, file, epoch, settings)
}

/// Creates `file`, keyed by `key` at the key epoch `epoch`, and returns its write handle.
///
/// The file is built under [`ModuleFile::staging_path`] with `_meta` and the key epoch, then the
/// Core track's migrations, each through the migration runner, so the file's Core tables are
/// at [`CORE_SCHEMA_VERSION`] and its module track at 0 (AD-26). It is closed, then its sidecar
/// is written, then it is renamed into place, so the final name exists only once the file and
/// its sidecar are durable. A crash leaves a staging file, alone or with a sidecar: that is an
/// interrupted `create`, which never held module data, and the next `create` discards it.
/// A sidecar with neither a file nor a staging file is not explained by `create`, and fails with
/// [`Error::EpochSidecarWithoutFile`].
pub fn create(file: &ModuleFile, key: &dyn FileKeying, epoch: KeyEpoch) -> Result<Handle<Write>> {
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

/// The staging file of `create`: keyed, set up like a writer, holding `_meta` and the Core
/// tables, closed after a TRUNCATE checkpoint so the database file alone holds them.
fn build_new_file(staging: &Path, key: &dyn FileKeying, epoch: KeyEpoch) -> Result<()> {
    let (mut connection, _) = connect_path(staging, key, Setup::Role(RoleKind::Write), true)?;
    let built = write_new_meta(&connection, epoch).and_then(|()| {
        (1..=CORE_SCHEMA_VERSION).try_for_each(|version| {
            run_migration(
                &mut connection,
                Migrating::Step(Step::of(MigrationTrack::Core, version, CORE_MIGRATIONS)),
            )
        })
    });
    let closed = checkpoint_and_close(connection);
    built.and(closed)?;
    let wal = suffixed(staging, "-wal");
    if !wal_of_is_empty(&wal)? {
        return Err(Error::WalNotEmpty(wal));
    }
    std::fs::File::open(staging)?.sync_all()?;
    Ok(())
}

/// `_meta` with the key epoch, in one transaction: the table both migration tracks record their
/// versions in, so it exists before either runs.
fn write_new_meta(connection: &Connection, epoch: KeyEpoch) -> Result<()> {
    connection
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
        .map_err(Error::from)
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
            checkpoint_retries: None,
            role: PhantomData,
        })
    }

    pub(crate) fn connection(&self) -> &Connection {
        self.connection
            .as_ref()
            .expect("a handle holds its connection until it is closed or dropped")
    }

    /// Runs `body`, one or more of the Core's own fixed statements on its tables, under
    /// [`Policy::Core`], then puts the role's policy back, whatever `body` returned, and while a
    /// panic unwinds through it too, so the handle never stays under the Core policy. The first
    /// error is the one returned.
    pub(crate) fn under_core_policy<T>(
        &self,
        body: impl FnOnce(&Connection) -> Result<T>,
    ) -> Result<T> {
        let connection = self.connection();
        let policy = Setup::Role(R::KIND)
            .opening_policy()
            .unwrap_or(Policy::Closed);
        authorizer::install(connection, Policy::Core)?;
        let guard = RolePolicy {
            connection,
            policy,
            restored: false,
        };
        let outcome = body(connection);
        let restored = guard.restore();
        match (outcome, restored) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }

    /// Refuses a Core operation that runs its own transaction while the handle is inside one: it
    /// would fail on its `BEGIN`, or commit the caller's statements with its own.
    pub(crate) fn require_no_transaction(&self) -> Result<()> {
        if self.connection().is_autocommit() {
            Ok(())
        } else {
            Err(Error::TransactionOpen)
        }
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

    /// Runs one statement with `values` bound to its parameters in order, and returns the number
    /// of rows it changed. A value keeps its storage class unless the column's affinity converts
    /// it, which the Core's validation makes moot by refusing a value of another class before it
    /// reaches a statement.
    pub fn execute_values(&self, sql: &str, values: &[SqlValue]) -> Result<usize> {
        Ok(self
            .connection()
            .execute(sql, rusqlite::params_from_iter(values))?)
    }

    /// Runs a query with `values` bound to its parameters in order, and returns every row, each
    /// column in its storage class.
    pub fn query_values(&self, sql: &str, values: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>> {
        let mut statement = self.connection().prepare(sql)?;
        let columns = statement.column_count();
        let rows = statement.query_map(rusqlite::params_from_iter(values), |row| {
            (0..columns).map(|index| row.get(index)).collect()
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
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
    /// Has `observer` called after each TRUNCATE checkpoint attempt of this handle that stays
    /// busy or leaves WAL content, before the handle pauses and tries again: how the Core sees,
    /// and a test waits for, a deletion's checkpoint held up by a reader (D132), without a timer.
    pub fn observe_checkpoint_retries(&mut self, observer: CheckpointRetryObserver) {
        self.checkpoint_retries = Some(observer);
    }

    /// Checkpoints the WAL into the file with `sqlite3_wal_checkpoint_v2` in TRUNCATE mode, which
    /// the authorizer does not see, retried until it reports not busy and the WAL is empty
    /// (D132): the step after a deletion that must be real. `PRAGMA wal_checkpoint` is refused
    /// on every handle. A reader that holds a snapshot keeps the deleted rows in the WAL until it
    /// ends, so a deletion that must be real needs short-lived readers; while one is open this
    /// returns [`Error::CheckpointIncomplete`] rather than claim the rows are gone.
    pub fn checkpoint_truncate(&self) -> Result<()> {
        checkpoint_until_empty(
            &self.file,
            self.connection(),
            self.checkpoint_retries.as_ref(),
        )
        .map(drop)
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

    /// Re-keys the file under `key` at the key epoch `epoch` (AD-5, `doc/key-management.md` section
    /// 8, "Database keys"), in durable steps: the WAL checkpointed empty, so no page under the old
    /// key stays in it; the pending sidecar `<file>.epoch.next`; every page re-encrypted under the
    /// new key with `sqlite3_rekey_v2`, in one transaction; `_meta` written under the Core policy;
    /// the WAL checkpointed empty again, so the file alone holds the new pages; then the pending
    /// sidecar renamed over `<file>.epoch`. The caller holds the file's only connection, this one,
    /// as a re-key does (D151): another connection would still read the pages under the old key.
    ///
    /// A failure before the pages are re-encrypted removes the pending sidecar, and the file stays
    /// under its key and epoch; a failure after it, or a crash anywhere, leaves the pending sidecar,
    /// and every later open fails with [`Error::EpochTransitionPending`] naming both epochs, which
    /// the Core resolves by the key that opens the file.
    pub fn rekey(&mut self, key: &dyn FileKeying, epoch: KeyEpoch) -> Result<()> {
        self.require_no_transaction()?;
        checkpoint_until_empty(&self.file, self.connection(), None)?;
        let pending = self.file.pending_epoch_path();
        file::write_sidecar(&pending, epoch)?;
        let connection = self.connection();
        let rekeyed = key.lend_key_text(&mut |text| {
            check_key_text(text)?;
            Ok(ffi::rekey(connection, text)?)
        });
        if let Err(error) = rekeyed {
            return Err(remove_if_present(&pending).err().unwrap_or(error));
        }
        self.update_meta(epoch)?;
        checkpoint_until_empty(&self.file, self.connection(), None)?;
        std::fs::rename(&pending, self.file.epoch_path())?;
        file::sync_parent(&self.file.epoch_path())?;
        self.epoch = epoch;
        Ok(())
    }

    /// Records `label` as a confirmed label of the reviewed vocabulary `vocabulary` in this file,
    /// confirmed by the member `confirmed_by` at `confirmed_at` (D104). The Core checks the
    /// label's form and that the file's module declares the vocabulary; this refuses a label
    /// outside the form of [`vilicus_types::is_vocabulary_label`] again, with
    /// [`Error::InvalidVocabularyLabel`], before any statement runs.
    ///
    /// `_vocabulary` is a Core table, written under the Core policy that module SQL never runs
    /// under, in one `BEGIN IMMEDIATE` transaction. A label confirmed again keeps its first
    /// confirmation.
    pub fn confirm_vocabulary_label(
        &self,
        vocabulary: &str,
        label: &str,
        confirmed_by: Id,
        confirmed_at: UtcMillis,
    ) -> Result<()> {
        if !is_vocabulary_label(label) {
            return Err(Error::InvalidVocabularyLabel);
        }
        let connection = self.connection();
        authorizer::install(connection, Policy::Core)?;
        let outcome = in_transaction(connection, || {
            connection.execute(
                "INSERT INTO _vocabulary (vocabulary, label, confirmed_by, confirmed_at) \
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT (vocabulary, label) DO NOTHING",
                rusqlite::params![
                    vocabulary,
                    label,
                    confirmed_by.to_bytes(),
                    confirmed_at.as_millis()
                ],
            )?;
            Ok(())
        });
        let restored = authorizer::install(connection, Policy::Write).map_err(Error::from);
        outcome.and(restored)
    }

    fn update_meta(&self, epoch: KeyEpoch) -> Result<()> {
        let connection = self.connection();
        authorizer::install(connection, Policy::Core)?;
        let outcome = write_meta(connection, epoch);
        let restored = authorizer::install(connection, Policy::Write).map_err(Error::from);
        outcome.and(restored)
    }
}

/// Runs `body` in a `BEGIN IMMEDIATE` transaction, committed when it succeeds. When `body` or
/// the `COMMIT` fails, the transaction is rolled back, so the connection never stays inside it,
/// and the original error is returned even if the rollback fails too.
pub(crate) fn in_transaction(
    connection: &Connection,
    body: impl FnOnce() -> Result<()>,
) -> Result<()> {
    connection.execute_batch("BEGIN IMMEDIATE")?;
    let outcome = body().and_then(|()| connection.execute_batch("COMMIT").map_err(Error::from));
    if outcome.is_err() {
        // The rollback's own failure is not reported: the original error says why nothing was
        // written. A COMMIT that failed on a deferred constraint leaves the transaction open,
        // which this rollback ends.
        let _ = connection.execute_batch("ROLLBACK");
    }
    outcome
}

/// The epoch rows of `_meta` in one transaction, which ends rolled back on any failure.
fn write_meta(connection: &Connection, epoch: KeyEpoch) -> Result<()> {
    in_transaction(connection, || {
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
        })?;
        if updated == 2 {
            Ok(())
        } else {
            Err(Error::MissingEpoch)
        }
    })
}

impl Handle<Migration> {
    /// Applies one migration without a version, for the replay of the Story 1.7 hostile
    /// statements, which test the runner itself. Product code has only
    /// [`apply_module_migrations`](Self::apply_module_migrations) and
    /// [`apply_core_migrations`](Self::apply_core_migrations), so every schema change moves a
    /// track's version and leaves its frozen hash in `_migrations`.
    #[cfg(test)]
    pub(crate) fn apply_migration(&mut self, sql: &str) -> Result<()> {
        self.run(Migrating::Unversioned(sql))
    }

    /// Brings the file's module track to the last of `migrations`, the module's migrations in
    /// order, the first being version 1, each with its frozen hash (AD-23, D21, D126). Returns the
    /// number of migrations applied: 0 for a file already at the last one.
    ///
    /// Before anything runs, with the authorizer removed: Core first, so while the file's Core
    /// track is not at [`CORE_SCHEMA_VERSION`] the call fails with [`Error::CoreSchemaNotCurrent`];
    /// a file at a module version beyond `migrations` fails with [`Error::NewerThanMigrations`];
    /// and the frozen hashes the file recorded for the versions it is at must be those of
    /// `migrations`, or the call fails with [`Error::MigrationChanged`]. This holds a file to the
    /// migrations it ran; that each frozen hash is the digest of its SQL is the Core's check,
    /// made before it calls this.
    ///
    /// Each pending migration then runs in its own transaction, which the runner opens with
    /// `BEGIN IMMEDIATE`, with the authorizer removed, so the checks are made again under the
    /// write lock and a concurrent writer makes the call fail as busy rather than race it;
    /// forward only and in order, or [`Error::MigrationOutOfOrder`]. The migration SQL runs under
    /// the migration policy, which refuses transaction control and every Core table; the version
    /// in `_meta` and the frozen hash in `_migrations` are written under the Core policy, never by
    /// the migration SQL. A migration that fails is rolled back and nothing of it is written, and
    /// the call fails with [`Error::MigrationFailed`], which names its version; on every exit the
    /// connection is left closed to every statement.
    pub fn apply_module_migrations(&mut self, migrations: &[FrozenMigration<'_>]) -> Result<u32> {
        let latest = track_length(migrations);
        let current = self.checked_before_running(MigrationTrack::Module, migrations)?;
        for version in current + 1..=latest {
            self.run(Migrating::Step(Step::of(
                MigrationTrack::Module,
                version,
                migrations,
            )))?;
        }
        Ok(latest - current)
    }

    /// Brings the file's Core track to [`CORE_SCHEMA_VERSION`], one migration after the other,
    /// each through the runner in its own transaction with its version and its frozen hash, as
    /// [`apply_module_migrations`](Self::apply_module_migrations) applies a module's, under the
    /// Core migration policy, which changes the Core tables only (AD-23, AD-26). Returns the
    /// number of migrations applied: 0 for a file already current, which every file `create`
    /// made is. A file whose Core track is newer than this code fails with
    /// [`Error::CoreSchemaNotCurrent`], and one whose record of the Core track differs from the
    /// Core's migrations with [`Error::MigrationChanged`]; neither is touched.
    pub fn apply_core_migrations(&mut self) -> Result<u32> {
        let current = self.checked_before_running(MigrationTrack::Core, CORE_MIGRATIONS)?;
        for version in current + 1..=CORE_SCHEMA_VERSION {
            self.run(Migrating::Step(Step::of(
                MigrationTrack::Core,
                version,
                CORE_MIGRATIONS,
            )))?;
        }
        Ok(CORE_SCHEMA_VERSION - current)
    }

    /// The checks made before a track's first pending migration, with the authorizer removed, as
    /// the runner reads, then the connection closed again. Returns the track's version.
    fn checked_before_running(
        &self,
        track: MigrationTrack,
        migrations: &[FrozenMigration<'_>],
    ) -> Result<u32> {
        let connection = self.connection();
        authorizer::remove(connection)?;
        let checked = checks_before_step(connection, track, migrations);
        let closed = authorizer::install(connection, Policy::Closed).map_err(Error::from);
        checked.and_then(|current| closed.map(|()| current))
    }

    fn run(&mut self, migrating: Migrating<'_, '_>) -> Result<()> {
        let connection = self
            .connection
            .as_mut()
            .expect("a handle holds its connection until it is closed or dropped");
        let outcome = run_migration(connection, migrating);
        let closed = authorizer::install(connection, Policy::Closed).map_err(Error::from);
        outcome.and(closed)
    }
}

impl<R: Inspect> Handle<R> {
    /// The schema version `_meta` records for `track`; 0 before the track's first migration.
    pub fn schema_version(&self, track: MigrationTrack) -> Result<u32> {
        read_schema_version(self.connection(), track)
    }

    /// The frozen hash of each migration of `track` the file ran, version 1 first, as the runner
    /// recorded it in the Core table `_migrations`, read under the Core policy: the registry
    /// compares it with the module's declaration and with the Core's migrations at every open.
    pub fn migration_hashes(&self, track: MigrationTrack) -> Result<Vec<[u8; 32]>> {
        if track == MigrationTrack::Core && self.schema_version(MigrationTrack::Core)? == 0 {
            return Ok(Vec::new());
        }
        self.under_core_policy(|connection| migration::recorded(connection, track))
    }

    /// True when `label` is a confirmed label of the reviewed vocabulary `vocabulary` in this
    /// file, compared byte for byte: another case or another spelling is another label.
    pub fn is_confirmed_label(&self, vocabulary: &str, label: &str) -> Result<bool> {
        Ok(self.connection().query_row(
            "SELECT EXISTS (SELECT 1 FROM _vocabulary WHERE vocabulary = ?1 AND label = ?2)",
            [vocabulary, label],
            |row| row.get(0),
        )?)
    }
}

pub(crate) fn read_schema_version(connection: &Connection, track: MigrationTrack) -> Result<u32> {
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

/// The number of migrations of a track, its last version. A track's migrations are a static list
/// written out in source; no build holds 2^32 of them.
fn track_length(migrations: &[FrozenMigration<'_>]) -> u32 {
    migrations.len() as u32
}

/// What the runner applies: a versioned step of a track, or, in the tests of the runner itself,
/// SQL with no version.
enum Migrating<'s, 'm> {
    Step(Step<'m>),
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "the unversioned runner exists in tests only")
    )]
    Unversioned(&'s str),
}

/// The migration that brings `track` to `version`, with the migrations before it, whose frozen
/// hashes the file must have recorded.
#[derive(Clone, Copy)]
struct Step<'m> {
    track: MigrationTrack,
    version: u32,
    migrations: &'m [FrozenMigration<'m>],
}

impl<'m> Step<'m> {
    /// Step `version` of `migrations`, the first being 1; the callers iterate within the list.
    fn of(track: MigrationTrack, version: u32, migrations: &'m [FrozenMigration<'m>]) -> Self {
        Self {
            track,
            version,
            migrations,
        }
    }

    fn migration(&self) -> &'m FrozenMigration<'m> {
        &self.migrations[self.version as usize - 1]
    }

    fn earlier(&self) -> &'m [FrozenMigration<'m>] {
        &self.migrations[..self.version as usize - 1]
    }
}

/// The checks of a track before its next migration, on a connection without authorizer: Core
/// first for the module track, the track's version within `migrations`, and its record of
/// frozen hashes equal to those of the versions it is at. Returns the track's version.
fn checks_before_step(
    connection: &Connection,
    track: MigrationTrack,
    migrations: &[FrozenMigration<'_>],
) -> Result<u32> {
    if track == MigrationTrack::Module {
        let core = read_schema_version(connection, MigrationTrack::Core)?;
        if core != CORE_SCHEMA_VERSION {
            return Err(Error::CoreSchemaNotCurrent {
                found: core,
                latest: CORE_SCHEMA_VERSION,
            });
        }
    }
    let latest = track_length(migrations);
    let current = read_schema_version(connection, track)?;
    if current > latest {
        return Err(match track {
            MigrationTrack::Core => Error::CoreSchemaNotCurrent {
                found: current,
                latest,
            },
            MigrationTrack::Module => Error::NewerThanMigrations {
                track,
                found: current,
                latest,
            },
        });
    }
    migration::check_recorded(connection, track, &migrations[..current as usize])?;
    Ok(current)
}

/// Runs one migration in the runner's transaction: a module migration, or one of the Core
/// track's, each under its own policy.
fn run_migration(connection: &mut Connection, migrating: Migrating<'_, '_>) -> Result<()> {
    authorizer::remove(connection)?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let applied = migrate_in_transaction(&transaction, &migrating);
    authorizer::remove(&transaction)?;
    match applied {
        Ok(()) => Ok(transaction.commit()?),
        Err(error) => {
            transaction.rollback()?;
            Err(error)
        }
    }
}

/// The body of the runner's transaction: the checks with no authorizer (Core statements), the
/// migration SQL under the policy of its track (the migration policy for a module's, the Core
/// migration policy for the Core's), then its version and frozen hash under the Core policy. A
/// failure of the SQL or of its record is [`Error::MigrationFailed`], naming the version.
fn migrate_in_transaction(transaction: &Connection, migrating: &Migrating<'_, '_>) -> Result<()> {
    let step = match migrating {
        Migrating::Unversioned(sql) => {
            authorizer::install(transaction, Policy::Migration)?;
            return Ok(transaction.execute_batch(sql)?);
        }
        Migrating::Step(step) => *step,
    };
    let current = checks_before_step(transaction, step.track, step.earlier())?;
    if current.checked_add(1) != Some(step.version) {
        return Err(Error::MigrationOutOfOrder {
            track: step.track,
            current,
            version: step.version,
        });
    }
    let policy = match step.track {
        MigrationTrack::Core => Policy::CoreMigration,
        MigrationTrack::Module => Policy::Migration,
    };
    let migration = step.migration();
    let applied = authorizer::install(transaction, policy)
        .map_err(Error::from)
        .and_then(|()| {
            transaction
                .execute_batch(migration.sql)
                .map_err(Error::from)
        })
        .and_then(|()| authorizer::install(transaction, Policy::Core).map_err(Error::from))
        .and_then(|()| {
            transaction.execute(
                "INSERT INTO _meta (key, value) VALUES (?1, ?2) \
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                rusqlite::params![step.track.meta_key(), step.version],
            )?;
            migration::record(transaction, step.track, step.version, migration)
        });
    applied.map_err(|cause| Error::MigrationFailed {
        track: step.track,
        version: step.version,
        cause: Box::new(cause),
    })
}
