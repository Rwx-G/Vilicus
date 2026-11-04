//! `wrappers.db` (`doc/architecture.md` section 5.2, `doc/key-management.md` section 2, D4): every
//! member DEK wrapper, one per KEK, and every member public key, each value starting with its
//! format version and algorithm identifier, in a file of its own beside `core.db`. Every value it
//! holds is ciphertext under a member secret or a public key, so it is not encrypted, and no key
//! of the instance is needed to read it: losing `core.db` or the instance key never loses the
//! wrappers a member unlocks with.
//!
//! The record set is authenticated as a whole (gate AD36-1): the file keeps a monotonic counter
//! and the MAC of the set at that counter, which the caller computes under a key derived from the
//! household key and cross-checks with the copy of the counter `core.db` keeps. Every write runs in
//! one transaction that checks the set as it is, applies its changes, raises the counter and
//! stores the MAC of the new set, so a record deleted, edited or restored from an older file no
//! longer matches the MAC, and an older file carries an older counter. This crate computes no MAC:
//! [`WrapperStore::write`] hands the set to the caller's closures.
//!
//! The connection is set up like a module file's writer, without a key, and runs under the write
//! policy of the authorizer, which allows the rows of its tables and no schema change, `ATTACH` or
//! extension; only the fixed statements of this module run on it.

use std::path::{Path, PathBuf};

use rusqlite::types::ValueRef;
use rusqlite::{Connection, ErrorCode, OptionalExtension, TransactionBehavior};
use vilicus_types::Id;

use crate::authorizer::{self, Policy};
use crate::error::{Error, Result};
use crate::file;
use crate::handle::{self, RoleKind, Settings, Setup};

/// The file name of `wrappers.db` in the data directory.
pub const WRAPPERS_FILE_NAME: &str = "wrappers.db";

/// The schema version of `wrappers.db` this Core creates and opens.
pub const WRAPPERS_SCHEMA_VERSION: i64 = 1;

/// The `_meta` row of the schema version.
const META_SCHEMA_VERSION: &str = "wrappers_schema_version";

/// The schema of version 1, made in one transaction by [`create_wrappers`]. Integers that a type
/// holds as `u32` are checked to its range, the member id is 16 bytes, the closed kinds are their
/// identifiers, and a stored public key holds at least its format version and algorithm
/// identifier.
const SCHEMA: &str = "
    CREATE TABLE _meta (key TEXT PRIMARY KEY NOT NULL, value INTEGER NOT NULL) STRICT, WITHOUT ROWID;
    INSERT INTO _meta (key, value) VALUES ('wrappers_schema_version', 1);
    CREATE TABLE member_dek_wrappers (
        member_id BLOB NOT NULL CHECK (length(member_id) = 16),
        kek_kind INTEGER NOT NULL CHECK (kek_kind IN (1, 2)),
        dek_version INTEGER NOT NULL CHECK (dek_version BETWEEN 0 AND 4294967295),
        wrapper BLOB NOT NULL,
        PRIMARY KEY (member_id, kek_kind)
    ) STRICT, WITHOUT ROWID;
    CREATE TABLE member_public_keys (
        member_id BLOB NOT NULL CHECK (length(member_id) = 16),
        key_kind INTEGER NOT NULL CHECK (key_kind IN (1, 2)),
        generation INTEGER NOT NULL CHECK (generation BETWEEN 0 AND 4294967295),
        public_key BLOB NOT NULL CHECK (length(public_key) >= 4),
        PRIMARY KEY (member_id, key_kind)
    ) STRICT, WITHOUT ROWID;
    CREATE TABLE wrapper_set (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        counter INTEGER NOT NULL CHECK (counter >= 0),
        mac BLOB
    ) STRICT;
    INSERT INTO wrapper_set (id, counter, mac) VALUES (1, 0, NULL);
";

/// The tables whose rows make the authenticated record set, in the order they are read; every
/// other table of the file is `wrapper_set`, which holds the counter and the MAC of the set
/// (`every_table_is_a_record_table_or_the_set_state` holds the schema to this).
pub const RECORD_TABLES: [&str; 3] = ["_meta", "member_dek_wrappers", "member_public_keys"];

/// The KEK a member DEK wrapper is sealed under (`doc/key-management.md` sections 2 and 3). A
/// passkey KEK comes after V0.1, with a format of its own (D153).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KekKind {
    /// The passphrase KEK, derived by Argon2id.
    Passphrase,
    /// The recovery KEK, derived from the printed recovery secret.
    Recovery,
}

impl KekKind {
    /// Every kind, in identifier order.
    pub const ALL: [Self; 2] = [Self::Passphrase, Self::Recovery];

    /// The identifier stored in `kek_kind`.
    pub const fn id(self) -> i64 {
        match self {
            Self::Passphrase => 1,
            Self::Recovery => 2,
        }
    }
}

/// The kind of a member public key (`doc/key-management.md` section 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PublicKeyKind {
    /// The member key pair, to which the household key is wrapped.
    Member,
    /// The inbox key pair of the member's personal partition.
    Inbox,
}

impl PublicKeyKind {
    /// Every kind, in identifier order.
    pub const ALL: [Self; 2] = [Self::Member, Self::Inbox];

    /// The identifier stored in `key_kind`.
    pub const fn id(self) -> i64 {
        match self {
            Self::Member => 1,
            Self::Inbox => 2,
        }
    }

    fn from_id(id: i64) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.id() == id)
            .ok_or(Error::MalformedWrapperRow)
    }
}

/// One member DEK wrapper: the member, the KEK it is sealed under, the DEK version it wraps, and
/// the wrapper as `vilicus-crypto` encodes it, its format version and algorithm identifiers first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DekWrapperRow {
    /// The member whose DEK it wraps.
    pub member: Id,
    /// The KEK it is sealed under.
    pub kek: KekKind,
    /// The version of the DEK it wraps, the generation of the member's partition root.
    pub dek_version: u32,
    /// The stored wrapper.
    pub wrapper: Vec<u8>,
}

/// One member public key: the member, its kind, its generation, and its stored encoding, its
/// format version and algorithm identifier first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyRow {
    /// The member it belongs to.
    pub member: Id,
    /// Its kind.
    pub kind: PublicKeyKind,
    /// Its generation.
    pub generation: u32,
    /// Its stored encoding.
    pub public_key: Vec<u8>,
}

/// One change of a write to the record set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WrapperChange {
    /// Writes a DEK wrapper, replacing the member's wrapper under the same KEK.
    PutDekWrapper(DekWrapperRow),
    /// Removes the member's DEK wrapper under `kek`, which must exist.
    RemoveDekWrapper {
        /// The member.
        member: Id,
        /// The KEK of the wrapper removed.
        kek: KekKind,
    },
    /// Writes a public key, replacing the member's key of the same kind.
    PutPublicKey(PublicKeyRow),
    /// Removes the member's public key of `kind`, which must exist.
    RemovePublicKey {
        /// The member.
        member: Id,
        /// The kind of the key removed.
        kind: PublicKeyKind,
    },
}

/// The record set as one transaction read it: the counter, the stored MAC (none before the first
/// write) and the encoding of every record, in the order of [`RECORD_TABLES`] and of each table's
/// primary key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrapperSet {
    /// The monotonic counter of the writes.
    pub counter: u64,
    /// The stored MAC of the set at `counter`; `None` while no write has run.
    pub mac: Option<Vec<u8>>,
    /// The encoding of each record: its table's name and each column, in the column order of the
    /// schema, each preceded by a type tag and, for a blob or a text, its length.
    pub records: Vec<Vec<u8>>,
}

impl WrapperSet {
    /// The records as the MAC takes them.
    pub fn record_slices(&self) -> Vec<&[u8]> {
        self.records.iter().map(Vec::as_slice).collect()
    }
}

/// An open `wrappers.db`.
pub struct WrapperStore {
    connection: Connection,
    path: PathBuf,
    settings: Settings,
}

impl core::fmt::Debug for WrapperStore {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("WrapperStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// A connection to the plain SQLite file at `path`, set up like a module file's writer but with no
/// key, its first page read so that a file that is not a database fails here.
fn connect(path: &Path, create: bool) -> Result<(Connection, Settings)> {
    let connection = handle::open_path(path, create)?;
    match connection.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    }) {
        Ok(_) => {}
        Err(error) if error.sqlite_error_code() == Some(ErrorCode::NotADatabase) => {
            return Err(Error::NotAWrapperFile(path.to_path_buf()));
        }
        Err(error) => return Err(error.into()),
    }
    let settings = handle::set_up(&connection, Setup::Role(RoleKind::Write))?;
    Ok((connection, settings))
}

/// Creates `wrappers.db` in `directory` with the schema of [`WRAPPERS_SCHEMA_VERSION`], its
/// counter at 0 and no MAC, and opens it. The file is built under `wrappers.db.create`, closed,
/// synced, then renamed into place, so the final name exists only once its schema is durable; a
/// staging file left by a crash is discarded by the next creation.
pub fn create_wrappers(directory: &Path) -> Result<WrapperStore> {
    let path = directory.join(WRAPPERS_FILE_NAME);
    if path.exists() {
        return Err(Error::AlreadyExists(path));
    }
    let staging = directory.join(format!("{WRAPPERS_FILE_NAME}.create"));
    for leftover in ["", "-wal", "-shm"] {
        handle::remove_if_present(
            &directory.join(format!("{WRAPPERS_FILE_NAME}.create{leftover}")),
        )?;
    }
    let (connection, _) = connect(&staging, true)?;
    let built = handle::in_transaction(&connection, || Ok(connection.execute_batch(SCHEMA)?));
    let closed = handle::checkpoint_and_close(connection);
    built.and(closed)?;
    std::fs::File::open(&staging)?.sync_all()?;
    std::fs::rename(&staging, &path)?;
    file::sync_parent(&path)?;
    open_wrappers(directory)
}

/// Opens `wrappers.db` in `directory`: [`Error::NotAWrapperFile`] for a file that is not a
/// database, [`Error::WrappersSchemaVersion`] for a schema version this Core does not know.
pub fn open_wrappers(directory: &Path) -> Result<WrapperStore> {
    let path = directory.join(WRAPPERS_FILE_NAME);
    if !path.exists() {
        return Err(Error::Io(std::io::Error::from(
            std::io::ErrorKind::NotFound,
        )));
    }
    let (connection, settings) = connect(&path, false)?;
    let version: Option<i64> = connection
        .query_row(
            "SELECT value FROM _meta WHERE key = ?1",
            [META_SCHEMA_VERSION],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| Error::WrappersSchemaVersion { found: None })?;
    if version != Some(WRAPPERS_SCHEMA_VERSION) {
        return Err(Error::WrappersSchemaVersion { found: version });
    }
    authorizer::install(&connection, Policy::Write)?;
    Ok(WrapperStore {
        connection,
        path,
        settings,
    })
}

/// Appends `value`, one column of a record, to `encoded`: a type tag, then an `i64` big-endian for
/// an integer, or a `u32` big-endian length and the bytes for a blob or a text; a null is its tag
/// alone. No column of the schema holds a real.
fn encode_column(encoded: &mut Vec<u8>, value: ValueRef<'_>) -> Result<()> {
    let with_length = |encoded: &mut Vec<u8>, tag: u8, bytes: &[u8]| -> Result<()> {
        let len = u32::try_from(bytes.len()).map_err(|_| Error::MalformedWrapperRow)?;
        encoded.push(tag);
        encoded.extend_from_slice(&len.to_be_bytes());
        encoded.extend_from_slice(bytes);
        Ok(())
    };
    match value {
        ValueRef::Null => encoded.push(0x00),
        ValueRef::Integer(integer) => {
            encoded.push(0x01);
            encoded.extend_from_slice(&integer.to_be_bytes());
        }
        ValueRef::Blob(bytes) => with_length(encoded, 0x02, bytes)?,
        ValueRef::Text(bytes) => with_length(encoded, 0x03, bytes)?,
        ValueRef::Real(_) => return Err(Error::MalformedWrapperRow),
    }
    Ok(())
}

/// The encoding of every record of [`RECORD_TABLES`]: the table's name with its `u16` big-endian
/// length, then each column of the row in schema order ([`encode_column`]).
fn read_records(connection: &Connection) -> Result<Vec<Vec<u8>>> {
    let mut records = Vec::new();
    for table in RECORD_TABLES {
        let mut statement = connection.prepare(&format!("SELECT * FROM {table} ORDER BY 1, 2"))?;
        let columns = statement.column_count();
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let mut encoded = Vec::new();
            let name = u16::try_from(table.len()).map_err(|_| Error::MalformedWrapperRow)?;
            encoded.extend_from_slice(&name.to_be_bytes());
            encoded.extend_from_slice(table.as_bytes());
            for index in 0..columns {
                encode_column(&mut encoded, row.get_ref(index)?)?;
            }
            records.push(encoded);
        }
    }
    Ok(records)
}

fn read_set(connection: &Connection) -> Result<WrapperSet> {
    let (counter, mac): (i64, Option<Vec<u8>>) = connection.query_row(
        "SELECT counter, mac FROM wrapper_set WHERE id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok(WrapperSet {
        counter: u64::try_from(counter).map_err(|_| Error::MalformedWrapperRow)?,
        mac,
        records: read_records(connection)?,
    })
}

fn member_of(bytes: Vec<u8>) -> Result<Id> {
    let bytes: [u8; 16] = bytes.try_into().map_err(|_| Error::MalformedWrapperRow)?;
    Id::from_bytes(bytes).map_err(|_| Error::MalformedWrapperRow)
}

fn u32_of(value: i64) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::MalformedWrapperRow)
}

fn apply(connection: &Connection, change: &WrapperChange) -> Result<()> {
    let changed = match change {
        WrapperChange::PutDekWrapper(row) => connection.execute(
            "INSERT OR REPLACE INTO member_dek_wrappers (member_id, kek_kind, dek_version, wrapper) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                row.member.to_bytes(),
                row.kek.id(),
                row.dek_version,
                row.wrapper
            ],
        )?,
        WrapperChange::RemoveDekWrapper { member, kek } => connection.execute(
            "DELETE FROM member_dek_wrappers WHERE member_id = ?1 AND kek_kind = ?2",
            rusqlite::params![member.to_bytes(), kek.id()],
        )?,
        WrapperChange::PutPublicKey(row) => connection.execute(
            "INSERT OR REPLACE INTO member_public_keys (member_id, key_kind, generation, public_key) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                row.member.to_bytes(),
                row.kind.id(),
                row.generation,
                row.public_key
            ],
        )?,
        WrapperChange::RemovePublicKey { member, kind } => connection.execute(
            "DELETE FROM member_public_keys WHERE member_id = ?1 AND key_kind = ?2",
            rusqlite::params![member.to_bytes(), kind.id()],
        )?,
    };
    if changed == 0 {
        return Err(Error::WrapperRecordMissing);
    }
    Ok(())
}

impl WrapperStore {
    /// The file's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The settings read back at open.
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// The record set, its counter and its stored MAC, read in one transaction.
    pub fn set(&self) -> Result<WrapperSet> {
        let mut set = None;
        handle::in_transaction(&self.connection, || {
            set = Some(read_set(&self.connection)?);
            Ok(())
        })?;
        set.ok_or(Error::MalformedWrapperRow)
    }

    /// The member's DEK wrapper under `kek`, if there is one. The record set is not checked here:
    /// a member's own wrapper is read before any key that checks the set is at hand, and the
    /// caller checks the set once it holds the household key.
    pub fn dek_wrapper(&self, member: Id, kek: KekKind) -> Result<Option<DekWrapperRow>> {
        let row: Option<(i64, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT dek_version, wrapper FROM member_dek_wrappers \
                 WHERE member_id = ?1 AND kek_kind = ?2",
                rusqlite::params![member.to_bytes(), kek.id()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        row.map(|(dek_version, wrapper)| {
            Ok(DekWrapperRow {
                member,
                kek,
                dek_version: u32_of(dek_version)?,
                wrapper,
            })
        })
        .transpose()
    }

    /// Every member public key, by member then kind.
    pub fn public_keys(&self) -> Result<Vec<PublicKeyRow>> {
        let mut statement = self.connection.prepare(
            "SELECT member_id, key_kind, generation, public_key FROM member_public_keys \
             ORDER BY member_id, key_kind",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        rows.map(|row| {
            let (member, kind, generation, public_key) = row?;
            Ok(PublicKeyRow {
                member: member_of(member)?,
                kind: PublicKeyKind::from_id(kind)?,
                generation: u32_of(generation)?,
                public_key,
            })
        })
        .collect()
    }

    /// Applies `changes` to the record set in one `BEGIN IMMEDIATE` transaction: `check` is given
    /// the set as it is, before any change, and refuses to go on with its error; the changes are
    /// applied in order ([`Error::WrapperRecordMissing`] for a removal of a record that is not
    /// there); the counter is raised by one; `seal` is given the new counter and the new set's
    /// records, and returns the MAC stored with them. Any failure rolls the whole write back.
    /// Once committed, the WAL is checkpointed empty, so a removed wrapper does not stay in it
    /// (D132). Returns the new counter.
    pub fn write<E: From<Error>>(
        &mut self,
        changes: &[WrapperChange],
        check: impl FnOnce(&WrapperSet) -> core::result::Result<(), E>,
        seal: impl FnOnce(u64, &[&[u8]]) -> core::result::Result<Vec<u8>, E>,
    ) -> core::result::Result<u64, E> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(Error::from)?;
        let current = read_set(&transaction)?;
        check(&current)?;
        for change in changes {
            apply(&transaction, change)?;
        }
        let counter = current
            .counter
            .checked_add(1)
            .ok_or(Error::MalformedWrapperRow)?;
        let records = read_records(&transaction)?;
        let slices: Vec<&[u8]> = records.iter().map(Vec::as_slice).collect();
        let mac = seal(counter, &slices)?;
        let stored_counter = i64::try_from(counter).map_err(|_| Error::MalformedWrapperRow)?;
        transaction
            .execute(
                "UPDATE wrapper_set SET counter = ?1, mac = ?2 WHERE id = 1",
                rusqlite::params![stored_counter, mac],
            )
            .map_err(Error::from)?;
        transaction.commit().map_err(Error::from)?;
        handle::checkpoint_wal_until_empty(&self.wal_path(), &self.connection, None)?;
        Ok(counter)
    }

    fn wal_path(&self) -> PathBuf {
        let mut wal = self.path.as_os_str().to_owned();
        wal.push("-wal");
        PathBuf::from(wal)
    }

    /// Closes the store after a TRUNCATE checkpoint.
    pub fn close(self) -> Result<()> {
        handle::checkpoint_and_close(self.connection)
    }

    #[cfg(test)]
    pub(crate) fn raw(&self) -> &Connection {
        &self.connection
    }
}

#[cfg(test)]
mod tests;
