//! The frozen hash of each migration (AD-23, D21) and the record a file keeps of the migrations
//! it ran, in the Core table `_migrations`.
//!
//! The storage layer computes no digest: each migration comes with the frozen hash its
//! declaration states, and the Core, which hashes through `vilicus-crypto`, checks that hash
//! against the SQL before it hands the migration over. What the storage layer holds is the
//! agreement between a file and the code: the runner records the frozen hash of every migration
//! it applies, in the migration's own transaction, and refuses to run anything on a file whose
//! record differs from the frozen hashes of the migrations before the next one, so a migration
//! edited after a file ran it is refused before any SQL runs.

use rusqlite::Connection;
use vilicus_types::SHA256_LEN;

use crate::error::{Error, Result};
use crate::handle::MigrationTrack;

/// One migration as the runner applies it: its SQL and its frozen hash, the SHA-256 of the SQL
/// that the migration's declaration states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrozenMigration<'a> {
    /// The SQL.
    pub sql: &'a str,
    /// The frozen hash.
    pub sha256: [u8; SHA256_LEN],
}

impl MigrationTrack {
    /// The track's name in `_migrations`.
    pub(crate) fn record_name(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Module => "module",
        }
    }
}

/// The frozen hashes `_migrations` records for `track`, version 1 first. The versions are
/// 1 to n with none missing, or the rows are malformed.
pub(crate) fn recorded(connection: &Connection, track: MigrationTrack) -> Result<Vec<[u8; 32]>> {
    let mut statement = connection
        .prepare("SELECT version, sha256 FROM _migrations WHERE track = ?1 ORDER BY version")?;
    let rows = statement.query_map([track.record_name()], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    let malformed = |column| Error::MalformedCoreRow {
        table: "_migrations",
        column,
    };
    let mut hashes = Vec::new();
    for (expected, row) in (1_i64..).zip(rows) {
        let (version, sha256) = row?;
        if version != expected {
            return Err(malformed("version"));
        }
        hashes.push(<[u8; 32]>::try_from(sha256).map_err(|_| malformed("sha256"))?);
    }
    Ok(hashes)
}

/// Refuses a file whose record of `track` is not exactly the frozen hashes of `expected`, the
/// migrations the file is at: [`Error::MigrationChanged`] names the first version that differs,
/// is missing or is recorded beyond them. A Core track at version 0 has no `_migrations` table
/// yet, since its first migration makes it, so it has nothing to compare.
pub(crate) fn check_recorded(
    connection: &Connection,
    track: MigrationTrack,
    expected: &[FrozenMigration<'_>],
) -> Result<()> {
    if track == MigrationTrack::Core && expected.is_empty() {
        return Ok(());
    }
    let recorded = recorded(connection, track)?;
    let first_difference = (1_u32..)
        .zip(
            expected
                .iter()
                .map(|migration| Some(&migration.sha256))
                .chain([None]),
        )
        .zip(recorded.iter().map(Some).chain([None]))
        .find_map(|((version, frozen), record)| (frozen != record).then_some(version));
    match first_difference {
        None => Ok(()),
        Some(version) => Err(Error::MigrationChanged { track, version }),
    }
}

/// Records the frozen hash of migration `version` of `track`, in the runner's transaction and
/// under the Core policy, never by migration SQL.
pub(crate) fn record(
    connection: &Connection,
    track: MigrationTrack,
    version: u32,
    migration: &FrozenMigration<'_>,
) -> Result<()> {
    connection.execute(
        "INSERT INTO _migrations (track, version, sha256) VALUES (?1, ?2, ?3)",
        rusqlite::params![track.record_name(), version, migration.sha256.as_slice()],
    )?;
    Ok(())
}
