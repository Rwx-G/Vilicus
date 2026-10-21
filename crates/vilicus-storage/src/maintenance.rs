//! The Core maintenance path (D126, D132, AD-23): copies of a file and VACUUM, which module
//! connections refuse because `VACUUM`, `VACUUM INTO` and `ATTACH` attach a database.
//!
//! Each function opens its own connections, set up like a writer but with no module authorizer,
//! runs one operation and closes them after a TRUNCATE checkpoint; no function takes SQL, so the
//! missing authorizer guards nothing a caller could reach.
//!
//! A copy is written under `<destination>.partial`, synced, given its key epoch sidecar
//! `<destination>.epoch` and renamed into place, so `<destination>` never names a partial copy;
//! a failure removes the partial file. An existing destination or destination sidecar is refused.

use std::fs::{self, File};
use std::os::raw::c_int;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use rusqlite::backup::Backup;

use crate::error::{Error, Result};
use crate::file::{self, KeyEpoch, ModuleFile};
use crate::handle::{self, Setup};

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Refuses a destination, or its sidecar, that is already in place, and clears what an earlier
/// failed copy to the same destination may have left under the partial name.
fn prepare_destination(destination: &Path) -> Result<PathBuf> {
    for taken in [destination.to_path_buf(), file::sidecar_of(destination)] {
        if taken.exists() {
            return Err(Error::AlreadyExists(taken));
        }
    }
    let partial = suffixed(destination, ".partial");
    remove_partial(&partial)?;
    Ok(partial)
}

fn remove_partial(partial: &Path) -> Result<()> {
    for path in [
        partial.to_path_buf(),
        suffixed(partial, "-wal"),
        suffixed(partial, "-shm"),
    ] {
        handle::remove_if_present(&path)?;
    }
    Ok(())
}

/// The synced partial copy becomes `destination`: its sidecar first, then the rename, then the
/// directory synced.
fn publish(partial: &Path, destination: &Path, epoch: KeyEpoch) -> Result<()> {
    File::open(partial)?.sync_all()?;
    file::write_sidecar(&file::sidecar_of(destination), epoch)?;
    fs::rename(partial, destination)?;
    file::sync_parent(destination)
}

/// What a copy compares before and after, to notice a connection that wrote meanwhile.
#[derive(PartialEq, Eq)]
struct Snapshot {
    length: u64,
    modified: SystemTime,
    wal_empty: bool,
}

fn snapshot(file: &ModuleFile) -> Result<Snapshot> {
    let metadata = fs::metadata(file.path())?;
    Ok(Snapshot {
        length: metadata.len(),
        modified: metadata.modified()?,
        wal_empty: handle::wal_of_is_empty(&file.wal_path())?,
    })
}

/// Copies `file` and its sidecar to `destination` as a plain file copy, as the migration copy
/// step and a small file's backup do (AD-23, AD-31).
///
/// The caller has closed every connection to the file first. Only the Core opens module files,
/// and it serializes the copy with the file's writer thread (AD-9), so no connection can open in
/// between; as a second line, the WAL is checked empty before the copy, and the file's length,
/// modification time and WAL are checked unchanged after it, and a difference fails with
/// [`Error::CopyRaced`] instead of producing a copy that may be torn.
pub fn copy_file(file: &ModuleFile, destination: &Path) -> Result<()> {
    let partial = prepare_destination(destination)?;
    let epoch = file::read_epoch(file)?;
    let before = snapshot(file)?;
    if !before.wal_empty {
        return Err(Error::WalNotEmpty(file.wal_path()));
    }
    let copied = fs::copy(file.path(), &partial)
        .map_err(Error::from)
        .and_then(|_| snapshot(file))
        .and_then(|after| {
            if after == before {
                Ok(())
            } else {
                Err(Error::CopyRaced(file.path()))
            }
        })
        .and_then(|()| publish(&partial, destination, epoch));
    if copied.is_err() {
        remove_partial(&partial)?;
    }
    copied
}

/// Copies `file` and its sidecar to `destination` with SQLite's online backup API,
/// `pages_per_step` pages at a time with `pause` between steps, so a writer of the file waits for
/// at most one step (AD-31, D136). The copy is a SQLCipher file under the same raw `key`, whose
/// connection is set up like every other (no URI, busy timeout, extension loading off, the setup
/// pragmas, `DEFENSIVE`, read back).
pub fn backup(
    file: &ModuleFile,
    key: &[u8; 32],
    destination: &Path,
    pages_per_step: c_int,
    pause: Duration,
) -> Result<()> {
    let partial = prepare_destination(destination)?;
    let (source, _) = handle::connect(file, key, Setup::Maintenance, false)?;
    let copied = handle::checked_epoch(file, &source).and_then(|epoch| {
        let (mut target, _) = handle::connect_path(&partial, key, Setup::Maintenance, true)?;
        let ran = Backup::new(&source, &mut target)
            .and_then(|backup| backup.run_to_completion(pages_per_step, pause, None))
            .map_err(Error::from);
        let closed = handle::checkpoint_and_close(target);
        ran.and(closed)?;
        let wal = suffixed(&partial, "-wal");
        if !handle::wal_of_is_empty(&wal)? {
            return Err(Error::WalNotEmpty(wal));
        }
        Ok(epoch)
    });
    let closed_source = handle::checkpoint_and_close(source);
    let published = copied
        .and_then(|epoch| closed_source.map(|()| epoch))
        .and_then(|epoch| publish(&partial, destination, epoch));
    if published.is_err() {
        remove_partial(&partial)?;
    }
    published
}

/// Runs VACUUM on `file`, on a connection opened for that purpose and closed after it. It is the
/// fallback for content deleted while `secure_delete` was off, never a routine step: deletions
/// under `secure_delete` = ON followed by a TRUNCATE checkpoint need none (D132, E17).
pub fn vacuum(file: &ModuleFile, key: &[u8; 32]) -> Result<()> {
    let (connection, _) = handle::connect(file, key, Setup::Maintenance, false)?;
    let outcome = handle::checked_epoch(file, &connection)
        .and_then(|_| connection.execute_batch("VACUUM").map_err(Error::from))
        .and_then(|()| handle::checkpoint_until_empty(file, &connection).map(drop));
    let closed = handle::checkpoint_and_close(connection);
    outcome.and(closed)
}
