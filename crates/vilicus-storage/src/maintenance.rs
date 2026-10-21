//! The Core maintenance path (D126, D132, AD-23): copies of a file and VACUUM, which module
//! connections refuse because `VACUUM`, `VACUUM INTO` and `ATTACH` attach a database.
//!
//! Each function opens its own connection, set up like a writer but with no module authorizer,
//! runs one operation and closes it after a TRUNCATE checkpoint; no function takes SQL, so the
//! missing authorizer guards nothing a caller could reach.

use std::fs::{self, File};
use std::os::raw::c_int;
use std::path::Path;
use std::time::Duration;

use rusqlite::Connection;
use rusqlite::backup::Backup;

use crate::error::{Error, Result};
use crate::file::ModuleFile;
use crate::handle::{self, Setup};

/// Copies `file` to `destination` as a plain file copy, synced, as the migration copy step and a
/// small file's backup do (AD-23, AD-31). The caller has closed every connection to the file
/// first; a WAL that still holds content is refused, since its frames would be missing from the
/// copy.
pub fn copy_file(file: &ModuleFile, destination: &Path) -> Result<()> {
    let wal = file.wal_path();
    match fs::metadata(&wal) {
        Ok(metadata) if metadata.len() > 0 => return Err(Error::WalNotEmpty(wal)),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    fs::copy(file.path(), destination)?;
    File::open(destination)?.sync_all()?;
    if let Some(directory) = destination.parent() {
        File::open(directory)?.sync_all()?;
    }
    Ok(())
}

/// Copies `file` to `destination` with SQLite's online backup API, `pages_per_step` pages at a
/// time with `pause` between steps, so a writer of the file waits for at most one step (AD-31,
/// D136). The copy is a SQLCipher file under the same raw `key`; `destination` must not exist.
pub fn backup(
    file: &ModuleFile,
    key: &[u8; 32],
    destination: &Path,
    pages_per_step: c_int,
    pause: Duration,
) -> Result<()> {
    if destination.exists() {
        return Err(Error::AlreadyExists(destination.to_path_buf()));
    }
    let (source, _) = handle::connect(file, key, Setup::Maintenance, false)?;
    handle::checked_epoch(file, &source)?;
    let mut target = Connection::open(destination)?;
    let copied = (|| -> Result<()> {
        prepare_backup_target(&target, key)?;
        Backup::new(&source, &mut target)?.run_to_completion(pages_per_step, pause, None)?;
        Ok(())
    })();
    let closed_target = target.close().map_err(|(_, error)| Error::from(error));
    let closed_source = handle::checkpoint_and_close(source);
    copied.and(closed_target).and(closed_source)?;
    File::open(destination)?.sync_all()?;
    Ok(())
}

/// The backup target is keyed like the source before the first page arrives; SQLCipher refuses
/// a backup between files with different keys or settings.
fn prepare_backup_target(target: &Connection, key: &[u8; 32]) -> Result<()> {
    crate::ffi::set_extension_loading_api(target, false)?;
    handle::key_connection(target, key)?;
    target.pragma_update(None, "secure_delete", true)?;
    Ok(())
}

/// Runs VACUUM on `file`, on a connection opened for that purpose and closed after it. It is the
/// fallback for content deleted while `secure_delete` was off, never a routine step: deletions
/// under `secure_delete` = ON followed by a TRUNCATE checkpoint need none (D132, E17).
pub fn vacuum(file: &ModuleFile, key: &[u8; 32]) -> Result<()> {
    let (connection, _) = handle::connect(file, key, Setup::Maintenance, false)?;
    let outcome = handle::checked_epoch(file, &connection)
        .and_then(|_| connection.execute_batch("VACUUM").map_err(Error::from))
        .and_then(|()| handle::checkpoint_until_empty(file, &connection));
    let closed = handle::checkpoint_and_close(connection);
    outcome.and(closed)
}
