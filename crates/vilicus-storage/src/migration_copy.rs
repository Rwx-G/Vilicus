//! Migrations on a copy (AD-23, D84, D126, D132), the file side of the Core's migration runner:
//! the working copy, its swap into place, the cold copies it leaves and the free space it needs.
//!
//! The working copy of `<file>` lives in its own directory, `<file>.migration/`, beside the file
//! and on the same file system, under the file's own name, so it is a [`ModuleFile`] the
//! migration and read handles open like any other, with its key epoch sidecar. The swap keeps
//! `<file>` naming a complete file at every instant: the original is hard-linked as the cold copy
//! `<file>.pre-<core>.<module>`, named after the versions of the two tracks it holds, with its own
//! sidecar, then the migrated copy is renamed over `<file>`, and the directories are synced. A
//! crash leaves the previous file in place, or the migrated one with its cold copy beside it;
//! what it may leave besides (a working directory, a cold copy that is still the live file, a
//! cold copy's sidecar alone) is cleared by the next migration of the file before it copies
//! anything, and none of it is ever opened as the file.
//!
//! Nothing here runs SQL a caller gives: the migration itself runs on a migration handle of the
//! working copy, under the migration authorizer.

use core::fmt;
use std::fs::{self, File};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::ffi;
use crate::file::{self, KeyEpoch, ModuleFile};
use crate::handle::{self, MigrationTrack, Setup};
use crate::maintenance;

/// The cold copies kept for one file, at most (AD-23, D84).
pub const MAX_COLD_COPIES: usize = 3;

/// The schema versions of a file's two migration tracks (AD-26).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SchemaVersions {
    /// The Core track's version.
    pub core: u32,
    /// The module track's version.
    pub module: u32,
}

impl SchemaVersions {
    /// True when a file at `self` is an earlier state of a file at `later`: both tracks only move
    /// forward, so no track of `later` is behind and the two differ.
    pub fn precedes(self, later: Self) -> bool {
        self != later && self.core <= later.core && self.module <= later.module
    }
}

impl fmt::Display for SchemaVersions {
    /// `<core>.<module>`, as a cold copy's name carries them.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}", self.core, self.module)
    }
}

/// The verified-backup marker of a file, which the caller records once a backup holding the file
/// is verified (AD-31) and gives to the storage layer: the schema versions of the file that
/// backup holds. Every cold copy of an earlier state is then covered by it and may go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedBackup {
    /// The versions of the file in the verified backup.
    pub versions: SchemaVersions,
}

/// A cold copy of a file: the file as it was before a migration, `<file>.pre-<core>.<module>`,
/// with its key epoch sidecar. It opens with the file's key at the versions it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColdCopy {
    versions: SchemaVersions,
    path: PathBuf,
}

impl ColdCopy {
    /// The schema versions the cold copy holds.
    pub fn versions(&self) -> SchemaVersions {
        self.versions
    }

    /// The path of the cold copy.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The key epoch in the cold copy's sidecar.
    pub fn epoch(&self) -> Result<KeyEpoch> {
        file::read_sidecar(&file::sidecar_of(&self.path))
    }
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn cold_copy_path(file: &ModuleFile, versions: SchemaVersions) -> PathBuf {
    suffixed(&file.path(), &format!(".pre-{versions}"))
}

fn working_directory(file: &ModuleFile) -> PathBuf {
    suffixed(&file.path(), ".migration")
}

/// The versions a name `<file>.pre-<core>.<module>` carries, in canonical digits.
fn parse_cold_copy(prefix: &str, name: &str) -> Option<SchemaVersions> {
    let (core, module) = name.strip_prefix(prefix)?.split_once('.')?;
    let number = |digits: &str| {
        let canonical = !digits.is_empty()
            && digits.bytes().all(|byte| byte.is_ascii_digit())
            && (digits == "0" || !digits.starts_with('0'));
        canonical.then(|| digits.parse().ok()).flatten()
    };
    Some(SchemaVersions {
        core: number(core)?,
        module: number(module)?,
    })
}

/// The cold copies of `file`, oldest first.
pub fn cold_copies(file: &ModuleFile) -> Result<Vec<ColdCopy>> {
    let prefix = format!("{}.pre-", file.file_name());
    let mut copies = Vec::new();
    for entry in fs::read_dir(file.directory())? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(versions) = name
            .to_str()
            .and_then(|name| parse_cold_copy(&prefix, name))
        else {
            continue;
        };
        copies.push(ColdCopy {
            versions,
            path: entry.path(),
        });
    }
    copies.sort_by_key(|copy| (copy.versions.core, copy.versions.module));
    Ok(copies)
}

fn remove_cold_copy(copy: &ColdCopy) -> Result<()> {
    handle::remove_if_present(&copy.path)?;
    handle::remove_if_present(&file::sidecar_of(&copy.path))?;
    handle::remove_if_present(&suffixed(&file::sidecar_of(&copy.path), ".tmp"))
}

/// Removes every cold copy of `file` that `backup` covers, an earlier state of the file than the
/// one the verified backup holds, and returns how many went; the others are kept, so no cold
/// copy goes before a verified backup holds a later state of its file (AD-23, AD-31).
pub fn remove_covered_cold_copies(file: &ModuleFile, backup: VerifiedBackup) -> Result<usize> {
    let mut removed = 0;
    for copy in cold_copies(file)? {
        if copy.versions.precedes(backup.versions) {
            remove_cold_copy(&copy)?;
            removed += 1;
        }
    }
    if removed > 0 {
        file::sync_parent(&file.path())?;
    }
    Ok(removed)
}

/// The free space, in bytes, of the file system that holds `directory`, as an unprivileged
/// process may use it.
pub fn available_space(directory: &Path) -> Result<u64> {
    Ok(ffi::available_bytes(directory)?)
}

/// Clears what an interrupted migration of `file` may have left: its working directory, a cold
/// copy that is still the live file (a crash between the link and the rename of the swap), and
/// a cold copy's sidecar without its copy.
fn clear_interrupted(file: &ModuleFile) -> Result<()> {
    remove_working_directory(&working_directory(file))?;
    let live = fs::metadata(file.path())?;
    for copy in cold_copies(file)? {
        let metadata = fs::metadata(&copy.path)?;
        if metadata.dev() == live.dev() && metadata.ino() == live.ino() {
            remove_cold_copy(&copy)?;
        }
    }
    let prefix = format!("{}.pre-", file.file_name());
    for entry in fs::read_dir(file.directory())? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let database = name
            .strip_suffix(".epoch.tmp")
            .or_else(|| name.strip_suffix(".epoch"));
        if let Some(database) = database
            && parse_cold_copy(&prefix, database).is_some()
            && !file.directory().join(database).exists()
        {
            handle::remove_if_present(&path)?;
        }
    }
    file::sync_parent(&file.path())
}

fn remove_working_directory(directory: &Path) -> Result<()> {
    match fs::read_dir(directory) {
        Ok(entries) => {
            for entry in entries {
                handle::remove_if_present(&entry?.path())?;
            }
            fs::remove_dir(directory)?;
            file::sync_parent(directory)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// What the swap compares with the state the copy was made from, to notice a connection that
/// wrote the live file meanwhile, or that is still open on it: the file's length, inode and
/// modification and change times, in nanoseconds, and whether its WAL or its shared-memory file
/// exists. SQLite removes both at the last close of a file in WAL mode, so a connection open on
/// the file, whether it wrote or not, leaves at least the shared-memory file; a write committed
/// into the WAL by a connection that stays open is never in the database file, and a swap past
/// such a connection would lose the write, or have a later connection read the old WAL into the
/// new file.
#[derive(Debug, PartialEq, Eq)]
struct LiveState {
    length: u64,
    inode: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    wal_present: bool,
    shm_present: bool,
}

fn live_state(file: &ModuleFile) -> Result<LiveState> {
    let metadata = fs::metadata(file.path())?;
    Ok(LiveState {
        length: metadata.len(),
        inode: metadata.ino(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
        wal_present: file.wal_path().exists(),
        shm_present: suffixed(&file.path(), "-shm").exists(),
    })
}

/// The state of the live file once the copy closed its own connection: no other connection may
/// be open on it, which its WAL or shared-memory file would show ([`Error::CopyRaced`]).
fn closed_live_state(file: &ModuleFile) -> Result<LiveState> {
    let state = live_state(file)?;
    if state.wal_present || state.shm_present {
        return Err(Error::CopyRaced(file.path()));
    }
    Ok(state)
}

/// The working copy of a migration (AD-23, D84): a copy of the live file, made on the Core
/// maintenance path, which the caller migrates and checks through the handles of
/// [`file`](Self::file), then swaps into place or discards. Dropped without either, it is
/// discarded.
#[derive(Debug)]
pub struct MigrationCopy {
    live: ModuleFile,
    copy: ModuleFile,
    from: SchemaVersions,
    epoch: KeyEpoch,
    before: LiveState,
    done: bool,
}

/// Starts the migration of `file` on a copy (AD-23, D84, D126):
///
/// 1. clears what an interrupted migration of the file left;
/// 2. removes the cold copies that `verified_backup`, the caller's verified-backup marker,
///    covers, and refuses with [`Error::ColdCopiesFull`] when [`MAX_COLD_COPIES`] remain, since
///    none of them may go before a verified backup and the migration would leave one more;
/// 3. reads the key epoch (a pending change of epoch fails, [`Error::EpochTransitionPending`]),
///    then, on a maintenance connection keyed with `key` and checked against the sidecar, the
///    versions of the two tracks, and runs a TRUNCATE checkpoint until the WAL is empty
///    (D132), before closing it; the caller has closed every other connection first, and a WAL
///    that still holds content fails with [`Error::WalNotEmpty`];
/// 4. copies the file and its sidecar into the working directory as a plain file copy on the
///    Core maintenance path, never with `VACUUM INTO` or `ATTACH` ([`maintenance::copy_file`]).
///
/// The live file is only read: on any failure it is as it was, and nothing of the copy is left.
pub fn copy_for_migration(
    file: &ModuleFile,
    key: &[u8; 32],
    verified_backup: Option<VerifiedBackup>,
) -> Result<MigrationCopy> {
    clear_interrupted(file)?;
    if let Some(backup) = verified_backup {
        remove_covered_cold_copies(file, backup)?;
    }
    let kept = cold_copies(file)?.len();
    if kept >= MAX_COLD_COPIES {
        return Err(Error::ColdCopiesFull { kept });
    }
    let epoch = file::read_epoch(file)?;
    let (connection, _) = handle::connect(file, key, Setup::Maintenance, false)?;
    let read = handle::checked_epoch(file, &connection).and_then(|_| {
        let from = SchemaVersions {
            core: handle::read_schema_version(&connection, MigrationTrack::Core)?,
            module: handle::read_schema_version(&connection, MigrationTrack::Module)?,
        };
        handle::checkpoint_until_empty(file, &connection).map(|_| from)
    });
    let closed = handle::checkpoint_and_close(connection);
    let from = read.and_then(|from| closed.map(|()| from))?;
    if !handle::wal_of_is_empty(&file.wal_path())? {
        return Err(Error::WalNotEmpty(file.wal_path()));
    }
    let directory = working_directory(file);
    fs::create_dir(&directory)?;
    file::sync_parent(&directory)?;
    let copy = ModuleFile::new(&directory, file.module().clone(), file.partition());
    let copied = maintenance::copy_file(file, &copy.path()).and_then(|()| closed_live_state(file));
    match copied {
        Ok(before) => Ok(MigrationCopy {
            live: file.clone(),
            copy,
            from,
            epoch,
            before,
            done: false,
        }),
        Err(error) => {
            remove_working_directory(&directory)?;
            Err(error)
        }
    }
}

impl MigrationCopy {
    /// The working copy, which the caller opens with the live file's key: a migration handle to
    /// migrate it, a read or write handle to check it.
    pub fn file(&self) -> &ModuleFile {
        &self.copy
    }

    /// The versions of the two tracks the live file was at when it was copied.
    pub fn from(&self) -> SchemaVersions {
        self.from
    }

    /// Swaps the migrated copy into place (AD-23): the caller has closed every handle of the
    /// copy, each with a TRUNCATE checkpoint. The copy's WAL must be empty
    /// ([`Error::WalNotEmpty`]), both sidecars at the epoch of the copy
    /// ([`Error::EpochMismatch`]), and the live file unchanged since it was copied, with no
    /// connection open on it ([`Error::CopyRaced`]), checked last, right before the link; then the
    /// copy is synced, the cold copy's sidecar written, the original hard-linked as the cold copy
    /// `<file>.pre-<core>.<module>` of [`from`](Self::from), the copy renamed over the file and the
    /// directory synced. `<file>` names the original until the rename and the migrated file after
    /// it, never nothing; `<file>.epoch` is not touched, since a migration keeps the key and its
    /// epoch. A failure before the rename leaves the original as the file, without its cold copy,
    /// and the working copy to discard.
    ///
    /// The checks narrow the window in which a connection could open on the live file between
    /// the copy and the rename, they do not close it: only the Core, which serializes every
    /// connection to a file on its writer thread (AD-9), keeps one from opening there.
    pub fn swap_in(mut self) -> Result<ColdCopy> {
        let swapped = self.swap();
        if swapped.is_ok() {
            self.done = true;
        }
        swapped
    }

    fn swap(&self) -> Result<ColdCopy> {
        let copy_wal = self.copy.wal_path();
        if !handle::wal_of_is_empty(&copy_wal)? {
            return Err(Error::WalNotEmpty(copy_wal));
        }
        File::open(self.copy.path())?.sync_all()?;
        for epoch in [file::read_epoch(&self.live)?, file::read_epoch(&self.copy)?] {
            if epoch != self.epoch {
                return Err(Error::EpochMismatch {
                    sidecar: epoch,
                    file: self.epoch,
                });
            }
        }
        let cold = ColdCopy {
            versions: self.from,
            path: cold_copy_path(&self.live, self.from),
        };
        if cold.path.exists() {
            return Err(Error::AlreadyExists(cold.path));
        }
        file::write_sidecar(&file::sidecar_of(&cold.path), self.epoch)?;
        let linked = closed_live_state(&self.live)
            .and_then(|now| {
                if now == self.before {
                    Ok(())
                } else {
                    Err(Error::CopyRaced(self.live.path()))
                }
            })
            .and_then(|()| fs::hard_link(self.live.path(), &cold.path).map_err(Error::from))
            .and_then(|()| file::sync_parent(&cold.path))
            .and_then(|()| fs::rename(self.copy.path(), self.live.path()).map_err(Error::from));
        if let Err(error) = linked {
            remove_cold_copy(&cold)?;
            file::sync_parent(&cold.path)?;
            return Err(error);
        }
        file::sync_parent(&self.live.path())?;
        remove_working_directory(self.copy.directory())?;
        Ok(cold)
    }

    /// Discards the working copy, its WAL and sidecar included, and its directory; the live file
    /// is not touched.
    pub fn discard(mut self) -> Result<()> {
        self.done = true;
        remove_working_directory(self.copy.directory())
    }
}

impl Drop for MigrationCopy {
    fn drop(&mut self) {
        if !self.done {
            // A copy neither swapped in nor discarded, as when a panic unwinds: no caller to
            // report to, and the next migration of the file clears it anyway.
            let _ = remove_working_directory(self.copy.directory());
        }
    }
}
