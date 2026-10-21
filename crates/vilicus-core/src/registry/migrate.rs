//! The migration runner of the Core (FR-23, FR-54, AD-23, D21, D84): every module file migrated
//! forward only, on a copy swapped in on success, one file after the other.
//!
//! [`Registry::migrate_files`] first reads where each file stands, then refuses to start unless
//! each data directory has at least twice the size of the largest file it would copy. Each file
//! with pending migrations is then copied on the maintenance path, the copy migrated through the
//! migration runner, Core track first, checked as the Core checks every file it opens (versions,
//! the record of frozen hashes, the schema against the declaration), every stored row checked
//! against the declaration and every FTS5 index checked, and only then swapped in. A file whose
//! migration fails keeps its previous file untouched and gets a typed instance admin alert, and
//! the next file proceeds.

use core::fmt;
use std::collections::BTreeMap;
use std::path::PathBuf;

use vilicus_module_api::ModuleDeclaration;
use vilicus_storage::maintenance::{self, ColdCopy, MigrationCopy, SchemaVersions, VerifiedBackup};
use vilicus_storage::{
    CORE_SCHEMA_VERSION, FrozenMigration, Migration, MigrationTrack, ModuleFile, Read, Write,
};
use vilicus_types::ModuleName;

use super::{FileError, Registry, check_recorded_tracks, frozen_migrations};
use crate::alert::InstanceAdminAlert;
use crate::record::{RecordError, check_stored_rows};

/// One file to migrate, with its raw key and the verified-backup marker the caller recorded for
/// it (AD-31): the cold copies that marker covers are removed before the file's migration.
#[derive(Clone, Copy)]
pub struct FileToMigrate<'a> {
    /// The file.
    pub file: &'a ModuleFile,
    /// Its raw 256-bit key.
    pub key: &'a [u8; 32],
    /// The schema versions of the file in the last verified backup that holds it, if any.
    pub verified_backup: Option<VerifiedBackup>,
}

impl fmt::Debug for FileToMigrate<'_> {
    /// The file and the marker; never the key.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileToMigrate")
            .field("file", &self.file.file_name())
            .field("verified_backup", &self.verified_backup)
            .finish_non_exhaustive()
    }
}

/// What the runner did with one file.
#[derive(Debug)]
#[non_exhaustive]
pub enum FileMigration {
    /// Nothing was pending: the file is at the code's versions, with the code's frozen hashes.
    Current,
    /// The file was migrated on a copy, swapped in; the original is its cold copy.
    Migrated {
        /// The versions the file was at.
        from: SchemaVersions,
        /// The versions it is at now, the code's.
        to: SchemaVersions,
        /// The cold copy of the original.
        cold_copy: ColdCopy,
        /// What failed after the migrated file was put in place, if anything: the sync of the
        /// directory or the removal of the working copy. A warning for the logs, not a failed
        /// migration; the next migration of the file clears the working copy.
        cleanup: Option<vilicus_storage::Error>,
    },
    /// The file could not be migrated (AD-54 `failed migration`): the previous file stays in
    /// place untouched, at its versions, which the Core's open refuses as pending, so the module
    /// is not started on it in that partition; the fix is a forward release (D84).
    Failed {
        /// The alert to the instance admin, naming the file and the version.
        alert: InstanceAdminAlert,
        /// Why it failed.
        error: MigrationError,
    },
    /// The file is newer than the code (D21, AD-54 `newer than code`): it is not touched, and
    /// the module is not started on it.
    NewerThanCode {
        /// The alert to the instance admin.
        alert: InstanceAdminAlert,
    },
}

/// Why one file's migration failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum MigrationError {
    /// The storage layer failed: the copy, a migration, its record, the swap.
    Storage(vilicus_storage::Error),
    /// The file, or its migrated copy, is not what the Core opens: a changed migration, versions
    /// other than the code's, a schema other than the declaration.
    File(FileError),
    /// A row of the migrated copy is outside the declaration (D146), as a back-fill may write.
    StoredRow(RecordError),
    /// FTS5's `integrity-check` failed on an index of the migrated copy (D127).
    Fts5Index {
        /// The FTS5 table.
        table: &'static str,
        /// The failure.
        error: vilicus_storage::Error,
    },
}

impl fmt::Display for MigrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(formatter, "{error}"),
            Self::File(error) => write!(formatter, "{error}"),
            Self::StoredRow(error) => write!(formatter, "a migrated row: {error}"),
            Self::Fts5Index { table, error } => {
                write!(formatter, "the FTS5 index {table} fails its check: {error}")
            }
        }
    }
}

impl std::error::Error for MigrationError {}

impl From<vilicus_storage::Error> for MigrationError {
    fn from(error: vilicus_storage::Error) -> Self {
        match FileError::from(error) {
            FileError::Storage(error) => Self::Storage(error),
            other => Self::File(other),
        }
    }
}

impl From<FileError> for MigrationError {
    fn from(error: FileError) -> Self {
        match error {
            FileError::Storage(error) => Self::Storage(error),
            other => Self::File(other),
        }
    }
}

/// Why a run does not start; nothing was touched.
#[derive(Debug)]
#[non_exhaustive]
pub enum MigrationRunError {
    /// A file belongs to no registered module.
    UnregisteredModule(ModuleName),
    /// A data directory has less free space than twice the largest file the run would copy there
    /// (AD-23).
    InsufficientSpace {
        /// The directory.
        directory: PathBuf,
        /// Its free space, in bytes.
        available: u64,
        /// Twice the largest file to migrate there, in bytes.
        required: u64,
    },
    /// The free space of a data directory could not be read.
    Storage(vilicus_storage::Error),
}

impl fmt::Display for MigrationRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnregisteredModule(module) => {
                write!(formatter, "module {module} is not registered")
            }
            Self::InsufficientSpace {
                directory,
                available,
                required,
            } => write!(
                formatter,
                "{}: {available} bytes free, {required} needed to migrate",
                directory.display()
            ),
            Self::Storage(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for MigrationRunError {}

/// Where a file stands before the run.
enum Standing {
    Current,
    Pending {
        from: SchemaVersions,
        migrations: Vec<FrozenMigration<'static>>,
        bytes: u64,
    },
    NewerThanCode(InstanceAdminAlert),
    Failed(InstanceAdminAlert, MigrationError),
}

impl Registry {
    /// Migrates each of `files` forward to the code's versions, on a copy swapped in on success
    /// (AD-23, D84), and returns what became of each, in order.
    ///
    /// The caller has closed every connection to these files. The run does not start, and
    /// touches nothing, when a file belongs to no registered module, or when a data directory
    /// has less free space than twice the largest file it would copy there
    /// ([`MigrationRunError::InsufficientSpace`]). Then, per file: a migration whose SQL differs
    /// from its frozen hash, or a file that recorded other frozen hashes for the versions it is
    /// at, fails before anything runs; a file newer than the code is left alone; a file with
    /// pending migrations is migrated on a copy (Core track first, then the module's), the copy
    /// checked as [`Registry::open`] checks every file, its stored rows held to the declaration
    /// and its FTS5 indexes checked, and only then swapped in, the original kept as a cold copy;
    /// at most three cold copies per file, the oldest removed only once `verified_backup`
    /// covers them. A failure keeps the previous file untouched and returns an alert naming the
    /// file and the version; the next file proceeds.
    pub fn migrate_files(
        &self,
        files: &[FileToMigrate<'_>],
    ) -> Result<Vec<FileMigration>, MigrationRunError> {
        let modules = files
            .iter()
            .map(|target| {
                self.module(target.file.module()).ok_or_else(|| {
                    MigrationRunError::UnregisteredModule(target.file.module().clone())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let standings: Vec<Standing> = files
            .iter()
            .zip(&modules)
            .map(|(target, module)| standing(module, target))
            .collect();
        check_space(files, &standings)?;
        Ok(files
            .iter()
            .zip(modules)
            .zip(standings)
            .map(|((target, module), standing)| match standing {
                Standing::Current => FileMigration::Current,
                Standing::NewerThanCode(alert) => FileMigration::NewerThanCode { alert },
                Standing::Failed(alert, error) => FileMigration::Failed { alert, error },
                Standing::Pending {
                    from, migrations, ..
                } => self.migrate_on_copy(module, target, from, &migrations),
            })
            .collect())
    }

    fn migrate_on_copy(
        &self,
        module: &'static ModuleDeclaration,
        target: &FileToMigrate<'_>,
        from: SchemaVersions,
        migrations: &[FrozenMigration<'static>],
    ) -> FileMigration {
        let to = SchemaVersions {
            core: CORE_SCHEMA_VERSION,
            module: module.latest_version(),
        };
        let swapped =
            maintenance::copy_for_migration(target.file, target.key, target.verified_backup)
                .map_err(MigrationError::from)
                .and_then(
                    |copy| match self.migrate_copy(module, &copy, target.key, migrations) {
                        Ok(()) => copy.swap_in().map_err(MigrationError::from),
                        Err(error) => {
                            // The copy's own failure to go is not reported: the migration's error says why
                            // the file was not migrated, and the next migration clears the copy anyway.
                            let _ = copy.discard();
                            Err(error)
                        }
                    },
                );
        match swapped {
            Ok(swapped) => FileMigration::Migrated {
                from,
                to,
                cold_copy: swapped.cold_copy,
                cleanup: swapped.cleanup,
            },
            Err(error) => {
                let (track, version) = failed_step(&error, from);
                FileMigration::Failed {
                    alert: InstanceAdminAlert::migration_failed(target.file, track, version),
                    error,
                }
            }
        }
    }

    /// Migrates the working copy, then checks it before it may be swapped in: as the Core opens
    /// every file, every stored row against the declaration (D146) and every FTS5 index with
    /// FTS5's `integrity-check` (D127). Every handle of the copy is closed after a TRUNCATE
    /// checkpoint.
    fn migrate_copy(
        &self,
        module: &'static ModuleDeclaration,
        copy: &MigrationCopy,
        key: &[u8; 32],
        migrations: &[FrozenMigration<'static>],
    ) -> Result<(), MigrationError> {
        let mut migration = vilicus_storage::open::<Migration>(copy.file(), key)?;
        let applied = migration
            .apply_core_migrations()
            .and_then(|_| migration.apply_module_migrations(migrations));
        let closed = migration.close();
        applied.and(closed)?;
        let handle = self.open::<Write>(copy.file(), key)?;
        let checked = check_stored_rows(&handle, module)
            .map_err(MigrationError::StoredRow)
            .and_then(|()| {
                module.fts5_tables.iter().try_for_each(|fts5| {
                    handle
                        .execute_batch(&format!(
                            "INSERT INTO {0} ({0}) VALUES ('integrity-check')",
                            fts5.name
                        ))
                        .map_err(|error| MigrationError::Fts5Index {
                            table: fts5.name,
                            error,
                        })
                })
            });
        let closed = handle.close().map_err(MigrationError::from);
        checked.and(closed)
    }
}

/// Where `target` stands: the code's own migrations checked against their frozen hashes, then
/// the file's versions and its record of frozen hashes, read on a read handle closed at once.
fn standing(module: &'static ModuleDeclaration, target: &FileToMigrate<'_>) -> Standing {
    let file = target.file;
    let migrations = match frozen_migrations(module) {
        Ok(migrations) => migrations,
        Err(error) => {
            let (track, version) = match &error {
                FileError::ChangedMigration { track, version } => (*track, *version),
                _ => (MigrationTrack::Module, 0),
            };
            return Standing::Failed(
                InstanceAdminAlert::migration_failed(file, track, version),
                error.into(),
            );
        }
    };
    let read = || -> Result<(SchemaVersions, u64), MigrationError> {
        let reader = vilicus_storage::open::<Read>(file, target.key)?;
        let versions = SchemaVersions {
            core: reader.schema_version(MigrationTrack::Core)?,
            module: reader.schema_version(MigrationTrack::Module)?,
        };
        let recorded =
            if versions.core <= CORE_SCHEMA_VERSION && versions.module <= module.latest_version() {
                check_recorded_tracks(&reader, module, versions)
            } else {
                Ok(())
            };
        reader.close()?;
        recorded?;
        let bytes = file_bytes(file)?;
        Ok((versions, bytes))
    };
    let latest = SchemaVersions {
        core: CORE_SCHEMA_VERSION,
        module: module.latest_version(),
    };
    match read() {
        Ok((from, _)) if from == latest => Standing::Current,
        Ok((from, _)) if from.core > latest.core => Standing::NewerThanCode(
            InstanceAdminAlert::newer_than_code(file, MigrationTrack::Core, from.core, latest.core),
        ),
        Ok((from, _)) if from.module > latest.module => {
            Standing::NewerThanCode(InstanceAdminAlert::newer_than_code(
                file,
                MigrationTrack::Module,
                from.module,
                latest.module,
            ))
        }
        Ok((from, bytes)) => Standing::Pending {
            from,
            migrations,
            bytes,
        },
        Err(error) => {
            let (track, version) = match &error {
                MigrationError::File(FileError::ChangedMigration { track, version }) => {
                    (*track, *version)
                }
                _ => (MigrationTrack::Module, 0),
            };
            Standing::Failed(
                InstanceAdminAlert::migration_failed(file, track, version),
                error,
            )
        }
    }
}

/// The bytes the copy of `file` takes: the file and what its WAL holds, which the checkpoint
/// before the copy moves into the file.
fn file_bytes(file: &ModuleFile) -> Result<u64, MigrationError> {
    let length = |path: PathBuf| match std::fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(MigrationError::Storage(vilicus_storage::Error::Io(error))),
    };
    Ok(length(file.path())? + length(file.wal_path())?)
}

/// AD-23: each data directory has at least twice the size of the largest file the run copies
/// there, or the run does not start.
fn check_space(
    files: &[FileToMigrate<'_>],
    standings: &[Standing],
) -> Result<(), MigrationRunError> {
    let mut largest: BTreeMap<PathBuf, u64> = BTreeMap::new();
    for (target, standing) in files.iter().zip(standings) {
        if let Standing::Pending { bytes, .. } = standing {
            let entry = largest
                .entry(target.file.directory().to_path_buf())
                .or_default();
            *entry = (*entry).max(*bytes);
        }
    }
    for (directory, bytes) in largest {
        let available =
            maintenance::available_space(&directory).map_err(MigrationRunError::Storage)?;
        let required = bytes.saturating_mul(2);
        if available < required {
            return Err(MigrationRunError::InsufficientSpace {
                directory,
                available,
                required,
            });
        }
    }
    Ok(())
}

/// The track and version a failed migration names: the step the runner reports, or else the
/// first pending one, Core track first.
fn failed_step(error: &MigrationError, from: SchemaVersions) -> (MigrationTrack, u32) {
    match error {
        MigrationError::Storage(vilicus_storage::Error::MigrationFailed {
            track, version, ..
        }) => (*track, *version),
        MigrationError::File(FileError::ChangedMigration { track, version }) => (*track, *version),
        _ if from.core < CORE_SCHEMA_VERSION => (MigrationTrack::Core, from.core + 1),
        _ => (MigrationTrack::Module, from.module + 1),
    }
}
