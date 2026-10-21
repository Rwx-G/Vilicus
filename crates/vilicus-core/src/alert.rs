//! Typed alerts to the instance admin (FR-23, FR-54, D84): what the Core reports when a module
//! file cannot serve. Each names the file by its module, partition and file name, and carries
//! identifiers and versions only, never a value of the file (spine conventions, Logging).
//! Delivering them, to the instance admin and, for a partition's file, to its members (AD-23),
//! is the alert path's.

use core::fmt;

use vilicus_storage::{MigrationTrack, ModuleFile, Partition};
use vilicus_types::ModuleName;

/// An alert to the instance admin.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InstanceAdminAlert {
    /// A migration of the file failed: the previous file is kept untouched and the module is
    /// not started on it in that partition (AD-23, AD-54 `failed migration`, D84).
    MigrationFailed {
        /// The module.
        module: ModuleName,
        /// The partition.
        partition: Partition,
        /// The file name, `<module>.<partition>.db`.
        file_name: String,
        /// The track of the migration that failed.
        track: MigrationTrack,
        /// The version that migration would have brought the track to.
        version: u32,
    },
    /// The file's schema is newer than the code: it is refused and the module is not started on
    /// it (D21, AD-54 `newer than code`).
    NewerThanCode {
        /// The module.
        module: ModuleName,
        /// The partition.
        partition: Partition,
        /// The file name, `<module>.<partition>.db`.
        file_name: String,
        /// The track that is ahead.
        track: MigrationTrack,
        /// The file's version of that track.
        found: u32,
        /// The code's last version of that track.
        latest: u32,
    },
}

impl InstanceAdminAlert {
    /// The alert of a migration of `file` that failed at `version` of `track`.
    pub fn migration_failed(file: &ModuleFile, track: MigrationTrack, version: u32) -> Self {
        Self::MigrationFailed {
            module: file.module().clone(),
            partition: file.partition(),
            file_name: file.file_name(),
            track,
            version,
        }
    }

    /// The alert of `file`, whose `track` is at `found`, beyond the code's `latest`.
    pub fn newer_than_code(
        file: &ModuleFile,
        track: MigrationTrack,
        found: u32,
        latest: u32,
    ) -> Self {
        Self::NewerThanCode {
            module: file.module().clone(),
            partition: file.partition(),
            file_name: file.file_name(),
            track,
            found,
            latest,
        }
    }
}

impl fmt::Display for InstanceAdminAlert {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MigrationFailed {
                file_name,
                track,
                version,
                ..
            } => write!(
                formatter,
                "{file_name}: {track} migration {version} failed; the previous file is kept and \
                 the module is stopped for this partition"
            ),
            Self::NewerThanCode {
                file_name,
                track,
                found,
                latest,
                ..
            } => write!(
                formatter,
                "{file_name}: {track} schema version {found} is newer than this code's {latest}; \
                 the module is not started for this partition"
            ),
        }
    }
}
