//! Typed alerts to the instance admin (FR-23, FR-24, FR-54, D84): what the Core reports when a
//! module file cannot serve, when an event moves to the dead letters, or when a link request is
//! refused. Each names the file by its module, partition and file name, and carries identifiers,
//! names from the declarations and versions only, never a value of the file (spine conventions,
//! Logging).
//! Delivering them, to the instance admin and, for a partition's file, to its members (AD-23),
//! is the alert path's.

use core::fmt;

use vilicus_storage::{MigrationTrack, ModuleFile, Partition};
use vilicus_types::{Id, ModuleName};

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
    /// A consumer failed an event of the file on every attempt: the event is in the file's dead
    /// letters, later events proceed, and `vilicus events replay <dead letter>` re-delivers it
    /// (AD-29).
    DeadLetter {
        /// The emitting module.
        module: ModuleName,
        /// The partition.
        partition: Partition,
        /// The file name, `<module>.<partition>.db`.
        file_name: String,
        /// The dead letter.
        dead_letter: Id,
        /// The event.
        event: Id,
        /// The event's topic.
        topic: String,
        /// The consumer, `<module>.<consumer>`.
        consumer: String,
    },
    /// A link request of the file names a record its target module's file in the same partition
    /// does not hold, or a module that is not registered: the link is not registered, since no
    /// link crosses partitions (AD-10).
    LinkRefused {
        /// The requesting module.
        module: ModuleName,
        /// The partition.
        partition: Partition,
        /// The file name, `<module>.<partition>.db`.
        file_name: String,
        /// The link request.
        link: Id,
        /// The module the link targets.
        target_module: String,
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

impl InstanceAdminAlert {
    /// The alert of the event `event` of `file`, of topic `topic`, that `consumer` kept failing,
    /// now the dead letter `dead_letter`.
    pub fn dead_letter(
        file: &ModuleFile,
        dead_letter: Id,
        event: Id,
        topic: &str,
        consumer: &str,
    ) -> Self {
        Self::DeadLetter {
            module: file.module().clone(),
            partition: file.partition(),
            file_name: file.file_name(),
            dead_letter,
            event,
            topic: topic.to_owned(),
            consumer: consumer.to_owned(),
        }
    }

    /// The alert of the link request `link` of `file` to `target_module`, refused.
    pub fn link_refused(file: &ModuleFile, link: Id, target_module: &str) -> Self {
        Self::LinkRefused {
            module: file.module().clone(),
            partition: file.partition(),
            file_name: file.file_name(),
            link,
            target_module: target_module.to_owned(),
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
            Self::DeadLetter {
                file_name,
                dead_letter,
                event,
                topic,
                consumer,
                ..
            } => write!(
                formatter,
                "{file_name}: event {event} of {topic} failed every delivery to {consumer}; it is \
                 dead letter {dead_letter}, and later events proceed"
            ),
            Self::LinkRefused {
                file_name,
                link,
                target_module,
                ..
            } => write!(
                formatter,
                "{file_name}: link request {link} names no record of {target_module} in this \
                 partition; it is not registered"
            ),
        }
    }
}
