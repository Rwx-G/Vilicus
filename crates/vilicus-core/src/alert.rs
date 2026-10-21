//! Typed alerts to the instance admin (FR-23, FR-24, FR-54, D84, AD-9, AD-54): what the Core
//! reports when a module file cannot serve, when a module faults, when an event moves to the dead
//! letters, or when a link request is refused. Each names the file by its module, partition and file name, and carries identifiers,
//! names from the declarations and versions only, never a value of the file (spine conventions,
//! Logging).
//! Delivering them, to the instance admin and, for a partition's file, to its members (AD-23),
//! is the alert path's.

use core::fmt;

use vilicus_storage::{MigrationTrack, ModuleFile, Partition};
use vilicus_types::{AvailabilityState, Id, ModuleName};

use crate::availability::Fault;

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
    /// A handler, undo handler or consumer of the module panicked or exceeded its time budget on
    /// the file: its call was rolled back, and the module is faulted for the partition and
    /// receives no further call there (AD-9, AD-54 `faulted`).
    ModuleFaulted {
        /// The module.
        module: ModuleName,
        /// The partition.
        partition: Partition,
        /// The file name, `<module>.<partition>.db`.
        file_name: String,
        /// What the module's code did.
        fault: Fault,
    },
    /// An event of the file stayed pending past the outbox's retention for a consumer whose
    /// file is in a lasting state: it is moved to that consumer's dead letters, so the outbox
    /// does not grow without bound behind a consumer that may never return (D150), and
    /// `vilicus events replay <dead letter>` re-delivers it.
    EventExpired {
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
        /// The state of the consumer's file.
        state: AvailabilityState,
    },
    /// The data directory had less free space than twice the file, so its migration did not
    /// start; the file is kept, and the migration is tried again at the partition's next unlock
    /// (AD-23).
    NoSpaceToMigrate {
        /// The module.
        module: ModuleName,
        /// The partition.
        partition: Partition,
        /// The file name, `<module>.<partition>.db`.
        file_name: String,
        /// The free space, in bytes.
        available: u64,
        /// Twice the file, in bytes.
        required: u64,
    },
    /// The file could not be migrated, opened or checked for a reason that is not the code's
    /// (the file system, its free space unread, a key or an epoch, a lock), or a file whose
    /// migrations all ran is not what its declaration says: it is not served until the
    /// partition's next unlock (AD-54).
    FileNotServed {
        /// The module.
        module: ModuleName,
        /// The partition.
        partition: Partition,
        /// The file name, `<module>.<partition>.db`.
        file_name: String,
    },
    /// A pending row of the file's outbox whose id does not decode: no delivery can be recorded
    /// for it, so it is closed `refused` rather than left to block the rows after it (AD-29).
    MalformedOutboxRow {
        /// The emitting module.
        module: ModuleName,
        /// The partition.
        partition: Partition,
        /// The file name, `<module>.<partition>.db`.
        file_name: String,
        /// The row's position in the outbox.
        seq: i64,
    },
    /// A link request of the file names a record its target module's file in the same partition
    /// does not hold, or a module that is not registered, or its linking record is gone from the
    /// file, or the request does not decode: the link is not registered, since no link crosses
    /// partitions or outlives its record (AD-10).
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
    /// The alert of `file`, not served for a reason that is not its migration's code.
    pub fn file_not_served(file: &ModuleFile) -> Self {
        Self::FileNotServed {
            module: file.module().clone(),
            partition: file.partition(),
            file_name: file.file_name(),
        }
    }

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

    /// The alert of the row at position `seq` of `file`'s outbox, whose id does not decode.
    pub fn malformed_outbox_row(file: &ModuleFile, seq: i64) -> Self {
        Self::MalformedOutboxRow {
            module: file.module().clone(),
            partition: file.partition(),
            file_name: file.file_name(),
            seq,
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
            Self::ModuleFaulted {
                file_name, fault, ..
            } => write!(
                formatter,
                "{file_name}: the module's code {fault}; its call was rolled back, and the module \
                 is faulted for this partition and receives no further call there"
            ),
            Self::EventExpired {
                file_name,
                dead_letter,
                event,
                topic,
                consumer,
                state,
                ..
            } => write!(
                formatter,
                "{file_name}: event {event} of {topic} outlived the outbox's retention while \
                 {consumer} is {state}; it is dead letter {dead_letter}"
            ),
            Self::NoSpaceToMigrate {
                file_name,
                available,
                required,
                ..
            } => write!(
                formatter,
                "{file_name}: {available} bytes free, {required} needed to migrate; the file is \
                 kept and its migration waits for the next unlock"
            ),
            Self::FileNotServed { file_name, .. } => write!(
                formatter,
                "{file_name}: the file could not be migrated, opened or checked; it is not served \
                 until the next unlock"
            ),
            Self::MalformedOutboxRow { file_name, seq, .. } => write!(
                formatter,
                "{file_name}: outbox row {seq} has no valid id; it is refused, and the rows after \
                 it proceed"
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
