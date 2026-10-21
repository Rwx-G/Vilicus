//! The bring-up of a partition's module files once its keys are derived (FR-11, AD-54, AD-23,
//! AD-29).
//!
//! Unlock completes when the keys are derived and the session is usable:
//! [`ModuleStates::unlock_partition`] puts every module file of the partition in `opening` at
//! once, and a typed call to any of them is answered `module_unavailable`, `retryable`, until its
//! file is ready. [`bring_up`] then runs in the background (on the Core's blocking pool) and moves
//! the files on in this order: each file is re-keyed if it must be, then migrated forward on a
//! copy, then opened and checked, and only once every file of the partition stands where it can,
//! the outbox of each ready file is delivered, so a consumer is ready before the events due to it
//! are. In V0.1 no inbox is ingested between migration and delivery (AD-37 starts with the home
//! milestone), and household key wraps, which run last (AD-54), are the unlock path's.
//!
//! A file is put to re-keying or migrating only when no call of module code runs on it, and the
//! bring-up holds no handle of a file until it is migrated: the Core's writer of the file is held
//! for the whole migration run (AD-9, D149). A file that cannot serve stops there, in its state,
//! with its alert; the other files proceed.

#[cfg(test)]
mod tests;

use core::fmt;
use std::path::Path;

use vilicus_storage::{Handle, ModuleFile, Partition, Write, maintenance};
use vilicus_types::ModuleName;

use crate::alert::InstanceAdminAlert;
use crate::availability::{CallsInFlight, ModuleStates, Stage};
use crate::boundary::Boundary;
use crate::bus::{
    ConsumerCode, ConsumerFiles, DeliveryError, DeliveryReport, LinkTable, deliver_outbox,
};
use crate::record::Stamper;
use crate::registry::{FileError, FileMigration, FileToMigrate, MigrationRunError, Registry};

/// The re-key of module files after a rotation or a sub-key revocation, as the key path performs
/// it (`doc/key-management.md` section 7).
pub trait Rekey {
    /// True when `file` must be re-keyed before it serves.
    fn pending(&mut self, file: &ModuleFile) -> bool;

    /// Re-keys `file`; no call of module code runs on it meanwhile.
    fn rekey(&mut self, file: &ModuleFile) -> Result<(), vilicus_storage::Error>;
}

/// No file to re-key: V0.1 rotates no file key before recovery and sub-keys exist (Epic 9).
#[derive(Clone, Copy, Debug, Default)]
pub struct NothingToRekey;

impl Rekey for NothingToRekey {
    fn pending(&mut self, _: &ModuleFile) -> bool {
        false
    }

    fn rekey(&mut self, _: &ModuleFile) -> Result<(), vilicus_storage::Error> {
        Ok(())
    }
}

/// The open module files of one partition, as the Core holds them once they serve: the write
/// handle of each ready file.
pub struct PartitionFiles {
    partition: Partition,
    handles: Vec<Handle<Write>>,
}

impl fmt::Debug for PartitionFiles {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let files: Vec<String> = self
            .handles
            .iter()
            .map(|handle| handle.file().file_name())
            .collect();
        formatter
            .debug_struct("PartitionFiles")
            .field("partition", &self.partition)
            .field("files", &files)
            .finish()
    }
}

impl PartitionFiles {
    /// The partition.
    pub fn partition(&self) -> Partition {
        self.partition
    }

    /// The write handle of `module`'s file, when it is open.
    pub fn handle(&self, module: &ModuleName) -> Option<&Handle<Write>> {
        self.handles
            .iter()
            .find(|handle| handle.file().module() == module)
    }

    /// Closes every handle, each with a TRUNCATE checkpoint; the first failure is returned once
    /// every handle was closed.
    pub fn close(self) -> Result<(), vilicus_storage::Error> {
        let mut first = Ok(());
        for handle in self.handles {
            let closed = handle.close();
            if first.is_ok() {
                first = closed;
            }
        }
        first
    }
}

impl ConsumerFiles for PartitionFiles {
    fn open(&self, module: &ModuleName) -> Option<&Handle<Write>> {
        self.handle(module)
    }
}

/// Where one file's bring-up stopped.
#[derive(Debug)]
#[non_exhaustive]
pub enum FileOutcome {
    /// The file serves.
    Ready,
    /// The re-key failed: the file stays `re-keying` until the next unlock tries it again.
    RekeyFailed(vilicus_storage::Error),
    /// The migration runner left the file `failed migration` or `newer than code`.
    Migration(Box<FileMigration>),
    /// The migration did not start: the file stays `failed migration` until the next unlock.
    MigrationNotStarted(MigrationRunError),
    /// The migrated file did not open as the Core opens every file.
    NotOpened(FileError),
    /// A call of module code still ran on the file, so it could not be re-keyed or migrated: it
    /// keeps its state until the next unlock.
    CallsInFlight(CallsInFlight),
}

/// What one bring-up did.
#[derive(Debug, Default)]
pub struct BringUpReport {
    /// Where each file stopped, in the order given.
    pub files: Vec<(ModuleName, FileOutcome)>,
    /// The delivery pass of each ready file's outbox, in the order given.
    pub deliveries: Vec<(ModuleName, Result<DeliveryReport, DeliveryError>)>,
    /// The alerts to the instance admin: failed migrations, files newer than the code or not
    /// served, and those of the delivery passes.
    pub alerts: Vec<InstanceAdminAlert>,
}

/// Why a bring-up did not start; no file was touched.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BringUpError {
    /// A file belongs to no registered module.
    UnregisteredModule(ModuleName),
    /// A file of another partition was given.
    OtherPartition(ModuleName),
}

impl fmt::Display for BringUpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnregisteredModule(module) => {
                write!(formatter, "module {module} is not registered")
            }
            Self::OtherPartition(module) => {
                write!(
                    formatter,
                    "the file of {module} given is of another partition"
                )
            }
        }
    }
}

impl std::error::Error for BringUpError {}

/// The ports a bring-up delivers the outboxes through.
pub struct Delivery<'a> {
    /// The consumers' code.
    pub code: &'a mut dyn ConsumerCode,
    /// The partition's link table.
    pub links: &'a mut dyn LinkTable,
    /// The time and the ids.
    pub stamper: &'a mut dyn Stamper,
}

/// Brings up `files`, every module file of `partition` with its key, whose keys were just derived
/// (AD-54): each is re-keyed through `rekey` if it must be, then migrated by `registry`'s runner,
/// then opened and checked, each move recorded in `boundary`'s availability states; then the
/// outbox of each ready file is delivered through `delivery`, its consumers' code run inside
/// `boundary`. Returns the ready files, which the Core holds from then on, and what became of each
/// file. Refused, before any file is touched, when a file is of another partition or of no
/// registered module.
pub fn bring_up(
    registry: &Registry,
    boundary: &Boundary<'_>,
    partition: Partition,
    files: &[FileToMigrate<'_>],
    rekey: &mut dyn Rekey,
    delivery: Delivery<'_>,
) -> Result<(PartitionFiles, BringUpReport), BringUpError> {
    bring_up_with_space(
        registry,
        boundary,
        partition,
        files,
        rekey,
        delivery,
        &maintenance::available_space,
    )
}

/// [`bring_up`], with the free space of the data directory read by `available_space`: `statvfs`
/// in production, a fixed value in the tests.
pub(crate) fn bring_up_with_space(
    registry: &Registry,
    boundary: &Boundary<'_>,
    partition: Partition,
    files: &[FileToMigrate<'_>],
    rekey: &mut dyn Rekey,
    delivery: Delivery<'_>,
    available_space: &dyn Fn(&Path) -> Result<u64, vilicus_storage::Error>,
) -> Result<(PartitionFiles, BringUpReport), BringUpError> {
    for target in files {
        let module = target.file.module();
        if registry.module(module).is_none() {
            return Err(BringUpError::UnregisteredModule(module.clone()));
        }
        if target.file.partition() != partition {
            return Err(BringUpError::OtherPartition(module.clone()));
        }
    }
    let states = boundary.states;
    let mut report = BringUpReport::default();
    let mut outcomes: Vec<Option<FileOutcome>> = files.iter().map(|_| None).collect();
    for (target, outcome) in files.iter().zip(&mut outcomes) {
        *outcome = rekeyed(states, rekey, target.file, &mut report.alerts).err();
    }
    for (target, outcome) in files.iter().zip(&mut outcomes) {
        if outcome.is_none() {
            *outcome = migrated(
                registry,
                states,
                target,
                available_space,
                &mut report.alerts,
            )
            .err();
        }
    }
    let mut open = PartitionFiles {
        partition,
        handles: Vec::new(),
    };
    for (target, outcome) in files.iter().zip(&mut outcomes) {
        if outcome.is_none() {
            match opened(registry, states, target, &mut report.alerts) {
                Ok(handle) => open.handles.push(handle),
                Err(failed) => *outcome = Some(failed),
            }
        }
    }
    for (target, outcome) in files.iter().zip(outcomes) {
        report.files.push((
            target.file.module().clone(),
            outcome.unwrap_or(FileOutcome::Ready),
        ));
    }
    let Delivery {
        code,
        links,
        stamper,
    } = delivery;
    for handle in &open.handles {
        let delivered = deliver_outbox(registry, handle, &open, boundary, code, links, stamper);
        if let Ok(delivered) = &delivered {
            report.alerts.extend(delivered.alerts.iter().cloned());
        }
        report
            .deliveries
            .push((handle.file().module().clone(), delivered));
    }
    Ok((open, report))
}

/// Puts `file` at a stage that holds its writer, refused with [`FileOutcome::CallsInFlight`]
/// while a call of module code still runs on it, such as one that began before the partition was
/// locked and has not ended yet: the file is left as it is, with an alert.
fn hold_writer(
    states: &ModuleStates,
    file: &ModuleFile,
    stage: Stage,
    alerts: &mut Vec<InstanceAdminAlert>,
) -> Result<(), FileOutcome> {
    states
        .set_stage(file.module(), file.partition(), stage)
        .map_err(|busy| {
            alerts.push(InstanceAdminAlert::file_not_served(file));
            FileOutcome::CallsInFlight(busy)
        })
}

/// Puts `file` at `stage`, one that does not hold its writer, which is never refused.
fn put(states: &ModuleStates, file: &ModuleFile, stage: Stage) {
    // Only re-keying and migrating are refused while a call runs (`hold_writer`).
    let _ = states.set_stage(file.module(), file.partition(), stage);
}

/// Re-keys `file` when it must be, `re-keying` meanwhile and `opening` after.
fn rekeyed(
    states: &ModuleStates,
    rekey: &mut dyn Rekey,
    file: &ModuleFile,
    alerts: &mut Vec<InstanceAdminAlert>,
) -> Result<(), FileOutcome> {
    if !rekey.pending(file) {
        return Ok(());
    }
    hold_writer(states, file, Stage::ReKeying, alerts)?;
    rekey.rekey(file).map_err(FileOutcome::RekeyFailed)?;
    put(states, file, Stage::Opening);
    Ok(())
}

/// Migrates `target`, `migrating` meanwhile: `opening` after when the file is at the code's
/// versions, otherwise `failed migration` or `newer than code`, with the runner's alert.
fn migrated(
    registry: &Registry,
    states: &ModuleStates,
    target: &FileToMigrate<'_>,
    available_space: &dyn Fn(&Path) -> Result<u64, vilicus_storage::Error>,
    alerts: &mut Vec<InstanceAdminAlert>,
) -> Result<(), FileOutcome> {
    let file = target.file;
    hold_writer(states, file, Stage::Migrating, alerts)?;
    let migration = match registry.migrate_file_with_space(target, available_space) {
        Ok(migration) => migration,
        Err(error) => {
            alerts.push(match &error {
                MigrationRunError::InsufficientSpace {
                    available,
                    required,
                    ..
                } => InstanceAdminAlert::NoSpaceToMigrate {
                    module: file.module().clone(),
                    partition: file.partition(),
                    file_name: file.file_name(),
                    available: *available,
                    required: *required,
                },
                _ => InstanceAdminAlert::file_not_served(file),
            });
            put(states, file, Stage::FailedMigration);
            return Err(FileOutcome::MigrationNotStarted(error));
        }
    };
    let stage = match &migration {
        FileMigration::Current | FileMigration::Migrated { .. } => {
            put(states, file, Stage::Opening);
            return Ok(());
        }
        FileMigration::NewerThanCode { alert } => {
            alerts.push(alert.clone());
            Stage::NewerThanCode
        }
        FileMigration::Failed { alert, .. } => {
            alerts.push(alert.clone());
            Stage::FailedMigration
        }
        FileMigration::StillFailed { .. } => Stage::FailedMigration,
    };
    put(states, file, stage);
    Err(FileOutcome::Migration(Box::new(migration)))
}

/// Opens `target` as the Core opens every file and puts it `ready`; a file that does not open is
/// `newer than code` when it is, otherwise not served this time, `failed migration`, with its
/// alert.
fn opened(
    registry: &Registry,
    states: &ModuleStates,
    target: &FileToMigrate<'_>,
    alerts: &mut Vec<InstanceAdminAlert>,
) -> Result<Handle<Write>, FileOutcome> {
    let file = target.file;
    match registry.open::<Write>(file, target.key) {
        Ok(handle) => {
            put(states, file, Stage::Ready);
            Ok(handle)
        }
        Err(error) => {
            match error.admin_alert(file) {
                Some(alert) => {
                    alerts.push(alert);
                    put(states, file, Stage::NewerThanCode);
                }
                None => {
                    alerts.push(InstanceAdminAlert::file_not_served(file));
                    put(states, file, Stage::FailedMigration);
                }
            }
            Err(FileOutcome::NotOpened(error))
        }
    }
}
