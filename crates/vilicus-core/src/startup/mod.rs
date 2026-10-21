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
//! with its alert; the other files proceed. A bring-up acts for one unlock, its generation: once
//! the partition is locked, its stage changes move no file, and it stops before opening or
//! delivering anything more.

#[cfg(test)]
mod tests;

use core::fmt;
use std::path::Path;

use vilicus_storage::{Handle, ModuleFile, Partition, Read, Write, maintenance};
use vilicus_types::ModuleName;

use crate::alert::InstanceAdminAlert;
use crate::api::{ApiFiles, Apis, Layered, NoApiFiles};
use crate::availability::{Generation, ModuleStates, Stage, StageRefused};
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
/// handle of each ready file, and the read handle the typed APIs of other modules read it through
/// (AD-5, AD-9).
pub struct PartitionFiles {
    partition: Partition,
    handles: Vec<Handle<Write>>,
    readers: Vec<Handle<Read>>,
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

    /// Closes every handle, the read handles first, each with a TRUNCATE checkpoint; the first
    /// failure is returned once every handle was closed.
    pub fn close(self) -> Result<(), vilicus_storage::Error> {
        let mut first = Ok(());
        let closes = self
            .readers
            .into_iter()
            .map(Handle::close)
            .chain(self.handles.into_iter().map(Handle::close));
        for closed in closes {
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

impl ApiFiles for PartitionFiles {
    fn reader(&self, module: &ModuleName, partition: Partition) -> Option<&Handle<Read>> {
        if partition != self.partition {
            return None;
        }
        self.readers
            .iter()
            .find(|reader| reader.file().module() == module)
    }
}

/// Where one file's bring-up stopped.
#[derive(Debug)]
#[non_exhaustive]
pub enum FileOutcome {
    /// The file serves.
    Ready,
    /// The re-key failed: the file is `locked`, not served until the next unlock tries again.
    RekeyFailed(vilicus_storage::Error),
    /// The migration runner left the file `failed migration` or `newer than code`.
    Migration(Box<FileMigration>),
    /// The migration did not start: the file stays `failed migration` until the next unlock.
    MigrationNotStarted(MigrationRunError),
    /// The migrated file did not open as the Core opens every file.
    NotOpened(FileError),
    /// A call of module code still ran on the file, or an earlier bring-up still re-keyed or
    /// migrated it, so it could not be re-keyed or migrated: it is `locked`, not served until the
    /// next unlock.
    WriterBusy(StageRefused),
    /// No file of the module was given: it is `locked`, not served until the next unlock.
    NotGiven,
    /// The partition was locked while the file was brought up: the bring-up stopped, and the file
    /// is as the lock left it.
    PartitionLocked,
}

/// What one bring-up did.
#[derive(Debug, Default)]
pub struct BringUpReport {
    /// Where each file of each registered module stopped: the files given, in their order, then
    /// the modules no file was given for.
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
    /// Two files of one module were given.
    DuplicateFile(ModuleName),
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
            Self::DuplicateFile(module) => {
                write!(formatter, "two files of {module} were given")
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

/// Brings up `files`, the module files of the partition `generation` unlocked, with their keys
/// (AD-54): each is re-keyed through `rekey` if it must be, then migrated by `registry`'s runner,
/// then opened and checked, each move recorded in `boundary`'s availability states under
/// `generation`; then the outbox of each ready file is delivered through `delivery`, its
/// consumers' code run inside `boundary`, their typed API reads served from the partition's
/// ready files, then from the files `boundary` serves (the household's, for a member's
/// partition). A registered module whose file is not given is reported
/// and left `locked`. Once the partition is locked again the bring-up stops where it is: no stage
/// change of it moves a file any more, it opens nothing and delivers nothing. Returns the ready
/// files, which the Core holds from then on, and what became of each file. Refused, before any
/// file is touched, when a file is of another partition or of no registered module, or two files
/// are of one module.
pub fn bring_up(
    registry: &Registry,
    boundary: &Boundary<'_>,
    generation: Generation,
    files: &[FileToMigrate<'_>],
    rekey: &mut dyn Rekey,
    delivery: Delivery<'_>,
) -> Result<(PartitionFiles, BringUpReport), BringUpError> {
    bring_up_with_space(
        registry,
        boundary,
        generation,
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
    generation: Generation,
    files: &[FileToMigrate<'_>],
    rekey: &mut dyn Rekey,
    delivery: Delivery<'_>,
    available_space: &dyn Fn(&Path) -> Result<u64, vilicus_storage::Error>,
) -> Result<(PartitionFiles, BringUpReport), BringUpError> {
    let partition = generation.partition();
    for (index, target) in files.iter().enumerate() {
        let module = target.file.module();
        if registry.module(module).is_none() {
            return Err(BringUpError::UnregisteredModule(module.clone()));
        }
        if target.file.partition() != partition {
            return Err(BringUpError::OtherPartition(module.clone()));
        }
        if files[..index]
            .iter()
            .any(|earlier| earlier.file.module() == module)
        {
            return Err(BringUpError::DuplicateFile(module.clone()));
        }
    }
    let mover = Mover {
        states: boundary.states,
        generation,
    };
    let mut report = BringUpReport::default();
    let mut outcomes: Vec<Option<FileOutcome>> = files.iter().map(|_| None).collect();
    for (target, outcome) in files.iter().zip(&mut outcomes) {
        *outcome = mover.rekeyed(rekey, target.file, &mut report.alerts).err();
    }
    for (target, outcome) in files.iter().zip(&mut outcomes) {
        if outcome.is_none() {
            *outcome = mover
                .migrated(registry, target, available_space, &mut report.alerts)
                .err();
        }
    }
    let mut open = PartitionFiles {
        partition,
        handles: Vec::new(),
        readers: Vec::new(),
    };
    for (target, outcome) in files.iter().zip(&mut outcomes) {
        if outcome.is_none() {
            match mover.opened(registry, target, &mut report.alerts) {
                Ok((handle, reader)) => {
                    open.handles.push(handle);
                    open.readers.push(reader);
                }
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
    for module in registry.modules() {
        let name = ModuleName::from_static(module.name);
        if files.iter().all(|target| *target.file.module() != name) {
            let file = ModuleFile::new("", name.clone(), partition);
            if mover.put(&file, Stage::Locked) {
                report
                    .alerts
                    .push(InstanceAdminAlert::file_not_served(&file));
            }
            report.files.push((name, FileOutcome::NotGiven));
        }
    }
    if !boundary.states.is_current(generation) {
        return Ok((mover.stopped(open, &mut report), report));
    }
    let Delivery {
        code,
        links,
        stamper,
    } = delivery;
    let given: &dyn ApiFiles = match &boundary.apis {
        Some(apis) => apis.files,
        None => &NoApiFiles,
    };
    let files = Layered {
        first: &open,
        then: given,
    };
    let boundary = Boundary {
        apis: Some(Apis {
            registry: *registry,
            files: &files,
        }),
        ..*boundary
    };
    for handle in &open.handles {
        let delivered = deliver_outbox(registry, handle, &open, &boundary, code, links, stamper);
        if let Ok(delivered) = &delivered {
            report.alerts.extend(delivered.alerts.iter().cloned());
        }
        report
            .deliveries
            .push((handle.file().module().clone(), delivered));
    }
    Ok((open, report))
}

/// The stage changes of one bring-up, all under the generation of its unlock.
struct Mover<'a> {
    states: &'a ModuleStates,
    generation: Generation,
}

impl Mover<'_> {
    /// Puts `file` at `stage`, one that does not hold its writer; false when the partition was
    /// locked since the unlock, the file then left as the lock left it.
    fn put(&self, file: &ModuleFile, stage: Stage) -> bool {
        self.states
            .set_stage(self.generation, file.module(), stage)
            .is_ok()
    }

    /// Puts `file` at a stage that holds its writer. Refused when the partition was locked since
    /// the unlock ([`FileOutcome::PartitionLocked`]), or, with an alert and the file `locked` until
    /// the next unlock, when a call of module code still runs on it or an earlier bring-up still
    /// holds its writer ([`FileOutcome::WriterBusy`]).
    fn hold_writer(
        &self,
        file: &ModuleFile,
        stage: Stage,
        alerts: &mut Vec<InstanceAdminAlert>,
    ) -> Result<(), FileOutcome> {
        match self.states.set_stage(self.generation, file.module(), stage) {
            Ok(()) => Ok(()),
            Err(StageRefused::Stale) => Err(FileOutcome::PartitionLocked),
            Err(busy) => {
                self.not_served(file, alerts);
                Err(FileOutcome::WriterBusy(busy))
            }
        }
    }

    /// `file` is not served until the next unlock: `locked`, with an alert.
    fn not_served(&self, file: &ModuleFile, alerts: &mut Vec<InstanceAdminAlert>) {
        if self.put(file, Stage::Locked) {
            alerts.push(InstanceAdminAlert::file_not_served(file));
        }
    }

    /// Re-keys `file` when it must be, `re-keying` meanwhile and `opening` after; a failed re-key
    /// leaves the file `locked` with an alert.
    fn rekeyed(
        &self,
        rekey: &mut dyn Rekey,
        file: &ModuleFile,
        alerts: &mut Vec<InstanceAdminAlert>,
    ) -> Result<(), FileOutcome> {
        if !rekey.pending(file) {
            return Ok(());
        }
        self.hold_writer(file, Stage::ReKeying, alerts)?;
        if let Err(error) = rekey.rekey(file) {
            self.not_served(file, alerts);
            return Err(FileOutcome::RekeyFailed(error));
        }
        if self.put(file, Stage::Opening) {
            Ok(())
        } else {
            Err(FileOutcome::PartitionLocked)
        }
    }

    /// Migrates `target`, `migrating` meanwhile: `opening` after when the file is at the code's
    /// versions, otherwise `failed migration` or `newer than code`, with the runner's alert.
    fn migrated(
        &self,
        registry: &Registry,
        target: &FileToMigrate<'_>,
        available_space: &dyn Fn(&Path) -> Result<u64, vilicus_storage::Error>,
        alerts: &mut Vec<InstanceAdminAlert>,
    ) -> Result<(), FileOutcome> {
        let file = target.file;
        self.hold_writer(file, Stage::Migrating, alerts)?;
        let migration = match registry.migrate_file_with_space(target, available_space) {
            Ok(migration) => migration,
            Err(error) => {
                if self.put(file, Stage::FailedMigration) {
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
                }
                return Err(FileOutcome::MigrationNotStarted(error));
            }
        };
        let (stage, alert) = match &migration {
            FileMigration::Current | FileMigration::Migrated { .. } => {
                return if self.put(file, Stage::Opening) {
                    Ok(())
                } else {
                    Err(FileOutcome::PartitionLocked)
                };
            }
            FileMigration::NewerThanCode { alert } => (Stage::NewerThanCode, Some(alert)),
            FileMigration::Failed { alert, .. } => (Stage::FailedMigration, Some(alert)),
            FileMigration::StillFailed { .. } => (Stage::FailedMigration, None),
        };
        if self.put(file, stage) {
            alerts.extend(alert.cloned());
        }
        Err(FileOutcome::Migration(Box::new(migration)))
    }

    /// Opens `target` as the Core opens every file, its write handle and the read handle the
    /// typed APIs read it through, and puts it `ready`; a file that does not open is `newer than
    /// code` when it is, otherwise not served this time, `failed migration`, with its alert. A
    /// file opened after the partition was locked is closed again.
    fn opened(
        &self,
        registry: &Registry,
        target: &FileToMigrate<'_>,
        alerts: &mut Vec<InstanceAdminAlert>,
    ) -> Result<(Handle<Write>, Handle<Read>), FileOutcome> {
        let file = target.file;
        let opened = registry.open::<Write>(file, target.key).and_then(|handle| {
            match registry.open::<Read>(file, target.key) {
                Ok(reader) => Ok((handle, reader)),
                Err(error) => {
                    // The read handle failed: the write handle goes, whatever its close reports.
                    let _ = handle.close();
                    Err(error)
                }
            }
        });
        match opened {
            Ok(handles) if self.put(file, Stage::Ready) => Ok(handles),
            Ok((handle, reader)) => {
                // The partition was locked: the handles go, whatever their closes report.
                let _ = reader.close();
                let _ = handle.close();
                Err(FileOutcome::PartitionLocked)
            }
            Err(error) => {
                let (stage, alert) = match error.admin_alert(file) {
                    Some(alert) => (Stage::NewerThanCode, alert),
                    None => (
                        Stage::FailedMigration,
                        InstanceAdminAlert::file_not_served(file),
                    ),
                };
                if self.put(file, stage) {
                    alerts.push(alert);
                }
                Err(FileOutcome::NotOpened(error))
            }
        }
    }

    /// The partition was locked during the bring-up: every handle it opened is closed, and every
    /// file reported ready is reported stopped by the lock.
    fn stopped(&self, open: PartitionFiles, report: &mut BringUpReport) -> PartitionFiles {
        let partition = open.partition;
        // The partition was locked: its handles go, whatever their closes report.
        let _ = open.close();
        for (_, outcome) in &mut report.files {
            if matches!(outcome, FileOutcome::Ready) {
                *outcome = FileOutcome::PartitionLocked;
            }
        }
        PartitionFiles {
            partition,
            handles: Vec::new(),
            readers: Vec::new(),
        }
    }
}
