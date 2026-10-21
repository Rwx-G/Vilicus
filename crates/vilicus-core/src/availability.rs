//! The availability state of every module file (AD-54, AD-9): one state per module and
//! partition, held by the Core and read by every caller, the event bus and unlock, so none of
//! them guesses whether a file can serve.
//!
//! A file's state is the first that applies of: `deactivated` while its activatable module is
//! off for the partition (AD-47); `faulted` once a handler, undo handler or consumer of the module
//! panicked or exceeded its time budget on it (AD-9); otherwise the stage its bring-up reached,
//! `locked` while the partition key is not in memory, then `opening`, `re-keying`, `migrating`,
//! and `ready`, or `failed migration` or `newer than code` where the bring-up stopped. A file the
//! Core has never heard of is `locked`, so an unknown file never serves.
//!
//! A fault lasts as long as the Core process: locking and unlocking the partition does not clear
//! it, so a module that faulted receives no further call in that partition until the Core
//! restarts. A failed migration lasts across starts through its mark beside the file, read by
//! the migration runner ([`Registry::migrate_files`](crate::registry::Registry::migrate_files)).
//!
//! Each call of module code registers itself with its deadline while it runs ([`ModuleStates`]
//! hands out a [`CallTicket`]); a file is put to re-keying or migrating only when no call runs on
//! it, and no call starts on a file that is not ready, so the migration runner never meets a
//! connection the Core opened for a call (AD-23, D149). [`ModuleStates::expire_overdue`] marks
//! faulted, at the time it is given, every module whose call outlived its deadline, without
//! waiting for the call to return: a handler that never returns keeps its writer thread, and the
//! Core's other threads, files and partitions go on.

use core::fmt;
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use vilicus_storage::{ModuleFile, Partition};
use vilicus_types::{
    AvailabilityState, ClientFacingError, ErrorCode, MessageKey, ModuleName, RetryClass,
};

use crate::alert::InstanceAdminAlert;
use crate::registry::Registry;

/// The Core's monotonic clock (AD-30): time elapsed since an origin of the clock's own, which a
/// change of the wall clock does not move. The time budget of module code is measured on it.
pub trait MonotonicClock: Sync {
    /// The time elapsed since the clock's origin.
    fn now(&self) -> Duration;
}

/// The monotonic clock of the host, from the moment it is made.
#[derive(Clone, Copy, Debug)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    /// A clock whose origin is now.
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for SystemClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

/// Why a module was marked faulted for a partition (AD-9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Fault {
    /// Its code panicked; the call was rolled back.
    Panicked,
    /// Its code ran past the handler time budget; the call was rolled back if it returned.
    TimeBudget,
}

impl fmt::Display for Fault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Panicked => "panicked",
            Self::TimeBudget => "exceeded its time budget",
        })
    }
}

/// The answer to a typed API call to a module file that is not ready (AD-54): the stable error
/// code `module_unavailable` with the retry class of the file's state. The module, the partition
/// and the state stay on the server side; a client receives the code, the message key and the
/// retry class only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleUnavailable {
    module: ModuleName,
    partition: Partition,
    state: AvailabilityState,
    retry_class: RetryClass,
}

impl ModuleUnavailable {
    /// The answer for `module`'s file in `partition` in `state`; `None` when `state` serves.
    pub fn of(module: ModuleName, partition: Partition, state: AvailabilityState) -> Option<Self> {
        state.retry_class().map(|retry_class| Self {
            module,
            partition,
            state,
            retry_class,
        })
    }

    /// The module.
    pub fn module(&self) -> &ModuleName {
        &self.module
    }

    /// The partition.
    pub fn partition(&self) -> Partition {
        self.partition
    }

    /// The state of the file.
    pub fn state(&self) -> AvailabilityState {
        self.state
    }
}

impl fmt::Display for ModuleUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "module {} is {} in partition {}",
            self.module, self.state, self.partition
        )
    }
}

impl std::error::Error for ModuleUnavailable {}

impl ClientFacingError for ModuleUnavailable {
    fn code(&self) -> ErrorCode {
        ErrorCode::from_static("module_unavailable")
    }

    fn message_key(&self) -> MessageKey {
        MessageKey::from_static("error.module_unavailable")
    }

    fn retry_class(&self) -> RetryClass {
        self.retry_class
    }
}

/// The stage a file's bring-up reached (AD-54): every state but the two that override it, a
/// deactivation and a fault. The Core moves a file from one to the next as it unlocks, opens,
/// re-keys and migrates it ([`bring_up`](crate::startup::bring_up)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// The partition key is not in memory.
    Locked,
    /// The keys are derived; the file is being opened and checked.
    Opening,
    /// The file is being re-keyed.
    ReKeying,
    /// A migration runs on a copy of the file.
    Migrating,
    /// The file serves.
    Ready,
    /// A migration of the file failed.
    FailedMigration,
    /// The file's schema is newer than the code.
    NewerThanCode,
}

impl Stage {
    const fn state(self) -> AvailabilityState {
        match self {
            Self::Locked => AvailabilityState::Locked,
            Self::Opening => AvailabilityState::Opening,
            Self::ReKeying => AvailabilityState::ReKeying,
            Self::Migrating => AvailabilityState::Migrating,
            Self::Ready => AvailabilityState::Ready,
            Self::FailedMigration => AvailabilityState::FailedMigration,
            Self::NewerThanCode => AvailabilityState::NewerThanCode,
        }
    }

    /// True for the stages in which the Core changes the file outside any call, so that no call
    /// may run on it meanwhile: its writer is held (AD-9, D149).
    const fn holds_the_writer(self) -> bool {
        matches!(self, Self::ReKeying | Self::Migrating)
    }
}

/// A call of module code running on one file, registered until it ends.
#[derive(Debug)]
pub struct CallTicket {
    module: ModuleName,
    partition: Partition,
    id: u64,
}

/// A file could not be put to a stage that holds its writer: calls of module code still run on
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallsInFlight {
    /// How many.
    pub calls: usize,
}

#[derive(Debug)]
struct Entry {
    stage: Stage,
    fault: Option<Fault>,
    deactivated: bool,
    calls: Vec<(u64, Duration)>,
}

impl Default for Entry {
    fn default() -> Self {
        Self {
            stage: Stage::Locked,
            fault: None,
            deactivated: false,
            calls: Vec::new(),
        }
    }
}

impl Entry {
    fn state(&self) -> AvailabilityState {
        if self.deactivated {
            AvailabilityState::Deactivated
        } else if self.fault.is_some() {
            AvailabilityState::Faulted
        } else {
            self.stage.state()
        }
    }
}

#[derive(Debug, Default)]
struct Files {
    entries: HashMap<(ModuleName, Partition), Entry>,
    next_call: u64,
}

/// The availability state of every module file of the instance, shared by the threads of the
/// Core: the writer threads, the event bus, unlock and the supervisor that expires overdue calls.
#[derive(Debug, Default)]
pub struct ModuleStates {
    files: Mutex<Files>,
}

/// The name of `module`'s file in `partition`, as the alerts carry it.
fn file_name(module: &ModuleName, partition: Partition) -> String {
    ModuleFile::new("", module.clone(), partition).file_name()
}

impl ModuleStates {
    /// No file known: every file is `locked`.
    pub fn new() -> Self {
        Self::default()
    }

    /// The table, whatever a thread that panicked while holding it left: every change it makes
    /// is one assignment, so no entry is ever half written.
    fn files(&self) -> MutexGuard<'_, Files> {
        self.files.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The state of `module`'s file in `partition`.
    pub fn state(&self, module: &ModuleName, partition: Partition) -> AvailabilityState {
        self.files()
            .entries
            .get(&(module.clone(), partition))
            .map_or(AvailabilityState::Locked, Entry::state)
    }

    /// The gate of every typed API call to `module` in `partition` (AD-54): `Ok` when its file is
    /// ready, otherwise `module_unavailable` with the retry class of its state.
    pub fn check(
        &self,
        module: &ModuleName,
        partition: Partition,
    ) -> Result<(), ModuleUnavailable> {
        match ModuleUnavailable::of(module.clone(), partition, self.state(module, partition)) {
            None => Ok(()),
            Some(unavailable) => Err(unavailable),
        }
    }

    /// The partition's keys were derived: every file of every module of `registry` in
    /// `partition` is `opening`, the unlock completes at once (FR-11), and the bring-up moves
    /// each file on in the background ([`bring_up`](crate::startup::bring_up)). A fault or a
    /// deactivation stays.
    pub fn unlock_partition(&self, registry: &Registry, partition: Partition) {
        let mut files = self.files();
        for module in registry.modules() {
            files
                .entries
                .entry((ModuleName::from_static(module.name), partition))
                .or_default()
                .stage = Stage::Opening;
        }
    }

    /// The partition's keys left memory: every file of `partition` is `locked`. A fault or a
    /// deactivation stays, and calls still running end on their own.
    pub fn lock_partition(&self, partition: Partition) {
        for ((_, file_partition), entry) in &mut self.files().entries {
            if *file_partition == partition {
                entry.stage = Stage::Locked;
            }
        }
    }

    /// `module`, an activatable module, is off for `partition` (AD-47): its file there is
    /// `deactivated` whatever else holds.
    pub fn deactivate(&self, module: &ModuleName, partition: Partition) {
        self.files()
            .entries
            .entry((module.clone(), partition))
            .or_default()
            .deactivated = true;
    }

    /// `module` is on again for `partition`: its file is in the state it would be in otherwise.
    pub fn activate(&self, module: &ModuleName, partition: Partition) {
        if let Some(entry) = self.files().entries.get_mut(&(module.clone(), partition)) {
            entry.deactivated = false;
        }
    }

    /// Puts `module`'s file in `partition` at `stage`, as the Core's bring-up moves it. A stage
    /// that holds the writer (re-keying, migrating) is refused while calls of module code run on
    /// the file, so the Core changes no file under a call (AD-9, D149).
    pub fn set_stage(
        &self,
        module: &ModuleName,
        partition: Partition,
        stage: Stage,
    ) -> Result<(), CallsInFlight> {
        let mut files = self.files();
        let entry = files
            .entries
            .entry((module.clone(), partition))
            .or_default();
        if stage.holds_the_writer() && !entry.calls.is_empty() {
            return Err(CallsInFlight {
                calls: entry.calls.len(),
            });
        }
        entry.stage = stage;
        Ok(())
    }

    /// Starts a call of module code on `module`'s file in `partition`, due to end by `deadline`
    /// on the Core's monotonic clock: refused with `module_unavailable` unless the file is
    /// ready. The call is registered until [`end_call`](Self::end_call).
    pub(crate) fn begin_call(
        &self,
        module: &ModuleName,
        partition: Partition,
        deadline: Duration,
    ) -> Result<CallTicket, ModuleUnavailable> {
        let mut files = self.files();
        let id = files.next_call;
        let entry = files.entries.get_mut(&(module.clone(), partition));
        let state = entry
            .as_ref()
            .map_or(AvailabilityState::Locked, |entry| entry.state());
        if let Some(unavailable) = ModuleUnavailable::of(module.clone(), partition, state) {
            return Err(unavailable);
        }
        if let Some(entry) = entry {
            entry.calls.push((id, deadline));
        }
        files.next_call = id.wrapping_add(1);
        Ok(CallTicket {
            module: module.clone(),
            partition,
            id,
        })
    }

    /// Ends the call `ticket` registered.
    pub(crate) fn end_call(&self, ticket: CallTicket) {
        if let Some(entry) = self
            .files()
            .entries
            .get_mut(&(ticket.module, ticket.partition))
        {
            entry.calls.retain(|(id, _)| *id != ticket.id);
        }
    }

    /// The fault of `module` in `partition`, if it faulted: the first one, which the state
    /// `faulted` does not tell.
    pub fn fault(&self, module: &ModuleName, partition: Partition) -> Option<Fault> {
        self.files()
            .entries
            .get(&(module.clone(), partition))
            .and_then(|entry| entry.fault)
    }

    /// Marks `module` faulted for `partition` (AD-9): it receives no further call there. Returns
    /// the instance admin alert the first time only; a module already faulted keeps its first
    /// fault.
    pub fn mark_faulted(
        &self,
        module: &ModuleName,
        partition: Partition,
        fault: Fault,
    ) -> Option<InstanceAdminAlert> {
        let mut files = self.files();
        let entry = files
            .entries
            .entry((module.clone(), partition))
            .or_default();
        if entry.fault.is_some() {
            return None;
        }
        entry.fault = Some(fault);
        Some(InstanceAdminAlert::ModuleFaulted {
            module: module.clone(),
            partition,
            file_name: file_name(module, partition),
            fault,
        })
    }

    /// Marks faulted every module with a call still running past its deadline at `now`, on the
    /// Core's monotonic clock (AD-9), and returns an alert for each module newly faulted. The
    /// call itself goes on until its code returns, then is rolled back; meanwhile no other call
    /// starts on the file. The Core's supervisor calls it on a timer.
    pub fn expire_overdue(&self, now: Duration) -> Vec<InstanceAdminAlert> {
        let mut alerts = Vec::new();
        for ((module, partition), entry) in &mut self.files().entries {
            if entry.fault.is_none() && entry.calls.iter().any(|(_, deadline)| now > *deadline) {
                entry.fault = Some(Fault::TimeBudget);
                alerts.push(InstanceAdminAlert::ModuleFaulted {
                    module: module.clone(),
                    partition: *partition,
                    file_name: file_name(module, *partition),
                    fault: Fault::TimeBudget,
                });
            }
        }
        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tasks() -> ModuleName {
        ModuleName::from_static("tasks")
    }

    fn ready(states: &ModuleStates) {
        states
            .set_stage(&tasks(), Partition::Household, Stage::Ready)
            .expect("no call runs");
    }

    #[test]
    fn a_deactivation_then_a_fault_override_the_stage() {
        let states = ModuleStates::new();
        ready(&states);
        let state = || states.state(&tasks(), Partition::Household);
        assert_eq!(state(), AvailabilityState::Ready);
        states.mark_faulted(&tasks(), Partition::Household, Fault::Panicked);
        assert_eq!(state(), AvailabilityState::Faulted);
        states.deactivate(&tasks(), Partition::Household);
        assert_eq!(state(), AvailabilityState::Deactivated);
        states.activate(&tasks(), Partition::Household);
        assert_eq!(state(), AvailabilityState::Faulted);
        let other = ModuleStates::new();
        other.deactivate(&tasks(), Partition::Household);
        other
            .set_stage(&tasks(), Partition::Household, Stage::Ready)
            .expect("no call runs");
        assert_eq!(
            other.state(&tasks(), Partition::Household),
            AvailabilityState::Deactivated
        );
        other.activate(&tasks(), Partition::Household);
        assert_eq!(
            other.state(&tasks(), Partition::Household),
            AvailabilityState::Ready
        );
    }

    #[test]
    fn locking_a_partition_keeps_faults_and_deactivations_and_touches_no_other() {
        let states = ModuleStates::new();
        let notes = ModuleName::from_static("notes");
        for (module, partition) in [
            (tasks(), Partition::Household),
            (notes.clone(), Partition::Household),
            (tasks(), Partition::Home),
        ] {
            states
                .set_stage(&module, partition, Stage::Ready)
                .expect("no call runs");
        }
        states.mark_faulted(&tasks(), Partition::Household, Fault::TimeBudget);
        states.lock_partition(Partition::Household);
        assert_eq!(
            [
                states.state(&tasks(), Partition::Household),
                states.state(&notes, Partition::Household),
                states.state(&tasks(), Partition::Home),
            ],
            [
                AvailabilityState::Faulted,
                AvailabilityState::Locked,
                AvailabilityState::Ready
            ]
        );
    }

    #[test]
    fn a_module_faults_once_and_keeps_its_first_fault() {
        let states = ModuleStates::new();
        ready(&states);
        let first = states.mark_faulted(&tasks(), Partition::Household, Fault::TimeBudget);
        assert_eq!(
            first,
            Some(InstanceAdminAlert::ModuleFaulted {
                module: tasks(),
                partition: Partition::Household,
                file_name: "tasks.household.db".to_owned(),
                fault: Fault::TimeBudget,
            })
        );
        assert_eq!(
            states.mark_faulted(&tasks(), Partition::Household, Fault::Panicked),
            None
        );
        assert_eq!(
            states.fault(&tasks(), Partition::Household),
            Some(Fault::TimeBudget)
        );
        assert_eq!(states.fault(&tasks(), Partition::Home), None);
    }

    /// A call is overdue only strictly past its deadline, and only while it runs.
    #[test]
    fn only_a_call_still_running_past_its_deadline_is_expired() {
        let states = ModuleStates::new();
        ready(&states);
        let deadline = Duration::from_secs(5);
        let ticket = states
            .begin_call(&tasks(), Partition::Household, deadline)
            .expect("ready");
        assert!(states.expire_overdue(deadline).is_empty());
        states.end_call(ticket);
        assert!(
            states
                .expire_overdue(deadline + Duration::from_millis(1))
                .is_empty(),
            "an ended call is not expired"
        );
        let running = states
            .begin_call(&tasks(), Partition::Household, deadline)
            .expect("ready");
        assert_eq!(
            states
                .expire_overdue(deadline + Duration::from_millis(1))
                .len(),
            1
        );
        states.end_call(running);
        assert_eq!(
            states.state(&tasks(), Partition::Household),
            AvailabilityState::Faulted
        );
    }

    #[test]
    fn a_ready_file_has_no_unavailable_answer() {
        for state in AvailabilityState::ALL {
            let answer = ModuleUnavailable::of(tasks(), Partition::Household, *state);
            assert_eq!(
                answer.is_none(),
                *state == AvailabilityState::Ready,
                "{state}"
            );
            if let Some(answer) = answer {
                assert_eq!(
                    (answer.module(), answer.partition(), answer.state()),
                    (&tasks(), Partition::Household, *state)
                );
                assert_eq!(
                    answer.to_string(),
                    format!("module tasks is {state} in partition household")
                );
            }
        }
    }
}
