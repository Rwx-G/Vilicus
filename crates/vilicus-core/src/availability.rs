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
//! Every stage change of a bring-up carries the generation of the unlock it acts for: each unlock
//! and each lock of a partition starts a new generation, and a stage change of an older one is
//! refused, so a bring-up still running when its partition is locked, and unlocked again, never
//! moves a file of the later unlock, nor leaves a locked partition's file ready. The writer a
//! re-key or a migration takes is held until the bring-up that took it moves the file on, whatever
//! its generation, so a second bring-up never migrates a file the first still migrates.
//!
//! Each call of module code is registered while it runs ([`ModuleStates`] hands out a
//! [`CallTicket`]), with a deadline while the module's code runs; a file is put to re-keying or
//! migrating only when no call runs on it, and no call starts on a file that is not ready, so the
//! migration runner never meets a connection the Core opened for a call (AD-23, D149). The
//! deadlines and their expiry read one clock, the states' own: [`ModuleStates::expire_overdue`]
//! marks faulted every module whose code outlived its deadline, without waiting for it to return:
//! a handler that never returns keeps its writer thread, and the Core's other threads, files and
//! partitions go on.

use core::fmt;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use vilicus_storage::{ModuleFile, Partition};
use vilicus_types::{
    AvailabilityState, ClientFacingError, ErrorCode, MessageKey, ModuleName, RetryClass,
};

use crate::alert::InstanceAdminAlert;
use crate::registry::Registry;

/// The Core's monotonic clock (AD-30): time elapsed since an origin of the clock's own, which a
/// change of the wall clock does not move. The time budget of module code is measured on it.
pub trait MonotonicClock: Send + Sync {
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

    /// The answer for `module`'s file in `partition` when the states report it ready but the Core
    /// holds no connection of it to serve the call: `opening`, as the event bus counts such a
    /// file, retryable.
    pub(crate) fn not_open(module: ModuleName, partition: Partition) -> Self {
        Self {
            module,
            partition,
            state: AvailabilityState::Opening,
            retry_class: RetryClass::Retryable,
        }
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
#[derive(Clone, Debug)]
pub struct CallTicket {
    module: ModuleName,
    partition: Partition,
    id: u64,
}

/// The unlock of one partition a bring-up acts for: each unlock and each lock of the partition
/// starts a new one ([`ModuleStates::unlock_partition`], [`ModuleStates::lock_partition`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Generation {
    partition: Partition,
    number: u64,
}

impl Generation {
    /// The partition.
    pub fn partition(self) -> Partition {
        self.partition
    }
}

/// Why a stage change was refused; the file keeps its stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageRefused {
    /// The change is of an earlier unlock of the partition, which was locked since: the bring-up
    /// that asks for it acts for keys no longer in memory.
    Stale,
    /// The stage holds the writer, and calls of module code still run on the file.
    CallsInFlight {
        /// How many.
        calls: usize,
    },
    /// The stage holds the writer, and a re-key or a migration, of this unlock or an earlier
    /// one, still holds it.
    WriterHeld,
}

#[derive(Debug)]
struct Entry {
    stage: Stage,
    fault: Option<Fault>,
    deactivated: bool,
    /// The calls running on the file, each with its deadline while the module's code runs.
    calls: Vec<(u64, Option<Duration>)>,
    /// The generation whose re-key or migration holds the file's writer.
    writer: Option<u64>,
}

impl Default for Entry {
    fn default() -> Self {
        Self {
            stage: Stage::Locked,
            fault: None,
            deactivated: false,
            calls: Vec::new(),
            writer: None,
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
    /// The current generation of each partition; 0 before its first unlock.
    generations: HashMap<Partition, u64>,
}

impl Files {
    /// Starts a new generation of `partition` and returns it.
    fn next_generation(&mut self, partition: Partition) -> Generation {
        let number = self.generations.entry(partition).or_default();
        *number = number.wrapping_add(1);
        Generation {
            partition,
            number: *number,
        }
    }
}

/// The availability state of every module file of the instance, shared by the threads of the
/// Core: the writer threads, the event bus, unlock and the supervisor that expires overdue calls;
/// with the Core's monotonic clock, which every deadline and its expiry read.
pub struct ModuleStates {
    files: Mutex<Files>,
    clock: Arc<dyn MonotonicClock>,
}

impl fmt::Debug for ModuleStates {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModuleStates")
            .field("files", &self.files)
            .finish_non_exhaustive()
    }
}

impl Default for ModuleStates {
    fn default() -> Self {
        Self::new()
    }
}

/// The name of `module`'s file in `partition`, as the alerts carry it.
fn file_name(module: &ModuleName, partition: Partition) -> String {
    ModuleFile::new("", module.clone(), partition).file_name()
}

impl ModuleStates {
    /// No file known: every file is `locked`; the host's monotonic clock.
    pub fn new() -> Self {
        Self::with_clock(Arc::new(SystemClock::new()))
    }

    /// No file known, with `clock` as the Core's monotonic clock.
    pub fn with_clock(clock: Arc<dyn MonotonicClock>) -> Self {
        Self {
            files: Mutex::new(Files::default()),
            clock,
        }
    }

    /// The time on the states' clock.
    pub fn now(&self) -> Duration {
        self.clock.now()
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
    /// each file on in the background ([`bring_up`](crate::startup::bring_up)), with the
    /// generation returned, a new one. A fault, a deactivation and a writer an earlier bring-up
    /// still holds stay.
    pub fn unlock_partition(&self, registry: &Registry, partition: Partition) -> Generation {
        let mut files = self.files();
        let generation = files.next_generation(partition);
        for module in registry.modules() {
            files
                .entries
                .entry((ModuleName::from_static(module.name), partition))
                .or_default()
                .stage = Stage::Opening;
        }
        generation
    }

    /// The partition's keys left memory: every file of `partition` is `locked`, and a new
    /// generation starts, so no later stage change of a bring-up of the earlier unlock moves a
    /// file. A fault, a deactivation and a writer that bring-up still holds stay, and calls still
    /// running end on their own.
    pub fn lock_partition(&self, partition: Partition) {
        let mut files = self.files();
        files.next_generation(partition);
        for ((_, file_partition), entry) in &mut files.entries {
            if *file_partition == partition {
                entry.stage = Stage::Locked;
            }
        }
    }

    /// True while `generation` is its partition's current one: the partition was not locked, or
    /// unlocked again, since.
    pub fn is_current(&self, generation: Generation) -> bool {
        self.files()
            .generations
            .get(&generation.partition)
            .is_some_and(|number| *number == generation.number)
    }

    /// The current generation of `partition`.
    #[cfg(test)]
    pub(crate) fn generation(&self, partition: Partition) -> Generation {
        Generation {
            partition,
            number: self
                .files()
                .generations
                .get(&partition)
                .copied()
                .unwrap_or_default(),
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

    /// Puts `module`'s file at `stage`, as the bring-up of `generation`, an unlock of the file's
    /// partition, moves it. Refused, the file keeping its stage, when `generation` is not the
    /// partition's current one ([`StageRefused::Stale`]); a stale change that leaves a stage holding
    /// the writer still releases the writer its own bring-up took. A stage that holds the writer
    /// (re-keying, migrating) is refused while calls of module code run on the file, or while a
    /// re-key or a migration holds the writer already, so the Core changes no file under a call
    /// and runs one re-key or migration of a file at a time (AD-9, D149).
    pub fn set_stage(
        &self,
        generation: Generation,
        module: &ModuleName,
        stage: Stage,
    ) -> Result<(), StageRefused> {
        let mut files = self.files();
        let current = files
            .generations
            .get(&generation.partition)
            .copied()
            .unwrap_or_default();
        let entry = files
            .entries
            .entry((module.clone(), generation.partition))
            .or_default();
        let holds = entry.writer == Some(generation.number);
        if generation.number != current {
            if holds && !stage.holds_the_writer() {
                entry.writer = None;
            }
            return Err(StageRefused::Stale);
        }
        if stage.holds_the_writer() && !holds {
            if entry.writer.is_some() {
                return Err(StageRefused::WriterHeld);
            }
            if !entry.calls.is_empty() {
                return Err(StageRefused::CallsInFlight {
                    calls: entry.calls.len(),
                });
            }
            entry.writer = Some(generation.number);
        } else if holds && !stage.holds_the_writer() {
            entry.writer = None;
        }
        entry.stage = stage;
        Ok(())
    }

    /// Starts a call of module code on `module`'s file in `partition`: refused with
    /// `module_unavailable` unless the file is ready. The call is registered until
    /// [`end_call`](Self::end_call), without a deadline until [`start_budget`](Self::start_budget).
    pub(crate) fn begin_call(
        &self,
        module: &ModuleName,
        partition: Partition,
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
            entry.calls.push((id, None));
        }
        files.next_call = id.wrapping_add(1);
        Ok(CallTicket {
            module: module.clone(),
            partition,
            id,
        })
    }

    /// The module's code of the call `ticket` starts: its deadline is `budget` from now, and is
    /// returned.
    pub(crate) fn start_budget(&self, ticket: &CallTicket, budget: Duration) -> Duration {
        let deadline = self.now().saturating_add(budget);
        self.set_deadline(ticket, Some(deadline));
        deadline
    }

    /// The module's code of the call `ticket` returned: the call has no deadline any more, so the
    /// Core's own work after it, the commit included, never faults the module.
    pub(crate) fn stop_budget(&self, ticket: &CallTicket) {
        self.set_deadline(ticket, None);
    }

    fn set_deadline(&self, ticket: &CallTicket, deadline: Option<Duration>) {
        if let Some(entry) = self
            .files()
            .entries
            .get_mut(&(ticket.module.clone(), ticket.partition))
            && let Some(call) = entry.calls.iter_mut().find(|(id, _)| *id == ticket.id)
        {
            call.1 = deadline;
        }
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

    /// Marks faulted every module whose code still runs past its deadline now, on the states'
    /// clock (AD-9), and returns an alert for each module newly faulted. The call itself goes on
    /// until its code returns, then is rolled back; meanwhile no other call starts on the file.
    /// The Core's supervisor calls it on a timer.
    pub fn expire_overdue(&self) -> Vec<InstanceAdminAlert> {
        let now = self.now();
        let mut alerts = Vec::new();
        for ((module, partition), entry) in &mut self.files().entries {
            let overdue = entry
                .calls
                .iter()
                .any(|(_, deadline)| deadline.is_some_and(|deadline| now > deadline));
            if entry.fault.is_none() && overdue {
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
            .set_stage(
                states.generation(Partition::Household),
                &tasks(),
                Stage::Ready,
            )
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
            .set_stage(
                other.generation(Partition::Household),
                &tasks(),
                Stage::Ready,
            )
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
                .set_stage(states.generation(partition), &module, Stage::Ready)
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

    /// A clock that moves only when a test moves it.
    #[derive(Default)]
    struct Manual(Mutex<Duration>);

    impl Manual {
        fn advance(&self, by: Duration) {
            let mut now = self.0.lock().expect("the clock");
            *now += by;
        }
    }

    impl MonotonicClock for Manual {
        fn now(&self) -> Duration {
            *self.0.lock().expect("the clock")
        }
    }

    /// A call is overdue only strictly past its deadline, only while its module's code runs, and
    /// only while it is registered; expiry reads the states' own clock.
    #[test]
    fn only_a_call_still_running_past_its_deadline_is_expired() {
        let clock = Arc::new(Manual::default());
        let states = ModuleStates::with_clock(Arc::clone(&clock) as Arc<dyn MonotonicClock>);
        ready(&states);
        let budget = Duration::from_secs(5);
        let ticket = states
            .begin_call(&tasks(), Partition::Household)
            .expect("ready");
        clock.advance(budget * 2);
        assert!(
            states.expire_overdue().is_empty(),
            "no deadline before the module's code starts"
        );
        let deadline = states.start_budget(&ticket, budget);
        assert_eq!(deadline, budget * 3);
        clock.advance(budget);
        assert!(states.expire_overdue().is_empty(), "at its deadline");
        clock.advance(Duration::from_millis(1));
        states.stop_budget(&ticket);
        assert!(
            states.expire_overdue().is_empty(),
            "the module's code returned: the Core's work after it is not counted"
        );
        states.end_call(ticket);
        let running = states
            .begin_call(&tasks(), Partition::Household)
            .expect("ready");
        states.start_budget(&running, budget);
        let ended = states
            .begin_call(&tasks(), Partition::Household)
            .expect("ready");
        states.start_budget(&ended, budget);
        states.end_call(ended);
        clock.advance(budget + Duration::from_millis(1));
        assert_eq!(states.expire_overdue().len(), 1);
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
