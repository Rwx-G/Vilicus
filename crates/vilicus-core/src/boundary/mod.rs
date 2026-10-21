//! The boundary of AD-9 around every call of module code: a tool handler, an undo handler or an
//! event consumer, run on the writer thread of the module's file.
//!
//! [`Boundary::run`] admits a call only on a file that is ready (AD-54), registers it, and runs the
//! module's code inside [`run_call`]'s transaction and inside `catch_unwind`, with the thread
//! marked as running module code. The handler time budget runs on the availability states' clock
//! from the moment the module's code starts to the moment it returns: the writes it makes through
//! the Core's record port count, as part of its work, while the Core's own work before it (the
//! write lock, the call's deduplication) and after it (the commit) does not, so a slow commit never
//! faults a module. A panic of the module's code is caught there and rolls the transaction back;
//! so does code that returns after its deadline, or after the supervisor expired it. Either
//! way the module is marked faulted for the file's partition and receives no further call there,
//! and the first fault returns a typed instance admin alert. Nothing of the module's code
//! unwinds into the Core.
//!
//! A panic of the Core is never taken for the module's: the record port the module's code writes
//! through is the Core's, so each of its methods runs with the thread unmarked, and a panic inside
//! one unwinds on through the module's code and out of the boundary, the transaction rolled back
//! and the module not faulted. In the Core process the panic hook (D131) reads [`in_module_code`]
//! to tell the two apart, and aborts on the Core's.

#[cfg(test)]
mod tests;

use std::any::Any;
use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::time::Duration;

use vilicus_module_api::{ModuleDeclaration, Records, Value, WriteError, Written};
use vilicus_storage::{Handle, Write};
use vilicus_types::{Id, ModuleName, Rev};

use crate::alert::InstanceAdminAlert;
use crate::availability::{CallTicket, Fault, ModuleStates, ModuleUnavailable};
use crate::record::{Call, CallResult, Invocation, RecordError, Stamper, run_call};

thread_local! {
    /// True while the module's code of a call runs on this thread, outside the Core's record
    /// port.
    static IN_MODULE_CODE: Cell<bool> = const { Cell::new(false) };
}

/// True while this thread runs a module's code inside the boundary of AD-9, and not one of the
/// Core's own functions that code called: the mark the Core's panic hook reads to tell a module's
/// panic, which the boundary catches, from the Core's, on which it wipes the key pool and aborts
/// (D131).
pub fn in_module_code() -> bool {
    IN_MODULE_CODE.with(Cell::get)
}

/// Sets the thread's mark for as long as it lives, and restores the previous mark when dropped,
/// on return and while a panic unwinds alike.
struct Mark {
    previous: bool,
}

impl Mark {
    fn set(in_module: bool) -> Self {
        Self {
            previous: IN_MODULE_CODE.with(|mark| mark.replace(in_module)),
        }
    }
}

impl Drop for Mark {
    fn drop(&mut self) {
        IN_MODULE_CODE.with(|mark| mark.set(self.previous));
    }
}

/// How many times a panic payload of the module's code is dropped again when its drop panics,
/// before the last payload is leaked: a payload is module code, and its drop may panic in turn.
const PAYLOAD_DROPS: usize = 8;

/// The payload the boundary unwinds with when the module's code caught a panic of the Core's
/// record port and returned: the Core failed, so the call is rolled back and the module is not
/// faulted.
const CORE_PANIC_CAUGHT: &str = "a panic of the Core in the record port was caught by module code";

/// Drops `payload`, a panic payload of the module's code, as module code: with the thread marked
/// and inside `catch_unwind`, so a payload whose drop panics never unwinds into the Core. Each
/// payload such a drop yields is dropped the same way, at most [`PAYLOAD_DROPS`] times, after
/// which the last one is leaked.
fn drop_module_payload(mut payload: Box<dyn Any + Send>) {
    for _ in 0..PAYLOAD_DROPS {
        let _module = Mark::set(true);
        match catch_unwind(AssertUnwindSafe(move || drop(payload))) {
            Ok(()) => return,
            Err(next) => payload = next,
        }
    }
    std::mem::forget(payload);
}

/// The record port as the module's code holds it inside the boundary: each method is the Core's
/// and runs with the thread unmarked; a panic in one is recorded as the Core's before it unwinds
/// on, so the boundary lets it through.
struct CorePort<'a> {
    inner: &'a mut dyn Records,
    core_panicked: &'a Cell<bool>,
}

impl CorePort<'_> {
    fn core<T>(&mut self, write: impl FnOnce(&mut dyn Records) -> T) -> T {
        let _core = Mark::set(false);
        match catch_unwind(AssertUnwindSafe(|| write(&mut *self.inner))) {
            Ok(value) => value,
            Err(payload) => {
                self.core_panicked.set(true);
                resume_unwind(payload)
            }
        }
    }
}

impl Records for CorePort<'_> {
    fn insert(
        &mut self,
        table: &str,
        fields: &[(&str, Value)],
        inputs: &[Id],
    ) -> Result<Written, WriteError> {
        self.core(|records| records.insert(table, fields, inputs))
    }

    fn update(
        &mut self,
        table: &str,
        id: Id,
        expected: Rev,
        fields: &[(&str, Value)],
        inputs: &[Id],
    ) -> Result<Written, WriteError> {
        self.core(|records| records.update(table, id, expected, fields, inputs))
    }

    fn delete(&mut self, table: &str, id: Id) -> Result<(), WriteError> {
        self.core(|records| records.delete(table, id))
    }

    fn request_effect(
        &mut self,
        effect: &str,
        idempotency_key: &[u8],
        payload: &[u8],
    ) -> Result<Id, WriteError> {
        self.core(|records| records.request_effect(effect, idempotency_key, payload))
    }

    fn emit(&mut self, topic: &str, record: Id, payload: &[u8]) -> Result<Id, WriteError> {
        self.core(|records| records.emit(topic, record, payload))
    }

    fn request_link(
        &mut self,
        record: Id,
        target_module: &str,
        target: Id,
    ) -> Result<Id, WriteError> {
        self.core(|records| records.request_link(record, target_module, target))
    }
}

/// Why a call of module code did not commit.
#[derive(Debug)]
#[non_exhaustive]
pub enum HandlerError {
    /// The module's file is not ready (AD-54); nothing ran.
    Unavailable(ModuleUnavailable),
    /// The handle is not a file of the module named; nothing ran.
    WrongFile,
    /// The module is not registered; nothing ran.
    UnregisteredModule(ModuleName),
    /// The module declares no tool of that name, or none with an undo handler; nothing ran.
    UnknownHandler,
    /// The Core refused a write of the call, or the module's code returned an error: the call
    /// was rolled back, and the module serves on.
    Refused(RecordError),
    /// The module's code panicked or ran past its deadline: the call was rolled back, and the
    /// module is faulted for the partition (AD-9). `alert` is the instance admin alert of the
    /// fault, when this call faulted the module; a module the supervisor faulted first returned
    /// its alert there.
    Faulted {
        /// What the module's code did.
        fault: Fault,
        /// The alert, the first time the module faults.
        alert: Option<Box<InstanceAdminAlert>>,
    },
}

impl core::fmt::Display for HandlerError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unavailable(unavailable) => write!(formatter, "{unavailable}"),
            Self::WrongFile => formatter.write_str("the handle is another module's file"),
            Self::UnregisteredModule(module) => {
                write!(formatter, "module {module} is not registered")
            }
            Self::UnknownHandler => formatter.write_str("the module declares no such handler"),
            Self::Refused(error) => write!(formatter, "{error}"),
            Self::Faulted { fault, .. } => write!(formatter, "the module's code {fault}"),
        }
    }
}

impl std::error::Error for HandlerError {}

/// Ends the call its ticket registered when dropped, on return and while a panic of the Core
/// unwinds alike.
struct Registered<'a> {
    states: &'a ModuleStates,
    ticket: Option<CallTicket>,
}

impl Drop for Registered<'_> {
    fn drop(&mut self) {
        if let Some(ticket) = self.ticket.take() {
            self.states.end_call(ticket);
        }
    }
}

/// The boundary of AD-9: the availability states the calls are admitted by and faults are
/// recorded in, whose clock the budgets run on, and the time budget of one call.
#[derive(Clone, Copy)]
pub struct Boundary<'a> {
    /// The availability states of the module files.
    pub states: &'a ModuleStates,
    /// How long the module's code of one call may run
    /// ([`HANDLER_TIME_BUDGET`](vilicus_types::HANDLER_TIME_BUDGET) in the Core).
    pub budget: Duration,
}

impl Boundary<'_> {
    /// Runs `body`, the module's code for one call, as [`run_call`] runs it on `handle`, the write
    /// handle of `module`'s file, inside the boundary: refused before anything runs unless the
    /// file is ready; the call registered until it ends, with a deadline while `body` runs; `body` run inside
    /// `catch_unwind` with the thread marked. A panic of `body`, or `body` returning after the
    /// deadline or after the supervisor expired the call, rolls the call back and faults the
    /// module for the partition ([`HandlerError::Faulted`]); a refusal or an error of `body`
    /// rolls it back and is [`HandlerError::Refused`]. A panic of the Core, in a method of the
    /// record port or around `body`, unwinds out of the boundary, the call rolled back and the
    /// module not faulted, even when the module's code caught it and returned. The payload of the
    /// module's panic is dropped as module code.
    pub fn run<T>(
        &self,
        handle: &Handle<Write>,
        module: &'static ModuleDeclaration,
        call: &Call,
        invocation: &Invocation,
        stamper: &mut dyn Stamper,
        body: impl FnOnce(&mut dyn Records) -> Result<T, WriteError>,
    ) -> Result<CallResult<T>, HandlerError> {
        let name = ModuleName::from_static(module.name);
        if *handle.file().module() != name {
            return Err(HandlerError::WrongFile);
        }
        let partition = handle.file().partition();
        let ticket = self
            .states
            .begin_call(&name, partition)
            .map_err(HandlerError::Unavailable)?;
        let _registered = Registered {
            states: self.states,
            ticket: Some(ticket.clone()),
        };
        let mut fault = None;
        let core_panicked = Cell::new(false);
        let result = run_call(handle, module, call, invocation, stamper, |records| {
            let deadline = self.states.start_budget(&ticket, self.budget);
            let returned = {
                let _module = Mark::set(true);
                let mut port = CorePort {
                    inner: records,
                    core_panicked: &core_panicked,
                };
                catch_unwind(AssertUnwindSafe(|| body(&mut port)))
            };
            let late = self.states.now() > deadline;
            self.states.stop_budget(&ticket);
            match returned {
                Err(payload) if core_panicked.get() => resume_unwind(payload),
                Err(payload) => {
                    drop_module_payload(payload);
                    fault = Some(Fault::Panicked);
                    Err(WriteError::Failed)
                }
                Ok(_) if core_panicked.get() => resume_unwind(Box::new(CORE_PANIC_CAUGHT)),
                Ok(_) if late => {
                    fault = Some(Fault::TimeBudget);
                    Err(WriteError::Failed)
                }
                Ok(returned) => returned,
            }
        });
        match (fault, result) {
            (Some(fault), _) => Err(HandlerError::Faulted {
                fault,
                alert: self
                    .states
                    .mark_faulted(&name, partition, fault)
                    .map(Box::new),
            }),
            (None, Ok(result)) => Ok(result),
            (None, Err(error)) => Err(HandlerError::Refused(error)),
        }
    }
}
