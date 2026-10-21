//! The Vilicus Core: the action pipeline, policy, capability tokens, module registry, event
//! bus, write journal, keys and timers.
//!
//! The Core is the only policy decision point, the only key holder and the only executor of
//! writes; it is the only crate that depends on `vilicus-crypto` and `vilicus-storage`
//! (`doc/architecture-spine.md`, Design Paradigm, AD-1 and AD-3). Unsafe code is allowed here
//! for the system calls D140 names, per block and with a `// SAFETY:` comment.
//!
//! [`registry`] holds the modules compiled into the binary and checks every module file against
//! its declaration; [`record`] runs a module's writes through the typed record API, stamping each
//! record's envelope, taint and data types, and holds every field a write gives to its
//! declaration (FR-18, FR-58, AD-6, AD-7); [`bus`] delivers the events and link requests of a
//! module file's outbox once its call committed (FR-24, AD-10, AD-27, AD-29). [`availability`]
//! holds the state of every module file (AD-54), [`boundary`] runs every call of a module's code
//! inside the fault boundary of AD-9, [`handlers`] binds each module's code to its declaration,
//! and [`startup`] brings a partition's files up once its keys are derived: re-key, migration,
//! then outbox delivery (FR-11).

// AD-9, D131: a module's panic is caught at the boundary of its call and never unwinds into the
// Core, which needs unwinding; a build that aborts on panic would take the Core down with any
// module.
#[cfg(not(panic = "unwind"))]
compile_error!("vilicus-core needs panic = \"unwind\" (AD-9): a module's panic must be caught");

pub mod alert;
pub mod availability;
pub mod boundary;
pub mod bus;
pub mod handlers;
pub mod record;
pub mod registry;
pub mod startup;
