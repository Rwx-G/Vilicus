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
//! declaration (FR-18, FR-58, AD-6, AD-7).

pub mod record;
pub mod registry;
