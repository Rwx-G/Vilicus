//! The module port of Vilicus: what a module declares (schema and migrations, record types,
//! tools, event topics, undo handlers) and the scoped handles it receives from the Core.
//!
//! Modules depend on this crate and never on the Core's internals, and it exports no key type
//! (`doc/architecture-spine.md`, AD-3 and AD-9).
