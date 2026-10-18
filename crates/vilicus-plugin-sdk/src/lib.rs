//! The Vilicus plugin SDK: the Core protocol as a plugin executable sees it.
//!
//! Every plugin, first-party or third-party, is a separate executable that depends on this crate
//! and never on the Core (`doc/architecture-spine.md`, AD-2 and AD-3).

#![forbid(unsafe_code)]
