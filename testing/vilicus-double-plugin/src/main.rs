//! The plugin test double: a plugin executable that exercises the plugin protocol of the Core
//! (`doc/architecture-spine.md` AD-2 and AD-12) while no shipped plugin exists.
//!
//! A test double is a separate executable under `testing/`, never packaged and run only with
//! `vilicus-testbed` (`doc/prd.md` FR-109, D102). Until Story 10.1 gives it behaviour, it starts
//! and exits with status 0.

#![forbid(unsafe_code)]

fn main() {}
