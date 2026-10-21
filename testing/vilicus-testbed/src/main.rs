//! The `vilicus-testbed` executable: built from the same workspace crates as `vilicus`, it also
//! links the reference module, and release gates that need a module or a test double run against
//! it (`doc/prd.md` FR-109, D102; `doc/architecture-spine.md` AD-3). The test doubles are
//! separate executables that ship beside it in the testbed artefact, not libraries it links.
//!
//! It is never packaged: `ci/check_packaging.py` fails when it reaches a release artefact. Until
//! later stories give it behaviour (the Core roles, the CI test key of D102, starting the doubles
//! in Story 10.1), it starts and exits with status 0.

#[cfg(test)]
mod registry;

fn main() {}
