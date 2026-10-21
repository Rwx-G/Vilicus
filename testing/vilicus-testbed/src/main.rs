//! The `vilicus-testbed` executable: built from the same workspace crates as `vilicus`, it also
//! links the reference module, and release gates that need a module or a test double run against
//! it (`doc/prd.md` FR-109, D102; `doc/architecture-spine.md` AD-3). The test doubles are
//! separate executables that ship beside it in the testbed artefact, not libraries it links.
//!
//! It is never packaged: `ci/check_packaging.py` fails when it reaches a release artefact. Until
//! later stories give it behaviour (the Core roles, the CI test key of D102, starting the doubles
//! in Story 10.1), it starts and exits with status 0. Its tests hold the registry of the modules
//! it links, the reference module and a second module that reads it, and run the gates that need
//! them against the Core's own paths (Story 3.10): the module contract end to end, and the fault
//! isolation release gate of AD-9.

#[cfg(test)]
mod contract;
#[cfg(test)]
mod gates;
#[cfg(test)]
mod reader;
#[cfg(test)]
mod registry;
#[cfg(test)]
mod support;

fn main() {}
