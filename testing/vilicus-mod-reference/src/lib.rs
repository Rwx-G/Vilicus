//! The Vilicus reference module: a module that exists to exercise the module contract of
//! `vilicus-module-api` in tests.
//!
//! It is never packaged. It is linked only into `vilicus-testbed`, and the crate graph check
//! keeps it out of the shipped binary's dependency closure (`doc/prd.md` FR-109, D102;
//! `doc/architecture-spine.md` AD-3). It declares nothing yet: Story 3.10 makes it use every
//! part of the contract once the module port exists.

#![forbid(unsafe_code)]
