//! The AI process test double: an AI process that exercises the MCP interface of the Core
//! (`doc/architecture-spine.md` AD-12 and AD-15) without a model.
//!
//! A test double is a separate executable under `testing/`, never packaged and run only with
//! `vilicus-testbed` (`doc/prd.md` FR-109, D102). Until Story 10.1 gives it behaviour, it starts
//! and exits with status 0.

#![forbid(unsafe_code)]

fn main() {}
