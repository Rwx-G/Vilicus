//! The channel test double: a channel that reports a sender identity to the Core, so that the
//! channel model is exercised while no shipped messaging channel exists.
//!
//! A test double is a separate executable under `testing/`, never packaged and run only with
//! `vilicus-testbed` (`doc/prd.md` FR-109, D102). Until Story 10.12 gives it behaviour, it starts
//! and exits with status 0.

#![forbid(unsafe_code)]

fn main() {}
