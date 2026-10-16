//! Spike E16 (story 1.10): does locked memory and zeroization behave as designed in the Rust
//! runtime, crash paths included?
//!
//! A subject process plants known keys, runs a Core code path and drops the keys; the harness,
//! a separate process, reads the subject's memory through `/proc/<pid>/mem` before and after
//! the drop and looks for the keys and for every intermediate derived from them. Linux only.

#![warn(clippy::undocumented_unsafe_blocks)]

#[cfg(not(target_os = "linux"))]
compile_error!("the E16 spike inspects Linux process memory; build and run it with run.sh");

pub mod checks;
pub mod material;
pub mod patterns;
pub mod pool;
pub mod scan;
pub mod subject;
