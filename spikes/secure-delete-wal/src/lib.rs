//! Spike E17 (story 1.11): what `secure_delete`, WAL checkpoints, VACUUM and
//! crypto-shredding leave on disk in a SQLCipher database file, its WAL and its shm.
//!
//! The inspection never goes through SQL: it reads the files as bytes, decrypts every
//! page and every WAL frame (stale frames included), and searches the result for the
//! known plaintext of deleted rows.

#![deny(unsafe_code)]

pub mod checks;
pub mod pages;
pub mod rng;
pub mod scan;
pub mod store;
