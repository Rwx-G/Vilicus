//! E32 spike: does the execution model of spine AD-9 keep one action through the full pipeline
//! (policy, write, audit), and a dedicated home rule thread, responsive under household load?
//!
//! The model: a tokio runtime for I/O and the pipeline, one writer thread per open SQLCipher
//! file ([`writer`]), a bounded blocking pool (a semaphore over `spawn_blocking`) for Argon2id,
//! HPKE-shaped sealing, file copies and hashing, and a dedicated rule thread ([`load`]). The
//! audit writer is a separate process reached over a Unix socket ([`audit`]).

#![deny(unsafe_code)]

pub mod audit;
pub mod crypto;
pub mod experiments;
pub mod load;
pub mod pipeline;
pub mod stats;
pub mod storage;
pub mod writer;
