//! Spike E19 (story 1.9): the AD-13 canonical CBOR profile on `dcbor`, a seeded corpus and a
//! fuzzed set of non-canonical inputs, written as language-neutral vector files that the
//! TypeScript side under `ts/` replays with `cbor2`.

#![forbid(unsafe_code)]

pub mod corpus;
pub mod fuzz;
pub mod notation;
pub mod profile;
pub mod rng;
pub mod vectors;
