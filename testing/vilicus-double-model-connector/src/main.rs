//! The model connector test double: a model provider that answers the AI process double, so that
//! the provider policy and the request bodies are exercised without a real provider.
//!
//! A test double is a separate executable under `testing/`, never packaged and run only with
//! `vilicus-testbed` (`doc/prd.md` FR-109, D102). Until Story 10.10 gives it behaviour, it starts
//! and exits with status 0.

#![forbid(unsafe_code)]

fn main() {}
