//! Spike E10 (story 1.6): the fixed systemd profile of a plugin, and how the Core identifies the
//! unit behind each connection to its Unix sockets. See `run.sh` and the story's Result.

pub mod client;
pub mod core;
pub mod notify;
pub mod peer;
pub mod probe;
pub mod startup;
pub mod unit;
