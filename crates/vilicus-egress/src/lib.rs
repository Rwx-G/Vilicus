//! The Vilicus egress proxy: the only component that reaches the network, with an
//! exact-hostname allowlist per caller and a block on internal addresses.
//!
//! An untrusted adapter that holds no key; it sees the Core through `vilicus-proto` only
//! (`doc/architecture-spine.md`, AD-3 and AD-16).
