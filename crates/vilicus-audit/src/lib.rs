//! The Vilicus audit writer: a separate process that appends to the audit log under its own
//! key, through one socket.
//!
//! It sees the Core through `vilicus-proto` only and holds no data key
//! (`doc/architecture-spine.md`, AD-3 and AD-17).
