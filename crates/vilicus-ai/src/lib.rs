//! The Vilicus AI process runtime: the MCP client of each AI process role and the model
//! connectors.
//!
//! An AI process sees tools, never storage, and holds no key; it sees the Core through
//! `vilicus-proto` only (`doc/architecture-spine.md`, AD-3, AD-15 and AD-51).
