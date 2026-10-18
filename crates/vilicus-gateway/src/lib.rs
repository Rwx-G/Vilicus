//! The Vilicus Gateway: TLS termination, the static web client and the relay of client requests
//! to the Core over its Unix socket.
//!
//! An untrusted adapter that holds no key and decides nothing the Core does not re-check; it
//! sees the Core through `vilicus-proto` only (`doc/architecture-spine.md`, AD-1, AD-3 and
//! AD-19). Unsafe code is allowed here only to take the socket-activated listener (D140), per
//! block and with a `// SAFETY:` comment.
