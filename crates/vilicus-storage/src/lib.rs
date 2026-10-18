//! SQLCipher handles, the SQLite authorizer and the migrations runner of Vilicus.
//!
//! A dependency of `vilicus-core` only: modules reach their file through the typed record API
//! and read handles the Core gives them, never through this crate (`doc/architecture-spine.md`,
//! AD-3, AD-5, AD-9 and AD-23). Unsafe code is allowed here for the SQLite calls D140 names,
//! per block and with a `// SAFETY:` comment.
