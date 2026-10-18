//! Key types, key wrappers and key derivation functions of Vilicus.
//!
//! A dependency of `vilicus-core` only, so no module, adapter or test crate can name a key type
//! (`doc/architecture-spine.md`, AD-3 and AD-4). Unsafe code is allowed here for memory locking,
//! per block and with a `// SAFETY:` comment (D140).
