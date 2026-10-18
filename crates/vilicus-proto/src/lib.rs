//! Wire and client API types of Vilicus, CBOR framing and the canonical encoding of anything
//! hashed or signed.
//!
//! Every process that talks to the Core over its Unix sockets goes through these types, and the
//! error enums of each crate boundary live here (`doc/architecture-spine.md`, AD-12, AD-13,
//! AD-14 and Consistency Conventions). It holds no key.
