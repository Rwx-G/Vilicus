//! Wire and client API types of Vilicus, CBOR framing and the canonical encoding of anything
//! hashed or signed.
//!
//! Every process that talks to the Core over its Unix sockets goes through these types, and the
//! error enums of each crate boundary live here (`doc/architecture-spine.md`, AD-12, AD-13,
//! AD-14 and Consistency Conventions). It holds no key and computes no hash: the Core hashes the
//! [`CanonicalBytes`] of this crate through `vilicus-crypto` (AD-3).
//!
//! - [`profile`]: the D130 profile over `dcbor`, the only decoder and encoder of canonical CBOR.
//! - [`wire`]: the closed-type check, and the [`Wire`] mapping every type implements by hand.
//! - [`frame`]: length-prefixed frames with a maximum per socket kind.
//! - [`message`]: `Hello`, version negotiation, requests, responses, `Cancel` and `Ping`.
//! - [`canonical`]: the bytes that are hashed or signed.
//!
//! ```
//! use vilicus_proto::{SocketKind, frame};
//! use vilicus_proto::message::{Hello, HelloReply, first_frame, negotiate};
//!
//! let hello = Hello {
//!     protocol: "vilicus.peer".to_owned(),
//!     versions: vec![1],
//!     unit: "vilicus-gateway.service".to_owned(),
//!     build: "0.0.0".to_owned(),
//! };
//! let mut socket = Vec::new();
//! frame::write_message(&mut socket, SocketKind::Control, &hello).unwrap();
//! let received = frame::read_frame(&mut socket.as_slice(), SocketKind::Control).unwrap();
//! let hello = first_frame(&received, SocketKind::Control).unwrap();
//! assert_eq!(negotiate(&hello, "vilicus.peer", &[1]), HelloReply::Accepted(1));
//! ```

pub mod canonical;
pub mod frame;
pub mod message;
pub mod profile;
mod vocabulary;
pub mod wire;

pub use canonical::CanonicalBytes;
pub use frame::{FrameError, SocketKind};
pub use wire::{DecodeError, Wire};
