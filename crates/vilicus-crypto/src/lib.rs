//! Key types, key wrappers and key derivation of Vilicus, and the Core's hashing.
//!
//! A dependency of `vilicus-core` only, so no module, adapter or test crate can name a key type
//! (`doc/architecture-spine.md`, AD-3 and AD-4). Unsafe code is allowed here for memory locking,
//! per block and with a `// SAFETY:` comment (D140).
//!
//! # Cryptographic suite, version 1
//!
//! Spine AD-18 fixes the suite. This crate implements no primitive: it calls aws-lc-rs, with its
//! `aws-lc-sys` backend, for each one it uses (D28: no home-made cryptography).
//!
//! - **Key wrapping**: AES-256-GCM from aws-lc-rs, with a 96-bit nonce drawn from the CSPRNG of
//!   aws-lc-rs for each wrap ([`Wrapper::wrap_key`]).
//! - **Key derivation**: HKDF-SHA-256 from aws-lc-rs, with no salt, a 32-byte output and an
//!   `info` made of a versioned [`Label`] and its end byte, then each context part preceded by
//!   its length ([`derive_key`]), so that no two derivations share an `info`.
//! - **Hashing**: SHA-256 from aws-lc-rs ([`sha256`]).
//!
//! The rest of the suite is not in this crate yet. Argon2id, for the passphrase and backup
//! secret KEKs, will come from the `argon2` crate, without its `parallel` feature, with the
//! `blake2` crate it depends on, under the exception to D28 that D129 records. HPKE, which wraps
//! the household key to member public keys and seals inbox rows, will come from the `hpke`
//! crate under the exception D61 and D120 record; inside HPKE, the `hpke` crate brings its own
//! primitive crates for X25519, HKDF and AES-GCM, which aws-lc-rs does not replace there. OPAQUE,
//! for pairing codes, will come from `opaque-ke` under the exception D123 records. None of
//! these three crates has a published audit of the version the Core pins: each one rests on
//! the reviews, test vectors and cross-tests its record requires. `ci/check_supply_chain.py`
//! lists every primitive source with its record (`ci/primitive_sources.toml`) and fails on a
//! crate of the dependency tree that its publisher classifies as cryptographic and that is not
//! one of them.
//!
//! This crate protects keys at rest. It states nothing about the transport, about which the
//! product says only what D27 says.
//!
//! # Wrappers
//!
//! Every [`Wrapper`] carries its format version and algorithm identifiers
//! (`doc/key-management.md` section 9), and a wrapper whose version is older than
//! [`OLDEST_ACCEPTED_FORMAT_VERSION`] or newer than [`FORMAT_VERSION`], or that names an
//! identifier its version does not define, is refused instead of being read another way. The
//! identifiers of version 1:
//!
//! ```
//! use vilicus_crypto::{ARGON2_VERSION, Aead, Argon2idParams, FORMAT_VERSION, Kdf, KekDerivation};
//!
//! assert_eq!(FORMAT_VERSION, 1);
//! // KDF: none (the KEK comes from a key), or Argon2id version 0x13 with its m, t and p.
//! assert_eq!(Kdf::None.id(), 0x0001);
//! let costs = Argon2idParams { memory_kib: 1, passes: 1, lanes: 1 };
//! assert_eq!(Kdf::Argon2id(costs).id(), 0x0002);
//! assert_eq!(ARGON2_VERSION, 0x13);
//! // KEK derivation: the KDF output or the parent key itself, or HKDF-SHA-256.
//! assert_eq!(KekDerivation::Direct.id(), 0x0001);
//! assert_eq!(KekDerivation::HkdfSha256.id(), 0x0002);
//! // AEAD: AES-256-GCM with a 96-bit nonce and a 128-bit tag.
//! assert_eq!(Aead::Aes256Gcm.id(), 0x0001);
//! ```
//!
//! A version 1 wrapper is encoded as these fields in this order, every integer big-endian; the
//! four Argon2id fields are present only when the KDF is Argon2id:
//!
//! | Field | Bytes |
//! |---|---|
//! | format version | 2 |
//! | KDF identifier | 2 |
//! | KEK derivation identifier | 2 |
//! | AEAD identifier | 2 |
//! | Argon2 version | 4 |
//! | Argon2id m, in KiB | 4 |
//! | Argon2id t | 4 |
//! | Argon2id p | 4 |
//! | length of the salt or credential reference | 2 |
//! | salt or credential reference | that length |
//! | creation time, UTC milliseconds since the Unix epoch, signed | 8 |
//! | wrapper id, a UUIDv7 | 16 |
//! | nonce | 12 |
//! | ciphertext of the key | 32 |
//! | tag | 16 |
//!
//! The additional data of the seal is every field before the ciphertext, then the purpose of the
//! wrap, a [`Label`] followed by its end byte, then a context the caller gives, which may not be
//! empty. A wrapper whose header is edited, or that is opened for another purpose or another
//! record than the ones it was made for, does not open.
//!
//! # Key types
//!
//! Every key type of Vilicus is defined here ([`SymmetricKey`]): none implements `Clone`,
//! `Debug` or `Display`, and each wipes its buffer when dropped. The crate never hands out key
//! bytes. Key buffers are heap allocations wiped on drop; they are not yet in locked memory,
//! which AD-4 and D131 require before keys are held in production.
//!
//! Each AES-256-GCM or HKDF operation builds the aws-lc-rs objects it needs from the key's
//! buffer and drops them before it returns, because a live aws-lc-rs key object keeps the key,
//! the HKDF input or the GHASH key in heap memory the Core neither wipes nor locks (D131).

mod aws_lc;
mod derive;
mod error;
mod key;
mod wrapper;

use vilicus_types::SHA256_LEN;

pub use derive::{Label, LabelError, derive_key};
pub use error::{CryptoError, WrapperError};
pub use key::{KEY_LEN, SymmetricKey};
pub use wrapper::{
    ARGON2_VERSION, Aead, Argon2idParams, FORMAT_VERSION, Kdf, KekDerivation,
    MAX_KEK_REFERENCE_LEN, OLDEST_ACCEPTED_FORMAT_VERSION, WrapParams, Wrapper,
};

/// The SHA-256 digest of `data`: the hash the Core compares with each migration's frozen hash
/// before the migration runs (spine AD-23, D21).
///
/// ```
/// // FIPS 180-2, appendix B.1.
/// assert_eq!(
///     vilicus_crypto::sha256(b"abc"),
///     vilicus_types::sha256_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
/// );
/// ```
pub fn sha256(data: &[u8]) -> [u8; SHA256_LEN] {
    aws_lc::sha256(data)
}

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod tests {
    use vilicus_types::sha256_hex;

    use super::*;

    /// The FIPS 180-2 vectors of appendix B: the empty string, a two-block message and the one
    /// million `a`s, which crosses many blocks.
    #[test]
    fn sha256_matches_the_fips_vectors() {
        let cases: [(Vec<u8>, &str); 3] = [
            (
                Vec::new(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".to_vec(),
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (
                vec![b'a'; 1_000_000],
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
            ),
        ];
        for (data, hex) in cases {
            assert_eq!(sha256(&data), sha256_hex(hex), "{} bytes", data.len());
        }
    }
}
