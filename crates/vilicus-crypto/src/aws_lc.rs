//! Every call this crate makes into aws-lc-rs, the source of its primitives (AD-18, D28).
//!
//! A live aws-lc-rs key object keeps a copy of what it was built from in heap memory that the
//! Core neither wipes nor locks: the AEAD key and its GHASH key, the HKDF input (Story 1.10,
//! `*-asis-key-object-on-unlocked-heap`). So each function here is lent the key bytes, builds
//! the objects it needs, runs one operation and drops them before it returns, and is never
//! inlined into its caller (D131). No signature names an aws-lc-rs key object, so none can
//! outlive its operation; `key_objects_live_for_one_operation` in `tests.rs` holds this file to
//! that shape, and no other source file of the crate names aws-lc-rs. That test reads the text
//! of the file: it refuses the ways out it knows (renames, re-exports, statics, `impl` and `dyn`
//! signatures, generic functions), and review covers the others.

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::hkdf::{HKDF_SHA256, Salt};
use aws_lc_rs::{aead, digest, rand};
use vilicus_types::SHA256_LEN;

use crate::KEY_LEN;

/// Bytes of an AES-256-GCM nonce: 96 bits.
pub(crate) const NONCE_LEN: usize = aead::NONCE_LEN;

/// Bytes of an AES-256-GCM tag: 128 bits.
pub(crate) const TAG_LEN: usize = aead::MAX_TAG_LEN;

#[cfg(test)]
mod tests;

/// The SHA-256 digest of `data`.
#[inline(never)]
pub(crate) fn sha256(data: &[u8]) -> [u8; SHA256_LEN] {
    let digest = digest::digest(&digest::SHA256, data);
    let mut bytes = [0; SHA256_LEN];
    bytes.copy_from_slice(digest.as_ref());
    bytes
}

/// Fills `out` from the CSPRNG of aws-lc-rs.
#[inline(never)]
pub(crate) fn fill_random(out: &mut [u8]) -> Result<(), Unspecified> {
    rand::fill(out)
}

/// Seals `in_out` in place with AES-256-GCM under `key`, `nonce` and the additional data `aad`,
/// and returns the tag.
#[inline(never)]
pub(crate) fn seal_aes_256_gcm(
    key: &[u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    aad: &[u8],
    in_out: &mut [u8],
) -> Result<[u8; TAG_LEN], Unspecified> {
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key)?);
    let tag = key.seal_in_place_separate_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad),
        in_out,
    )?;
    let mut bytes = [0; TAG_LEN];
    bytes.copy_from_slice(tag.as_ref());
    Ok(bytes)
}

/// Opens `ciphertext` and `tag` with AES-256-GCM under `key`, `nonce` and the additional data
/// `aad`, writing the plaintext into `out`, which is as long as `ciphertext`. On failure `out`
/// may hold anything, and the caller wipes it.
#[inline(never)]
pub(crate) fn open_aes_256_gcm(
    key: &[u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
    out: &mut [u8],
) -> Result<(), Unspecified> {
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key)?);
    key.open_separate_gather(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad),
        ciphertext,
        tag,
        out,
    )
}

/// HKDF-SHA-256 of `ikm` with no salt and the concatenation of `info` as its info, into `out`.
#[inline(never)]
pub(crate) fn hkdf_sha256(
    ikm: &[u8],
    info: &[&[u8]],
    out: &mut [u8; KEY_LEN],
) -> Result<(), Unspecified> {
    let prk = Salt::new(HKDF_SHA256, &[]).extract(ikm);
    prk.expand(info, HKDF_SHA256)?.fill(out)
}
