//! The HPKE profile Vilicus uses (spine AD-18), with the usage rules of `REVIEW.md`: base mode,
//! DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, single-shot only.
//!
//! The functions are thin on purpose: they fix the suite and the mode, so no caller can pick
//! another one (U2); they refuse a recipient public key that is not canonically encoded; they
//! derive key pairs only from 32 bytes of input (U4); and they open in place, so the plaintext
//! lands in a buffer the caller owns (locked and zeroized in the Core) instead of in a fresh
//! `Vec` the crate allocates (U5), with one refusal for every failure (U6). The `hpke::Kem`
//! trait is deliberately not re-exported, so a caller of this module cannot reach
//! `derive_keypair` with an input of another length.

#![forbid(unsafe_code)]

use hpke::{
    Deserializable, HpkeError, Kem, OpModeR, OpModeS, Serializable,
    aead::{AeadTag, AesGcm256},
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    rand_core::{CryptoRng, RngCore},
};

/// DHKEM(X25519, HKDF-SHA256), KEM identifier 0x0020.
pub type SuiteKem = X25519HkdfSha256;
/// HKDF-SHA256, KDF identifier 0x0001.
pub type SuiteKdf = HkdfSha256;
/// AES-256-GCM, AEAD identifier 0x0002.
pub type SuiteAead = AesGcm256;

/// Recipient public key of the suite.
pub type PublicKey = <SuiteKem as Kem>::PublicKey;
/// Recipient private key of the suite. The type compares by value; the Core never compares
/// private keys (U7), and its own key type implements no equality.
pub type PrivateKey = <SuiteKem as Kem>::PrivateKey;
/// Encapsulated key of the suite (the ephemeral public key).
pub type EncappedKey = <SuiteKem as Kem>::EncappedKey;

/// Length in bytes of the encapsulated key and of a public key of the suite.
pub const ENC_LEN: usize = 32;
/// Length in bytes of the AES-256-GCM tag.
pub const TAG_LEN: usize = 16;

/// The X25519 field prime 2^255 - 19, little-endian.
const FIELD_PRIME_LE: [u8; 32] = {
    let mut p = [0xff; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    p
};

/// A sealed value as stored: encapsulated key, then ciphertext and tag.
pub struct Sealed {
    /// Encapsulated key.
    pub enc: [u8; ENC_LEN],
    /// AEAD ciphertext followed by its tag.
    pub ciphertext_and_tag: Vec<u8>,
}

/// The single outcome of a failed open (U6): which check failed is not reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused;

impl core::fmt::Display for Refused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HPKE open refused")
    }
}

impl std::error::Error for Refused {}

/// Whether `bytes` is the canonical encoding of an X25519 u-coordinate: bit 255 clear and
/// the value below the field prime. X25519 masks bit 255 and reduces modulo p, so a
/// non-canonical key computes the same DH output as its canonical form, but HPKE binds the
/// key's bytes into `kem_context`, where the recipient uses the canonical bytes it derives
/// from its private key: a seal to a non-canonical key never opens.
pub fn is_canonical_public_key(bytes: &[u8; ENC_LEN]) -> bool {
    for i in (0..ENC_LEN).rev() {
        if bytes[i] != FIELD_PRIME_LE[i] {
            return bytes[i] < FIELD_PRIME_LE[i];
        }
    }
    false
}

/// Derives the backup key pair from the 32-byte Argon2id output of the backup secret, with
/// RFC 9180 `DeriveKeyPair` (U4: never from a shorter input).
pub fn derive_backup_keypair(ikm: &[u8; 32]) -> (PrivateKey, PublicKey) {
    SuiteKem::derive_keypair(ikm)
}

/// Seals `plaintext` to `recipient` in base mode. `rng` must be backed by the operating system
/// generator (usage rule U3); the crate draws exactly one 32-byte ephemeral seed from it.
/// `info` must bind a value unique to this seal (U3b). A recipient key that is not canonically
/// encoded is refused with `ValidationError`.
pub fn seal<R: CryptoRng + RngCore>(
    recipient: &PublicKey,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Sealed, HpkeError> {
    let mut recipient_bytes = [0u8; ENC_LEN];
    recipient.write_exact(&mut recipient_bytes);
    if !is_canonical_public_key(&recipient_bytes) {
        return Err(HpkeError::ValidationError);
    }
    let (encapped, ciphertext_and_tag) = hpke::single_shot_seal::<SuiteAead, SuiteKdf, SuiteKem, _>(
        &OpModeS::Base,
        recipient,
        info,
        plaintext,
        aad,
        rng,
    )?;
    let mut enc = [0u8; ENC_LEN];
    encapped.write_exact(&mut enc);
    Ok(Sealed {
        enc,
        ciphertext_and_tag,
    })
}

/// Opens `ciphertext_and_tag` into `out`, which must be exactly the plaintext length. On
/// refusal the content of `out` is unspecified and the caller must zeroize it (U5). A key
/// opened here is used only after its confirmation against an independently authenticated
/// value (U10): base mode authenticates no sender.
pub fn open_into(
    recipient: &PrivateKey,
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
    out: &mut [u8],
) -> Result<(), Refused> {
    let plaintext_len = ciphertext_and_tag
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(Refused)?;
    if out.len() != plaintext_len {
        return Err(Refused);
    }
    let encapped = EncappedKey::from_bytes(enc).map_err(|_| Refused)?;
    let (ciphertext, tag_bytes) = ciphertext_and_tag.split_at(plaintext_len);
    let tag = AeadTag::<SuiteAead>::from_bytes(tag_bytes).map_err(|_| Refused)?;
    out.copy_from_slice(ciphertext);
    hpke::single_shot_open_in_place_detached::<SuiteAead, SuiteKdf, SuiteKem>(
        &OpModeR::Base,
        recipient,
        &encapped,
        info,
        out,
        aad,
        &tag,
    )
    .map_err(|_| Refused)
}
