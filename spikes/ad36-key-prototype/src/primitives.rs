//! Thin wrappers over the AD-18 suite. Nothing here builds a primitive: HKDF, HMAC and
//! AES-256-GCM come from `aws-lc-rs`, HPKE from the `hpke` crate.

use aws_lc_rs::aead::{AES_256_GCM, Aad, NONCE_LEN, Nonce, RandomizedNonceKey};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::{constant_time, hkdf, hmac};
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::rand_core::{self, CryptoRng, RngCore};
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};

use crate::error::Error;

/// Length of every symmetric key and MAC tag in this construction.
pub const KEY_LEN: usize = 32;
/// Length of an X25519 public key and of a DHKEM(X25519) encapsulated key.
pub const X25519_LEN: usize = 32;
/// Length of an AES-256-GCM tag.
pub const AEAD_TAG_LEN: usize = 16;
/// Length of a random AES-256-GCM nonce.
pub const AEAD_NONCE_LEN: usize = NONCE_LEN;

/// The HPKE KEM of AD-18.
pub type HpkeKem = X25519HkdfSha256;
/// An X25519 private key; the `hpke` crate zeroizes it on drop.
pub type HpkePrivateKey = <HpkeKem as Kem>::PrivateKey;
type HpkePublicKey = <HpkeKem as Kem>::PublicKey;
type HpkeEncappedKey = <HpkeKem as Kem>::EncappedKey;

/// A 256-bit secret, overwritten on drop and never printed.
///
/// The overwrite goes through `black_box` so it is not elided; this is best effort
/// without `unsafe` or the `zeroize` crate, which the spike may not depend on directly.
pub struct Secret32([u8; KEY_LEN]);

impl Secret32 {
    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub(crate) fn random() -> Result<Self, Error> {
        let mut bytes = [0u8; KEY_LEN];
        SystemRandom::new().fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    pub(crate) fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl Drop for Secret32 {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&self.0);
    }
}

/// `hpke::rand_core` CSPRNG backed by the AWS-LC system generator, so HPKE key
/// generation and encapsulation draw from the same source as the rest of the Core.
pub struct SystemCsprng(SystemRandom);

impl SystemCsprng {
    pub(crate) fn new() -> Self {
        Self(SystemRandom::new())
    }
}

impl RngCore for SystemCsprng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // rand_core 0.9's infallible entry point has no error channel; continuing with an
        // unfilled buffer would produce predictable keys, so a CSPRNG failure aborts.
        if self.0.fill(dest).is_err() {
            panic!("system CSPRNG failure");
        }
    }
}

impl CryptoRng for SystemCsprng {}

struct OutputLen(usize);

impl hkdf::KeyType for OutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-SHA-256 with no salt (RFC 5869: a zero-filled salt), `info` the concatenation of
/// `info_parts`, 32 bytes of output.
pub(crate) fn hkdf_sha256(ikm: &[u8], info_parts: &[&[u8]]) -> Result<Secret32, Error> {
    let prk = hkdf::Salt::none(hkdf::HKDF_SHA256).extract(ikm);
    let mut out = Secret32([0u8; KEY_LEN]);
    prk.expand(info_parts, OutputLen(KEY_LEN))?
        .fill(&mut out.0)?;
    Ok(out)
}

pub(crate) fn hmac_sha256(key: &Secret32, data: &[u8]) -> [u8; KEY_LEN] {
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key.expose()), data);
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Constant-time HMAC-SHA-256 verification.
pub(crate) fn hmac_sha256_verify(key: &Secret32, data: &[u8], tag: &[u8]) -> bool {
    hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, key.expose()), data, tag).is_ok()
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    constant_time::verify_slices_are_equal(a, b).is_ok()
}

/// AES-256-GCM seal of a 32-byte secret with a random 96-bit nonce.
/// Returns the nonce and `ciphertext || tag`.
pub(crate) fn aead_seal(
    key: &Secret32,
    aad: &[u8],
    plaintext: &Secret32,
) -> Result<([u8; AEAD_NONCE_LEN], Vec<u8>), Error> {
    let sealing_key = RandomizedNonceKey::new(&AES_256_GCM, key.expose())?;
    let mut in_out = plaintext.expose().to_vec();
    let nonce = sealing_key.seal_in_place_append_tag(Aad::from(aad), &mut in_out)?;
    Ok((*nonce.as_ref(), in_out))
}

/// Opens what [`aead_seal`] produced; `None` when the key, nonce, AAD or ciphertext is wrong.
pub(crate) fn aead_open(
    key: &Secret32,
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Option<Secret32> {
    let opening_key = RandomizedNonceKey::new(&AES_256_GCM, key.expose()).ok()?;
    let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
    let mut in_out = ciphertext_and_tag.to_vec();
    let opened = opening_key
        .open_in_place(nonce, Aad::from(aad), &mut in_out)
        .ok()
        .and_then(|plaintext| <[u8; KEY_LEN]>::try_from(&*plaintext).ok())
        .map(Secret32);
    in_out.fill(0);
    std::hint::black_box(&in_out);
    opened
}

/// Generates an X25519 key pair; returns the private key and the public key bytes.
pub(crate) fn hpke_generate_keypair() -> (HpkePrivateKey, [u8; X25519_LEN]) {
    let (private_key, public_key) = HpkeKem::gen_keypair(&mut SystemCsprng::new());
    let mut public_bytes = [0u8; X25519_LEN];
    public_bytes.copy_from_slice(&public_key.to_bytes());
    (private_key, public_bytes)
}

pub(crate) fn hpke_public_bytes(private_key: &HpkePrivateKey) -> [u8; X25519_LEN] {
    let mut public_bytes = [0u8; X25519_LEN];
    public_bytes.copy_from_slice(&HpkeKem::sk_to_pk(private_key).to_bytes());
    public_bytes
}

/// HPKE base mode single-shot seal of a 32-byte secret.
/// Returns the encapsulated key and `ciphertext || tag`.
pub(crate) fn hpke_seal(
    recipient: &[u8; X25519_LEN],
    info: &[u8],
    aad: &[u8],
    plaintext: &Secret32,
) -> Result<([u8; X25519_LEN], Vec<u8>), Error> {
    let recipient = HpkePublicKey::from_bytes(recipient).map_err(|_| Error::Crypto)?;
    let (encapped, ciphertext) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, HpkeKem, _>(
        &OpModeS::Base,
        &recipient,
        info,
        plaintext.expose(),
        aad,
        &mut SystemCsprng::new(),
    )
    .map_err(|_| Error::Crypto)?;
    let mut encapped_bytes = [0u8; X25519_LEN];
    encapped_bytes.copy_from_slice(&encapped.to_bytes());
    Ok((encapped_bytes, ciphertext))
}

/// Opens what [`hpke_seal`] produced; `None` on any failure.
pub(crate) fn hpke_open(
    private_key: &HpkePrivateKey,
    encapped: &[u8; X25519_LEN],
    info: &[u8],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Option<Secret32> {
    let encapped = HpkeEncappedKey::from_bytes(encapped).ok()?;
    let mut plaintext = hpke::single_shot_open::<AesGcm256, HkdfSha256, HpkeKem>(
        &OpModeR::Base,
        private_key,
        &encapped,
        info,
        ciphertext_and_tag,
        aad,
    )
    .ok()?;
    let opened = <[u8; KEY_LEN]>::try_from(plaintext.as_slice())
        .ok()
        .map(Secret32);
    plaintext.fill(0);
    std::hint::black_box(&plaintext);
    opened
}
