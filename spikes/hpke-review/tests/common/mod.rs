//! Test support shared by the integration tests: hex helpers, the case generator, the queued
//! randomness that fixes the ephemeral key of both implementations, and the hpke-rs providers
//! that accept it.

// Each test binary compiles this module and uses a different subset of it.
#![allow(dead_code)]

use std::{collections::VecDeque, convert::Infallible};

use hpke_rs::{
    Hpke, Mode, hpke_types::AeadAlgorithm, hpke_types::KdfAlgorithm, hpke_types::KemAlgorithm,
};
use hpke_rs_crypto::{
    HpkeCrypto,
    error::Error,
    types::{SingleStageKdfAlgorithm, TwoStageKdfAlgorithm},
};
use hpke_rs_libcrux::HpkeLibcrux;
use hpke_rs_rust_crypto::HpkeRustCrypto;

pub fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd hex length");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digit"))
        .collect()
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Deterministic generator of test inputs (SplitMix64). It is not a cryptographic generator and
/// never stands in for one: it only chooses keys, lengths and messages so that a seed replays a
/// run exactly. The secrecy of test keys is irrelevant to agreement between implementations.
pub struct CaseRng(u64);

impl CaseRng {
    pub fn new(seed: u64) -> Self {
        CaseRng(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform enough for test lengths: a value in `low..=high`.
    pub fn between(&mut self, low: usize, high: usize) -> usize {
        let span = (high - low + 1) as u64;
        low + (self.next_u64() % span) as usize
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + 8);
        while out.len() < len {
            out.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        out.truncate(len);
        out
    }

    pub fn array32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.bytes(32));
        out
    }
}

/// Randomness that serves exactly the bytes it was loaded with, then panics. Both
/// implementations derive the HPKE ephemeral key pair as `DeriveKeyPair(32 random bytes)`, so
/// loading the same 32 bytes into each fixes the same ephemeral key, which is how the RFC 9180
/// vectors (`ikmE`) and the byte-for-byte comparison of the cross-test drive them. It is marked
/// as a cryptographic generator for the crates' trait bounds only, in tests only.
pub struct QueuedBytes(VecDeque<u8>);

impl QueuedBytes {
    pub fn new(bytes: &[u8]) -> Self {
        QueuedBytes(bytes.iter().copied().collect())
    }

    pub fn is_drained(&self) -> bool {
        self.0.is_empty()
    }

    fn serve(&mut self, dst: &mut [u8]) {
        assert!(
            dst.len() <= self.0.len(),
            "implementation drew {} random bytes, {} were queued",
            dst.len(),
            self.0.len()
        );
        for byte in dst.iter_mut() {
            *byte = self.0.pop_front().expect("length checked above");
        }
    }
}

impl hpke::rand_core::RngCore for QueuedBytes {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.serve(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.serve(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.serve(dst);
    }
}

impl hpke::rand_core::CryptoRng for QueuedBytes {}

impl hpke_rs_crypto::TryRng for QueuedBytes {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(hpke::rand_core::RngCore::next_u32(self))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(hpke::rand_core::RngCore::next_u64(self))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.serve(dst);
        Ok(())
    }
}

impl hpke_rs_crypto::TryCryptoRng for QueuedBytes {}

/// The RustCrypto provider of hpke-rs with its randomness replaced by `QueuedBytes`. Every
/// primitive is delegated unchanged to `HpkeRustCrypto`; only the source of the ephemeral seed
/// differs. The two randomized KEM entry points serve post-quantum KEMs only (DH KEMs draw
/// their seed through `Hpke::random`), so they refuse here.
#[derive(Debug)]
pub struct SeededRustCrypto;

impl HpkeCrypto for SeededRustCrypto {
    type HpkePrng = QueuedBytes;

    fn name() -> String {
        format!("{} with queued randomness", HpkeRustCrypto::name())
    }

    fn supports_kdf(alg: KdfAlgorithm) -> Result<(), Error> {
        HpkeRustCrypto::supports_kdf(alg)
    }

    fn supports_kem(alg: KemAlgorithm) -> Result<(), Error> {
        HpkeRustCrypto::supports_kem(alg)
    }

    fn supports_aead(alg: AeadAlgorithm) -> Result<(), Error> {
        HpkeRustCrypto::supports_aead(alg)
    }

    fn kdf_extract(alg: TwoStageKdfAlgorithm, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::kdf_extract(alg, salt, ikm)
    }

    fn kdf_expand(
        alg: TwoStageKdfAlgorithm,
        prk: &[u8],
        info: &[u8],
        output_size: usize,
    ) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::kdf_expand(alg, prk, info, output_size)
    }

    fn kdf_derive(alg: SingleStageKdfAlgorithm, ikm: &[u8], l: usize) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::kdf_derive(alg, ikm, l)
    }

    fn dh(alg: KemAlgorithm, pk: &[u8], sk: &[u8]) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::dh(alg, pk, sk)
    }

    fn secret_to_public(alg: KemAlgorithm, sk: &[u8]) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::secret_to_public(alg, sk)
    }

    fn kem_key_gen(
        _alg: KemAlgorithm,
        _prng: &mut Self::HpkePrng,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        Err(Error::UnsupportedKemOperation)
    }

    fn kem_key_gen_derand(alg: KemAlgorithm, seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        HpkeRustCrypto::kem_key_gen_derand(alg, seed)
    }

    fn kem_encaps(
        _alg: KemAlgorithm,
        _pk_r: &[u8],
        _prng: &mut Self::HpkePrng,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        Err(Error::UnsupportedKemOperation)
    }

    fn kem_encaps_derand(
        alg: KemAlgorithm,
        pk_r: &[u8],
        randomness: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        HpkeRustCrypto::kem_encaps_derand(alg, pk_r, randomness)
    }

    fn kem_decaps(alg: KemAlgorithm, ct: &[u8], sk_r: &[u8]) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::kem_decaps(alg, ct, sk_r)
    }

    fn dh_validate_sk(alg: KemAlgorithm, sk: &[u8]) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::dh_validate_sk(alg, sk)
    }

    fn aead_seal(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::aead_seal(alg, key, nonce, aad, msg)
    }

    fn aead_open(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, Error> {
        HpkeRustCrypto::aead_open(alg, key, nonce, aad, msg)
    }
}

/// The libcrux provider of hpke-rs, with `QueuedBytes` as its randomness: X25519, AES-GCM,
/// HKDF and SHA-256 from libcrux, outside the dalek and RustCrypto lineage of `hpke`.
pub type SeededLibcrux = HpkeLibcrux<QueuedBytes>;

/// An hpke-rs instance on provider `P` for the AD-18 suite in base mode whose next ephemeral
/// seed is `seed`.
pub fn independent_on<P: HpkeCrypto<HpkePrng = QueuedBytes> + 'static>(seed: &[u8]) -> Hpke<P> {
    Hpke::new_with_rng(
        Mode::Base,
        KemAlgorithm::DhKem25519,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::Aes256Gcm,
        QueuedBytes::new(seed),
    )
}

/// An hpke-rs instance on the RustCrypto provider; see `independent_on`.
pub fn independent(seed: &[u8]) -> Hpke<SeededRustCrypto> {
    independent_on::<SeededRustCrypto>(seed)
}

/// The public key provider `P` computes for a raw private key.
pub fn independent_public_key<P: HpkeCrypto>(sk: &[u8]) -> Vec<u8> {
    P::secret_to_public(KemAlgorithm::DhKem25519, sk).expect("X25519 public key")
}
