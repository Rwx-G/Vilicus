//! The test key material: one file the harness writes with fresh random secrets and the public
//! values that go with them (wrapped DEK, HPKE-wrapped household key, member public key).
//!
//! The subject process reads each secret with `pread` straight into a locked slot, so the only
//! copies in its memory are the ones the code paths under test make. The harness keeps the
//! secrets in its own memory to compute the patterns; it is a different process.

use std::fs;
use std::io;
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use hpke::aead::{AeadTag, AesGcm256};
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::rand_core::{CryptoRng, RngCore};
use hpke::{Deserializable, OpModeS, Serializable};

/// A field of the material file: byte offset and length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    /// Offset in the file.
    pub offset: usize,
    /// Length in bytes.
    pub len: usize,
}

impl Field {
    const fn after(previous: Field, len: usize) -> Field {
        Field {
            offset: previous.offset + previous.len,
            len,
        }
    }

    /// The field's byte range.
    pub fn range(self) -> std::ops::Range<usize> {
        self.offset..self.offset + self.len
    }
}

/// A plain 256-bit key, for the copy and crash checks.
pub const KEY: Field = Field { offset: 0, len: 32 };
/// The member passphrase (random bytes; Argon2id takes any bytes).
pub const PASSPHRASE: Field = Field::after(KEY, 32);
/// The member DEK.
pub const DEK: Field = Field::after(PASSPHRASE, 32);
/// The household key.
pub const HK: Field = Field::after(DEK, 32);
/// The member's X25519 private key.
pub const MEMBER_SK: Field = Field::after(HK, 32);
/// The 32 random bytes that seed the ephemeral key of an HPKE seal.
pub const EPH_IKM: Field = Field::after(MEMBER_SK, 32);
/// Public: the DEK sealed under the passphrase KEK, ciphertext then tag.
pub const WRAPPED_DEK: Field = Field::after(EPH_IKM, 48);
/// Public: the HPKE encapsulated key of the household key wrap.
pub const HPKE_ENC: Field = Field::after(WRAPPED_DEK, 32);
/// Public: the HPKE ciphertext of the household key.
pub const HPKE_CT: Field = Field::after(HPKE_ENC, 32);
/// Public: the HPKE tag of the household key wrap.
pub const HPKE_TAG: Field = Field::after(HPKE_CT, 16);
/// Public: the member's X25519 public key.
pub const MEMBER_PK: Field = Field::after(HPKE_TAG, 32);
/// Total file length.
pub const FILE_LEN: usize = MEMBER_PK.offset + MEMBER_PK.len;

/// Argon2id memory cost in KiB: the crate default (19 MiB), not the E12 value; the question
/// here is what the buffers leave behind, not how long they take.
pub const ARGON2_M_KIB: u32 = Params::DEFAULT_M_COST;
/// Argon2id iterations.
pub const ARGON2_T: u32 = Params::DEFAULT_T_COST;
/// Argon2id lanes.
pub const ARGON2_P: u32 = Params::DEFAULT_P_COST;
/// Argon2id salt of the test wrapper.
pub const ARGON2_SALT: &[u8] = b"vilicus-e16-salt";
/// Nonce of the DEK wrap.
pub const DEK_NONCE: [u8; 12] = *b"e16-dek-wrap";
/// Associated data of the DEK wrap.
pub const DEK_AAD: &[u8] = b"vilicus/e16/dek";
/// HKDF salt of the derived file key.
pub const HKDF_SALT: &[u8] = b"vilicus/e16/hkdf-salt";
/// HKDF info of the derived file key.
pub const HKDF_INFO: &[u8] = b"vilicus/v1/partition/e16";
/// Nonce of the record sealed with the derived key.
pub const RECORD_NONCE: [u8; 12] = *b"e16-record-n";
/// HPKE info of the household key wrap.
pub const HPKE_INFO: &[u8] = b"vilicus/v1/hk-wrap";
/// HPKE associated data of the household key wrap.
pub const HPKE_AAD: &[u8] = b"e16";

/// The Argon2id instance of the passphrase KEK.
pub fn argon2() -> Argon2<'static> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(32))
        .expect("constant Argon2id parameters are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// The harness copy of the material file.
pub struct Material {
    bytes: Vec<u8>,
    /// The passphrase KEK the harness derived to wrap the DEK.
    pub kek: [u8; 32],
}

impl Material {
    /// Draws fresh secrets, derives the public values and writes the file at `path`.
    pub fn generate(path: &Path) -> io::Result<Material> {
        let mut bytes = vec![0u8; FILE_LEN];
        for field in [KEY, PASSPHRASE, DEK, HK, MEMBER_SK, EPH_IKM] {
            aws_lc_rs::rand::fill(&mut bytes[field.range()]).map_err(other)?;
        }

        let mut kek = [0u8; 32];
        argon2()
            .hash_password_into(&bytes[PASSPHRASE.range()], ARGON2_SALT, &mut kek)
            .map_err(other)?;
        let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &kek).map_err(other)?);
        let mut wrapped = bytes[DEK.range()].to_vec();
        let tag = key
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(DEK_NONCE),
                Aad::from(DEK_AAD),
                &mut wrapped,
            )
            .map_err(other)?;
        wrapped.extend_from_slice(tag.as_ref());
        bytes[WRAPPED_DEK.range()].copy_from_slice(&wrapped);

        let member_sk =
            <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(&bytes[MEMBER_SK.range()])
                .map_err(other)?;
        let member_pk = <X25519HkdfSha256 as hpke::Kem>::sk_to_pk(&member_sk);
        bytes[MEMBER_PK.range()].copy_from_slice(&member_pk.to_bytes());

        let mut seed = [0u8; 32];
        aws_lc_rs::rand::fill(&mut seed).map_err(other)?;
        let mut hk_ct = bytes[HK.range()].to_vec();
        let (enc, tag) =
            hpke::single_shot_seal_in_place_detached::<AesGcm256, HkdfSha256, X25519HkdfSha256, _>(
                &OpModeS::Base,
                &member_pk,
                HPKE_INFO,
                &mut hk_ct,
                HPKE_AAD,
                &mut SliceRng::new(&seed),
            )
            .map_err(other)?;
        bytes[HPKE_ENC.range()].copy_from_slice(&enc.to_bytes());
        bytes[HPKE_CT.range()].copy_from_slice(&hk_ct);
        bytes[HPKE_TAG.range()].copy_from_slice(&tag.to_bytes());

        fs::write(path, &bytes)?;
        Ok(Material { bytes, kek })
    }

    /// The bytes of `field`.
    pub fn get(&self, field: Field) -> &[u8] {
        &self.bytes[field.range()]
    }

    /// The bytes of `field` as a 32-byte array.
    pub fn get32(&self, field: Field) -> [u8; 32] {
        self.get(field).try_into().expect("field of 32 bytes")
    }
}

/// Parses the public HPKE values of the household key wrap.
pub fn hpke_public(
    enc: &[u8],
    tag: &[u8],
) -> Result<
    (
        <X25519HkdfSha256 as hpke::Kem>::EncappedKey,
        AeadTag<AesGcm256>,
    ),
    hpke::HpkeError,
> {
    Ok((
        <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(enc)?,
        AeadTag::<AesGcm256>::from_bytes(tag)?,
    ))
}

/// A generator that hands out the bytes of a slice, so an HPKE seal draws a known ephemeral
/// seed. Test use only: it repeats once the slice is spent.
pub struct SliceRng<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> SliceRng<'a> {
    /// A generator over `bytes`, which must not be empty.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
}

impl RngCore for SliceRng<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut word = [0u8; 4];
        self.fill_bytes(&mut word);
        u32::from_le_bytes(word)
    }

    fn next_u64(&mut self) -> u64 {
        let mut word = [0u8; 8];
        self.fill_bytes(&mut word);
        u64::from_le_bytes(word)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        for byte in destination {
            *byte = self.bytes[self.position % self.bytes.len()];
            self.position += 1;
        }
    }
}

impl CryptoRng for SliceRng<'_> {}

/// Maps any library error to an I/O error by its debug text (some of these crates implement
/// `Error` only with features this spike does not enable).
pub fn other(error: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{error:?}"))
}
