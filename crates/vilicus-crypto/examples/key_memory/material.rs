//! The planted material: one file of fresh random secrets the harness writes for each run, and
//! the patterns it recomputes from them. The subject reads each secret straight into a slot of
//! its pool, so the only copies in its memory are those the code under test makes.

use std::fs;
use std::io;
use std::path::Path;

use aws_lc_rs::cipher::{AES_256, EncryptingKey, UnboundCipherKey};
use aws_lc_rs::hmac;
use vilicus_crypto::{Label, SymmetricKey, derive_key, label, testing};

/// A secret of the material file: its byte offset; every secret is 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field(pub u64);

/// A key held and dropped, for the copy, crash and signal paths.
pub const KEY: Field = Field(0);
/// A key encryption key.
pub const KEK: Field = Field(32);
/// The key wrapped under [`KEK`].
pub const DEK: Field = Field(64);
/// The parent of a derivation.
pub const PARENT: Field = Field(96);
/// Bytes kept in ordinary heap memory as the control of the fork and core dump checks; not a key.
pub const MARKER: Field = Field(128);
const FILE_LEN: usize = 160;
const SECRET_LEN: usize = 32;

/// The label and context of the derivation the subject runs.
pub const DERIVE_LABEL: Label = label!("vilicus/v1/test/key-memory");
pub const DERIVE_CONTEXT: &[u8] = b"key-memory";

/// One pattern: a name for the report and the bytes to look for.
#[derive(Clone, PartialEq, Eq)]
pub struct Pattern {
    pub name: String,
    pub bytes: Vec<u8>,
}

pub fn pattern(name: impl Into<String>, bytes: impl AsRef<[u8]>) -> Pattern {
    Pattern {
        name: name.into(),
        bytes: bytes.as_ref().to_vec(),
    }
}

/// The harness's copy of the material.
pub struct Material {
    bytes: Vec<u8>,
}

impl Material {
    /// Draws fresh secrets and writes them to `path`.
    pub fn generate(path: &Path) -> io::Result<Material> {
        let mut bytes = vec![0_u8; FILE_LEN];
        aws_lc_rs::rand::fill(&mut bytes).map_err(other)?;
        fs::write(path, &bytes)?;
        Ok(Material { bytes })
    }

    pub fn get(&self, field: Field) -> [u8; SECRET_LEN] {
        let start = usize::try_from(field.0).expect("small offset");
        self.bytes[start..start + SECRET_LEN]
            .try_into()
            .expect("32 bytes")
    }

    /// The key `vilicus_crypto::derive_key` derives from [`PARENT`], computed by the crate in the
    /// harness's own pool, which the caller has locked.
    pub fn derived(&self, path: &Path) -> io::Result<[u8; SECRET_LEN]> {
        let file = fs::File::open(path)?;
        let parent = testing::key_from_file(&file, PARENT.0)?;
        let child = derive_key(&parent, DERIVE_LABEL, &[DERIVE_CONTEXT]).map_err(other)?;
        testing::with_key(&child, |bytes| *bytes).map_err(other)
    }
}

/// The patterns of an AES-256-GCM key `name`: the key, and its GHASH key H = AES-256(key, 0^128),
/// raw and in the POLYVAL form a GCM implementation keeps (`mulX_POLYVAL(byte-reverse(H))`).
pub fn aead_key(name: &str, key: &[u8; SECRET_LEN]) -> io::Result<Vec<Pattern>> {
    let mut h = [0_u8; 16];
    EncryptingKey::ecb(UnboundCipherKey::new(&AES_256, key).map_err(other)?)
        .map_err(other)?
        .encrypt(&mut h)
        .map_err(other)?;
    let mut reversed = h;
    reversed.reverse();
    Ok(vec![
        pattern(name, key),
        pattern(format!("{name}-gcm-h"), h),
        pattern(format!("{name}-gcm-h-polyval"), polyval_mulx(reversed)),
    ])
}

/// Multiplication by x in POLYVAL's field, as GHASH implementations store their key.
fn polyval_mulx(block: [u8; 16]) -> [u8; 16] {
    let value = u128::from_le_bytes(block);
    let high = value >> 127;
    let shifted = (value << 1) ^ high ^ (high << 127) ^ (high << 126) ^ (high << 121);
    shifted.to_le_bytes()
}

/// The pseudorandom key HKDF-SHA-256 extracts from `ikm` with no salt: HMAC-SHA-256 under a key
/// of zeroes, which an empty key is.
pub fn hkdf_prk(ikm: &[u8; SECRET_LEN]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, &[]);
    hmac::sign(&key, ikm).as_ref().to_vec()
}

pub fn other(error: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{error:?}"))
}

/// A planted secret in ordinary heap memory, for the default shape: at offset 32 of a 64-byte
/// allocation, so that the allocator's free-list pointers, written over the first 16 bytes of a
/// freed chunk, do not hide it.
pub fn plain_copy(secret: &[u8; SECRET_LEN]) -> Vec<u8> {
    let mut heap = vec![0_u8; 64];
    heap[32..].copy_from_slice(secret);
    heap
}

/// The planted key of `field`, read into a slot of the pool.
pub fn planted(file: &fs::File, field: Field) -> io::Result<SymmetricKey> {
    testing::key_from_file(file, field.0)
}
