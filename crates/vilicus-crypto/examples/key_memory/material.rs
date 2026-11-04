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

/// The planted key of `field`, read into a slot of the pool.
pub fn planted(file: &fs::File, field: Field) -> io::Result<SymmetricKey> {
    testing::key_from_file(file, field.0)
}

/// Lowercase hex of `bytes`, as SQLCipher's raw key text writes a key.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The patterns of SQLCipher's raw key text of `key`: its 64 hex digits, and the whole text.
pub fn key_text(key: &[u8; SECRET_LEN]) -> Vec<Pattern> {
    let digits = hex(key);
    vec![
        pattern("key-hex", digits.as_bytes()),
        pattern("key-text", format!("x'{digits}'").as_bytes()),
    ]
}

// The HMAC states below are search patterns, recomputed from the planted secrets the way the
// spike did (spikes/locked-memory/src/patterns.rs, from the sha2 crate's `compress256`, which the
// workspace does not vendor). The SHA-256 compression function here is the scanner's, never used
// to protect anything; `sha256_compression_agrees_with_aws_lc` checks it against aws-lc-rs on
// each run, and the harness fails when they disagree.

const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// One SHA-256 compression of `block` into `state`.
fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0_u32; 64];
    for (index, word) in block.as_chunks::<4>().0.iter().enumerate() {
        w[index] = u32::from_be_bytes(*word);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choice = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(choice)
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(majority);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (word, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *word = word.wrapping_add(value);
    }
}

/// Whether [`compress`], over the padded blocks of a two-block message, gives the digest
/// aws-lc-rs computes for it: the check that the HMAC state patterns are the states SHA-256
/// keeps.
pub fn sha256_compression_agrees_with_aws_lc() -> bool {
    let message: Vec<u8> = (0..100_u8).collect();
    let mut padded = message.clone();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&(message.len() as u64 * 8).to_be_bytes());
    let mut state = SHA256_IV;
    for block in padded.as_chunks::<64>().0 {
        compress(&mut state, block);
    }
    let ours: Vec<u8> = state.iter().flat_map(|word| word.to_be_bytes()).collect();
    ours == aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &message).as_ref()
}

/// The two SHA-256 states an HMAC keyed with `key` keeps, after its ipad and its opad block, as
/// native-endian words: each lets its holder compute HMAC under the key.
pub fn hmac_states(key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let state = |pad: u8| {
        let mut block = [pad; 64];
        for (byte, key_byte) in block.iter_mut().zip(key) {
            *byte ^= key_byte;
        }
        let mut words = SHA256_IV;
        compress(&mut words, &block);
        words
            .iter()
            .flat_map(|word| word.to_ne_bytes())
            .collect::<Vec<u8>>()
    };
    (state(0x36), state(0x5c))
}

/// The inner digest of HKDF-Extract with no salt, SHA-256 of the ipad block of an empty key then
/// `ikm`: with the opad state, it gives the PRK.
pub fn extract_inner(ikm: &[u8; SECRET_LEN]) -> Vec<u8> {
    let mut data = vec![0x36_u8; 64];
    data.extend_from_slice(ikm);
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &data)
        .as_ref()
        .to_vec()
}
