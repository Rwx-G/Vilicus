//! The CPU-heavy work the blocking pool runs: the unlock (Argon2id, AES-256-GCM unwrap, the
//! HPKE open of the household key, HKDF file keys) and the backup's key sealing.
//!
//! "HPKE-shaped" means the operations HPKE base mode performs (an X25519 agreement with an
//! ephemeral key, HKDF-SHA-256, AES-256-GCM), composed here from aws-lc-rs without the RFC 9180
//! key schedule. It stands in for the `hpke` crate's cost only; it is load, not a construction.

use argon2::{Algorithm, Argon2, Params, Version};
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
use aws_lc_rs::encoding::{AsBigEndian, Curve25519SeedBin};
use aws_lc_rs::hkdf::{HKDF_SHA256, Salt};
use aws_lc_rs::rand;

/// Argon2id cost parameters.
#[derive(Clone, Copy, Debug)]
pub struct Argon2Cost {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl std::fmt::Display for Argon2Cost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "m={} MiB, t={}, p={}", self.m_kib / 1024, self.t, self.p)
    }
}

/// Random bytes from the aws-lc-rs system RNG.
pub fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    rand::fill(&mut bytes).expect("the system RNG is available");
    bytes
}

/// HKDF-SHA-256 with a domain label as `info`, as `doc/key-management.md` section 2 derives
/// file keys.
pub fn hkdf(ikm: &[u8], info: &str) -> [u8; 32] {
    let mut out = [0; 32];
    Salt::new(HKDF_SHA256, &[])
        .extract(ikm)
        .expand(&[info.as_bytes()], HKDF_SHA256)
        .and_then(|okm| okm.fill(&mut out))
        .expect("32 bytes is a valid HKDF-SHA-256 output length");
    out
}

fn aead_key(key: &[u8; 32]) -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).expect("a 32-byte AES-256 key"))
}

/// AES-256-GCM with a random nonce; returns nonce || ciphertext || tag.
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let nonce = random::<NONCE_LEN>();
    let mut sealed = plaintext.to_vec();
    aead_key(key)
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::empty(),
            &mut sealed,
        )
        .expect("sealing a short buffer succeeds");
    let mut out = nonce.to_vec();
    out.extend_from_slice(&sealed);
    out
}

/// Opens what [`seal`] produced.
pub fn open(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, String> {
    if sealed.len() < NONCE_LEN {
        return Err("sealed value too short".into());
    }
    let (nonce, body) = sealed.split_at(NONCE_LEN);
    let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| "bad nonce".to_owned())?;
    let mut buffer = body.to_vec();
    let plaintext = aead_key(key)
        .open_in_place(nonce, Aad::empty(), &mut buffer)
        .map_err(|_| "authentication failed".to_owned())?;
    Ok(plaintext.to_vec())
}

/// Seals `plaintext` to an X25519 public key, HPKE-shaped: ephemeral public key || sealed.
pub fn seal_to(recipient_public: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let ephemeral = PrivateKey::generate(&X25519).expect("X25519 key generation");
    let ephemeral_public = ephemeral
        .compute_public_key()
        .expect("X25519 public key")
        .as_ref()
        .to_vec();
    let key = agreement::agree(
        &ephemeral,
        UnparsedPublicKey::new(&X25519, recipient_public),
        "agreement failed",
        |shared| Ok(hkdf(shared, "spike/e32/hpke-shaped")),
    )
    .expect("agreement with a valid X25519 public key");
    let mut out = ephemeral_public;
    out.extend_from_slice(&seal(&key, plaintext));
    out
}

/// Opens what [`seal_to`] produced with the recipient's private key.
pub fn open_with(recipient: &PrivateKey, sealed: &[u8]) -> Result<Vec<u8>, String> {
    if sealed.len() < 32 {
        return Err("sealed value too short".into());
    }
    let (ephemeral_public, body) = sealed.split_at(32);
    let key = agreement::agree(
        recipient,
        UnparsedPublicKey::new(&X25519, ephemeral_public),
        "agreement failed".to_owned(),
        |shared| Ok(hkdf(shared, "spike/e32/hpke-shaped")),
    )?;
    open(&key, body)
}

/// Argon2id with the lanes computed on the calling thread (no `parallel` feature).
pub fn derive_kek(cost: Argon2Cost, passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], String> {
    let params = Params::new(cost.m_kib, cost.t, cost.p, Some(32)).map_err(|e| e.to_string())?;
    let mut kek = [0; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, &mut kek)
        .map_err(|e| e.to_string())?;
    Ok(kek)
}

/// What the Core stores for one member: the passphrase wrapper of the DEK, the member's X25519
/// private key wrapped under the DEK, and the household key sealed to that key (AD-36 shape).
pub struct MemberWrappers {
    pub salt: [u8; 16],
    pub wrapped_dek: Vec<u8>,
    pub wrapped_private_key: Vec<u8>,
    pub sealed_household_key: Vec<u8>,
}

/// The keys an unlock recovers.
pub struct UnlockedKeys {
    pub dek: [u8; 32],
    pub household_key: [u8; 32],
}

/// Enrolls a member: a fresh DEK and X25519 key pair, wrapped under the passphrase KEK.
pub fn enroll(
    cost: Argon2Cost,
    passphrase: &[u8],
    household_key: &[u8; 32],
) -> Result<(MemberWrappers, [u8; 32]), String> {
    let salt = random::<16>();
    let kek = derive_kek(cost, passphrase, &salt)?;
    let dek = random::<32>();
    let private_key = PrivateKey::generate(&X25519).map_err(|_| "X25519 key generation")?;
    let public_key = private_key
        .compute_public_key()
        .map_err(|_| "X25519 public key")?;
    let seed: Curve25519SeedBin<'_> = private_key
        .as_be_bytes()
        .map_err(|_| "X25519 private key bytes")?;
    Ok((
        MemberWrappers {
            salt,
            wrapped_dek: seal(&kek, &dek),
            wrapped_private_key: seal(&dek, seed.as_ref()),
            sealed_household_key: seal_to(public_key.as_ref(), household_key),
        },
        dek,
    ))
}

/// One unlock: Argon2id, then the DEK, the member's private key and the household key.
pub fn unlock(
    cost: Argon2Cost,
    passphrase: &[u8],
    wrappers: &MemberWrappers,
) -> Result<UnlockedKeys, String> {
    let kek = derive_kek(cost, passphrase, &wrappers.salt)?;
    let dek: [u8; 32] = open(&kek, &wrappers.wrapped_dek)?
        .try_into()
        .map_err(|_| "DEK length")?;
    let seed = open(&dek, &wrappers.wrapped_private_key)?;
    let private_key =
        PrivateKey::from_private_key(&X25519, &seed).map_err(|_| "X25519 private key")?;
    let household_key: [u8; 32] = open_with(&private_key, &wrappers.sealed_household_key)?
        .try_into()
        .map_err(|_| "household key length")?;
    Ok(UnlockedKeys { dek, household_key })
}
