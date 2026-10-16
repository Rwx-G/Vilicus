//! The byte patterns the scan looks for, recomputed by the harness from the material file:
//! the secrets themselves and every intermediate the code paths are known or suspected to copy
//! (spikes/hpke-review/REVIEW.md, findings F1 and F2).

use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::material::{
    self, ARGON2_SALT, DEK, EPH_IKM, HK, HKDF_INFO, HKDF_SALT, HPKE_ENC, HPKE_INFO, KEY, MEMBER_PK,
    MEMBER_SK, Material, PASSPHRASE,
};

/// One pattern: a name for the report and the bytes to look for.
#[derive(Clone, PartialEq, Eq)]
pub struct Pattern {
    /// Name printed in the report.
    pub name: String,
    /// Bytes searched for.
    pub bytes: Vec<u8>,
}

fn pattern(name: impl Into<String>, bytes: impl AsRef<[u8]>) -> Pattern {
    Pattern {
        name: name.into(),
        bytes: bytes.as_ref().to_vec(),
    }
}

/// The code path a subject process runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodePath {
    /// A key held in a slot, copied to the heap and to the stack.
    Copies,
    /// Passphrase to KEK (Argon2id), DEK unwrap and re-wrap (aws-lc-rs AES-256-GCM).
    Passphrase,
    /// File key derivation (aws-lc-rs HKDF-SHA-256) and a record sealed with it.
    Hkdf,
    /// Household key unwrap: HPKE open with the member private key.
    HpkeOpen,
    /// Household key wrap: HPKE seal to the member public key.
    HpkeSeal,
}

impl CodePath {
    /// Every path, in report order.
    pub const ALL: [CodePath; 5] = [
        CodePath::Copies,
        CodePath::Passphrase,
        CodePath::Hkdf,
        CodePath::HpkeOpen,
        CodePath::HpkeSeal,
    ];

    /// Name used on the command line and in the report.
    pub fn name(self) -> &'static str {
        match self {
            CodePath::Copies => "copies",
            CodePath::Passphrase => "passphrase",
            CodePath::Hkdf => "hkdf",
            CodePath::HpkeOpen => "hpke-open",
            CodePath::HpkeSeal => "hpke-seal",
        }
    }

    /// The path named `name`.
    pub fn from_name(name: &str) -> Option<CodePath> {
        CodePath::ALL.into_iter().find(|path| path.name() == name)
    }

    /// The patterns the path holds in locked slots while it is live: the positive control.
    pub fn held(self, m: &Material) -> Vec<Pattern> {
        match self {
            CodePath::Copies => vec![pattern("key", m.get(KEY))],
            CodePath::Passphrase => vec![
                pattern("passphrase", m.get(PASSPHRASE)),
                pattern("kek", m.kek),
                pattern("dek", m.get(DEK)),
            ],
            CodePath::Hkdf => vec![pattern("dek", m.get(DEK)), pattern("file-key", hkdf_okm(m))],
            CodePath::HpkeOpen => vec![
                pattern("member-sk", m.get(MEMBER_SK)),
                pattern("hk", m.get(HK)),
            ],
            CodePath::HpkeSeal => {
                vec![pattern("eph-ikm", m.get(EPH_IKM)), pattern("hk", m.get(HK))]
            }
        }
    }

    /// Every pattern of the path: the held secrets and the intermediates.
    pub fn all(self, m: &Material) -> Vec<Pattern> {
        let mut patterns = self.held(m);
        match self {
            CodePath::Copies => {}
            CodePath::Passphrase => {
                let (first, last) = argon2_blocks(m);
                patterns.push(pattern("argon2-first-block", first));
                patterns.push(pattern("argon2-last-block", last));
                patterns.extend(gcm_h_patterns("kek", &m.kek));
            }
            CodePath::Hkdf => {
                let prk = hkdf_prk(m);
                patterns.push(pattern("hkdf-prk", prk));
                patterns.extend(hmac_state_patterns("hkdf-prk", &prk));
                patterns.extend(gcm_h_patterns("file-key", &hkdf_okm(m)));
            }
            CodePath::HpkeOpen => {
                let sk = m.get32(MEMBER_SK);
                patterns.extend(scalar_patterns("member-sk", &sk));
                let enc: [u8; 32] = m.get32(HPKE_ENC);
                let dh = x25519_dalek::x25519(sk, enc);
                patterns.extend(hpke_schedule_patterns(&dh, &enc, &m.get32(MEMBER_PK)));
            }
            CodePath::HpkeSeal => {
                let ikm = m.get32(EPH_IKM);
                let dkp_prk = labeled_extract(&kem_suite(), b"", b"dkp_prk", &ikm);
                patterns.push(pattern("eph-dkp-prk", dkp_prk));
                patterns.extend(hmac_state_patterns("eph-dkp-prk", &dkp_prk));
                let eph_sk = ephemeral_sk(&ikm);
                patterns.push(pattern("eph-sk", eph_sk));
                patterns.extend(scalar_patterns("eph-sk", &eph_sk));
                let enc = x25519_dalek::x25519(eph_sk, x25519_dalek::X25519_BASEPOINT_BYTES);
                let pk_r = m.get32(MEMBER_PK);
                let dh = x25519_dalek::x25519(eph_sk, pk_r);
                patterns.extend(hpke_schedule_patterns(&dh, &enc, &pk_r));
            }
        }
        patterns
    }
}

/// The encapsulated key an HPKE seal seeded with `ikm` produces (public).
pub fn expected_enc(ikm: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(ephemeral_sk(ikm), x25519_dalek::X25519_BASEPOINT_BYTES)
}

/// RFC 9180 DeriveKeyPair for DHKEM(X25519, HKDF-SHA256).
pub fn ephemeral_sk(ikm: &[u8; 32]) -> [u8; 32] {
    let dkp_prk = labeled_extract(&kem_suite(), b"", b"dkp_prk", ikm);
    labeled_expand32(&kem_suite(), &dkp_prk, b"sk", b"")
}

/// The HPKE key schedule values of base mode, in the AD-18 suite, with their names.
pub struct HpkeSchedule {
    /// `eae_prk` of ExtractAndExpand.
    pub eae_prk: [u8; 32],
    /// The KEM shared secret.
    pub shared_secret: [u8; 32],
    /// The key schedule `secret`.
    pub secret: [u8; 32],
    /// The AEAD key.
    pub key: [u8; 32],
    /// The AEAD base nonce.
    pub base_nonce: [u8; 12],
    /// The exporter secret.
    pub exporter_secret: [u8; 32],
}

/// Runs DHKEM ExtractAndExpand and the base-mode key schedule on a DH output.
pub fn hpke_schedule(dh: &[u8; 32], enc: &[u8; 32], pk_r: &[u8; 32]) -> HpkeSchedule {
    let kem = kem_suite();
    let eae_prk = labeled_extract(&kem, b"", b"eae_prk", dh);
    let kem_context = [enc.as_slice(), pk_r.as_slice()].concat();
    let shared_secret = labeled_expand32(&kem, &eae_prk, b"shared_secret", &kem_context);

    let hpke = hpke_suite();
    let psk_id_hash = labeled_extract(&hpke, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(&hpke, b"", b"info_hash", HPKE_INFO);
    let ks_context = [&[0u8][..], &psk_id_hash, &info_hash].concat();
    let secret = labeled_extract(&hpke, &shared_secret, b"secret", b"");
    let key = labeled_expand32(&hpke, &secret, b"key", &ks_context);
    let mut base_nonce = [0u8; 12];
    labeled_expand(&hpke, &secret, b"base_nonce", &ks_context, &mut base_nonce);
    let exporter_secret = labeled_expand32(&hpke, &secret, b"exp", &ks_context);
    HpkeSchedule {
        eae_prk,
        shared_secret,
        secret,
        key,
        base_nonce,
        exporter_secret,
    }
}

fn hpke_schedule_patterns(dh: &[u8; 32], enc: &[u8; 32], pk_r: &[u8; 32]) -> Vec<Pattern> {
    let s = hpke_schedule(dh, enc, pk_r);
    let mut patterns = vec![
        pattern("dh", dh),
        pattern("eae-prk", s.eae_prk),
        pattern("shared-secret", s.shared_secret),
        pattern("ks-secret", s.secret),
        pattern("aead-key", s.key),
        pattern("base-nonce", s.base_nonce),
        pattern("exporter-secret", s.exporter_secret),
    ];
    patterns.extend(hmac_state_patterns("eae-prk", &s.eae_prk));
    patterns.extend(hmac_state_patterns("ks-secret", &s.secret));
    patterns.extend(gcm_h_patterns("aead-key", &s.key));
    patterns
}

fn kem_suite() -> Vec<u8> {
    [&b"KEM"[..], &[0x00, 0x20]].concat()
}

fn hpke_suite() -> Vec<u8> {
    [&b"HPKE"[..], &[0x00, 0x20], &[0x00, 0x01], &[0x00, 0x02]].concat()
}

fn labeled_extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let labeled = [&b"HPKE-v1"[..], suite, label, ikm].concat();
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &labeled);
    prk.into()
}

fn labeled_expand(suite: &[u8], prk: &[u8; 32], label: &[u8], info: &[u8], out: &mut [u8]) {
    let length = u16::try_from(out.len())
        .expect("short output")
        .to_be_bytes();
    let labeled = [&length[..], b"HPKE-v1", suite, label, info].concat();
    Hkdf::<Sha256>::from_prk(prk)
        .expect("32-byte PRK")
        .expand(&labeled, out)
        .expect("short output");
}

fn labeled_expand32(suite: &[u8], prk: &[u8; 32], label: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    labeled_expand(suite, prk, label, info, &mut out);
    out
}

/// HKDF-Extract of the file key derivation.
pub fn hkdf_prk(m: &Material) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(HKDF_SALT), m.get(DEK));
    prk.into()
}

/// The derived file key.
pub fn hkdf_okm(m: &Material) -> [u8; 32] {
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(Some(HKDF_SALT), m.get(DEK))
        .expand(HKDF_INFO, &mut okm)
        .expect("32-byte output");
    okm
}

/// The X25519 scalar forms of a private key that curve25519-dalek computes: the clamped
/// scalar, and its signed radix-16 digits used by the fixed-base multiplication.
fn scalar_patterns(name: &str, sk: &[u8; 32]) -> Vec<Pattern> {
    let clamped = clamp(sk);
    vec![
        pattern(format!("{name}-clamped"), clamped),
        pattern(format!("{name}-radix16"), radix16(&clamped)),
    ]
}

fn clamp(sk: &[u8; 32]) -> [u8; 32] {
    let mut s = *sk;
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
    s
}

/// Same algorithm as curve25519-dalek 4.1.3 `Scalar::as_radix_16`, which is crate-private.
fn radix16(scalar: &[u8; 32]) -> [u8; 64] {
    let mut digits = [0i8; 64];
    for (i, byte) in scalar.iter().enumerate() {
        digits[2 * i] = (byte & 15) as i8;
        digits[2 * i + 1] = ((byte >> 4) & 15) as i8;
    }
    for i in 0..63 {
        let carry = (digits[i] + 8) >> 4;
        digits[i] -= carry << 4;
        digits[i + 1] += carry;
    }
    digits.map(|d| d as u8)
}

/// The GHASH key H = AES-256(key, 0^128) of an AES-GCM key, as stored raw and in the POLYVAL
/// form the RustCrypto `ghash` crate keeps (`mulX_POLYVAL(byte-reverse(H))`).
fn gcm_h_patterns(name: &str, key: &[u8; 32]) -> Vec<Pattern> {
    let cipher = Aes256::new(key.into());
    let mut h = aes::Block::default();
    cipher.encrypt_block(&mut h);
    let mut reversed = h;
    reversed.reverse();
    let polyval_h = polyval::mulx(&reversed);
    vec![
        pattern(format!("{name}-gcm-h"), h),
        pattern(format!("{name}-gcm-h-polyval"), polyval_h),
    ]
}

/// The two SHA-256 states an HMAC keyed with `key` keeps (after the ipad and the opad block),
/// as native-endian words. Each one lets its holder compute HMAC under the key, so each is
/// worth as much as the key.
fn hmac_state_patterns(name: &str, key: &[u8; 32]) -> Vec<Pattern> {
    let state = |pad: u8| {
        let mut block = [pad; 64];
        for (b, k) in block.iter_mut().zip(key) {
            *b ^= k;
        }
        let mut words = SHA256_IV;
        sha2::compress256(&mut words, &[block.into()]);
        words
            .iter()
            .flat_map(|w| w.to_ne_bytes())
            .collect::<Vec<u8>>()
    };
    vec![
        pattern(format!("{name}-hmac-ipad"), state(0x36)),
        pattern(format!("{name}-hmac-opad"), state(0x5c)),
    ]
}

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

/// The first 64 bytes of the first and of the last Argon2id memory block of the passphrase KEK.
pub fn argon2_blocks(m: &Material) -> (Vec<u8>, Vec<u8>) {
    // `fill_memory` hashes a zero output length into H0, so it fills different blocks; the
    // blocks of the KEK come from the same call the Core makes.
    let mut blocks = vec![argon2::Block::default(); material::ARGON2_M_KIB as usize];
    let mut kek = [0u8; 32];
    material::argon2()
        .hash_password_into_with_memory(m.get(PASSPHRASE), ARGON2_SALT, &mut kek, &mut blocks)
        .expect("valid Argon2id inputs");
    let head = |block: &argon2::Block| {
        block.as_ref()[..8]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect::<Vec<u8>>()
    };
    let first = head(&blocks[0]);
    let last = head(blocks.last().expect("non-empty"));
    (first, last)
}
