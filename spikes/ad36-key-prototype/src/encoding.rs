//! Versioned encodings of every stored value (key-management section 9) and of the MAC
//! input. Each stored field starts with `format_version u8, alg_id u8`; a field whose
//! version or algorithm differs from the one expected at that position is refused, so a
//! stored value can never be downgraded or reinterpreted.

use crate::error::Error;
use crate::primitives::{AEAD_NONCE_LEN, AEAD_TAG_LEN, KEY_LEN, X25519_LEN};

/// Format version of every stored value written by this build.
pub const FORMAT_VERSION: u8 = 1;

/// Algorithm identifiers, one byte each, naming the whole suite a stored value uses.
pub mod alg {
    /// Token check hash: HKDF-SHA-256 of the token, 32 bytes.
    pub const TOKEN_CHECK_HKDF_SHA256: u8 = 0x01;
    /// Key wrap: AES-256-GCM, random 96-bit nonce, key from HKDF-SHA-256.
    pub const WRAP_AES256GCM_HKDF_SHA256: u8 = 0x02;
    /// MAC: HMAC-SHA-256, key from HKDF-SHA-256.
    pub const MAC_HMAC_SHA256_HKDF_SHA256: u8 = 0x03;
    /// Public key of the HPKE KEM DHKEM(X25519, HKDF-SHA256).
    pub const PUBLIC_KEY_X25519: u8 = 0x04;
    /// HPKE base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM (RFC 9180).
    pub const HPKE_BASE_X25519_SHA256_AES256GCM: u8 = 0x05;

    /// Every identifier above, for tests that hold the documentation to the code.
    pub const ALL: [u8; 5] = [
        TOKEN_CHECK_HKDF_SHA256,
        WRAP_AES256GCM_HKDF_SHA256,
        MAC_HMAC_SHA256_HKDF_SHA256,
        PUBLIC_KEY_X25519,
        HPKE_BASE_X25519_SHA256_AES256GCM,
    ];
}

/// Domain labels. Each derivation appends its context after the label.
pub mod label {
    /// `HKDF(token, label || member_id)`: enrollment authentication key.
    pub const ENROLL_AUTH: &[u8] = b"vilicus/v1/enroll-auth/";
    /// `HKDF(token, label || member_id)`: check hash kept to verify the token.
    pub const ENROLL_TOKEN_CHECK: &[u8] = b"vilicus/v1/enroll-token-check/";
    /// `HKDF(HK, label || member_id || hk_version)`: key wrapping the enrollment
    /// authentication key.
    pub const HK_ENROLL_WRAP: &[u8] = b"vilicus/v1/hk/enroll-wrap/";
    /// `HKDF(HK, label || member_id || hk_version)`: permanent public key MAC key.
    pub const PUBKEY_MAC: &[u8] = b"vilicus/v1/pubkey-mac/";
    /// HPKE `info` of the household key wrap: `label || member_id || hk_version`.
    pub const HK_WRAP: &[u8] = b"vilicus/v1/hk/wrap/";

    /// Every label above, for tests that hold the documentation to the code.
    pub const ALL: [&[u8]; 5] = [
        ENROLL_AUTH,
        ENROLL_TOKEN_CHECK,
        HK_ENROLL_WRAP,
        PUBKEY_MAC,
        HK_WRAP,
    ];
}

const HEADER_LEN: usize = 2;
const HK_VERSION_LEN: usize = 4;

fn header(alg_id: u8) -> [u8; HEADER_LEN] {
    [FORMAT_VERSION, alg_id]
}

fn check_header(bytes: &[u8], alg_id: u8, expected_len: usize) -> Result<&[u8], Error> {
    if bytes.len() < HEADER_LEN {
        return Err(Error::MalformedStore("field shorter than its header"));
    }
    if bytes[..HEADER_LEN] != header(alg_id) {
        return Err(Error::UnsupportedFormat);
    }
    if bytes.len() != expected_len {
        return Err(Error::MalformedStore(
            "field length does not match its algorithm",
        ));
    }
    Ok(&bytes[HEADER_LEN..])
}

fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    out
}

/// A 32-byte value tagged with one algorithm: token check hash, public key, enrollment tag.
#[derive(Clone, PartialEq, Eq)]
pub struct Tagged32 {
    pub(crate) alg_id: u8,
    pub(crate) value: [u8; KEY_LEN],
}

impl Tagged32 {
    pub(crate) const ENCODED_LEN: usize = HEADER_LEN + KEY_LEN;

    pub(crate) fn new(alg_id: u8, value: [u8; KEY_LEN]) -> Self {
        Self { alg_id, value }
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        [&header(self.alg_id)[..], &self.value].concat()
    }

    pub(crate) fn decode(bytes: &[u8], alg_id: u8) -> Result<Self, Error> {
        let body = check_header(bytes, alg_id, Self::ENCODED_LEN)?;
        Ok(Self::new(alg_id, array(body)))
    }
}

/// The enrollment authentication key wrapped under a key derived from HK, bound to the HK
/// version that keys it.
#[derive(Clone)]
pub struct EnrollKeyWrap {
    pub(crate) hk_version: u32,
    pub(crate) nonce: [u8; AEAD_NONCE_LEN],
    pub(crate) ciphertext: Vec<u8>,
}

impl EnrollKeyWrap {
    pub(crate) const ENCODED_LEN: usize =
        HEADER_LEN + HK_VERSION_LEN + AEAD_NONCE_LEN + KEY_LEN + AEAD_TAG_LEN;
    const ALG: u8 = alg::WRAP_AES256GCM_HKDF_SHA256;

    /// AES-GCM additional data: the field header, the HK version and the member identifier,
    /// so a wrap copied onto another record, relabelled to another HK version or
    /// reinterpreted under another algorithm fails to open.
    pub(crate) fn aad(hk_version: u32, member_id: &[u8]) -> Vec<u8> {
        [&header(Self::ALG)[..], &hk_version.to_be_bytes(), member_id].concat()
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        [
            &header(Self::ALG)[..],
            &self.hk_version.to_be_bytes(),
            &self.nonce,
            &self.ciphertext,
        ]
        .concat()
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let body = check_header(bytes, Self::ALG, Self::ENCODED_LEN)?;
        let (version, rest) = body.split_at(HK_VERSION_LEN);
        Ok(Self {
            hk_version: u32::from_be_bytes(array(version)),
            nonce: array(&rest[..AEAD_NONCE_LEN]),
            ciphertext: rest[AEAD_NONCE_LEN..].to_vec(),
        })
    }
}

/// The permanent public key MAC, bound to the HK version that keys it.
#[derive(Clone, PartialEq, Eq)]
pub struct PubkeyMac {
    pub(crate) hk_version: u32,
    pub(crate) tag: [u8; KEY_LEN],
}

impl PubkeyMac {
    pub(crate) const ENCODED_LEN: usize = HEADER_LEN + HK_VERSION_LEN + KEY_LEN;
    const ALG: u8 = alg::MAC_HMAC_SHA256_HKDF_SHA256;

    pub(crate) fn encode(&self) -> Vec<u8> {
        [
            &header(Self::ALG)[..],
            &self.hk_version.to_be_bytes(),
            &self.tag,
        ]
        .concat()
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let body = check_header(bytes, Self::ALG, Self::ENCODED_LEN)?;
        Ok(Self {
            hk_version: u32::from_be_bytes(array(&body[..HK_VERSION_LEN])),
            tag: array(&body[HK_VERSION_LEN..]),
        })
    }
}

/// HK sealed with HPKE to a member public key.
#[derive(Clone)]
pub struct HkWrap {
    pub(crate) hk_version: u32,
    pub(crate) encapped: [u8; X25519_LEN],
    pub(crate) ciphertext: Vec<u8>,
}

impl HkWrap {
    pub(crate) const ENCODED_LEN: usize =
        HEADER_LEN + HK_VERSION_LEN + X25519_LEN + KEY_LEN + AEAD_TAG_LEN;
    const ALG: u8 = alg::HPKE_BASE_X25519_SHA256_AES256GCM;

    pub(crate) fn encode(&self) -> Vec<u8> {
        [
            &header(Self::ALG)[..],
            &self.hk_version.to_be_bytes(),
            &self.encapped,
            &self.ciphertext,
        ]
        .concat()
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let body = check_header(bytes, Self::ALG, Self::ENCODED_LEN)?;
        Ok(Self {
            hk_version: u32::from_be_bytes(array(&body[..HK_VERSION_LEN])),
            encapped: array(&body[HK_VERSION_LEN..HK_VERSION_LEN + X25519_LEN]),
            ciphertext: body[HK_VERSION_LEN + X25519_LEN..].to_vec(),
        })
    }
}

/// Appends `len u16 big-endian || bytes`.
pub(crate) fn put_length_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    let len = u16::try_from(bytes.len())
        .map_err(|_| Error::MalformedStore("field longer than a u16 length prefix"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Canonical MAC input shared by the enrollment tag and the permanent MAC:
/// `member_id || member_pk || inbox_pk`, each length-prefixed, the public keys in their
/// stored encoding (format version and algorithm included), so field boundaries and
/// algorithm identifiers cannot shift under the MAC.
pub(crate) fn mac_input(
    member_id: &[u8],
    member_pk: &Tagged32,
    inbox_pk: &Tagged32,
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    put_length_prefixed(&mut out, member_id)?;
    put_length_prefixed(&mut out, &member_pk.encode())?;
    put_length_prefixed(&mut out, &inbox_pk.encode())?;
    Ok(out)
}

/// `label || member_id || hk_version u32 big-endian`, the context of the per-version
/// derivations. The member identifier is the only variable-length part and the version is
/// fixed-width at the end, so the concatenation is unambiguous.
pub(crate) fn versioned_context(label: &[u8], member_id: &[u8], hk_version: u32) -> Vec<u8> {
    [label, member_id, &hk_version.to_be_bytes()].concat()
}
