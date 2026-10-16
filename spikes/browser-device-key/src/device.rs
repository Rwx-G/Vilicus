//! Device key signatures: the AD-21 per-request byte string, the proof of possession sent with a
//! new public key, and the session-opening challenge.
//!
//! The browser signs with WebCrypto ECDSA P-256 and SHA-256, which yields the fixed-length
//! `r || s` form (IEEE P1363), so the Core verifies with `ECDSA_P256_SHA256_FIXED`. The public
//! key travels as the 65-byte uncompressed SEC1 point that `exportKey('raw')` produces.

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};

/// Domain label of the per-request byte string (AD-21).
pub const REQUEST_LABEL: &[u8] = b"vilicus/v1/req";
/// Domain label of a proof of possession over a new device public key.
pub const POP_LABEL: &[u8] = b"vilicus/v1/device-pop";
/// Domain label of the challenge that opens a session for a registered device.
pub const SESSION_LABEL: &[u8] = b"vilicus/v1/session";

/// Length of an uncompressed P-256 public key.
pub const PUBLIC_KEY_LEN: usize = 65;
/// Length of a fixed-form P-256 signature.
pub const SIGNATURE_LEN: usize = 64;
/// Length of a session identifier, a device identifier and a nonce.
pub const ID_LEN: usize = 16;

/// Session, device and pending-request identifiers, and nonces.
pub type Id = [u8; ID_LEN];

/// The 32 bytes a browser signs for one request (AD-21): SHA-256 of the label, the session id,
/// the counter, the method, the path and SHA-256 of the raw body.
///
/// AD-21 says "concatenated"; method and path have variable lengths, so each is preceded by its
/// length as a 4-byte big-endian integer, and the counter is an 8-byte big-endian integer. With
/// fixed-length label, session id and body hash, no two field tuples give the same bytes.
pub fn request_digest(
    session_id: &Id,
    counter: u64,
    method: &str,
    path: &str,
    body: &[u8],
) -> [u8; 32] {
    let body_hash = sha256(body);
    let mut input =
        Vec::with_capacity(REQUEST_LABEL.len() + ID_LEN + 8 + 8 + method.len() + path.len() + 32);
    input.extend_from_slice(REQUEST_LABEL);
    input.extend_from_slice(session_id);
    input.extend_from_slice(&counter.to_be_bytes());
    push_with_length(&mut input, method.as_bytes());
    push_with_length(&mut input, path.as_bytes());
    input.extend_from_slice(&body_hash);
    sha256(&input)
}

/// The bytes a device signs to prove it holds the private key of `public_key` in `context` (an
/// enrollment token or a pairing binding).
pub fn pop_message(context: &[u8], public_key: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(POP_LABEL.len() + 4 + context.len() + public_key.len());
    message.extend_from_slice(POP_LABEL);
    push_with_length(&mut message, context);
    message.extend_from_slice(public_key);
    message
}

/// The bytes a registered device signs to open a session.
pub fn session_message(device_id: &Id, nonce: &Id) -> Vec<u8> {
    [SESSION_LABEL, device_id.as_slice(), nonce.as_slice()].concat()
}

/// Verifies a fixed-form ECDSA P-256 SHA-256 signature. A malformed key or signature is a
/// failed verification.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    public_key.len() == PUBLIC_KEY_LEN
        && signature.len() == SIGNATURE_LEN
        && UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key)
            .verify(message, signature)
            .is_ok()
}

/// SHA-256 from aws-lc-rs.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest(&SHA256, bytes).as_ref());
    out
}

fn push_with_length(buffer: &mut Vec<u8>, field: &[u8]) {
    let length = u32::try_from(field.len()).expect("a field shorter than 4 GiB");
    buffer.extend_from_slice(&length.to_be_bytes());
    buffer.extend_from_slice(field);
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

    #[test]
    fn request_digest_separates_method_from_path() {
        let session = [7u8; ID_LEN];
        let a = request_digest(&session, 1, "POST", "/api/x", b"");
        let b = request_digest(&session, 1, "POS", "T/api/x", b"");
        assert_ne!(a, b);
    }

    #[test]
    fn verify_accepts_aws_lc_signature_and_rejects_other_message() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap();
        let signature = pair.sign(&rng, b"message").unwrap();
        let public_key = pair.public_key().as_ref();
        assert!(verify(public_key, b"message", signature.as_ref()));
        assert!(!verify(public_key, b"other", signature.as_ref()));
        assert!(!verify(&public_key[..64], b"message", signature.as_ref()));
    }
}
