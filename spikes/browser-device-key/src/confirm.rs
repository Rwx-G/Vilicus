//! Light confirmations (D38, FR-28): the canonical bytes the Core sends a signer, built with the
//! AD-13 profile of story 1.9 (`canonical-cbor`).
//!
//! The Core encodes a pending request canonically and hashes it; a confirmation challenge is a
//! second canonical value that names that hash, the request, the device, a fresh nonce and an
//! expiry. The browser signs the challenge bytes exactly as received (ECDSA P-256 SHA-256), so
//! the signature covers one request, one device and one nonce.

use canonical_cbor::profile::{self, Rejection};
use dcbor::{CBOR, Map};

use crate::device::Id;

/// `kind` of a pending request value.
pub const PENDING_KIND: &str = "vilicus/v1/pending-request";
/// `kind` of a light confirmation challenge.
pub const CONFIRMATION_KIND: &str = "vilicus/v1/light-confirmation";

/// The canonical bytes of a pending elevated request: what the assistant asked to do.
pub fn pending_request_bytes(
    request_id: &Id,
    tool: &str,
    title: &str,
) -> Result<Vec<u8>, Rejection> {
    let mut params = Map::new();
    profile::insert_unique(&mut params, CBOR::from("title"), CBOR::from(title))?;
    let mut map = Map::new();
    profile::insert_unique(&mut map, CBOR::from("kind"), CBOR::from(PENDING_KIND))?;
    profile::insert_unique(&mut map, CBOR::from("id"), CBOR::to_byte_string(request_id))?;
    profile::insert_unique(&mut map, CBOR::from("tool"), CBOR::from(tool))?;
    profile::insert_unique(&mut map, CBOR::from("params"), CBOR::from(params))?;
    profile::encode(&CBOR::from(map))
}

/// The fields of one confirmation challenge.
pub struct Challenge<'a> {
    pub request_id: &'a Id,
    pub request_hash: &'a [u8; 32],
    pub device_id: &'a Id,
    pub nonce: &'a Id,
    pub expires_at: u64,
}

/// The canonical bytes of a confirmation challenge, which the device signs.
pub fn challenge_bytes(challenge: &Challenge<'_>) -> Result<Vec<u8>, Rejection> {
    let mut map = Map::new();
    profile::insert_unique(&mut map, CBOR::from("kind"), CBOR::from(CONFIRMATION_KIND))?;
    profile::insert_unique(&mut map, CBOR::from("decision"), CBOR::from("approve"))?;
    profile::insert_unique(
        &mut map,
        CBOR::from("request_id"),
        CBOR::to_byte_string(challenge.request_id),
    )?;
    profile::insert_unique(
        &mut map,
        CBOR::from("request_hash"),
        CBOR::to_byte_string(challenge.request_hash),
    )?;
    profile::insert_unique(
        &mut map,
        CBOR::from("device_id"),
        CBOR::to_byte_string(challenge.device_id),
    )?;
    profile::insert_unique(
        &mut map,
        CBOR::from("nonce"),
        CBOR::to_byte_string(challenge.nonce),
    )?;
    profile::insert_unique(
        &mut map,
        CBOR::from("expires_at"),
        CBOR::from(challenge.expires_at),
    )?;
    profile::encode(&CBOR::from(map))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_bytes_are_canonical_and_differ_per_request() {
        let hash = [1u8; 32];
        let device = [2u8; 16];
        let nonce = [3u8; 16];
        let a = challenge_bytes(&Challenge {
            request_id: &[4u8; 16],
            request_hash: &hash,
            device_id: &device,
            nonce: &nonce,
            expires_at: 1_800_000_000,
        })
        .unwrap();
        let b = challenge_bytes(&Challenge {
            request_id: &[5u8; 16],
            request_hash: &hash,
            device_id: &device,
            nonce: &nonce,
            expires_at: 1_800_000_000,
        })
        .unwrap();
        assert_ne!(a, b);
        assert!(profile::decode(&a).is_ok());
        let pending = pending_request_bytes(&[4u8; 16], "tasks.create", "Buy bread").unwrap();
        assert!(profile::decode(&pending).is_ok());
    }
}
