//! The bytes that are hashed or signed (spine AD-13, D130).
//!
//! A value is hashed through [`CanonicalBytes`], whose only constructor from a value runs the
//! profile check, so anything hashed is dCBOR restricted by D130. The hash itself is SHA-256,
//! computed by the Core through `vilicus-crypto` (AD-3): this crate never hashes, it hands out the
//! exact bytes. A stored hash is checked against the stored bytes it was computed from, never
//! against a re-encoding of the value they hold: a change of the Unicode tables can change what a
//! value re-encodes to, while the stored bytes and their hash stay what was signed (D130).

use crate::profile::Rejection;
use crate::wire::{self, Wire};

/// The canonical encoding of one value: the bytes the Core hashes and sends to signers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalBytes(Vec<u8>);

impl CanonicalBytes {
    /// Encodes a value, refusing it if the profile does not allow it.
    pub fn encode<T: Wire>(value: &T) -> Result<Self, Rejection> {
        wire::encode(value).map(Self)
    }

    /// Wraps bytes read back from storage, exactly as they were stored, without decoding or
    /// re-encoding them.
    pub fn from_stored(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The bytes to hash, sign, send or store.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Whether `stored_hash` is the hash of these bytes, by the hash function the caller gives
    /// (SHA-256 of `vilicus-crypto`). The bytes are hashed as they are: they are never decoded
    /// and encoded again first.
    pub fn matches_hash<const N: usize>(
        &self,
        stored_hash: &[u8; N],
        hash: impl FnOnce(&[u8]) -> [u8; N],
    ) -> bool {
        hash(&self.0) == *stored_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::tests::{SampleMessage, every_message_kind, handshake_replies, hello};
    use crate::profile::{self, LISTED_TAGS, MAX_DEPTH};
    use crate::vocabulary::tests::{every_source_kind, sample_id};
    use dcbor::{CBOR, CBORCase};
    use vilicus_types::{ClientError, ErrorCode, MessageKey, RetryClass, UtcMillis};

    /// Whether a decoded value, sitting in `depth` containers, stays within the limits AC4 states.
    /// It repeats what `profile::check_value` checks on purpose: the test states the limits
    /// itself instead of trusting the code under test.
    fn within_the_limits_of_ac4(value: &CBOR, depth: usize) -> bool {
        match value.as_case() {
            CBORCase::Unsigned(_) | CBORCase::ByteString(_) => true,
            CBORCase::Negative(magnitude) => *magnitude <= i64::MAX.unsigned_abs(),
            CBORCase::Text(text) => unicode_normalization::is_nfc(text),
            CBORCase::Array(items) => {
                depth < MAX_DEPTH
                    && items
                        .iter()
                        .all(|item| within_the_limits_of_ac4(item, depth + 1))
            }
            CBORCase::Map(map) => {
                depth < MAX_DEPTH
                    && map.iter().all(|(key, item)| {
                        within_the_limits_of_ac4(key, depth + 1)
                            && within_the_limits_of_ac4(item, depth + 1)
                    })
            }
            CBORCase::Tagged(tag, item) => {
                LISTED_TAGS.contains(&tag.value())
                    && depth < MAX_DEPTH
                    && within_the_limits_of_ac4(item, depth + 1)
            }
            CBORCase::Simple(simple) => !simple.is_float(),
        }
    }

    fn assert_canonical<T: Wire + PartialEq + core::fmt::Debug>(value: &T) {
        let bytes = CanonicalBytes::encode(value).expect("encodes under the profile");
        let decoded = profile::decode(bytes.as_bytes()).expect("decodes under the profile");
        assert!(within_the_limits_of_ac4(&decoded, 0), "{value:?}");
        assert_eq!(wire::decode::<T>(bytes.as_bytes()).as_ref(), Ok(value));
    }

    /// AC4: every type of this crate that can be hashed, signed or sent encodes within the D130
    /// limits and round-trips. No hashed or signed message type exists yet (light confirmations,
    /// audit parameters and step-up challenges come with their stories); each of them is built
    /// from these types and must join this test when it lands.
    #[test]
    fn every_wire_type_respects_the_profile_limits() {
        for message in every_message_kind() {
            assert_canonical::<SampleMessage>(&message);
        }
        assert_canonical(&hello());
        for reply in handshake_replies() {
            assert_canonical(&reply);
        }
        for source in every_source_kind() {
            assert_canonical(&source);
        }
        assert_canonical(&sample_id());
        assert_canonical(&UtcMillis::MIN);
        assert_canonical(&UtcMillis::MAX);
        assert_canonical(&ClientError {
            code: ErrorCode::from_static("policy.denied"),
            message_key: MessageKey::from_static("error.policy.denied"),
            retry_class: RetryClass::UnknownOutcome,
        });
        for (type_name, _, value) in crate::vocabulary::closed_set_members() {
            assert!(within_the_limits_of_ac4(&value, 0), "{type_name}");
        }
    }

    #[test]
    fn a_value_outside_the_profile_has_no_canonical_bytes() {
        assert_eq!(
            CanonicalBytes::encode(&"cafe\u{301}".to_owned()),
            Err(Rejection::NonNfcText)
        );
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes);
        digest.as_ref().try_into().expect("32 bytes")
    }

    /// AC7: bytes stored by a Core whose tables put U+1AE1 after U+0337 (`a` U+1AE1 U+0337, as a
    /// Unicode 16 Core encodes it, Story 1.9 finding 5) no longer decode under this Core's
    /// Unicode 17 tables. Their stored hash still verifies, because it is checked against the
    /// stored bytes, never against a re-encoding.
    #[test]
    fn a_stored_hash_is_checked_against_the_stored_bytes() {
        let stored = vec![0x66, 0x61, 0xe1, 0xab, 0xa1, 0xcc, 0xb7];
        let stored_hash = sha256(&stored);
        assert!(profile::decode(&stored).is_err());
        let bytes = CanonicalBytes::from_stored(stored);
        assert!(bytes.matches_hash(&stored_hash, sha256));
        assert!(!bytes.matches_hash(&[0u8; 32], sha256));

        let value = CanonicalBytes::encode(&vec![1u64, 2]).expect("canonical");
        let hash = sha256(value.as_bytes());
        assert!(CanonicalBytes::from_stored(value.as_bytes().to_vec()).matches_hash(&hash, sha256));
    }
}
