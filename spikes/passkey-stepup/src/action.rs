//! A pending action and its canonical hash (AD-13), the value a step-up is bound to (AD-8, D71).
//!
//! The encoding and the hash come from story 1.9's profile (`spikes/canonical-cbor`), so the
//! request is hashed exactly as the Core would hash it for a signer.

use canonical_cbor::profile::{self, Rejection};
use dcbor::{CBOR, Map};
use serde::Deserialize;

/// Length of a request identifier, chosen by the server with its CSPRNG.
pub const REQUEST_ID_LEN: usize = 16;
/// Length of a member identifier (the Core's binary UUID).
pub const MEMBER_ID_LEN: usize = 16;
/// Version of the hashed request layout.
const REQUEST_LAYOUT_VERSION: u64 = 1;
/// Longest text field a client may send; the spike has no other use for long text.
const MAX_FIELD_LEN: usize = 256;

/// What the client asks the server to do. The server adds the request identifier and the
/// member before hashing, so two identical inputs never produce the same request hash.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionInput {
    pub kind: String,
    pub target: String,
    pub detail: String,
}

/// Why an action input is refused before any request exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionError {
    FieldTooLong,
    /// The canonical profile refused the value (non-NFC text, for instance).
    NotCanonical(Rejection),
    /// Canonical CBOR, but not the request layout.
    NotARequest,
}

impl std::fmt::Display for ActionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FieldTooLong => write!(f, "a field exceeds {MAX_FIELD_LEN} bytes"),
            Self::NotCanonical(rejection) => write!(f, "not canonical: {rejection}"),
            Self::NotARequest => write!(f, "not a request"),
        }
    }
}

impl std::error::Error for ActionError {}

/// The canonical bytes of one request: a map of the layout version, the request identifier,
/// the member and the action fields, encoded by the AD-13 profile.
pub fn canonical_request(
    request_id: &[u8; REQUEST_ID_LEN],
    member: &[u8; MEMBER_ID_LEN],
    input: &ActionInput,
) -> Result<Vec<u8>, ActionError> {
    for field in [&input.kind, &input.target, &input.detail] {
        if field.len() > MAX_FIELD_LEN {
            return Err(ActionError::FieldTooLong);
        }
    }
    let entries = [
        ("v", CBOR::from(REQUEST_LAYOUT_VERSION)),
        ("id", CBOR::to_byte_string(request_id.as_slice())),
        ("member", CBOR::to_byte_string(member.as_slice())),
        ("kind", CBOR::from(input.kind.as_str())),
        ("target", CBOR::from(input.target.as_str())),
        ("detail", CBOR::from(input.detail.as_str())),
    ];
    let mut map = Map::new();
    for (key, value) in entries {
        profile::insert_unique(&mut map, CBOR::from(key), value)
            .map_err(ActionError::NotCanonical)?;
    }
    profile::encode(&map.into()).map_err(ActionError::NotCanonical)
}

/// SHA-256 of the canonical request bytes, as every signer computes it (AD-13).
pub fn request_hash(canonical: &[u8]) -> [u8; 32] {
    profile::hash(canonical)
}

/// A request read back from its canonical bytes: what an executor runs after a step-up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRequest {
    pub request_id: [u8; REQUEST_ID_LEN],
    pub member: [u8; MEMBER_ID_LEN],
    pub input: ActionInput,
}

/// Decodes canonical request bytes, refusing anything that is not exactly the layout
/// [`canonical_request`] writes.
pub fn decode_request(bytes: &[u8]) -> Result<DecodedRequest, ActionError> {
    let map = profile::decode(bytes)
        .map_err(ActionError::NotCanonical)?
        .try_into_map()
        .map_err(|_| ActionError::NotARequest)?;
    let field = |key: &str| map.get::<_, CBOR>(key).ok_or(ActionError::NotARequest);
    let text = |key: &str| {
        field(key)?
            .try_into_text()
            .map_err(|_| ActionError::NotARequest)
    };
    let bytes_of = |key: &str| {
        field(key)?
            .try_into_byte_string()
            .map_err(|_| ActionError::NotARequest)
    };
    let version: u64 = map.get("v").ok_or(ActionError::NotARequest)?;
    let decoded = DecodedRequest {
        request_id: bytes_of("id")?
            .try_into()
            .map_err(|_| ActionError::NotARequest)?,
        member: bytes_of("member")?
            .try_into()
            .map_err(|_| ActionError::NotARequest)?,
        input: ActionInput {
            kind: text("kind")?,
            target: text("target")?,
            detail: text("detail")?,
        },
    };
    // Re-encoding refuses extra keys and any other layout difference in one comparison.
    let expected = canonical_request(&decoded.request_id, &decoded.member, &decoded.input)?;
    if version != REQUEST_LAYOUT_VERSION || expected != bytes {
        return Err(ActionError::NotARequest);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(detail: &str) -> ActionInput {
        ActionInput {
            kind: "member.suspend".to_owned(),
            target: "member-2".to_owned(),
            detail: detail.to_owned(),
        }
    }

    #[test]
    fn canonical_request_round_trips_through_the_profile_decoder() {
        let bytes = canonical_request(&[1; 16], &[2; 16], &input("now")).unwrap();
        let decoded = profile::decode(&bytes).unwrap();
        assert_eq!(profile::encode(&decoded).unwrap(), bytes);
    }

    #[test]
    fn request_id_and_fields_change_the_hash() {
        let base = request_hash(&canonical_request(&[1; 16], &[2; 16], &input("a")).unwrap());
        let other_id = request_hash(&canonical_request(&[3; 16], &[2; 16], &input("a")).unwrap());
        let other_member =
            request_hash(&canonical_request(&[1; 16], &[4; 16], &input("a")).unwrap());
        let other_detail =
            request_hash(&canonical_request(&[1; 16], &[2; 16], &input("b")).unwrap());
        assert_ne!(base, other_id);
        assert_ne!(base, other_member);
        assert_ne!(base, other_detail);
    }

    #[test]
    fn non_nfc_text_is_refused() {
        let result = canonical_request(&[1; 16], &[2; 16], &input("cafe\u{301}"));
        assert_eq!(
            result,
            Err(ActionError::NotCanonical(Rejection::NonNfcText))
        );
    }

    #[test]
    fn long_fields_are_refused() {
        let result = canonical_request(&[1; 16], &[2; 16], &input(&"x".repeat(MAX_FIELD_LEN + 1)));
        assert_eq!(result, Err(ActionError::FieldTooLong));
    }

    #[test]
    fn decode_request_reads_back_what_was_encoded() {
        let bytes = canonical_request(&[1; 16], &[2; 16], &input("x")).unwrap();
        let decoded = decode_request(&bytes).unwrap();
        assert_eq!(decoded.request_id, [1; 16]);
        assert_eq!(decoded.member, [2; 16]);
        assert_eq!(decoded.input, input("x"));
    }

    #[test]
    fn decode_request_refuses_another_layout() {
        let mut map = Map::new();
        map.insert(CBOR::from("v"), CBOR::from(REQUEST_LAYOUT_VERSION));
        map.insert(CBOR::from("extra"), CBOR::from(1u64));
        let bytes = profile::encode(&map.into()).unwrap();
        assert_eq!(decode_request(&bytes), Err(ActionError::NotARequest));
        let mut extended =
            profile::decode(&canonical_request(&[1; 16], &[2; 16], &input("x")).unwrap())
                .unwrap()
                .try_into_map()
                .unwrap();
        extended.insert(CBOR::from("extra"), CBOR::from(1u64));
        let bytes = profile::encode(&extended.into()).unwrap();
        assert_eq!(decode_request(&bytes), Err(ActionError::NotARequest));
    }
}
