//! The AD-13 canonical profile on top of `dcbor`.
//!
//! `dcbor` already enforces the deterministic encoding of RFC 8949 section 4.2.1 on decode
//! (shortest heads, definite lengths, sorted and unique map keys, no trailing bytes, NFC text,
//! simple values limited to false, true and null). This module adds what the profile states
//! and `dcbor` allows: no floating-point value, no tag outside [`LISTED_TAGS`], integers within
//! [-2^63, 2^64 - 1], a nesting bound checked before the recursive decoder runs, and, on
//! encode, NFC text and unique map keys, because `dcbor` normalizes text silently when it
//! encodes and its map insertion silently replaces an equal key.

use dcbor::{CBOR, CBORCase, Map, Simple};
use sha2::{Digest, Sha256};
use unicode_normalization::is_nfc;

/// Most arrays, maps and tags an item may sit in, counting itself when it is one.
///
/// `dcbor` decodes recursively without a bound, so a deeply nested frame would exhaust the
/// stack; the bound is checked by [`scan_heads`] before `dcbor` sees the bytes.
pub const MAX_DEPTH: usize = 32;

/// Tags a hashed or signed type may carry. Empty: no Vilicus type needs one yet.
pub const LISTED_TAGS: &[u64] = &[];

/// Why the profile refuses an input or a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    /// Truncated input, reserved additional information, or an indefinite length.
    Malformed(&'static str),
    /// Bytes after the first item.
    TrailingBytes,
    /// More than [`MAX_DEPTH`] nested arrays, maps or tags.
    TooDeep,
    /// A tag outside [`LISTED_TAGS`].
    UnlistedTag(u64),
    /// Refused by `dcbor` as not well-formed deterministic CBOR.
    NotDeterministic(String),
    /// A floating-point value.
    Float,
    /// A negative integer below -2^63, outside the dCBOR integer range.
    NegativeOutOfRange,
    /// Text not in NFC, which `dcbor` would normalize silently on encode.
    NonNfcText,
    /// A map key equal to an earlier one once canonicalized.
    DuplicateKey,
    /// Accepted by `dcbor`, but its re-encoding differs from the input.
    NotRoundTrip,
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(what) => write!(f, "malformed: {what}"),
            Self::TrailingBytes => write!(f, "bytes after the first item"),
            Self::TooDeep => write!(f, "more than {MAX_DEPTH} nested arrays, maps or tags"),
            Self::UnlistedTag(tag) => write!(f, "unlisted tag {tag}"),
            Self::NotDeterministic(error) => write!(f, "not deterministic: {error}"),
            Self::Float => write!(f, "floating-point value"),
            Self::NegativeOutOfRange => write!(f, "negative integer below -2^63"),
            Self::NonNfcText => write!(f, "text not in Unicode Normalization Form C"),
            Self::DuplicateKey => write!(f, "duplicate map key"),
            Self::NotRoundTrip => write!(f, "re-encoding differs from the input"),
        }
    }
}

impl std::error::Error for Rejection {}

/// Decodes bytes received from a peer, refusing anything outside the profile.
pub fn decode(bytes: &[u8]) -> Result<CBOR, Rejection> {
    scan_heads(bytes)?;
    let value = CBOR::try_from_data(bytes)
        .map_err(|error| Rejection::NotDeterministic(error.to_string()))?;
    check_value(&value)?;
    require_round_trip(&value, bytes)?;
    Ok(value)
}

/// Refuses a decoded value whose re-encoding differs from the bytes it came from.
///
/// This makes canonicality hold whatever gap `dcbor` has: it accepts integral floats outside
/// the `i32` (single) or `i64` (double) range, and silently reduces such doubles to integers,
/// so two byte strings decode to one value. Floats are refused earlier by [`scan_heads`]; the
/// comparison is the backstop for anything similar.
pub fn require_round_trip(value: &CBOR, bytes: &[u8]) -> Result<(), Rejection> {
    if value.to_cbor_data() == bytes {
        Ok(())
    } else {
        Err(Rejection::NotRoundTrip)
    }
}

/// Encodes a value the Core built, refusing it if the profile does not allow it.
pub fn encode(value: &CBOR) -> Result<Vec<u8>, Rejection> {
    check_value(value)?;
    Ok(value.to_cbor_data())
}

/// Inserts into a map under construction, refusing a key equal to an earlier one once
/// canonicalized; `dcbor`'s own `insert` silently replaces the earlier entry.
pub fn insert_unique(map: &mut Map, key: CBOR, value: CBOR) -> Result<(), Rejection> {
    let before = map.len();
    map.insert(key, value);
    if map.len() == before {
        Err(Rejection::DuplicateKey)
    } else {
        Ok(())
    }
}

/// SHA-256 of canonical bytes, as the Core and every signer compute it.
pub fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Checks the profile rules on a value: no float, no unlisted tag, the integer range, NFC
/// text and the nesting bound.
pub fn check_value(value: &CBOR) -> Result<(), Rejection> {
    check_value_at(value, 0, LISTED_TAGS)
}

fn check_value_at(value: &CBOR, enclosing: usize, listed: &[u64]) -> Result<(), Rejection> {
    match value.as_case() {
        CBORCase::Unsigned(_) | CBORCase::ByteString(_) => Ok(()),
        CBORCase::Text(text) => {
            if is_nfc(text) {
                Ok(())
            } else {
                Err(Rejection::NonNfcText)
            }
        }
        CBORCase::Negative(magnitude) => {
            if *magnitude > i64::MAX as u64 {
                Err(Rejection::NegativeOutOfRange)
            } else {
                Ok(())
            }
        }
        CBORCase::Array(items) => {
            enter(enclosing)?;
            items
                .iter()
                .try_for_each(|item| check_value_at(item, enclosing + 1, listed))
        }
        CBORCase::Map(map) => {
            enter(enclosing)?;
            map.iter().try_for_each(|(key, item)| {
                check_value_at(key, enclosing + 1, listed)?;
                check_value_at(item, enclosing + 1, listed)
            })
        }
        CBORCase::Tagged(tag, item) => {
            if !listed.contains(&tag.value()) {
                return Err(Rejection::UnlistedTag(tag.value()));
            }
            enter(enclosing)?;
            check_value_at(item, enclosing + 1, listed)
        }
        CBORCase::Simple(Simple::Float(_)) => Err(Rejection::Float),
        CBORCase::Simple(_) => Ok(()),
    }
}

fn enter(enclosing: usize) -> Result<(), Rejection> {
    if enclosing + 1 > MAX_DEPTH {
        Err(Rejection::TooDeep)
    } else {
        Ok(())
    }
}

/// Walks the item heads without recursion and refuses, before any recursive decoding, an
/// input nested deeper than [`MAX_DEPTH`], carrying an unlisted tag or a float, or followed
/// by trailing bytes. Every refusal here is also a refusal of the full profile.
pub fn scan_heads(bytes: &[u8]) -> Result<(), Rejection> {
    scan_heads_with(bytes, LISTED_TAGS)
}

fn scan_heads_with(bytes: &[u8], listed: &[u64]) -> Result<(), Rejection> {
    // Items still expected in each open container; the bottom entry stands for the root.
    let mut expected: Vec<u64> = vec![1];
    let mut pos = 0usize;
    while let Some(&remaining) = expected.last() {
        if remaining == 0 {
            expected.pop();
            continue;
        }
        let top = expected.len() - 1;
        expected[top] = remaining - 1;
        let head = read_head(bytes, pos)?;
        pos = head.next;
        match head.major {
            0 | 1 => {}
            2 | 3 => {
                pos = usize::try_from(head.argument)
                    .ok()
                    .and_then(|length| pos.checked_add(length))
                    .filter(|end| *end <= bytes.len())
                    .ok_or(Rejection::Malformed("string runs past the input"))?;
            }
            4..=6 => {
                if head.major == 6 && !listed.contains(&head.argument) {
                    return Err(Rejection::UnlistedTag(head.argument));
                }
                // `expected` holds the root entry, so its length is the depth of the new item.
                if expected.len() > MAX_DEPTH {
                    return Err(Rejection::TooDeep);
                }
                let items = match head.major {
                    4 => Some(head.argument),
                    5 => head.argument.checked_mul(2),
                    // A tag is a level holding exactly one item.
                    _ => Some(1),
                };
                expected.push(items.ok_or(Rejection::Malformed("map length overflows"))?);
            }
            7 if head.width >= 2 => return Err(Rejection::Float),
            _ => {}
        }
    }
    if pos != bytes.len() {
        return Err(Rejection::TrailingBytes);
    }
    Ok(())
}

struct Head {
    major: u8,
    width: usize,
    argument: u64,
    next: usize,
}

fn read_head(bytes: &[u8], pos: usize) -> Result<Head, Rejection> {
    let initial = *bytes
        .get(pos)
        .ok_or(Rejection::Malformed("input ends before an item"))?;
    let major = initial >> 5;
    let additional = initial & 0x1f;
    let width = match additional {
        0..=23 => 0,
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        31 => return Err(Rejection::Malformed("indefinite length or break")),
        _ => return Err(Rejection::Malformed("reserved additional information")),
    };
    let start = pos + 1;
    let argument_bytes = bytes
        .get(start..start + width)
        .ok_or(Rejection::Malformed("input ends inside a head"))?;
    let argument = if width == 0 {
        u64::from(additional)
    } else {
        argument_bytes
            .iter()
            .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte))
    };
    Ok(Head {
        major,
        width,
        argument,
        next: start + width,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nested_arrays(depth: usize) -> Vec<u8> {
        let mut bytes = vec![0x81; depth - 1];
        bytes.push(0x80);
        bytes
    }

    #[test]
    fn depth_bound_is_inclusive() {
        assert!(decode(&nested_arrays(MAX_DEPTH)).is_ok());
        assert_eq!(
            decode(&nested_arrays(MAX_DEPTH + 1)),
            Err(Rejection::TooDeep)
        );
    }

    #[test]
    fn listed_tags_count_toward_depth() {
        // A test-only listed tag: tag 1 around tag 1 ... around 0.
        let listed = [1u64];
        let mut within = vec![0xc1u8; MAX_DEPTH];
        within.push(0x00);
        assert_eq!(scan_heads_with(&within, &listed), Ok(()));
        let mut over = vec![0xc1u8; MAX_DEPTH + 1];
        over.push(0x00);
        assert_eq!(scan_heads_with(&over, &listed), Err(Rejection::TooDeep));
        let mut value = CBOR::from(0u64);
        for _ in 0..=MAX_DEPTH {
            value = CBOR::to_tagged_value(1u64, value);
        }
        assert_eq!(check_value_at(&value, 0, &listed), Err(Rejection::TooDeep));
    }

    #[test]
    fn trailing_bytes_are_refused_by_the_scan() {
        let mut bytes = vec![0x00];
        bytes.extend(std::iter::repeat_n(0x81, 100_000));
        assert_eq!(scan_heads(&bytes), Err(Rejection::TrailingBytes));
        assert_eq!(decode(&bytes), Err(Rejection::TrailingBytes));
    }

    #[test]
    fn round_trip_comparison_refuses_a_reduced_float() {
        let double = [0xfb, 0x43, 0xe0, 0, 0, 0, 0, 0, 1];
        let reduced = CBOR::try_from_data(double).expect("dcbor accepts it");
        assert_eq!(
            require_round_trip(&reduced, &double),
            Err(Rejection::NotRoundTrip)
        );
        assert_eq!(
            require_round_trip(&reduced, &reduced.to_cbor_data()),
            Ok(())
        );
    }

    #[test]
    fn encode_refuses_values_outside_the_profile() {
        assert_eq!(encode(&CBOR::from(1.5f64)), Err(Rejection::Float));
        assert_eq!(
            encode(&CBOR::to_tagged_value(0u64, CBOR::from(0u64))),
            Err(Rejection::UnlistedTag(0))
        );
        let mut deep = CBOR::from(Vec::<CBOR>::new());
        for _ in 0..MAX_DEPTH {
            deep = CBOR::from(vec![deep]);
        }
        assert_eq!(encode(&deep), Err(Rejection::TooDeep));
        assert_eq!(
            encode(&CBOR::from("cafe\u{301}")),
            Err(Rejection::NonNfcText)
        );
    }

    #[test]
    fn keys_equal_after_nfc_do_not_collapse_silently() {
        // dcbor keys a map by the encoded key, which it normalizes: these two keys would
        // become one entry, so what is signed would differ from what was built.
        let mut map = Map::new();
        assert_eq!(
            insert_unique(&mut map, CBOR::from("caf\u{e9}"), CBOR::from(1u64)),
            Ok(())
        );
        assert_eq!(
            insert_unique(&mut map, CBOR::from("cafe\u{301}"), CBOR::from(2u64)),
            Err(Rejection::DuplicateKey)
        );
    }

    #[test]
    fn deep_input_is_refused_without_recursion() {
        let bytes = vec![0x81; 4 * 1024 * 1024];
        assert_eq!(decode(&bytes), Err(Rejection::TooDeep));
        let tags = [0xc0u8].repeat(4 * 1024 * 1024);
        assert_eq!(decode(&tags), Err(Rejection::UnlistedTag(0)));
    }

    #[test]
    fn dcbor_accepts_integral_floats_the_dcbor_rules_forbid() {
        // dCBOR requires an integral float in [-2^63, 2^64 - 1] to be encoded as an integer.
        // dcbor 0.25.2 accepts 2^32 as a single, kept as a float, and 2^63 + 2048 as a double,
        // silently reduced to the integer, so a second encoding of that integer exists.
        let single = [0xfa, 0x4f, 0x80, 0, 0];
        assert!(CBOR::try_from_data(single).is_ok());
        assert_eq!(decode(&single), Err(Rejection::Float));
        let double = [0xfb, 0x43, 0xe0, 0, 0, 0, 0, 0, 1];
        let reduced = CBOR::try_from_data(double).expect("dcbor accepts it");
        assert_eq!(reduced.to_cbor_data(), [0x1b, 0x80, 0, 0, 0, 0, 0, 0x08, 0]);
        assert_eq!(decode(&double), Err(Rejection::Float));
    }

    #[test]
    fn float_and_large_negative_are_refused_when_dcbor_accepts_them() {
        // dcbor accepts both; the profile does not.
        let half = [0xf9, 0x3e, 0x00];
        assert!(CBOR::try_from_data(half).is_ok());
        assert_eq!(decode(&half), Err(Rejection::Float));
        let below = [0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0];
        assert!(CBOR::try_from_data(below).is_ok());
        assert_eq!(decode(&below), Err(Rejection::NegativeOutOfRange));
        let lowest = [0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert!(decode(&lowest).is_ok());
    }

    #[test]
    fn marks_new_in_the_core_unicode_version_are_ordered_on_decode() {
        // From random-00145 and fuzz-036083: U+1AE1 and U+1AD5 are combining marks new in
        // Unicode 17. A Core on older tables would leave them in this order; this Core's
        // tables require the other one, so it refuses these bytes (fails closed).
        for bytes in [
            &[0x66, 0x61, 0xe1, 0xab, 0xa1, 0xcc, 0xb7][..],
            &[0x66, 0x61, 0xe1, 0xab, 0x95, 0xcc, 0xac][..],
        ] {
            assert!(matches!(decode(bytes), Err(Rejection::NotDeterministic(_))));
        }
    }
}
