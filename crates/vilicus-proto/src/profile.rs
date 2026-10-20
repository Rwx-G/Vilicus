//! The canonical CBOR profile of D130 on top of `dcbor` (spine AD-13).
//!
//! `dcbor` already enforces the deterministic encoding of RFC 8949 section 4.2.1 on decode
//! (shortest heads, definite lengths, sorted and unique map keys, no trailing bytes, NFC text,
//! simple values limited to false, true and null). This module adds what the profile states and
//! `dcbor` 0.25.2 allows: no floating-point value, no tag outside [`LISTED_TAGS`], integers within
//! [-2^63, 2^64 - 1], a nesting bound checked before the recursive decoder runs, and, on encode,
//! NFC text and unique map keys, because `dcbor` normalizes text silently when it encodes and its
//! map insertion silently replaces an equal key (Story 1.9, findings 1, 2 and 7).
//!
//! It was moved from `spikes/canonical-cbor/src/profile.rs` without a change of behaviour: the
//! rejection messages are part of the E19 vector files, which `tests/canonical_vectors.rs`
//! regenerates and compares byte for byte.

use core::fmt;

use dcbor::{CBOR, CBORCase, Map, Simple};
use unicode_normalization::is_nfc;

/// Most arrays, maps and tags an item may sit in, counting itself when it is one.
///
/// `dcbor` decodes recursively without a bound, so a deeply nested frame would exhaust the stack;
/// the bound is checked by [`scan_heads`] before `dcbor` sees the bytes.
pub const MAX_DEPTH: usize = 32;

/// Tags a canonical value may carry. Empty (D130): no Vilicus type needs one.
pub const LISTED_TAGS: &[u64] = &[];

/// Smallest integer the profile allows, -2^63.
pub const INT_MIN: i128 = i64::MIN as i128;

/// Largest integer the profile allows, 2^64 - 1.
pub const INT_MAX: i128 = u64::MAX as i128;

/// Unicode version of the NFC tables the canonical form is checked against, as
/// `(major, minor, update)`. It comes from the exactly pinned `unicode-normalization`; a change is
/// a change of the canonical format (D130).
pub const UNICODE_VERSION: (u8, u8, u8) = unicode_normalization::UNICODE_VERSION;

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
    /// More data items than the caller's bound ([`decode_with_max_items`]).
    TooManyItems(usize),
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
            Self::TooManyItems(max) => write!(f, "more than {max} data items"),
        }
    }
}

impl std::error::Error for Rejection {}

/// Decodes canonical bytes, refusing anything outside the profile: the head walk of
/// [`scan_heads`] first, then `dcbor`, then [`check_value`], then [`require_round_trip`].
///
/// The profile bounds nesting, not the number of items: bytes read from a socket go through
/// [`decode_with_max_items`], with the bound of the socket kind ([`crate::frame`]).
pub fn decode(bytes: &[u8]) -> Result<CBOR, Rejection> {
    decode_with_max_items(bytes, usize::MAX)
}

/// [`decode`], also refusing in the head walk, before `dcbor` builds anything, an input of more
/// than `max_items` data items. Every item counts once: the top-level item, each array element,
/// each map key and each map value.
pub fn decode_with_max_items(bytes: &[u8], max_items: usize) -> Result<CBOR, Rejection> {
    scan_heads_with(bytes, LISTED_TAGS, max_items)?;
    decode_scanned(bytes)
}

/// The stages of [`decode`] after the head walk.
fn decode_scanned(bytes: &[u8]) -> Result<CBOR, Rejection> {
    let value = CBOR::try_from_data(bytes)
        .map_err(|error| Rejection::NotDeterministic(error.to_string()))?;
    check_value(&value)?;
    require_round_trip(&value, bytes)?;
    Ok(value)
}

/// Refuses a decoded value whose re-encoding differs from the bytes it came from.
///
/// This makes canonicality hold whatever gap `dcbor` has: it accepts integral floats outside the
/// `i32` (single) or `i64` (double) range, and silently reduces such doubles to integers, so two
/// byte strings decode to one value. Floats are refused earlier by [`scan_heads`]; the comparison
/// is the backstop for anything similar.
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

/// Checks the profile rules on a value: no float, no unlisted tag, the integer range, NFC text
/// and the nesting bound.
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
            if *magnitude > i64::MAX.unsigned_abs() {
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

/// Walks the item heads without recursion and refuses, before any recursive decoding, an input
/// nested deeper than [`MAX_DEPTH`], carrying an unlisted tag or a float, or followed by trailing
/// bytes. Every refusal here is also a refusal of the full profile.
pub fn scan_heads(bytes: &[u8]) -> Result<(), Rejection> {
    scan_heads_with(bytes, LISTED_TAGS, usize::MAX)
}

fn scan_heads_with(bytes: &[u8], listed: &[u64], max_items: usize) -> Result<(), Rejection> {
    // Items still expected in each open container; the bottom entry stands for the root.
    let mut expected: Vec<u64> = vec![1];
    let mut pos = 0usize;
    let mut items = 0usize;
    while let Some(&remaining) = expected.last() {
        if remaining == 0 {
            expected.pop();
            continue;
        }
        let top = expected.len() - 1;
        expected[top] = remaining - 1;
        items += 1;
        if items > max_items {
            return Err(Rejection::TooManyItems(max_items));
        }
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
        assert_eq!(scan_heads_with(&within, &listed, usize::MAX), Ok(()));
        let mut over = vec![0xc1u8; MAX_DEPTH + 1];
        over.push(0x00);
        assert_eq!(
            scan_heads_with(&over, &listed, usize::MAX),
            Err(Rejection::TooDeep)
        );
        let mut value = CBOR::from(0u64);
        for _ in 0..=MAX_DEPTH {
            value = CBOR::to_tagged_value(1u64, value);
        }
        assert_eq!(check_value_at(&value, 0, &listed), Err(Rejection::TooDeep));
    }

    #[test]
    fn the_item_bound_counts_every_item_and_is_inclusive() {
        // [0, {1: 2}]: the array, its two elements, and the map's key and value.
        let bytes = [0x82, 0x00, 0xa1, 0x01, 0x02];
        assert!(decode_with_max_items(&bytes, 5).is_ok());
        assert_eq!(
            decode_with_max_items(&bytes, 4),
            Err(Rejection::TooManyItems(4))
        );
        // An array head declaring 2^32 elements is refused once the bound is passed, without
        // waiting for the end of the input.
        let mut huge = vec![0x9a, 0xff, 0xff, 0xff, 0xff];
        huge.extend(std::iter::repeat_n(0x00, 10));
        assert_eq!(
            decode_with_max_items(&huge, 8),
            Err(Rejection::TooManyItems(8))
        );
    }

    /// The round-trip comparison as the last stage of decoding. Through [`decode`], no input is
    /// known to reach it: the only gap of `dcbor` 0.25.2 it closes, integral floats reduced to
    /// integers, is refused earlier by the head walk (every float is), and neither the committed
    /// fuzz set nor the hand-written set has an input it refuses. So this runs the stages after
    /// the head walk on such a float, whose only refusal there is the comparison.
    #[test]
    fn the_stages_after_the_head_walk_refuse_a_reduced_float_by_round_trip_alone() {
        let double = [0xfb, 0x43, 0xe0, 0, 0, 0, 0, 0, 1];
        assert_eq!(decode_scanned(&double), Err(Rejection::NotRoundTrip));
        assert_eq!(decode(&double), Err(Rejection::Float));
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
        assert_eq!(
            encode(&CBORCase::Negative(i64::MAX.unsigned_abs() + 1).into()),
            Err(Rejection::NegativeOutOfRange)
        );
    }

    /// AC6, third defect: `dcbor` keys a map by the encoded key, which it normalizes, so these
    /// two keys would become one entry and what is signed would differ from what was built.
    #[test]
    fn keys_equal_after_nfc_do_not_collapse_silently() {
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

    /// AC6, second defect: raw `dcbor` overflows the stack on 10 000 nested arrays. The head walk
    /// refuses them, and far deeper inputs, without recursion: this runs on a 64 KiB stack.
    #[test]
    fn deep_input_is_refused_without_recursion() {
        let refused = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(|| {
                let arrays = vec![0x81; 10_000];
                let deepest = vec![0x81; 4 * 1024 * 1024];
                let tags = [0xc0u8].repeat(4 * 1024 * 1024);
                // `dcbor` values are reference-counted and stay on this thread; the verdicts leave.
                let verdict = |bytes: &[u8]| decode(bytes).map(|_| ());
                (verdict(&arrays), verdict(&deepest), verdict(&tags))
            })
            .expect("thread")
            .join()
            .expect("no stack overflow");
        assert_eq!(refused.0, Err(Rejection::TooDeep));
        assert_eq!(refused.1, Err(Rejection::TooDeep));
        assert_eq!(refused.2, Err(Rejection::UnlistedTag(0)));
    }

    /// AC6, first defect: dCBOR requires an integral float in [-2^63, 2^64 - 1] to be encoded as an
    /// integer. `dcbor` 0.25.2 accepts 2^32 as a single, kept as a float, and 2^63 + 2048 as a
    /// double, silently reduced to the integer, so a second encoding of that integer exists.
    #[test]
    fn dcbor_accepts_integral_floats_the_dcbor_rules_forbid() {
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
        let half = [0xf9, 0x3e, 0x00];
        assert!(CBOR::try_from_data(half).is_ok());
        assert_eq!(decode(&half), Err(Rejection::Float));
        let below = [0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0];
        assert!(CBOR::try_from_data(below).is_ok());
        assert_eq!(decode(&below), Err(Rejection::NegativeOutOfRange));
        let lowest = [0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert!(decode(&lowest).is_ok());
    }

    /// AC6: non-NFC text is refused on encode, never normalized, and refused on decode.
    #[test]
    fn non_nfc_text_is_refused_never_normalized() {
        let decomposed = CBOR::from("cafe\u{301}");
        assert_eq!(encode(&decomposed), Err(Rejection::NonNfcText));
        // What raw `dcbor` would have hashed: the composed form, a different text.
        assert_eq!(
            decomposed.to_cbor_data(),
            CBOR::from("caf\u{e9}").to_cbor_data()
        );
        assert!(matches!(
            decode(&[0x66, b'c', b'a', b'f', b'e', 0xcc, 0x81]),
            Err(Rejection::NotDeterministic(_))
        ));
    }

    #[test]
    fn marks_new_in_the_core_unicode_version_are_ordered_on_decode() {
        // From random-00145 and fuzz-036083 of Story 1.9: U+1AE1 and U+1AD5 are combining marks
        // new in Unicode 17. A Core on older tables would leave them in this order; this Core's
        // tables require the other one, so it refuses these bytes (fails closed).
        for bytes in [
            &[0x66, 0x61, 0xe1, 0xab, 0xa1, 0xcc, 0xb7][..],
            &[0x66, 0x61, 0xe1, 0xab, 0x95, 0xcc, 0xac][..],
        ] {
            assert!(matches!(decode(bytes), Err(Rejection::NotDeterministic(_))));
        }
    }
}
