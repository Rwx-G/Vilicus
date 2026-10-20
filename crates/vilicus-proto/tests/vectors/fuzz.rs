//! The fuzzed set: mutations of canonical corpus encodings.
//!
//! Targeted mutations each break one profile rule (non-minimal head, indefinite length,
//! misordered or duplicate map key, float, tag, trailing or missing bytes, invalid simple value,
//! integer below -2^63, non-NFC text, invalid UTF-8) and must be refused. Blind mutations flip,
//! replace, insert or delete one byte; their verdict is whatever the Rust profile decides, and
//! the TypeScript decoder has to reach the same verdict.

use vilicus_proto::profile;

use super::rng::Rng;

/// One mutated input with the Rust verdict.
pub struct Case {
    pub id: String,
    pub kind: &'static str,
    pub base: String,
    pub bytes: Vec<u8>,
    pub must_reject: bool,
    pub verdict: Result<(), profile::Rejection>,
}

/// The extent of one data item inside canonical bytes.
#[derive(Clone, Copy)]
struct Span {
    start: usize,
    head_len: usize,
    major: u8,
    argument: u64,
    end: usize,
}

fn head_len(argument: u64) -> usize {
    match argument {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// Encodes a head with an argument in exactly `width` extra bytes (0 for the short form).
fn head_with_width(major: u8, argument: u64, width: usize) -> Vec<u8> {
    let additional = match width {
        0 => argument as u8,
        1 => 24,
        2 => 25,
        4 => 26,
        _ => 27,
    };
    let mut out = vec![(major << 5) | additional];
    out.extend_from_slice(&argument.to_be_bytes()[8 - width..]);
    out
}

fn minimal_head(major: u8, argument: u64) -> Vec<u8> {
    let width = match head_len(argument) {
        1 => 0,
        2 => 1,
        3 => 2,
        5 => 4,
        _ => 8,
    };
    head_with_width(major, argument, width)
}

/// Lists every item of canonical bytes, parents before children.
fn spans(bytes: &[u8]) -> Vec<Span> {
    let mut out = Vec::new();
    walk(bytes, 0, &mut out);
    out
}

fn walk(bytes: &[u8], start: usize, out: &mut Vec<Span>) -> usize {
    let initial = bytes[start];
    let major = initial >> 5;
    let additional = initial & 0x1f;
    let width = match additional {
        0..=23 => 0,
        24 => 1,
        25 => 2,
        26 => 4,
        _ => 8,
    };
    let argument = if width == 0 {
        u64::from(additional)
    } else {
        bytes[start + 1..start + 1 + width]
            .iter()
            .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte))
    };
    let head = 1 + width;
    let index = out.len();
    out.push(Span {
        start,
        head_len: head,
        major,
        argument,
        end: 0,
    });
    let mut pos = start + head;
    match major {
        2 | 3 => pos += argument as usize,
        4 => {
            for _ in 0..argument {
                pos = walk(bytes, pos, out);
            }
        }
        5 => {
            for _ in 0..argument * 2 {
                pos = walk(bytes, pos, out);
            }
        }
        6 => pos = walk(bytes, pos, out),
        _ => {}
    }
    out[index].end = pos;
    pos
}

fn splice(bytes: &[u8], from: usize, to: usize, with: &[u8]) -> Vec<u8> {
    let mut out = bytes[..from].to_vec();
    out.extend_from_slice(with);
    out.extend_from_slice(&bytes[to..]);
    out
}

/// Direct children of a container span, in order.
fn children(all: &[Span], parent: &Span) -> Vec<Span> {
    let mut out = Vec::new();
    let mut pos = parent.start + parent.head_len;
    for span in all {
        if span.start == pos && pos < parent.end && span.start > parent.start {
            out.push(*span);
            pos = span.end;
        }
    }
    out
}

const TARGETED: &[&str] = &[
    "non_minimal_head",
    "indefinite_length",
    "misordered_key",
    "duplicate_key",
    "float_for_int",
    "tag",
    "trailing_bytes",
    "truncated",
    "invalid_simple",
    "negative_below_range",
    "non_nfc_text",
    "invalid_utf8",
];

const BLIND: &[&str] = &["flip_bit", "replace_byte", "insert_byte", "delete_byte"];

const NON_NFC_TEXTS: &[&[u8]] = &[
    b"\x63\x65\xcc\x81",
    b"\x65\x61\xcc\x81\xcc\x96",
    b"\x63\xe2\x84\xab",
    b"\x66\xe1\x84\x80\xe1\x85\xa1",
];

const INVALID_UTF8_TEXTS: &[&[u8]] = &[
    b"\x61\xff",
    b"\x62\xc0\x80",
    b"\x63\xed\xa0\x80",
    b"\x64\xf4\x90\x80\x80",
    b"\x62\xc3\x28",
    b"\x61\x80",
    b"\x62\xe2\x82",
];

const INVALID_SIMPLES: &[&[u8]] = &[
    b"\xf7",
    b"\xe0",
    b"\xf0",
    b"\xf3",
    b"\xf8\x18",
    b"\xf8\x20",
    b"\xf8\xff",
    b"\xfc",
    b"\xff",
];

/// Applies one targeted mutation, or returns `None` when the base has no item it applies to.
fn targeted(kind: &str, bytes: &[u8], rng: &mut Rng) -> Option<Vec<u8>> {
    let all = spans(bytes);
    let any = *rng.pick(&all);
    match kind {
        "non_minimal_head" => {
            let candidates: Vec<&Span> = all
                .iter()
                .filter(|s| s.major != 7 && s.head_len < 9)
                .collect();
            if candidates.is_empty() {
                return None;
            }
            let span = **rng.pick(&candidates);
            let wider: Vec<usize> = [1usize, 2, 4, 8]
                .into_iter()
                .filter(|width| width + 1 > span.head_len)
                .collect();
            let width = *rng.pick(&wider);
            let head = head_with_width(span.major, span.argument, width);
            Some(splice(bytes, span.start, span.start + span.head_len, &head))
        }
        "indefinite_length" => {
            let candidates: Vec<&Span> =
                all.iter().filter(|s| (2..=5).contains(&s.major)).collect();
            if candidates.is_empty() {
                return None;
            }
            let span = **rng.pick(&candidates);
            let mut replacement = vec![(span.major << 5) | 31];
            if span.major <= 3 {
                // One definite chunk inside the indefinite string.
                replacement.extend_from_slice(&bytes[span.start..span.end]);
            } else {
                replacement.extend_from_slice(&bytes[span.start + span.head_len..span.end]);
            }
            replacement.push(0xff);
            Some(splice(bytes, span.start, span.end, &replacement))
        }
        "misordered_key" | "duplicate_key" => {
            let maps: Vec<&Span> = all
                .iter()
                .filter(|s| {
                    s.major == 5 && s.argument >= if kind == "misordered_key" { 2 } else { 1 }
                })
                .collect();
            if maps.is_empty() {
                return None;
            }
            let map = **rng.pick(&maps);
            let members = children(&all, &map);
            let entries: Vec<(usize, usize)> = members
                .chunks(2)
                .map(|pair| (pair[0].start, pair[1].end))
                .collect();
            let body = if kind == "misordered_key" {
                let i = rng.index(entries.len() - 1);
                let mut order: Vec<usize> = (0..entries.len()).collect();
                order.swap(i, i + 1);
                order
                    .iter()
                    .flat_map(|&e| bytes[entries[e].0..entries[e].1].to_vec())
                    .collect::<Vec<u8>>()
            } else {
                let i = rng.index(entries.len());
                let mut out = Vec::new();
                for (e, (from, to)) in entries.iter().enumerate() {
                    out.extend_from_slice(&bytes[*from..*to]);
                    if e == i {
                        out.extend_from_slice(&bytes[*from..*to]);
                    }
                }
                out
            };
            let count = if kind == "misordered_key" {
                map.argument
            } else {
                map.argument + 1
            };
            let mut replacement = minimal_head(5, count);
            replacement.extend_from_slice(&body);
            Some(splice(bytes, map.start, map.end, &replacement))
        }
        "float_for_int" => {
            let ints: Vec<&Span> = all.iter().filter(|s| s.major <= 1).collect();
            if ints.is_empty() {
                return None;
            }
            let span = **rng.pick(&ints);
            let value = if span.major == 0 {
                span.argument as f64
            } else {
                -1.0 - span.argument as f64
            };
            let mut float = Vec::new();
            if rng.chance(1, 2) && (value as f32) as f64 == value {
                float.push(0xfa);
                float.extend_from_slice(&(value as f32).to_bits().to_be_bytes());
            } else {
                float.push(0xfb);
                float.extend_from_slice(&value.to_bits().to_be_bytes());
            }
            Some(splice(bytes, span.start, span.end, &float))
        }
        "tag" => {
            let tag = *rng.pick(&[0u64, 1, 2, 3, 24, 32, 258, 1000, 55_799, 1 << 32]);
            let head = minimal_head(6, tag);
            Some(splice(bytes, any.start, any.start, &head))
        }
        "trailing_bytes" => {
            let mut out = bytes.to_vec();
            let extra = 1 + rng.below(3) as usize;
            out.extend_from_slice(&rng.bytes(extra));
            Some(out)
        }
        "truncated" => {
            let cut = 1 + rng.index(bytes.len());
            Some(bytes[..bytes.len() - cut].to_vec())
        }
        "invalid_simple" => Some(splice(
            bytes,
            any.start,
            any.end,
            rng.pick::<&[u8]>(INVALID_SIMPLES),
        )),
        "negative_below_range" => {
            let magnitude = (1u64 << 63) + rng.below(1 << 63);
            Some(splice(
                bytes,
                any.start,
                any.end,
                &head_with_width(1, magnitude, 8),
            ))
        }
        "non_nfc_text" => Some(splice(
            bytes,
            any.start,
            any.end,
            rng.pick::<&[u8]>(NON_NFC_TEXTS),
        )),
        "invalid_utf8" => Some(splice(
            bytes,
            any.start,
            any.end,
            rng.pick::<&[u8]>(INVALID_UTF8_TEXTS),
        )),
        _ => unreachable!("unknown targeted mutation {kind}"),
    }
}

fn blind(kind: &str, bytes: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let at = rng.index(out.len());
    match kind {
        "flip_bit" => out[at] ^= 1 << rng.below(8),
        "replace_byte" => out[at] = rng.next_u64() as u8,
        "insert_byte" => out.insert(rng.index(out.len() + 1), rng.next_u64() as u8),
        _ => {
            out.remove(at);
        }
    }
    out
}

/// Inputs one level deeper than [`profile::MAX_DEPTH`], `deep` levels of arrays, maps and
/// tags that would exhaust a recursive decoder's stack, and one item followed by `deep`
/// array heads that only a trailing-bytes check refuses before any decoding.
fn depth_cases(deep: usize) -> Vec<(&'static str, Vec<u8>)> {
    let over = profile::MAX_DEPTH + 1;
    let nested = |depth: usize, open: &[u8], innermost: &[u8]| {
        let mut bytes = open.repeat(depth - 1);
        bytes.extend_from_slice(innermost);
        bytes
    };
    let mut trailing = vec![0x00];
    trailing.extend(std::iter::repeat_n(0x81, deep));
    vec![
        ("too_deep", nested(over, &[0x81], &[0x80])),
        ("too_deep", nested(over, &[0xa1, 0x00], &[0xa0])),
        ("too_deep", nested(over, &[0x82, 0x00], &[0x80])),
        ("too_deep", nested(deep, &[0x81], &[0x80])),
        ("too_deep", nested(deep, &[0xa1, 0x00], &[0xa0])),
        ("too_deep", nested(deep, &[0xc0], &[0x00])),
        ("trailing_deep_heads", trailing),
    ]
}

/// Generates the depth cases, then `count` mutations of the given canonical encodings, half
/// targeted, half blind.
pub fn generate(seed: u64, count: usize, deep: usize, bases: &[(String, Vec<u8>)]) -> Vec<Case> {
    let mut rng = Rng::new(seed);
    let mut cases = Vec::with_capacity(count);
    for (kind, bytes) in depth_cases(deep) {
        let verdict = profile::decode(&bytes).map(|_| ());
        cases.push(Case {
            id: format!("fuzz-{:06}", cases.len()),
            kind,
            base: "derived".to_owned(),
            bytes,
            must_reject: true,
            verdict,
        });
    }
    let total = cases.len() + count;
    while cases.len() < total {
        let (base_id, base) = rng.pick(bases);
        let (kind, mutated, must_reject) = if rng.chance(1, 2) {
            let kind = *rng.pick(TARGETED);
            match targeted(kind, base, &mut rng) {
                Some(mutated) => (kind, mutated, true),
                None => continue,
            }
        } else {
            let kind = *rng.pick(BLIND);
            (kind, blind(kind, base, &mut rng), false)
        };
        let verdict = profile::decode(&mutated).map(|_| ());
        cases.push(Case {
            id: format!("fuzz-{:06}", cases.len()),
            kind,
            base: base_id.clone(),
            bytes: mutated,
            must_reject,
            verdict,
        });
    }
    cases
}
