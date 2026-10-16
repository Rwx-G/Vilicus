//! The seeded corpus of valid values, in three families:
//!
//! - `boundary`: every head length boundary, string and container lengths, map key orderings
//!   that tell bytewise sorting from length-first sorting, normalization cases and the depth
//!   bound, built deterministically from the profile constants;
//! - `shaped`: maps shaped like the hashed and signed messages AD-13 names (light confirmation,
//!   step-up challenge, audit parameters), with random contents. `vilicus-proto` does not exist
//!   yet, so these model the expected shapes; they are not the real types;
//! - `random`: recursively generated values of every kind.
//!
//! Valid text is in NFC. [`encode_invalid`] lists the values the profile encoder must refuse.

use std::collections::BTreeSet;

use serde_json::{Value, json};
use unicode_normalization::{UnicodeNormalization, is_nfc};

use crate::{notation, profile, rng::Rng};

/// One corpus value before encoding.
pub struct Item {
    pub id: String,
    pub family: &'static str,
    pub value: Value,
}

/// Smallest and largest integer the profile allows.
pub const INT_MIN: i128 = i64::MIN as i128;
pub const INT_MAX: i128 = u64::MAX as i128;

pub fn int(value: i128) -> Value {
    json!({ "int": value.to_string() })
}

pub fn bytes(value: &[u8]) -> Value {
    json!({ "bytes": hex::encode(value) })
}

/// Text as a valid value carries it: in NFC, which the profile encoder requires.
pub fn text(value: &str) -> Value {
    raw_text(value.nfc().collect::<String>().as_str())
}

/// Text exactly as given, for the values the encoder must refuse.
pub fn raw_text(value: &str) -> Value {
    json!({ "text": value })
}

pub fn array(items: Vec<Value>) -> Value {
    json!({ "array": items })
}

pub fn map(entries: Vec<(Value, Value)>) -> Value {
    json!({ "map": entries.into_iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>() })
}

pub fn simple(name: &str) -> Value {
    json!({ "simple": name })
}

/// Generates the whole corpus.
pub fn generate(seed: u64, shaped: usize, random: usize) -> Vec<Item> {
    let mut items = Vec::new();
    for (index, value) in boundary_values().into_iter().enumerate() {
        items.push(Item {
            id: format!("boundary-{index:05}"),
            family: "boundary",
            value,
        });
    }
    let mut rng = Rng::new(seed);
    for index in 0..shaped {
        items.push(Item {
            id: format!("shaped-{index:05}"),
            family: "shaped",
            value: shaped_value(&mut rng),
        });
    }
    for index in 0..random {
        items.push(Item {
            id: format!("random-{index:05}"),
            family: "random",
            value: random_value(&mut rng, 3),
        });
    }
    items
}

/// Integers at and around every head length boundary, both signs, within the profile range.
fn boundary_integers() -> BTreeSet<i128> {
    let bases: [i128; 15] = [
        0,
        23,
        24,
        255,
        256,
        65_535,
        65_536,
        (1 << 32) - 1,
        1 << 32,
        (1 << 53) - 1,
        1 << 53,
        (1 << 53) + 1,
        (1 << 63) - 1,
        1 << 63,
        (1 << 64) - 1,
    ];
    let mut values = BTreeSet::new();
    for base in bases {
        for delta in -1..=1 {
            for candidate in [base + delta, -1 - (base + delta)] {
                if (INT_MIN..=INT_MAX).contains(&candidate) {
                    values.insert(candidate);
                }
            }
        }
    }
    values
}

/// Texts whose NFC form differs from the input, or that are easy to get wrong in UTF-8.
pub const SPECIAL_TEXTS: &[&str] = &[
    "",
    "\u{feff}leading byte order mark",
    "nul\u{0}inside",
    "\u{7f}\u{80}\u{7ff}\u{800}\u{ffff}\u{10000}\u{10ffff}",
    "caf\u{e9}",
    "cafe\u{301}",
    "\u{212b}ngstr\u{f6}m",
    "\u{2126}hm",
    "\u{1100}\u{1161}\u{11a8}",
    "a\u{301}\u{316}",
    "a\u{316}\u{301}",
    "\u{958}",
    "\u{fb2c}",
    "\u{1f600}\u{1f1eb}\u{1f1f7}",
    "\u{65e5}\u{672c}\u{8a9e}",
    "\u{fdd0}\u{fffe}\u{1fffe}",
    "\u{e000}\u{f8ff}\u{f0000}",
    "\u{e01}\u{e48}\u{e33}",
];

fn boundary_values() -> Vec<Value> {
    let mut values: Vec<Value> = boundary_integers().into_iter().map(int).collect();

    // The two-byte to four-byte length head boundary (65 535 to 65 536) is crossed with text
    // only, which keeps the committed corpus small; the head logic is the same for bytes.
    let lengths = [0usize, 1, 23, 24, 25, 255, 256, 257, 65_535, 65_536];
    for length in lengths {
        if length < 65_535 {
            values.push(bytes(&(0..length).map(|i| i as u8).collect::<Vec<_>>()));
        }
        values.push(text(&"a".repeat(length)));
    }
    // Byte lengths at a boundary reached with two, three and four byte characters.
    for (character, width) in [('\u{e9}', 2usize), ('\u{20ac}', 3), ('\u{1f600}', 4)] {
        for length in [24usize, 256] {
            values.push(text(&character.to_string().repeat(length / width + 1)));
        }
    }
    values.extend(SPECIAL_TEXTS.iter().map(|special| text(special)));

    for length in [0usize, 1, 23, 24, 255, 256] {
        values.push(array((0..length).map(|i| int(i as i128)).collect()));
        values.push(map((0..length)
            .map(|i| (int(i as i128), simple("null")))
            .collect()));
    }
    for name in ["false", "true", "null"] {
        values.push(simple(name));
    }

    // Key orderings: generated in reverse canonical order where it matters. 24 sorts before -1
    // bytewise (0x18 < 0x20) but after it length-first; "b" sorts before "aa" either way.
    let orderings: Vec<Vec<Value>> = vec![
        vec![int(-1), int(24)],
        vec![text("aa"), text("b")],
        vec![text(&"x".repeat(24)), text(&"y".repeat(23))],
        vec![text("z"), text("\u{e9}"), text("B"), text("a")],
        vec![
            map(vec![]),
            array(vec![]),
            text(""),
            bytes(&[]),
            int(-1),
            int(0),
            simple("null"),
            simple("true"),
            simple("false"),
        ],
        vec![
            int(INT_MAX),
            int(INT_MIN),
            int(65_536),
            int(-65_537),
            int(255),
        ],
        vec![
            array(vec![int(1), int(2)]),
            array(vec![int(1)]),
            map(vec![(int(1), int(1))]),
        ],
        vec![text("cafe\u{301}x"), text("caf\u{e9}")],
    ];
    for keys in orderings {
        values.push(map(keys.into_iter().map(|key| (key, int(0))).collect()));
    }

    // The depth bound, reached with arrays, maps and both alternating.
    values.push(nest(profile::MAX_DEPTH, |inner, _| array(vec![inner])));
    values.push(nest(profile::MAX_DEPTH, |inner, _| {
        map(vec![(text("k"), inner)])
    }));
    values.push(nest(profile::MAX_DEPTH, |inner, level| {
        if level % 2 == 0 {
            array(vec![int(level as i128), inner])
        } else {
            map(vec![(int(level as i128), inner)])
        }
    }));
    values
}

/// Values the profile encoder must refuse, with the rule each breaks: every non-NFC special
/// text, alone and as a map key next to its NFC form (the two would collapse into one entry),
/// containers one level over the depth bound, and the integer below the range.
pub fn encode_invalid() -> Vec<(String, Value)> {
    let mut values = Vec::new();
    for (index, special) in SPECIAL_TEXTS.iter().enumerate() {
        if is_nfc(special) {
            continue;
        }
        values.push((format!("non_nfc_text_{index}"), raw_text(special)));
        values.push((
            format!("keys_equal_after_nfc_{index}"),
            map(vec![(text(special), int(1)), (raw_text(special), int(2))]),
        ));
    }
    let over = profile::MAX_DEPTH + 1;
    values.push((
        "arrays_over_depth".to_owned(),
        nest(over, |inner, _| array(vec![inner])),
    ));
    values.push((
        "maps_over_depth".to_owned(),
        nest(over, |inner, _| map(vec![(text("k"), inner)])),
    ));
    values.push(("int_below_range".to_owned(), int(INT_MIN - 1)));
    values
}

/// `depth` nested containers around an empty array, the empty array counted.
fn nest(depth: usize, wrap: impl Fn(Value, usize) -> Value) -> Value {
    let mut value = array(vec![]);
    for level in 1..depth {
        value = wrap(value, level);
    }
    value
}

fn random_int(rng: &mut Rng) -> i128 {
    let magnitude: u64 = match rng.below(6) {
        0 => rng.below(24),
        1 => 24 + rng.below(256 - 24),
        2 => 256 + rng.below(65_536 - 256),
        3 => 65_536 + rng.below((1 << 32) - 65_536),
        4 => (1 << 32) + rng.below(u64::MAX - (1 << 32)),
        _ => *rng.pick(&[0, 23, 24, 255, 256, 65_535, 65_536, u64::MAX, 1 << 63]),
    };
    if rng.chance(1, 2) {
        i128::from(magnitude)
    } else {
        (-1 - i128::from(magnitude)).max(INT_MIN)
    }
}

/// A random scalar value from a Unicode class chosen to stress UTF-8 and normalization.
fn random_char(rng: &mut Rng) -> char {
    let ranges: &[(u32, u32)] = &[
        (0x20, 0x7e),
        (0x00, 0x1f),
        (0xa0, 0x24f),
        (0x300, 0x36f),
        (0x370, 0x3ff),
        (0x591, 0x5c7),
        (0x900, 0x97f),
        (0x1100, 0x11ff),
        (0xac00, 0xd7a3),
        (0x1e00, 0x1eff),
        (0x2100, 0x214f),
        (0x4e00, 0x9fff),
        (0xf900, 0xfaff),
        (0xfb00, 0xfb4f),
        (0x1d15e, 0x1d1c0),
        (0x1f300, 0x1faff),
        (0x0, 0x10ffff),
    ];
    let (low, high) = *rng.pick(ranges);
    loop {
        let candidate = low + rng.below(u64::from(high - low + 1)) as u32;
        if let Some(character) = char::from_u32(candidate) {
            return character;
        }
    }
}

fn random_text(rng: &mut Rng) -> String {
    if rng.chance(1, 10) {
        return (*rng.pick(SPECIAL_TEXTS)).to_owned();
    }
    let length = match rng.below(10) {
        0..=6 => rng.below(12),
        7 | 8 => rng.below(40),
        _ => 40 + rng.below(60),
    };
    (0..length).map(|_| random_char(rng)).collect()
}

fn random_scalar(rng: &mut Rng) -> Value {
    match rng.below(10) {
        0..=2 => int(random_int(rng)),
        3 => {
            let length = match rng.below(8) {
                0..=5 => rng.below(32),
                6 => 20 + rng.below(16),
                _ => 200 + rng.below(100),
            };
            bytes(&rng.bytes(length as usize))
        }
        4..=7 => text(&random_text(rng)),
        _ => simple(rng.pick::<&str>(&["false", "true", "null"])),
    }
}

/// Map keys are mostly text and integers, as closed types will use, with a few of every kind.
fn random_key(rng: &mut Rng, depth_left: u32) -> Value {
    match rng.below(20) {
        0..=9 => text(&random_text(rng)),
        10..=15 => int(random_int(rng)),
        16 if depth_left > 0 => random_value(rng, 0),
        17 if depth_left > 0 => array(vec![random_scalar(rng)]),
        _ => random_scalar(rng),
    }
}

/// Adds `(key, value)` unless the key encodes to the same canonical bytes as an earlier one.
fn push_unique(
    entries: &mut Vec<(Value, Value)>,
    seen: &mut BTreeSet<Vec<u8>>,
    key: Value,
    value: Value,
) {
    let encoded = notation::to_cbor(&key)
        .expect("generated keys are valid notation")
        .to_cbor_data();
    if seen.insert(encoded) {
        entries.push((key, value));
    }
}

pub fn random_value(rng: &mut Rng, depth_left: u32) -> Value {
    if depth_left == 0 || rng.chance(2, 5) {
        return random_scalar(rng);
    }
    // A long container crosses the one-byte length boundary (24) and holds scalars only, which
    // keeps the corpus size bounded.
    let (length, child_depth) = if rng.chance(1, 15) {
        (22 + rng.below(4), 0)
    } else {
        (rng.below(6), depth_left - 1)
    };
    if rng.chance(1, 2) {
        array(
            (0..length)
                .map(|_| random_value(rng, child_depth))
                .collect(),
        )
    } else {
        let mut entries = Vec::new();
        let mut seen = BTreeSet::new();
        for _ in 0..length {
            let key = random_key(rng, child_depth);
            let value = random_value(rng, child_depth);
            push_unique(&mut entries, &mut seen, key, value);
        }
        map(entries)
    }
}

fn random_id(rng: &mut Rng) -> Value {
    bytes(&rng.bytes(16))
}

fn shaped_value(rng: &mut Rng) -> Value {
    let issued_at = 1_700_000_000_000 + i128::from(rng.below(1 << 40));
    match rng.below(3) {
        0 => {
            let mut params = Vec::new();
            let mut seen = BTreeSet::new();
            for _ in 0..rng.below(8) {
                let key = text(&random_text(rng));
                let value = random_value(rng, 2);
                push_unique(&mut params, &mut seen, key, value);
            }
            map(vec![
                (text("v"), int(1)),
                (text("kind"), text("light_confirmation")),
                (text("request_id"), random_id(rng)),
                (text("call_id"), random_id(rng)),
                (text("member"), random_id(rng)),
                (
                    text("action"),
                    text(rng.pick::<&str>(&[
                        "tasks.create",
                        "calendar.update",
                        "budget.record",
                        "meals.plan",
                    ])),
                ),
                (text("tier"), int(i128::from(rng.below(3)))),
                (text("issued_at"), int(issued_at)),
                (text("expires_at"), int(issued_at + 86_400_000)),
                (
                    text("taint"),
                    text(rng.pick::<&str>(&["clean", "external", "personal"])),
                ),
                (text("params"), map(params)),
            ])
        }
        1 => map(vec![
            (text("v"), int(1)),
            (text("kind"), text("step_up")),
            (text("request_id"), random_id(rng)),
            (text("request_hash"), bytes(&rng.bytes(32))),
            (text("session"), random_id(rng)),
            (text("counter"), int(i128::from(rng.next_u64()))),
            (text("issued_at"), int(issued_at)),
        ]),
        _ => {
            let parameters = (0..rng.below(6))
                .map(|_| array(vec![text(&random_text(rng)), random_scalar(rng)]))
                .collect();
            map(vec![
                (int(0), int(1)),
                (int(1), text("audit_params")),
                (int(2), random_id(rng)),
                (int(3), array(parameters)),
                (int(-1), int(random_int(rng))),
            ])
        }
    }
}
