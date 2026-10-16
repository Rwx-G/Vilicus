//! Holds the byte layouts documented in `README.md` to the constants in the code, so the
//! documented construction cannot drift from the one the tests exercise.

use ad36_key_prototype::{Field, alg, label};

const README: &str = include_str!("../README.md");

#[test]
fn every_label_is_documented() {
    for label in label::ALL {
        let label = std::str::from_utf8(label).expect("labels are ASCII");
        assert!(README.contains(&format!("\"{label}")), "{label} missing");
    }
}

#[test]
fn every_algorithm_identifier_is_documented() {
    for alg_id in alg::ALL {
        let row = format!("| `0x{alg_id:02x}` |");
        assert!(README.contains(&row), "{row} missing");
    }
}

#[test]
fn every_fixed_field_length_is_documented() {
    for field in Field::ORDER {
        if let Some(len) = field.encoded_len() {
            let row = format!("| `{field:?}` | {len} |");
            assert!(README.contains(&row), "{row} missing");
        }
    }
}
