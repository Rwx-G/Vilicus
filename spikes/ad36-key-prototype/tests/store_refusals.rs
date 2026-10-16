//! `wrappers.db` is refused, never repaired, when its structure is not one this build
//! writes.

mod common;

use std::fs;

use ad36_key_prototype::{Error, Field, Store};
use common::{Household, founded, overwrite, stored_field};

/// `"VLCW" || format_version u8 || record_count u16 BE`.
const FILE_HEADER_LEN: usize = 7;
const FILE_VERSION_OFFSET: usize = 4;

fn household_with_alice() -> Household {
    let household = Household::new();
    let _ = founded(&household);
    household
}

#[test]
fn duplicated_record_is_refused() {
    let household = household_with_alice();
    let bytes = fs::read(household.store()).expect("read store");
    let record = &bytes[FILE_HEADER_LEN..];
    let duplicated = [
        &bytes[..FILE_VERSION_OFFSET + 1],
        &2u16.to_be_bytes()[..],
        record,
        record,
    ]
    .concat();
    fs::write(household.store(), duplicated).expect("write store");

    assert!(matches!(
        Store::load(&household.store()),
        Err(Error::MalformedStore("duplicate member identifier"))
    ));
}

#[test]
fn trailing_byte_is_refused() {
    let household = household_with_alice();
    let mut bytes = fs::read(household.store()).expect("read store");
    bytes.push(0);
    fs::write(household.store(), bytes).expect("write store");

    assert!(matches!(
        Store::load(&household.store()),
        Err(Error::MalformedStore("trailing bytes"))
    ));
}

#[test]
fn changed_field_algorithm_identifier_is_refused() {
    let household = household_with_alice();
    let honest = stored_field(&household.store(), b"alice", Field::MemberPublicKey);
    let mut relabelled = honest.clone();
    relabelled[1] ^= 0x07;
    overwrite(&household.store(), &honest, &relabelled);

    assert!(matches!(
        Store::load(&household.store()),
        Err(Error::UnsupportedFormat)
    ));
}

#[test]
fn file_version_2_is_refused() {
    let household = household_with_alice();
    let mut bytes = fs::read(household.store()).expect("read store");
    bytes[FILE_VERSION_OFFSET] = 2;
    fs::write(household.store(), bytes).expect("write store");

    assert!(matches!(
        Store::load(&household.store()),
        Err(Error::UnsupportedFormat)
    ));
}
