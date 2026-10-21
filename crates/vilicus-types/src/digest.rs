//! SHA-256 digests written out in source: the frozen hash of each migration (spine AD-23, D21),
//! which a declaration states and the Core compares with the digest of the migration's SQL.

/// The length of a SHA-256 digest, in bytes.
pub const SHA256_LEN: usize = 32;

/// The digest a SHA-256 digest's 64 lowercase hexadecimal digits name, as a migration states its
/// frozen hash in a `const` item. This reads the digest; it computes none, which the Core does.
///
/// ```
/// use vilicus_types::sha256_hex;
///
/// // SHA-256 of the empty string.
/// const EMPTY: [u8; 32] =
///     sha256_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
/// assert_eq!(EMPTY[0], 0xe3);
/// assert_eq!(EMPTY[31], 0x55);
/// ```
///
/// # Panics
///
/// When `hex` is not exactly 64 lowercase hexadecimal digits; in a `const` item that is a build
/// error, so a malformed frozen hash never reaches a binary.
pub const fn sha256_hex(hex: &str) -> [u8; SHA256_LEN] {
    let digits = hex.as_bytes();
    assert!(
        digits.len() == 2 * SHA256_LEN,
        "a SHA-256 digest is 64 hexadecimal digits"
    );
    let mut digest = [0; SHA256_LEN];
    let mut index = 0;
    while index < SHA256_LEN {
        digest[index] = (nibble(digits[2 * index]) << 4) | nibble(digits[2 * index + 1]);
        index += 1;
    }
    digest
}

const fn nibble(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        _ => panic!("a SHA-256 digest is lowercase hexadecimal digits"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_digit_reads_as_its_value() {
        let digest = sha256_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        assert_eq!(
            digest[..8],
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
        assert_eq!(digest[..16], digest[16..]);
    }

    #[test]
    fn a_digest_of_another_shape_is_refused() {
        let valid = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let refused = [
            String::new(),
            valid[..63].to_owned(),
            format!("{valid}0"),
            valid.to_ascii_uppercase(),
            format!("{}g", &valid[..63]),
            format!("{} ", &valid[..63]),
        ];
        for hex in refused {
            assert!(
                std::panic::catch_unwind(|| sha256_hex(&hex)).is_err(),
                "{hex:?}"
            );
        }
    }
}
