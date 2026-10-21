//! Key types, key wrappers and key derivation functions of Vilicus, and the Core's hashing.
//!
//! A dependency of `vilicus-core` only, so no module, adapter or test crate can name a key type
//! (`doc/architecture-spine.md`, AD-3 and AD-4). Unsafe code is allowed here for memory locking,
//! per block and with a `// SAFETY:` comment (D140).
//!
//! Every primitive comes from `aws-lc-rs`, the cryptographic library of the spine's Stack, with
//! its `aws-lc-sys` backend (D28: no home-made cryptography).

use vilicus_types::SHA256_LEN;

/// The SHA-256 digest of `data`: the hash the Core compares with each migration's frozen hash
/// before the migration runs (spine AD-23, D21).
///
/// ```
/// // FIPS 180-2, appendix B.1.
/// assert_eq!(
///     vilicus_crypto::sha256(b"abc"),
///     vilicus_types::sha256_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
/// );
/// ```
pub fn sha256(data: &[u8]) -> [u8; SHA256_LEN] {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data);
    let mut bytes = [0; SHA256_LEN];
    bytes.copy_from_slice(digest.as_ref());
    bytes
}

#[cfg(test)]
mod tests {
    use vilicus_types::sha256_hex;

    use super::*;

    /// The FIPS 180-2 vectors of appendix B: the empty string, a two-block message and the one
    /// million `a`s, which crosses many blocks.
    #[test]
    fn sha256_matches_the_fips_vectors() {
        let cases: [(Vec<u8>, &str); 3] = [
            (
                Vec::new(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".to_vec(),
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (
                vec![b'a'; 1_000_000],
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
            ),
        ];
        for (data, hex) in cases {
            assert_eq!(sha256(&data), sha256_hex(hex), "{} bytes", data.len());
        }
    }
}
