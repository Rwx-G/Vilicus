//! Names of TLS supported groups (IANA "TLS Supported Groups" registry), as they appear in logs.

/// IANA code point of the hybrid group D27 prefers.
pub const X25519MLKEM768: u16 = 0x11ec;
/// IANA code point of the classical fallback group.
pub const X25519: u16 = 0x001d;

/// Returns the registry name of a group code point, `GREASE` for RFC 8701 reserved values, and
/// the hexadecimal code point for anything this spike does not name.
pub fn name(code: u16) -> String {
    let known = match code {
        0x0017 => "secp256r1",
        0x0018 => "secp384r1",
        0x0019 => "secp521r1",
        X25519 => "X25519",
        0x001e => "X448",
        0x0100 => "ffdhe2048",
        0x0101 => "ffdhe3072",
        0x0102 => "ffdhe4096",
        0x0103 => "ffdhe6144",
        0x0104 => "ffdhe8192",
        0x0200 => "MLKEM512",
        0x0201 => "MLKEM768",
        0x0202 => "MLKEM1024",
        0x11eb => "SecP256r1MLKEM768",
        X25519MLKEM768 => "X25519MLKEM768",
        0x11ed => "SecP384r1MLKEM1024",
        // The pre-standard draft codepoint some older browsers still send.
        0x6399 => "X25519Kyber768Draft00",
        _ if is_grease(code) => "GREASE",
        _ => return format!("0x{code:04x}"),
    };
    known.to_owned()
}

/// Joins group names with commas, or `-` for an empty list, so a log field never is empty.
pub fn join(codes: &[u16]) -> String {
    if codes.is_empty() {
        return "-".to_owned();
    }
    codes
        .iter()
        .map(|&code| name(code))
        .collect::<Vec<_>>()
        .join(",")
}

/// RFC 8701: both bytes equal, low nibble 0xa.
fn is_grease(code: u16) -> bool {
    let [high, low] = code.to_be_bytes();
    high == low && low & 0x0f == 0x0a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_the_hybrid_and_classical_groups() {
        assert_eq!(name(X25519MLKEM768), "X25519MLKEM768");
        assert_eq!(name(X25519), "X25519");
        assert_eq!(name(0x0017), "secp256r1");
    }

    #[test]
    fn names_grease_and_unknown_values() {
        assert_eq!(name(0x0a0a), "GREASE");
        assert_eq!(name(0xfafa), "GREASE");
        assert_eq!(name(0x0a0b), "0x0a0b");
    }

    #[test]
    fn joins_with_commas_and_marks_empty_lists() {
        assert_eq!(join(&[X25519MLKEM768, X25519]), "X25519MLKEM768,X25519");
        assert_eq!(join(&[]), "-");
    }
}
