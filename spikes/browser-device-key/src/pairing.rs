//! OPAQUE pairing codes (D35, AD-21): the cipher suite shared with `@serenity-kit/opaque`, the
//! code format, and the binding of a new browser's public key to the OPAQUE session key.
//!
//! The issuer (a paired browser, or the Core for `vilicus device pair`) registers the code's
//! secret as an OPAQUE password under a fresh credential identifier. The new browser runs an
//! OPAQUE login with the secret; both ends obtain the same session key only if the browser knew
//! the secret, and nothing on the wire lets an observer test a guess offline. The browser then
//! sends its device public key with an HMAC under a key derived from that session key, so a
//! relay that swaps the public key cannot produce a matching tag.

use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Salt};
use aws_lc_rs::hmac;
use opaque_ke::argon2::{Algorithm, Argon2, Params, Version};
use opaque_ke::{CipherSuite, Ristretto255, TripleDh};

/// The cipher suite of `@serenity-kit/opaque` 1.1.0 (its `DefaultCipherSuite` without the `p256`
/// feature): ristretto255 OPRF, 3DH over ristretto255 with SHA-512, Argon2id as the KSF.
pub struct Suite;

impl CipherSuite for Suite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

/// The KSF the browser package applies by default (`memory-constrained`: Argon2id, 64 MiB,
/// 3 passes, 4 lanes, RFC 9106 section 4 second recommendation). Only the client runs it; the
/// Core needs it only when it registers a code itself (`vilicus device pair`) and in tests.
pub fn client_ksf() -> Argon2<'static> {
    let params = Params::new(1 << 16, 3, 4, None).expect("constant Argon2id parameters are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Domain label of the public-key binding.
pub const BIND_LABEL: &[u8] = b"vilicus/v1/pair/bind";
/// Prefix of the OPAQUE credential identifier of a pairing.
pub const CREDENTIAL_LABEL: &[u8] = b"vilicus/v1/pair/";

/// Digits of the public handle that names a pending pairing.
pub const HANDLE_DIGITS: usize = 3;
/// Digits of the secret that is the OPAQUE password.
pub const SECRET_DIGITS: usize = 8;

/// A pairing code as typed: the handle, then the secret, as `HHH-SSSS-SSSS`.
#[derive(Clone, PartialEq, Eq)]
pub struct Code {
    pub handle: String,
    pub secret: String,
}

impl Code {
    /// Parses a typed code, ignoring spaces and hyphens.
    pub fn parse(typed: &str) -> Option<Self> {
        let digits: String = typed.chars().filter(|c| *c != '-' && *c != ' ').collect();
        if digits.len() != HANDLE_DIGITS + SECRET_DIGITS
            || !digits.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let (handle, secret) = digits.split_at(HANDLE_DIGITS);
        Some(Self {
            handle: handle.to_owned(),
            secret: secret.to_owned(),
        })
    }

    /// The code as displayed to the member.
    pub fn display(&self) -> String {
        format!(
            "{}-{}-{}",
            self.handle,
            &self.secret[..4],
            &self.secret[4..]
        )
    }
}

/// Uniform decimal digits from a random source, by rejection sampling.
pub fn random_digits(count: usize, mut fill: impl FnMut(&mut [u8])) -> String {
    let mut out = String::with_capacity(count);
    let mut byte = [0u8; 1];
    while out.len() < count {
        fill(&mut byte);
        // 250 is the largest multiple of 10 not above 256.
        if byte[0] < 250 {
            out.push(char::from(b'0' + byte[0] % 10));
        }
    }
    out
}

/// The OPAQUE credential identifier of a pairing.
pub fn credential_identifier(pairing_id: &[u8]) -> Vec<u8> {
    [CREDENTIAL_LABEL, pairing_id].concat()
}

/// The bytes the binding tag and the proof of possession cover: the label, the handle, the
/// login identifier the Core assigned to this OPAQUE run, and the new public key.
pub fn bind_message(handle: &str, login_id: &[u8], public_key: &[u8]) -> Vec<u8> {
    [BIND_LABEL, handle.as_bytes(), login_id, public_key].concat()
}

/// The HMAC-SHA-256 key derived from the OPAQUE session key: HKDF-SHA-256 with an empty salt and
/// the binding label as info.
pub fn bind_key(session_key: &[u8]) -> [u8; 32] {
    struct Len32;
    impl KeyType for Len32 {
        fn len(&self) -> usize {
            32
        }
    }
    let prk = Salt::new(HKDF_SHA256, &[]).extract(session_key);
    let okm = prk
        .expand(&[BIND_LABEL], Len32)
        .expect("32 bytes is within the HKDF-SHA-256 output limit");
    let mut key = [0u8; 32];
    okm.fill(&mut key)
        .expect("the buffer has the requested length");
    key
}

/// The binding tag a browser sends with its public key.
pub fn bind_tag(session_key: &[u8], message: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, &bind_key(session_key));
    hmac::sign(&key, message).as_ref().to_vec()
}

/// Checks a binding tag in constant time.
pub fn verify_bind_tag(session_key: &[u8], message: &[u8], tag: &[u8]) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, &bind_key(session_key));
    hmac::verify(&key, message, tag).is_ok()
}

/// Domain label of the Core's signature over a registration response.
pub const REGISTRATION_LABEL: &[u8] = b"vilicus/v1/pair/registration";
/// Domain label of the tag that hands the Core's identity key to a newly paired browser.
pub const CORE_KEY_LABEL: &[u8] = b"vilicus/v1/pair/core-key";

/// The bytes the Core signs with its identity key so the issuing device can tell its
/// registration response from one an on-path attacker substituted.
pub fn registration_message(handle: &str, response: &[u8]) -> Vec<u8> {
    [REGISTRATION_LABEL, handle.as_bytes(), response].concat()
}

/// The tag, under the binding key, over the Core's identity public key: a newly paired
/// browser learns that key authenticated by the OPAQUE run instead of trusting the channel.
pub fn core_key_tag(session_key: &[u8], core_key: &[u8]) -> Vec<u8> {
    bind_tag(session_key, &[CORE_KEY_LABEL, core_key].concat())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_parses_its_display_form_and_refuses_wrong_lengths() {
        let code = Code::parse("123 4567-8901").unwrap();
        assert_eq!(code.display(), "123-4567-8901");
        assert!(Code::parse(&code.display()).is_some_and(|parsed| parsed == code));
        assert!(Code::parse("123-4567-890").is_none());
        assert!(Code::parse("123-4567-89a1").is_none());
    }

    #[test]
    fn random_digits_skips_biased_bytes() {
        let mut source = [255u8, 250, 3, 249].into_iter();
        let digits = random_digits(2, |buf| buf[0] = source.next().unwrap());
        assert_eq!(digits, "39");
    }
}
