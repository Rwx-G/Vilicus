//! URL-safe base64 without padding: the encoding `@serenity-kit/opaque` uses for OPAQUE
//! messages, used here for every binary field of the JSON API.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Encodes bytes as URL-safe base64 without padding.
pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes URL-safe base64 without padding; `None` on any other input.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text).ok()
}

/// Decodes into a fixed-length array; `None` when the length differs.
pub fn decode_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    decode(text)?.try_into().ok()
}
