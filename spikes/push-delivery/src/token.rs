//! Random values: the one-time alert id, topic names, ntfy-style access tokens for the test
//! network, and the exponential gaps of the send schedule. All come from the OS random source.

const ALERT_ID_LEN: usize = 32;

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    // The OS random source failing is not recoverable for a tool whose ids must be unguessable.
    getrandom::fill(&mut bytes).expect("the OS random source is unavailable");
    bytes
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A new one-time alert id: 128 random bits as 32 lowercase hex characters. It names nothing
/// (no phone, server, alert kind or time), so it can travel in the push payload.
pub fn new_alert_id() -> String {
    hex(&random_bytes::<16>())
}

/// A new topic name of 128 random bits (32 lowercase hex characters), the AD-32 minimum for a
/// topic without an access token.
pub fn new_topic() -> String {
    hex(&random_bytes::<16>())
}

/// A new ntfy access token (`tk_` and 29 lowercase alphanumerics, the format ntfy requires),
/// used only to provision the simulated self-hosted server.
pub fn new_ntfy_token() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let bytes = random_bytes::<29>();
    let tail: String = bytes
        .iter()
        // 256 is not a multiple of 36, so the first 4 letters are very slightly more likely;
        // irrelevant for a throwaway test-network token.
        .map(|b| char::from(ALPHABET[usize::from(*b) % ALPHABET.len()]))
        .collect();
    format!("tk_{tail}")
}

/// Whether `text` has the exact shape of an alert id.
pub fn is_alert_id(text: &str) -> bool {
    text.len() == ALERT_ID_LEN && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The last alert id found in `text`, a whitespace-separated word of exactly the id shape.
/// An acknowledgement may post the whole notification text, so the id is searched, not parsed.
pub fn find_alert_id(text: &str) -> Option<&str> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .rev()
        .find(|word| is_alert_id(word))
}

/// A random gap of the send schedule: exponential with the given mean, so the alerts form a
/// Poisson process and fall at any time of day or night with the same probability.
pub fn exponential_gap_ms(mean_ms: u64) -> u64 {
    let draw = u64::from_le_bytes(random_bytes::<8>()) >> 11;
    // `uniform` is in (0, 1]: the 53-bit draw is shifted so 0 never reaches the logarithm.
    let uniform = (draw as f64 + 1.0) / (1u64 << 53) as f64;
    (-uniform.ln() * mean_ms as f64).round() as u64
}

/// A uniform draw in `low..=high`, for the simulated phone's processing delays.
pub fn uniform_ms(low: u64, high: u64) -> u64 {
    let span = high.saturating_sub(low).saturating_add(1);
    low + u64::from_le_bytes(random_bytes::<8>()) % span
}

/// True with probability `per_mille` / 1000.
pub fn chance_per_mille(per_mille: u64) -> bool {
    uniform_ms(0, 999) < per_mille
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_ids_are_128_bit_hex_and_distinct() {
        let first = new_alert_id();
        let second = new_alert_id();
        assert!(is_alert_id(&first));
        assert!(is_alert_id(&second));
        assert_ne!(first, second);
        assert!(is_alert_id(&new_topic()));
    }

    #[test]
    fn ntfy_tokens_have_the_required_format() {
        let token = new_ntfy_token();
        assert_eq!(token.len(), 32);
        assert!(token.starts_with("tk_"));
        assert!(
            token[3..]
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        );
    }

    #[test]
    fn id_is_found_in_a_notification_text() {
        let id = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            find_alert_id(&format!("Vilicus security alert. ref {id}")),
            Some(id)
        );
        assert_eq!(find_alert_id(&format!("{id}\n")), Some(id));
        assert_eq!(find_alert_id("no id here"), None);
        assert_eq!(find_alert_id("0123456789ABCDEF0123456789ABCDEF"), None);
        assert_eq!(find_alert_id("0123456789abcdef0123456789abcdef0"), None);
    }

    #[test]
    fn uniform_draws_stay_in_range() {
        for _ in 0..1_000 {
            assert!((10..=20).contains(&uniform_ms(10, 20)));
        }
        assert_eq!(uniform_ms(7, 7), 7);
        assert!(!chance_per_mille(0));
        assert!(chance_per_mille(1_000));
    }

    #[test]
    fn exponential_gaps_have_the_requested_mean() {
        let samples = 20_000u64;
        let total: u64 = (0..samples).map(|_| exponential_gap_ms(1_000)).sum();
        let mean = total / samples;
        assert!((930..=1_070).contains(&mean), "mean {mean} ms");
    }
}
