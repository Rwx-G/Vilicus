//! The push payload: one generic text and the one-time id, nothing else (AD-32). The publish
//! request sets no title, tags, priority, click URL, icon, actions or attachment.

use crate::token::is_alert_id;

/// The single generic text of every alert. It names no alert kind, member, sender or amount.
pub const GENERIC_TEXT: &str = "Vilicus security alert.";

const ID_PREFIX: &str = " ref ";

/// The body posted to the push server for the alert `id`.
pub fn alert_body(id: &str) -> String {
    format!("{GENERIC_TEXT}{ID_PREFIX}{id}")
}

/// Whether `body` is exactly a generic alert: the generic text and one alert id.
pub fn is_content_free_body(body: &str) -> bool {
    body.strip_prefix(GENERIC_TEXT)
        .and_then(|rest| rest.strip_prefix(ID_PREFIX))
        .is_some_and(is_alert_id)
}

/// The fields an ntfy server may return for a stored message that carries only a body. Any
/// other field (title, tags, priority, click, icon, actions, attachment, and fields added by a
/// later ntfy release) makes the audit refuse the message.
const ALLOWED_MESSAGE_FIELDS: &[&str] = &["id", "time", "expires", "event", "topic", "message"];

/// Checks one message object of an ntfy JSON stream or poll answer. Returns the reason when it
/// is not a content-free alert.
pub fn audit_ntfy_message(message: &serde_json::Value) -> Result<(), String> {
    let object = message
        .as_object()
        .ok_or_else(|| "not a JSON object".to_owned())?;
    if let Some(field) = object
        .keys()
        .find(|key| !ALLOWED_MESSAGE_FIELDS.contains(&key.as_str()))
    {
        return Err(format!("unexpected field `{field}`"));
    }
    match object.get("message").and_then(serde_json::Value::as_str) {
        Some(body) if is_content_free_body(body) => Ok(()),
        Some(_) => Err("body is not the generic text and one alert id".to_owned()),
        None => Err("no body".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::new_alert_id;

    #[test]
    fn alert_body_is_content_free() {
        assert!(is_content_free_body(&alert_body(&new_alert_id())));
        assert!(!is_content_free_body("Vilicus security alert. ref nothex"));
        assert!(!is_content_free_body(
            "Member added. ref 0123456789abcdef0123456789abcdef"
        ));
        assert!(!is_content_free_body(&format!(
            "{} extra",
            alert_body(&new_alert_id())
        )));
    }

    #[test]
    fn audit_refuses_any_field_beyond_the_body() {
        let body = alert_body(&new_alert_id());
        let plain = serde_json::json!({
            "id": "abc", "time": 1, "expires": 2, "event": "message", "topic": "t", "message": body
        });
        assert_eq!(audit_ntfy_message(&plain), Ok(()));
        for (field, value) in [
            ("title", serde_json::json!("Recovery started")),
            ("tags", serde_json::json!(["warning"])),
            ("priority", serde_json::json!(5)),
            ("click", serde_json::json!("https://example.com/")),
        ] {
            let mut with_field = plain.clone();
            with_field[field] = value;
            assert!(audit_ntfy_message(&with_field).is_err(), "{field} accepted");
        }
        let mut wrong_body = plain;
        wrong_body["message"] = serde_json::json!("Recovery started for a member");
        assert!(audit_ntfy_message(&wrong_body).is_err());
    }
}
