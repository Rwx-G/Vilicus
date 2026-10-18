//! The shape of an error that reaches a client (spine conventions, Errors): a stable error code,
//! a message key and a retry class, never an internal message or a stack trace. The error enum of
//! each crate boundary lives in `vilicus-proto` and implements [`ClientFacingError`].

use core::fmt;
use std::borrow::Cow;

use crate::name::{DOTTED_NAME_MAX_LEN, NameError, is_dotted_name};

closed_set! {
    /// Whether a client may retry the call that failed.
    pub enum RetryClass {
        /// The call had no effect and may be retried as it is.
        Retryable => "retryable",
        /// The call had no effect and fails again unless something changes first.
        NotRetryable => "not_retryable",
        /// The effect of the call is unknown; it is reported, never retried blindly (spine AD-28).
        UnknownOutcome => "unknown_outcome",
    }
}

/// Declares a dotted-name newtype: segments of a lowercase ASCII letter followed by lowercase
/// ASCII letters, digits or underscores, joined by single dots, at most [`DOTTED_NAME_MAX_LEN`]
/// characters. The grammar admits no space, so the value cannot carry a sentence.
macro_rules! dotted_name {
    ($(#[$meta:meta])* $name:ident, $kind:literal) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct $name(Cow<'static, str>);

        impl $name {
            /// Longest value accepted, in characters.
            pub const MAX_LEN: usize = DOTTED_NAME_MAX_LEN;

            /// A value known at build time, as the error enums of `vilicus-proto` declare them.
            ///
            /// # Panics
            ///
            /// When `text` is outside the grammar; in a `const` item that is a build error.
            pub const fn from_static(text: &'static str) -> Self {
                assert!(is_dotted_name(text), concat!("not a valid ", $kind));
                Self(Cow::Borrowed(text))
            }

            /// Reads a value; one outside the grammar is refused, never normalized.
            pub fn parse(text: &str) -> Result<Self, NameError> {
                if is_dotted_name(text) {
                    Ok(Self(Cow::Owned(text.to_owned())))
                } else {
                    Err(NameError::new($kind))
                }
            }

            /// The value as text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct TextVisitor;

                impl serde::de::Visitor<'_> for TextVisitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str(concat!("a ", $kind))
                    }

                    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<$name, E> {
                        $name::parse(value).map_err(E::custom)
                    }
                }

                deserializer.deserialize_str(TextVisitor)
            }
        }
    };
}

dotted_name! {
    /// A stable error code, such as `policy.denied`: it never changes meaning once released, so
    /// clients may branch on it.
    ErrorCode, "error code"
}

dotted_name! {
    /// The key of a user-facing message in the French and English catalogs (spine conventions,
    /// Text and language), such as `error.policy.denied`.
    MessageKey, "message key"
}

/// What a client receives for a failed call.
///
/// ```
/// use vilicus_types::{ClientError, ClientFacingError, ErrorCode, MessageKey, RetryClass};
///
/// enum PipelineError {
///     AuditSpoolFull,
/// }
///
/// impl ClientFacingError for PipelineError {
///     fn code(&self) -> ErrorCode {
///         ErrorCode::from_static("audit.spool_full")
///     }
///     fn message_key(&self) -> MessageKey {
///         MessageKey::from_static("error.audit.spool_full")
///     }
///     fn retry_class(&self) -> RetryClass {
///         RetryClass::Retryable
///     }
/// }
///
/// let sent = PipelineError::AuditSpoolFull.to_client_error();
/// assert_eq!(sent.retry_class, RetryClass::Retryable);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientError {
    /// The stable error code.
    pub code: ErrorCode,
    /// The key of the message the client shows.
    pub message_key: MessageKey,
    /// Whether the call may be retried.
    pub retry_class: RetryClass,
}

/// An error that crosses a crate boundary toward a client. Its details stay on the server side:
/// what leaves is [`to_client_error`](Self::to_client_error), built from the three fields alone.
pub trait ClientFacingError {
    /// The stable error code.
    fn code(&self) -> ErrorCode;

    /// The key of the message the client shows.
    fn message_key(&self) -> MessageKey;

    /// Whether the call may be retried.
    fn retry_class(&self) -> RetryClass;

    /// The error as a client receives it.
    fn to_client_error(&self) -> ClientError {
        ClientError {
            code: self.code(),
            message_key: self.message_key(),
            retry_class: self.retry_class(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{from_fields, from_str, to_json};

    /// Spine conventions, Errors: the independent statement the retry classes are checked against.
    const SPINE_RETRY_CLASSES: [&str; 3] = ["retryable", "not_retryable", "unknown_outcome"];

    #[test]
    fn retry_classes_are_the_spine_conventions() {
        let names: Vec<&str> = RetryClass::ALL.iter().map(|class| class.as_str()).collect();
        assert_eq!(names, SPINE_RETRY_CLASSES);
        for class in RetryClass::ALL {
            assert_eq!(to_json(class), Ok(format!("\"{class}\"")));
            assert_eq!(from_str::<RetryClass>(class.as_str()), Ok(*class));
        }
        assert!(from_str::<RetryClass>("Retryable").is_err());
        assert!(from_str::<RetryClass>("unknown").is_err());
    }

    enum SampleError {
        Denied { internal_reason: String },
        Timeout,
    }

    impl ClientFacingError for SampleError {
        fn code(&self) -> ErrorCode {
            match self {
                Self::Denied { .. } => ErrorCode::from_static("policy.denied"),
                Self::Timeout => ErrorCode::from_static("egress.timeout"),
            }
        }

        fn message_key(&self) -> MessageKey {
            match self {
                Self::Denied { .. } => MessageKey::from_static("error.policy.denied"),
                Self::Timeout => MessageKey::from_static("error.egress.timeout"),
            }
        }

        fn retry_class(&self) -> RetryClass {
            match self {
                Self::Denied { .. } => RetryClass::NotRetryable,
                Self::Timeout => RetryClass::UnknownOutcome,
            }
        }
    }

    #[test]
    fn client_error_carries_code_key_and_retry_class_only() {
        let error = SampleError::Denied {
            internal_reason: "token 42 revoked at 12:00".to_owned(),
        };
        let sent = error.to_client_error();
        let json = to_json(&sent).expect("serializable");
        assert_eq!(
            json,
            r#"{"code":"policy.denied","message_key":"error.policy.denied","retry_class":"not_retryable"}"#
        );
        if let SampleError::Denied { internal_reason } = &error {
            assert!(!json.contains(internal_reason.as_str()));
        }
        assert_eq!(
            SampleError::Timeout.to_client_error().retry_class,
            RetryClass::UnknownOutcome
        );
    }

    #[test]
    fn client_error_deserializes_closed() {
        let fields = [
            ("code", "policy.denied"),
            ("message_key", "error.policy.denied"),
            ("retry_class", "not_retryable"),
        ];
        assert_eq!(
            from_fields::<ClientError>(&fields),
            Ok(SampleError::Denied {
                internal_reason: String::new()
            }
            .to_client_error())
        );

        let with_message = [
            ("code", "policy.denied"),
            ("message_key", "error.policy.denied"),
            ("retry_class", "not_retryable"),
            ("message", "token revoked"),
        ];
        assert!(
            from_fields::<ClientError>(&with_message).is_err(),
            "unknown field accepted"
        );
        assert!(
            from_fields::<ClientError>(&fields[..2]).is_err(),
            "missing field accepted"
        );
        for (field, value) in [
            ("code", "the token was revoked"),
            ("code", "Policy.Denied"),
            ("message_key", "error policy denied"),
            ("retry_class", "maybe"),
        ] {
            let mut altered = fields;
            altered
                .iter_mut()
                .filter(|(name, _)| *name == field)
                .for_each(|entry| entry.1 = value);
            assert!(
                from_fields::<ClientError>(&altered).is_err(),
                "{field} = {value:?} accepted"
            );
        }
    }

    #[test]
    fn codes_and_keys_follow_the_dotted_grammar() {
        assert_eq!(
            ErrorCode::parse("policy.denied")
                .map(|code| code.to_string())
                .as_deref(),
            Ok("policy.denied")
        );
        assert!(ErrorCode::parse("policy denied").is_err());
        assert!(MessageKey::parse("").is_err());
        assert!(MessageKey::parse(&"a".repeat(MessageKey::MAX_LEN + 1)).is_err());
        assert!(MessageKey::parse(&"a".repeat(MessageKey::MAX_LEN)).is_ok());
    }

    #[test]
    #[should_panic(expected = "not a valid error code")]
    fn invalid_static_code_panics() {
        let _ = ErrorCode::from_static("Internal failure: stack trace");
    }
}
