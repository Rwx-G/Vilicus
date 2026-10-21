//! Shared vocabulary of Vilicus: identifiers, time, taint, tier, principal, record revisions,
//! the `source` vocabulary, the closed sets every other crate maps to, the confirmed V0.1 values
//! and the shape of an error that reaches a client.
//!
//! It holds no key and depends on no other workspace crate; every crate of the dependency graph
//! reaches it (`doc/architecture-spine.md`, AD-3 and Consistency Conventions). It does no I/O and
//! reads no clock and no random source: whatever needs one receives the value as a parameter.

/// Declares a closed set as a fieldless enum whose members are named once, by the string given
/// to each variant: `as_str`, `Display`, serialization and deserialization all read that string,
/// and `ALL` lists every variant, so no second list exists to fall out of step. Deserialization
/// accepts exactly one of the names, as a string, and refuses anything else.
macro_rules! closed_set {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident => $text:literal,
            )+
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum $name {
            $(
                $(#[$variant_meta])*
                $variant,
            )+
        }

        impl $name {
            /// Every member of the closed set, in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            const NAMES: &'static [&'static str] = &[$($text),+];

            /// The name of this member, as it is serialized.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text,)+
                }
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
                struct NameVisitor;

                impl serde::de::Visitor<'_> for NameVisitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                        write!(formatter, "one of {:?}", $name::NAMES)
                    }

                    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<$name, E> {
                        $name::ALL
                            .iter()
                            .copied()
                            .find(|member| member.as_str() == value)
                            .ok_or_else(|| E::unknown_variant(value, $name::NAMES))
                    }
                }

                deserializer.deserialize_str(NameVisitor)
            }
        }
    };
}

mod data_type;
mod error;
mod exception_class;
mod id;
mod label;
mod limits;
mod name;
mod principal;
mod rev;
mod source;
mod taint;
mod tier;
mod time;

#[cfg(test)]
mod test_support;

pub use data_type::DataType;
pub use error::{ClientError, ClientFacingError, ErrorCode, MessageKey, RetryClass};
pub use exception_class::ExceptionClass;
pub use id::{Id, IdError};
pub use label::{
    VOCABULARY_LABEL_MAX_LEN, VOCABULARY_LABEL_SEPARATORS, is_vocabulary_label,
    is_vocabulary_label_letter,
};
pub use limits::{
    CAPABILITY_TOKEN_DEFAULT_BUDGET, CAPABILITY_TOKEN_LIFETIME, DEFAULT_AUDIT_SPOOL_ENTRIES,
    DEFAULT_BACKUP_INTERVAL, DEFAULT_CERTIFICATE_ALERT_LEAD_TIME, OperatorSetting,
    UNDO_JOURNAL_RETENTION, UNLOCK_WINDOW_DEFAULT, UNLOCK_WINDOW_MAX,
};
pub use name::NameError;
pub use principal::Principal;
pub use rev::Rev;
pub use source::{ModuleName, Source};
pub use taint::{EffectiveTaint, Taint};
pub use tier::Tier;
pub use time::{TimeError, UtcMillis, is_full_date};
