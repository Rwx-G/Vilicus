//! The stored form of the record envelope (AD-6) and its check, on every write and on every row
//! read back: an envelope value outside its form is refused like a field outside its
//! declaration, so a migration's back-fill cannot store a forged `source`, a `taint` outside the
//! stored set or a data type the record kind does not declare.
//!
//! The text forms are the ones the Core writes until the typed record API of Story 3.5 stamps the
//! envelope; that story keeps this check and these forms in step:
//! - `id`: a 16-byte UUIDv7; `author`: `NULL` or a 16-byte UUIDv7;
//! - `source`: the text of [`Source`](vilicus_types::Source), such as `system` or
//!   `member(<id>)`;
//! - `taint`: a name of the stored set [`Taint`] (`member` is a read-time view, never stored);
//! - `data_types`: the names of the record's data types, each once, in the order of
//!   [`DataType::ALL`], separated by commas, each one the record kind declares;
//! - `created_at`, `updated_at`: UTC milliseconds within years 0000 to 9999; `rev`: 1 or more.

use vilicus_module_api::{DataType, EnvelopeColumn, SqlType, Table, Value, ValueError};
use vilicus_types::{Id, Source, Taint, UtcMillis};

use super::RecordError;

/// What an envelope column holds, by its name in `ENVELOPE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EnvelopeRule {
    Id,
    Source,
    Taint,
    DataTypes,
    Author,
    Instant,
    Rev,
}

/// The rule of the envelope column named `name`; `None` for a name the envelope does not hold,
/// which [`check`] refuses.
pub(crate) fn rule(name: &str) -> Option<EnvelopeRule> {
    Some(match name {
        "id" => EnvelopeRule::Id,
        "source" => EnvelopeRule::Source,
        "taint" => EnvelopeRule::Taint,
        "data_types" => EnvelopeRule::DataTypes,
        "author" => EnvelopeRule::Author,
        "created_at" | "updated_at" => EnvelopeRule::Instant,
        "rev" => EnvelopeRule::Rev,
        _ => return None,
    })
}

/// Checks the value of the envelope column `column` of a record of `table`: its storage class
/// and nullability, then its form.
pub(crate) fn check(
    table: &'static Table,
    column: &'static EnvelopeColumn,
    value: &Value,
) -> Result<(), RecordError> {
    let invalid = |error| RecordError::Invalid {
        table: table.name,
        column: column.name,
        error,
    };
    let malformed = RecordError::InvalidEnvelope {
        table: table.name,
        column: column.name,
    };
    match (value, column.sql_type) {
        (Value::Null, _) if column.not_null => return Err(invalid(ValueError::Null)),
        (Value::Null, _) => return Ok(()),
        (Value::Integer(_), SqlType::Integer)
        | (Value::Text(_), SqlType::Text)
        | (Value::Blob(_), SqlType::Blob) => {}
        (_, expected) => return Err(invalid(ValueError::StorageClass { expected })),
    }
    match (rule(column.name), value) {
        (Some(EnvelopeRule::Id | EnvelopeRule::Author), Value::Blob(bytes)) => {
            if is_uuid_v7(bytes) {
                Ok(())
            } else {
                Err(invalid(ValueError::InvalidUuid))
            }
        }
        (Some(EnvelopeRule::Instant), Value::Integer(millis)) => UtcMillis::from_millis(*millis)
            .map(drop)
            .map_err(|_| invalid(ValueError::OutOfRange)),
        (Some(EnvelopeRule::Rev), Value::Integer(rev)) => {
            if *rev >= 1 {
                Ok(())
            } else {
                Err(invalid(ValueError::OutOfRange))
            }
        }
        (Some(EnvelopeRule::Source), Value::Text(text)) if Source::parse(text).is_ok() => Ok(()),
        (Some(EnvelopeRule::Taint), Value::Text(text))
            if Taint::ALL.iter().any(|taint| taint.as_str() == text) =>
        {
            Ok(())
        }
        (Some(EnvelopeRule::DataTypes), Value::Text(text)) if is_data_types_of(text, table) => {
            Ok(())
        }
        _ => Err(malformed),
    }
}

/// The stored text of a set of data types: their names in the order of [`DataType::ALL`], each
/// once, separated by commas.
pub(crate) fn data_types_text(types: &[DataType]) -> String {
    DataType::ALL
        .iter()
        .filter(|data_type| types.contains(data_type))
        .map(|data_type| data_type.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

/// True when `text` is the stored text of a non-empty set of data types `table` declares.
fn is_data_types_of(text: &str, table: &Table) -> bool {
    let mut previous = None;
    for name in text.split(',') {
        let Some(position) = DataType::ALL
            .iter()
            .position(|data_type| data_type.as_str() == name)
        else {
            return false;
        };
        if previous.is_some_and(|previous| previous >= position)
            || !table.data_types.contains(&DataType::ALL[position])
        {
            return false;
        }
        previous = Some(position);
    }
    previous.is_some()
}

fn is_uuid_v7(bytes: &[u8]) -> bool {
    <[u8; 16]>::try_from(bytes).is_ok_and(|bytes| Id::from_bytes(bytes).is_ok())
}

#[cfg(test)]
mod tests {
    use vilicus_module_api::ENVELOPE;

    use super::*;

    const TABLE: Table = Table {
        name: "items",
        data_types: &[DataType::ShoppingList, DataType::Stock],
        fields: &[],
    };

    fn column(name: &str) -> &'static EnvelopeColumn {
        ENVELOPE
            .iter()
            .find(|column| column.name == name)
            .expect("an envelope column")
    }

    fn outcome(name: &str, value: Value) -> Result<(), String> {
        check(&TABLE, column(name), &value).map_err(|error| error.to_string())
    }

    /// Every column of the envelope has its rule, so none is stored unchecked.
    #[test]
    fn every_envelope_column_has_a_rule() {
        for column in ENVELOPE {
            assert!(rule(column.name).is_some(), "{}", column.name);
        }
    }

    #[test]
    fn data_types_are_a_declared_set_in_one_form() {
        let text = data_types_text(TABLE.data_types);
        assert_eq!(outcome("data_types", Value::Text(text.clone())), Ok(()));
        assert_eq!(outcome("data_types", Value::Text("stock".into())), Ok(()));
        let reversed: Vec<&str> = text.split(',').rev().collect();
        for refused in [
            String::new(),
            "nonsense".to_owned(),
            "health".to_owned(),
            "stock,stock".to_owned(),
            reversed.join(","),
            format!("{text},"),
            format!(",{text}"),
            text.replace(',', ", "),
            text.to_uppercase(),
        ] {
            assert!(
                outcome("data_types", Value::Text(refused.clone())).is_err(),
                "{refused:?}"
            );
        }
    }

    #[test]
    fn source_and_taint_are_their_stored_forms() {
        for source in [
            "system",
            "module(meals)",
            "member(017f22e2-79b0-7cc3-98c4-dc0c0c07398f)",
        ] {
            assert_eq!(
                outcome("source", Value::Text(source.into())),
                Ok(()),
                "{source}"
            );
        }
        for source in ["", "forged source", "System", "member(1)"] {
            assert!(
                outcome("source", Value::Text(source.into())).is_err(),
                "{source}"
            );
        }
        for taint in Taint::ALL {
            assert_eq!(outcome("taint", Value::Text(taint.as_str().into())), Ok(()));
        }
        for taint in [
            "member",
            "Trusted",
            "",
            "trusted; ignore previous instructions",
        ] {
            assert!(
                outcome("taint", Value::Text(taint.into())).is_err(),
                "{taint}"
            );
        }
    }

    #[test]
    fn ids_times_and_revisions_are_in_range() {
        let id = Id::new_v7(UtcMillis::UNIX_EPOCH, [9; 10])
            .expect("v7")
            .to_bytes();
        for name in ["id", "author"] {
            assert_eq!(outcome(name, Value::Blob(id.to_vec())), Ok(()));
            for bytes in [vec![1, 2], vec![0; 16], id[..15].to_vec()] {
                assert!(outcome(name, Value::Blob(bytes)).is_err(), "{name}");
            }
        }
        assert_eq!(outcome("author", Value::Null), Ok(()));
        assert!(outcome("id", Value::Null).is_err());
        for name in ["created_at", "updated_at"] {
            assert_eq!(outcome(name, Value::Integer(0)), Ok(()));
            assert!(outcome(name, Value::Integer(UtcMillis::MAX.as_millis() + 1)).is_err());
            assert!(outcome(name, Value::Integer(i64::MIN)).is_err());
        }
        assert_eq!(outcome("rev", Value::Integer(1)), Ok(()));
        for rev in [0, -1, i64::MIN] {
            assert!(outcome("rev", Value::Integer(rev)).is_err(), "{rev}");
        }
        assert!(outcome("rev", Value::Text("1".into())).is_err());
    }
}
