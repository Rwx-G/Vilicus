//! The write journal as the Core keeps it (AD-26, FR-29, I9, D132): what a call's change records
//! of its record and of its inputs, and the encoding of both.
//!
//! An image is the stored row of the record, read in the write transaction: every envelope
//! column, both labels included, then every declared field, each with its name. It holds the
//! module table's own columns and nothing else, so a record's wrapped key, which lives in the
//! Core table `_record_keys`, is never part of an image (D132), and an undo that restores an
//! image cannot restore a destroyed key. The inputs of a change are journaled with the
//! provenance the Core read for them (labels, author, data types), declared and implicit alike,
//! since an implicit input is a snapshot no later read can give back (D147); their free text is
//! not journaled.
//!
//! The encoding is a length-prefixed sequence the storage layer keeps as an opaque blob:
//!
//! - a row: version byte 1, the number of columns as 2 bytes big-endian, then each column: its
//!   name's length as 1 byte, the name, a tag byte and the value: tag 0 `NULL`; tag 1 an integer,
//!   8 bytes big-endian; tag 2 text and tag 3 a blob, each its length as 4 bytes big-endian then
//!   its bytes; tag 4 a real, its 8 bytes of IEEE 754 big-endian;
//! - the inputs: version byte 1, their number as 2 bytes big-endian, then each input as a row of
//!   the columns of [`INPUT_COLUMNS`], its length first as 4 bytes big-endian.

use vilicus_module_api::{ENVELOPE, Table, Value};
use vilicus_storage::{Handle, SqlValue, Write};
use vilicus_types::Id;

use super::envelope::data_types_text;
use super::provenance::RecordProvenance;
use super::{RecordError, from_stored};

const ENCODING_VERSION: u8 = 1;

const NULL: u8 = 0;
const INTEGER: u8 = 1;
const TEXT: u8 = 2;
const BLOB: u8 = 3;
const REAL: u8 = 4;

/// The columns of a journaled input, in order.
pub const INPUT_COLUMNS: [&str; 6] = [
    "id",
    "implicit",
    "taint",
    "text_taint",
    "author",
    "data_types",
];

/// A decoded row: each column with its value, in the order it was journaled.
pub type Row = Vec<(String, Value)>;

/// Encodes a row of named values.
pub(crate) fn encode_row<'a>(
    columns: impl ExactSizeIterator<Item = (&'a str, &'a Value)>,
) -> Vec<u8> {
    let mut bytes = vec![ENCODING_VERSION];
    let count = u16::try_from(columns.len()).expect("a row has fewer than 65536 columns");
    bytes.extend_from_slice(&count.to_be_bytes());
    for (name, value) in columns {
        let name = name.as_bytes();
        bytes.push(u8::try_from(name.len()).expect("a column name is an identifier"));
        bytes.extend_from_slice(name);
        match value {
            Value::Null => bytes.push(NULL),
            Value::Integer(number) => {
                bytes.push(INTEGER);
                bytes.extend_from_slice(&number.to_be_bytes());
            }
            Value::Real(number) => {
                bytes.push(REAL);
                bytes.extend_from_slice(&number.to_bits().to_be_bytes());
            }
            Value::Text(text) => {
                bytes.push(TEXT);
                push_sized(&mut bytes, text.as_bytes());
            }
            Value::Blob(blob) => {
                bytes.push(BLOB);
                push_sized(&mut bytes, blob);
            }
        }
    }
    bytes
}

fn push_sized(bytes: &mut Vec<u8>, content: &[u8]) {
    let length = u32::try_from(content.len()).expect("a stored value is below 4 GiB");
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(content);
}

/// A cursor over encoded bytes; every read past the end, or any byte out of place, is
/// [`RecordError::InvalidJournal`].
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], RecordError> {
        if self.bytes.len() < length {
            return Err(RecordError::InvalidJournal);
        }
        let (taken, rest) = self.bytes.split_at(length);
        self.bytes = rest;
        Ok(taken)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RecordError> {
        self.take(N)?
            .try_into()
            .map_err(|_| RecordError::InvalidJournal)
    }

    fn byte(&mut self) -> Result<u8, RecordError> {
        Ok(self.array::<1>()?[0])
    }

    fn sized(&mut self) -> Result<&'a [u8], RecordError> {
        let length = usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| RecordError::InvalidJournal)?;
        self.take(length)
    }

    fn version_and_count(&mut self) -> Result<u16, RecordError> {
        if self.byte()? != ENCODING_VERSION {
            return Err(RecordError::InvalidJournal);
        }
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn finish(&self) -> Result<(), RecordError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(RecordError::InvalidJournal)
        }
    }
}

/// Decodes a row [`encode_row`] wrote.
pub fn decode_row(bytes: &[u8]) -> Result<Row, RecordError> {
    let mut reader = Reader { bytes };
    let count = reader.version_and_count()?;
    let mut row = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let name_length = usize::from(reader.byte()?);
        let name = std::str::from_utf8(reader.take(name_length)?)
            .map_err(|_| RecordError::InvalidJournal)?
            .to_owned();
        let value = match reader.byte()? {
            NULL => Value::Null,
            INTEGER => Value::Integer(i64::from_be_bytes(reader.array()?)),
            REAL => Value::Real(f64::from_bits(u64::from_be_bytes(reader.array()?))),
            TEXT => Value::Text(
                std::str::from_utf8(reader.sized()?)
                    .map_err(|_| RecordError::InvalidJournal)?
                    .to_owned(),
            ),
            BLOB => Value::Blob(reader.sized()?.to_vec()),
            _ => return Err(RecordError::InvalidJournal),
        };
        row.push((name, value));
    }
    reader.finish()?;
    Ok(row)
}

/// The image of the record `id` of `table` as stored now, in the write transaction: every
/// envelope column then every declared field; `None` when the table holds no such record.
pub(crate) fn image(
    handle: &Handle<Write>,
    table: &'static Table,
    id: Id,
) -> Result<Option<Vec<u8>>, RecordError> {
    let names: Vec<&'static str> = ENVELOPE
        .iter()
        .map(|column| column.name)
        .chain(table.fields.iter().map(|field| field.name))
        .collect();
    let row = handle
        .query_values(
            &format!(
                "SELECT {} FROM {} WHERE id = ?1",
                names.join(", "),
                table.name
            ),
            &[SqlValue::Blob(id.to_bytes().to_vec())],
        )?
        .into_iter()
        .next();
    Ok(row.map(|row| {
        let values: Vec<Value> = row.into_iter().map(from_stored).collect();
        encode_row(names.iter().copied().zip(values.iter()))
    }))
}

/// One input of a change, as the journal keeps it: the provenance the Core read for it, and
/// whether the call carried it rather than the module naming it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournaledInput {
    /// The input's id.
    pub id: Id,
    /// True for an implicit input of the call (D147), false for one the write declared.
    pub implicit: bool,
    /// Its stored `taint`.
    pub taint: String,
    /// Its stored `text_taint`.
    pub text_taint: String,
    /// Its author.
    pub author: Option<Id>,
    /// Its data types, in their stored form.
    pub data_types: String,
}

/// Encodes the inputs of a change: each with its provenance, implicit unless `declared` names it.
pub(crate) fn encode_inputs(inputs: &[RecordProvenance], declared: &[Id]) -> Vec<u8> {
    let mut bytes = vec![ENCODING_VERSION];
    let count = u16::try_from(inputs.len()).expect("a write has fewer than 65536 inputs");
    bytes.extend_from_slice(&count.to_be_bytes());
    for input in inputs {
        let values = [
            Value::Blob(input.id.to_bytes().to_vec()),
            Value::Integer(i64::from(!declared.contains(&input.id))),
            Value::Text(input.labels.taint().as_str().to_owned()),
            Value::Text(input.labels.text_taint().as_str().to_owned()),
            input.author.map_or(Value::Null, |author| {
                Value::Blob(author.to_bytes().to_vec())
            }),
            Value::Text(data_types_text(&input.data_types)),
        ];
        push_sized(
            &mut bytes,
            &encode_row(INPUT_COLUMNS.iter().copied().zip(values.iter())),
        );
    }
    bytes
}

fn journaled_id(value: &Value) -> Result<Id, RecordError> {
    match value {
        Value::Blob(bytes) => <[u8; 16]>::try_from(bytes.as_slice())
            .ok()
            .and_then(|bytes| Id::from_bytes(bytes).ok())
            .ok_or(RecordError::InvalidJournal),
        _ => Err(RecordError::InvalidJournal),
    }
}

fn journaled_text(value: Value) -> Result<String, RecordError> {
    match value {
        Value::Text(text) => Ok(text),
        _ => Err(RecordError::InvalidJournal),
    }
}

/// Decodes the inputs [`encode_inputs`] wrote, in order.
pub fn decode_inputs(bytes: &[u8]) -> Result<Vec<JournaledInput>, RecordError> {
    let mut reader = Reader { bytes };
    let count = reader.version_and_count()?;
    let mut inputs = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let row = decode_row(reader.sized()?)?;
        let names: Vec<&str> = row.iter().map(|(name, _)| name.as_str()).collect();
        if names != INPUT_COLUMNS {
            return Err(RecordError::InvalidJournal);
        }
        let mut values = row.into_iter().map(|(_, value)| value);
        let mut next = || values.next().ok_or(RecordError::InvalidJournal);
        inputs.push(JournaledInput {
            id: journaled_id(&next()?)?,
            implicit: match next()? {
                Value::Integer(0) => false,
                Value::Integer(1) => true,
                _ => return Err(RecordError::InvalidJournal),
            },
            taint: journaled_text(next()?)?,
            text_taint: journaled_text(next()?)?,
            author: match next()? {
                Value::Null => None,
                other => Some(journaled_id(&other)?),
            },
            data_types: journaled_text(next()?)?,
        });
    }
    reader.finish()?;
    Ok(inputs)
}
