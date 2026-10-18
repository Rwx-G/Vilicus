//! Test-only serde drivers. The crate depends on no serialization format, so the tests drive
//! `Serialize` through a minimal JSON writer, covering only what the vocabulary emits (strings,
//! unit and newtype variants, structs), and `Deserialize` through serde's own value deserializers.

use serde::de::value::{Error, MapAccessDeserializer, MapDeserializer};
use serde::de::{DeserializeOwned, IntoDeserializer};
use serde::ser::{self, Impossible, Serialize};

/// Serializes `value` as compact JSON. Strings are written between quotes without escaping,
/// which the test values never need.
pub fn to_json<T: Serialize + ?Sized>(value: &T) -> Result<String, Error> {
    value.serialize(Json)
}

/// Deserializes `T` from a single string, as a JSON string or a CBOR text string would give it.
pub fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, Error> {
    T::deserialize(IntoDeserializer::<Error>::into_deserializer(text))
}

/// Deserializes `T` from a map of string keys to string values, as a struct is read.
pub fn from_fields<T: DeserializeOwned>(fields: &[(&str, &str)]) -> Result<T, Error> {
    T::deserialize(MapDeserializer::<_, Error>::new(fields.iter().copied()))
}

/// Deserializes `T` from a one-entry map, as an externally tagged newtype variant is read.
pub fn from_single_entry_map<T: DeserializeOwned>(key: &str, value: &str) -> Result<T, Error> {
    T::deserialize(MapAccessDeserializer::new(
        MapDeserializer::<_, Error>::new(std::iter::once((key, value))),
    ))
}

/// Deserializes `T` from a map of the given entries, whose keys and values may be of any kind
/// serde's value deserializers offer (an integer or byte-string key, a unit value).
pub fn from_map<'de, K, V, T>(entries: Vec<(K, V)>) -> Result<T, Error>
where
    K: IntoDeserializer<'de, Error>,
    V: IntoDeserializer<'de, Error>,
    T: serde::Deserialize<'de>,
{
    T::deserialize(MapAccessDeserializer::new(MapDeserializer::new(
        entries.into_iter(),
    )))
}

fn quoted(text: &str) -> String {
    format!("\"{text}\"")
}

fn unsupported<T>() -> Result<T, Error> {
    Err(ser::Error::custom("not emitted by the vocabulary"))
}

struct Json;

/// The fields of a struct being written.
struct JsonStruct(Vec<String>);

impl ser::SerializeStruct for JsonStruct {
    type Ok = String;
    type Error = Error;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.0
            .push(format!("{}:{}", quoted(key), value.serialize(Json)?));
        Ok(())
    }

    fn end(self) -> Result<String, Error> {
        Ok(format!("{{{}}}", self.0.join(",")))
    }
}

impl ser::Serializer for Json {
    type Ok = String;
    type Error = Error;
    type SerializeSeq = Impossible<String, Error>;
    type SerializeTuple = Impossible<String, Error>;
    type SerializeTupleStruct = Impossible<String, Error>;
    type SerializeTupleVariant = Impossible<String, Error>;
    type SerializeMap = Impossible<String, Error>;
    type SerializeStruct = JsonStruct;
    type SerializeStructVariant = Impossible<String, Error>;

    fn serialize_str(self, value: &str) -> Result<String, Error> {
        Ok(quoted(value))
    }

    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
    ) -> Result<String, Error> {
        Ok(quoted(variant))
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<String, Error> {
        Ok(format!(
            "{{{}:{}}}",
            quoted(variant),
            value.serialize(Json)?
        ))
    }

    fn serialize_struct(self, _: &'static str, fields: usize) -> Result<JsonStruct, Error> {
        Ok(JsonStruct(Vec::with_capacity(fields)))
    }

    fn serialize_bool(self, _: bool) -> Result<String, Error> {
        unsupported()
    }

    fn serialize_i8(self, _: i8) -> Result<String, Error> {
        unsupported()
    }

    fn serialize_i16(self, _: i16) -> Result<String, Error> {
        unsupported()
    }

    fn serialize_i32(self, _: i32) -> Result<String, Error> {
        unsupported()
    }

    fn serialize_i64(self, _: i64) -> Result<String, Error> {
        unsupported()
    }

    fn serialize_u8(self, _: u8) -> Result<String, Error> {
        unsupported()
    }

    fn serialize_u16(self, _: u16) -> Result<String, Error> {
        unsupported()
    }

    fn serialize_u32(self, _: u32) -> Result<String, Error> {
        unsupported()
    }

    fn serialize_u64(self, _: u64) -> Result<String, Error> {
        unsupported()
    }

    fn serialize_f32(self, _: f32) -> Result<String, Error> {
        unsupported()
    }

    fn serialize_f64(self, _: f64) -> Result<String, Error> {
        unsupported()
    }

    fn serialize_char(self, _: char) -> Result<String, Error> {
        unsupported()
    }

    fn serialize_bytes(self, _: &[u8]) -> Result<String, Error> {
        unsupported()
    }

    fn serialize_none(self) -> Result<String, Error> {
        unsupported()
    }

    fn serialize_some<T: Serialize + ?Sized>(self, _: &T) -> Result<String, Error> {
        unsupported()
    }

    fn serialize_unit(self) -> Result<String, Error> {
        unsupported()
    }

    fn serialize_unit_struct(self, _: &'static str) -> Result<String, Error> {
        unsupported()
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: &T,
    ) -> Result<String, Error> {
        unsupported()
    }

    fn serialize_seq(self, _: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        unsupported()
    }

    fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, Error> {
        unsupported()
    }

    fn serialize_tuple_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleStruct, Error> {
        unsupported()
    }

    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        unsupported()
    }

    fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, Error> {
        unsupported()
    }

    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        unsupported()
    }
}
