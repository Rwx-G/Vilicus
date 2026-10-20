//! The language-neutral value notation of the vector files, in JSON.
//!
//! Each value is a one-key object: `{"int": "<decimal>"}`, `{"bytes": "<hex>"}`,
//! `{"text": "<string>"}`, `{"array": [...]}`, `{"map": [[key, value], ...]}` or
//! `{"simple": "false" | "true" | "null"}`. Integers are decimal strings because JSON numbers
//! lose precision above 2^53. Map entries keep the order they were generated in, never the
//! canonical one, so an encoder under test has to sort by itself.

use dcbor::{CBOR, CBORCase, Map};
use serde_json::Value;

use vilicus_proto::profile;

use super::hex;

/// Builds the CBOR value a notation describes.
pub fn to_cbor(notation: &Value) -> Result<CBOR, String> {
    let object = notation
        .as_object()
        .filter(|object| object.len() == 1)
        .ok_or_else(|| format!("not a one-key object: {notation}"))?;
    let (kind, body) = object.iter().next().expect("one key checked above");
    match kind.as_str() {
        "int" => {
            let text = body.as_str().ok_or("int is not a string")?;
            let value: i128 = text.parse().map_err(|_| format!("bad int {text}"))?;
            if value >= 0 {
                let unsigned =
                    u64::try_from(value).map_err(|_| format!("int out of range {text}"))?;
                Ok(CBORCase::Unsigned(unsigned).into())
            } else {
                let magnitude =
                    u64::try_from(-1 - value).map_err(|_| format!("int out of range {text}"))?;
                Ok(CBORCase::Negative(magnitude).into())
            }
        }
        "bytes" => {
            let text = body.as_str().ok_or("bytes is not a string")?;
            Ok(CBOR::to_byte_string(hex::decode(text)?))
        }
        "text" => Ok(CBOR::from(body.as_str().ok_or("text is not a string")?)),
        "array" => body
            .as_array()
            .ok_or("array is not an array")?
            .iter()
            .map(to_cbor)
            .collect::<Result<Vec<_>, _>>()
            .map(CBOR::from),
        "map" => {
            let mut map = Map::new();
            for entry in body.as_array().ok_or("map is not an array")? {
                let pair = entry
                    .as_array()
                    .filter(|pair| pair.len() == 2)
                    .ok_or("map entry is not a pair")?;
                profile::insert_unique(&mut map, to_cbor(&pair[0])?, to_cbor(&pair[1])?)
                    .map_err(|rejection| rejection.to_string())?;
            }
            Ok(map.into())
        }
        "simple" => match body.as_str() {
            Some("false") => Ok(CBOR::from(false)),
            Some("true") => Ok(CBOR::from(true)),
            Some("null") => Ok(CBOR::null()),
            _ => Err(format!("bad simple {body}")),
        },
        _ => Err(format!("unknown kind {kind}")),
    }
}
