//! Deterministic CBOR (RFC 8949 §4.2.1) on top of `ciborium`.
//!
//! `ciborium` already writes integers, lengths and tags in their shortest
//! form and uses definite lengths. What it does not do is sort map keys,
//! so [`canonicalize`] sorts every map by the bytewise order of the
//! encoded keys before encoding. This matches `tools/scc_cbor.py`.

use anyhow::{anyhow, bail, Result};
pub use ciborium::Value;
use serde::{de::DeserializeOwned, Serialize};

/// Encode a value without reordering (internal).
fn raw_encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(v, &mut out).expect("CBOR encoding cannot fail");
    out
}

/// Sort the keys of every map, recursively, by their encoded bytes.
pub fn canonicalize(v: Value) -> Value {
    match v {
        Value::Map(entries) => {
            let mut items: Vec<(Vec<u8>, Value, Value)> = entries
                .into_iter()
                .map(|(k, v)| {
                    let k = canonicalize(k);
                    (raw_encode(&k), k, canonicalize(v))
                })
                .collect();
            items.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Map(items.into_iter().map(|(_, k, v)| (k, v)).collect())
        }
        Value::Array(a) => Value::Array(a.into_iter().map(canonicalize).collect()),
        Value::Tag(t, inner) => Value::Tag(t, Box::new(canonicalize(*inner))),
        other => other,
    }
}

/// Encode a value with deterministic encoding.
pub fn encode(v: &Value) -> Vec<u8> {
    raw_encode(&canonicalize(v.clone()))
}

/// Encode a serde value with deterministic encoding.
pub fn to_vec<T: Serialize + ?Sized>(t: &T) -> Result<Vec<u8>> {
    let v = Value::serialized(t).map_err(|e| anyhow!("CBOR serialization: {e}"))?;
    Ok(encode(&v))
}

/// Convert a serde value to a CBOR value.
pub fn to_value<T: Serialize + ?Sized>(t: &T) -> Result<Value> {
    Value::serialized(t).map_err(|e| anyhow!("CBOR serialization: {e}"))
}

/// Decode a CBOR item. Trailing bytes are an error.
pub fn decode(data: &[u8]) -> Result<Value> {
    let mut reader = data;
    let v: Value =
        ciborium::de::from_reader(&mut reader).map_err(|e| anyhow!("CBOR decoding: {e}"))?;
    if !reader.is_empty() {
        bail!("trailing bytes after CBOR item");
    }
    Ok(v)
}

/// Decode CBOR into a serde type.
pub fn from_slice<T: DeserializeOwned>(data: &[u8]) -> Result<T> {
    from_value(decode(data)?)
}

pub fn from_value<T: DeserializeOwned>(v: Value) -> Result<T> {
    v.deserialized().map_err(|e| anyhow!("CBOR structure: {e}"))
}

/// True if `data` is one deterministically encoded CBOR item.
pub fn is_deterministic(data: &[u8]) -> bool {
    match decode(data) {
        Ok(v) => encode(&v) == data,
        Err(_) => false,
    }
}

/// Decode and require deterministic encoding (README "Encoding").
pub fn decode_deterministic(data: &[u8]) -> Result<Value> {
    let v = decode(data)?;
    if encode(&v) != data {
        bail!("not deterministically encoded");
    }
    Ok(v)
}

// ---- Value helpers ----

pub fn int(i: i64) -> Value {
    Value::Integer(i.into())
}

pub fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}

pub fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

/// Look up an integer key in a map.
pub fn map_int<'a>(m: &'a [(Value, Value)], key: i64) -> Option<&'a Value> {
    m.iter().find_map(|(k, v)| match k {
        Value::Integer(i) if i128::from(*i) == key as i128 => Some(v),
        _ => None,
    })
}

/// Look up a text key in a map.
pub fn map_text<'a>(m: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    m.iter().find_map(|(k, v)| match k {
        Value::Text(t) if t == key => Some(v),
        _ => None,
    })
}

pub fn as_map(v: &Value) -> Result<&Vec<(Value, Value)>> {
    v.as_map().ok_or_else(|| anyhow!("expected a CBOR map"))
}

pub fn as_bytes(v: &Value) -> Result<&Vec<u8>> {
    v.as_bytes().ok_or_else(|| anyhow!("expected a byte string"))
}

pub fn as_text(v: &Value) -> Result<&str> {
    v.as_text().ok_or_else(|| anyhow!("expected a text string"))
}

pub fn as_u64(v: &Value) -> Result<u64> {
    match v {
        Value::Integer(i) => u64::try_from(*i).map_err(|_| anyhow!("expected an unsigned integer")),
        _ => bail!("expected an unsigned integer"),
    }
}

pub fn as_i64(v: &Value) -> Result<i64> {
    match v {
        Value::Integer(i) => i64::try_from(*i).map_err(|_| anyhow!("integer out of range")),
        _ => bail!("expected an integer"),
    }
}

/// Serde helper for byte strings that must be exactly 32 bytes (hash32).
pub mod hash32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let v: serde_bytes::ByteBuf = Deserialize::deserialize(d)?;
        if v.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        Ok(v.into_vec())
    }
}

/// Render a CBOR value in (approximate) diagnostic notation, showing
/// embedded CBOR byte strings decoded as `<< ... >>`.
pub fn diag(v: &Value) -> String {
    let mut s = String::new();
    diag_into(v, 0, &mut s);
    s
}

fn diag_into(v: &Value, indent: usize, out: &mut String) {
    let pad = "  ".repeat(indent);
    let inner = "  ".repeat(indent + 1);
    match v {
        Value::Integer(i) => out.push_str(&i128::from(*i).to_string()),
        Value::Bytes(b) => {
            if b.len() > 2 && matches!(b[0] >> 5, 4 | 5 | 6) {
                if let Ok(e) = decode(b) {
                    if matches!(e, Value::Map(_) | Value::Array(_) | Value::Tag(..)) && encode(&e) == *b {
                        out.push_str("<< ");
                        diag_into(&e, indent, out);
                        out.push_str(" >>");
                        return;
                    }
                }
            }
            out.push_str(&format!("h'{}'", hex::encode(b)));
        }
        Value::Text(t) => out.push_str(&serde_json::to_string(t).unwrap()),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Null => out.push_str("null"),
        Value::Float(f) => out.push_str(&f.to_string()),
        Value::Tag(t, inner_v) => {
            out.push_str(&format!("{t}("));
            diag_into(inner_v, indent, out);
            out.push(')');
        }
        Value::Array(a) => {
            if a.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push_str("[\n");
            for (i, x) in a.iter().enumerate() {
                out.push_str(&inner);
                diag_into(x, indent + 1, out);
                if i + 1 < a.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad);
            out.push(']');
        }
        Value::Map(m) => {
            if m.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push_str("{\n");
            for (i, (k, x)) in m.iter().enumerate() {
                out.push_str(&inner);
                diag_into(k, indent + 1, out);
                out.push_str(": ");
                diag_into(x, indent + 1, out);
                if i + 1 < m.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad);
            out.push('}');
        }
        _ => out.push_str("?"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_keys_bytewise() {
        // integer keys 1, -1, 4, and text "a": encodings 01, 20, 04, 6161
        let v = Value::Map(vec![
            (text("a"), int(1)),
            (int(4), int(2)),
            (int(-1), int(3)),
            (int(1), int(4)),
        ]);
        let enc = encode(&v);
        assert_eq!(hex::encode(&enc), "a4010404022003616101");
        assert!(is_deterministic(&enc));
    }
}
