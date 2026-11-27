//! DAG-CBOR record block → `serde_json::Value` for push classification.
//!
//! The JSON produced here is stored as `event_record` on push candidates, so its shape is
//! part of the contract with the push sender. Strings, integers, booleans, null, arrays and
//! maps map directly. A CID link becomes `{"$link": "<cid>"}` and a byte string becomes
//! `{"$bytes": "<unpadded base64>"}`, the AT Protocol JSON forms, so a record that carries a
//! blob (an image post, for example) is classified like any other.

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use petrel_core::dagcbor::{self, Limits};
use petrel_core::Value;

/// Why a record block could not be turned into classification JSON.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RecordJsonError {
    #[error("invalid DAG-CBOR record block: {0}")]
    Decode(String),
    #[error("record contains a {0}, which has no JSON form for classification")]
    Unrepresentable(&'static str),
}

/// Decodes one canonical DAG-CBOR record block into classification JSON.
pub fn dag_cbor_record_to_json(block: &[u8]) -> Result<serde_json::Value, RecordJsonError> {
    let value = dagcbor::decode_with(block, Limits::REPOSITORY_BLOCK)
        .map_err(|err| RecordJsonError::Decode(err.to_string()))?;
    value_to_json(value)
}

fn value_to_json(value: Value) -> Result<serde_json::Value, RecordJsonError> {
    Ok(match value {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(b),
        Value::Integer(i) => serde_json::Value::from(i),
        Value::String(s) => serde_json::Value::String(s),
        Value::Float(f) => serde_json::Number::from_f64(f.get())
            .map(serde_json::Value::Number)
            .ok_or(RecordJsonError::Unrepresentable("non-finite float"))?,
        Value::Bytes(bytes) => serde_json::json!({ "$bytes": STANDARD_NO_PAD.encode(bytes) }),
        Value::Link(cid) => serde_json::json!({ "$link": cid.to_string() }),
        Value::Array(items) => serde_json::Value::Array(
            items
                .into_iter()
                .map(value_to_json)
                .collect::<Result<_, _>>()?,
        ),
        Value::Object(map) => serde_json::Value::Object(
            map.into_iter()
                .map(|(k, v)| value_to_json(v).map(|v| (k, v)))
                .collect::<Result<_, _>>()?,
        ),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use petrel_core::{Cid, Value};
    use serde_json::json;

    use super::{dag_cbor_record_to_json, RecordJsonError};

    fn object(entries: Vec<(&str, Value)>) -> Value {
        Value::Object(
            entries
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect::<BTreeMap<_, _>>(),
        )
    }

    #[test]
    fn plain_record_maps_to_the_same_json_as_before() {
        let record = object(vec![
            ("$type", Value::String("app.bsky.feed.post".into())),
            ("text", Value::String("hi @alice".into())),
            ("createdAt", Value::String("2026-11-27T00:00:00Z".into())),
            ("langs", Value::Array(vec![Value::String("en".into())])),
            ("count", Value::Integer(-3)),
            ("flag", Value::Bool(true)),
            ("none", Value::Null),
        ]);
        let json = dag_cbor_record_to_json(&petrel_core::dagcbor::encode(&record)).unwrap();
        assert_eq!(
            json,
            json!({
                "$type": "app.bsky.feed.post",
                "text": "hi @alice",
                "createdAt": "2026-11-27T00:00:00Z",
                "langs": ["en"],
                "count": -3,
                "flag": true,
                "none": null,
            })
        );
    }

    #[test]
    fn image_post_keeps_its_blob_link_as_atproto_json() {
        let cid = Cid::for_dag_cbor(b"blob");
        let blob = object(vec![
            ("$type", Value::String("blob".into())),
            ("ref", Value::Link(cid.clone())),
            ("mimeType", Value::String("image/jpeg".into())),
            ("size", Value::Integer(1234)),
        ]);
        let image = object(vec![
            ("alt", Value::String("a cat".into())),
            ("image", blob),
        ]);
        let record = object(vec![
            ("$type", Value::String("app.bsky.feed.post".into())),
            ("text", Value::String("look @alice".into())),
            (
                "embed",
                object(vec![
                    ("$type", Value::String("app.bsky.embed.images".into())),
                    ("images", Value::Array(vec![image])),
                ]),
            ),
        ]);
        let json = dag_cbor_record_to_json(&petrel_core::dagcbor::encode(&record)).unwrap();
        assert_eq!(
            json,
            json!({
                "$type": "app.bsky.feed.post",
                "text": "look @alice",
                "embed": {
                    "$type": "app.bsky.embed.images",
                    "images": [{
                        "alt": "a cat",
                        "image": {
                            "$type": "blob",
                            "ref": { "$link": cid.to_string() },
                            "mimeType": "image/jpeg",
                            "size": 1234,
                        },
                    }],
                },
            })
        );
    }

    #[test]
    fn byte_strings_become_unpadded_base64() {
        let record = object(vec![("b", Value::Bytes(vec![1, 2]))]);
        assert_eq!(
            dag_cbor_record_to_json(&petrel_core::dagcbor::encode(&record)).unwrap(),
            json!({ "b": { "$bytes": "AQI" } })
        );
    }

    #[test]
    fn non_canonical_cbor_is_rejected() {
        // {"b": 1, "a": 2}: keys out of canonical order.
        let bytes = [0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x02];
        assert!(matches!(
            dag_cbor_record_to_json(&bytes),
            Err(RecordJsonError::Decode(_))
        ));
    }
}
