// envelope.rs — plaintext envelope carried inside a ratchet message.
// Mirrors trino/src/core/envelope.ts. Not signed, so it only needs to be valid
// JSON with matching field names (parsing is order-independent across runtimes).

use crate::group::{FileRef, GroupRoster};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "ty")]
pub enum Envelope {
    #[serde(rename = "text")]
    Text {
        body: String,
        // Stable message id for dedup on resend (empty on legacy messages).
        #[serde(default, skip_serializing_if = "String::is_empty")]
        id: String,
    },
    #[serde(rename = "grp")]
    Group { gid: String, ep: u64, body: String },
    #[serde(rename = "roster")]
    Roster { roster: GroupRoster },
    #[serde(rename = "file")]
    File {
        file: FileRef,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        gid: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        body: Option<String>,
    },
    // WebRTC call signaling (offer/answer/ICE/bye) — payload is a JSON string the
    // frontend builds and parses. Travels E2E-encrypted like any other message.
    #[serde(rename = "call")]
    Call { call: String },
}

pub fn encode_envelope(e: &Envelope) -> Vec<u8> {
    serde_json::to_vec(e).unwrap_or_default()
}

pub fn decode_envelope(plaintext: &[u8]) -> Envelope {
    let raw = String::from_utf8_lossy(plaintext).to_string();
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
        if let Some(ty) = val.get("ty").and_then(|v| v.as_str()) {
            if matches!(ty, "text" | "grp" | "roster" | "file" | "call") {
                if let Ok(env) = serde_json::from_value::<Envelope>(val) {
                    return env;
                }
            }
        }
    }
    Envelope::Text {
        body: raw,
        id: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_roundtrip() {
        let e = Envelope::Text {
            body: "hola".into(),
            id: "m1".into(),
        };
        assert_eq!(decode_envelope(&encode_envelope(&e)), e);
    }

    #[test]
    fn group_roundtrip() {
        let e = Envelope::Group {
            gid: "abc123".into(),
            ep: 4,
            body: "hola grupo".into(),
        };
        assert_eq!(decode_envelope(&encode_envelope(&e)), e);
    }

    #[test]
    fn legacy_raw_text_falls_back() {
        let e = decode_envelope(b"mensaje viejo sin sobre");
        assert_eq!(
            e,
            Envelope::Text {
                body: "mensaje viejo sin sobre".into(),
                id: String::new(),
            }
        );
    }

    #[test]
    fn unknown_type_falls_back_to_text() {
        let raw = br#"{"ty":"weird","x":1}"#;
        match decode_envelope(raw) {
            Envelope::Text { body, .. } => assert_eq!(body, r#"{"ty":"weird","x":1}"#),
            other => panic!("expected text fallback, got {:?}", other),
        }
    }

    #[test]
    fn decodes_ts_group_envelope() {
        // Exact JSON produced by the TS encodeEnvelope(groupEnvelope(...)).
        let ts = br#"{"ty":"grp","gid":"abc123","ep":4,"body":"hola grupo"}"#;
        assert_eq!(
            decode_envelope(ts),
            Envelope::Group {
                gid: "abc123".into(),
                ep: 4,
                body: "hola grupo".into()
            }
        );
    }
}
