use serde::Deserialize;

pub const MAX_CALL_SIGNAL_BYTES: usize = 64 * 1024;
const MAX_SDP_BYTES: usize = 56 * 1024;
const MAX_CANDIDATE_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CallSignal {
    #[serde(rename = "t")]
    kind: String,
    call_id: String,
    sdp: Option<String>,
    candidate: Option<IceCandidate>,
    video: Option<bool>,
    renegotiate: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IceCandidate {
    candidate: String,
    sdp_mid: Option<String>,
    sdp_m_line_index: Option<u16>,
    username_fragment: Option<String>,
}

pub fn validate_call_signal(payload: &str) -> Result<(), &'static str> {
    if payload.is_empty() || payload.len() > MAX_CALL_SIGNAL_BYTES {
        return Err("call signal is empty or too large");
    }
    let signal: CallSignal =
        serde_json::from_str(payload).map_err(|_| "call signal is malformed")?;

    if signal.call_id.len() < 16
        || signal.call_id.len() > 64
        || !signal
            .call_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err("invalid call id");
    }

    match signal.kind.as_str() {
        "offer" | "answer" => {
            let sdp = signal.sdp.as_deref().ok_or("SDP is required")?;
            if sdp.is_empty() || sdp.len() > MAX_SDP_BYTES || !sdp.starts_with("v=0") {
                return Err("invalid SDP");
            }
            if signal.candidate.is_some() {
                return Err("unexpected ICE candidate");
            }
        }
        "ice" => {
            if signal.sdp.is_some() {
                return Err("unexpected SDP");
            }
            let candidate = signal
                .candidate
                .as_ref()
                .ok_or("ICE candidate is required")?;
            if candidate.candidate.is_empty()
                || candidate.candidate.len() > MAX_CANDIDATE_BYTES
                || candidate
                    .sdp_mid
                    .as_ref()
                    .is_some_and(|value| value.len() > 256)
                || candidate
                    .username_fragment
                    .as_ref()
                    .is_some_and(|value| value.len() > 256)
            {
                return Err("invalid ICE candidate");
            }
            let _ = candidate.sdp_m_line_index;
        }
        "bye" | "reject" => {
            if signal.sdp.is_some()
                || signal.candidate.is_some()
                || signal.video.is_some()
                || signal.renegotiate.is_some()
            {
                return Err("unexpected call signal fields");
            }
        }
        _ => return Err("unsupported call signal type"),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_offer_and_candidate() {
        let offer = r#"{"t":"offer","callId":"0123456789abcdef","sdp":"v=0\r\n","video":true}"#;
        let candidate = r#"{"t":"ice","callId":"0123456789abcdef","candidate":{"candidate":"candidate:1 1 UDP 1 127.0.0.1 9999 typ host","sdpMid":"0","sdpMLineIndex":0,"usernameFragment":"abc"}}"#;
        assert!(validate_call_signal(offer).is_ok());
        assert!(validate_call_signal(candidate).is_ok());
    }

    #[test]
    fn rejects_unknown_fields_and_oversized_payloads() {
        let unknown = r#"{"t":"bye","callId":"0123456789abcdef","unexpected":"data"}"#;
        let oversized = "x".repeat(MAX_CALL_SIGNAL_BYTES + 1);
        assert!(validate_call_signal(unknown).is_err());
        assert!(validate_call_signal(&oversized).is_err());
    }

    #[test]
    fn rejects_invalid_ids_and_missing_sdp() {
        let short_id = r#"{"t":"bye","callId":"short"}"#;
        let missing_sdp = r#"{"t":"offer","callId":"0123456789abcdef"}"#;
        assert!(validate_call_signal(short_id).is_err());
        assert!(validate_call_signal(missing_sdp).is_err());
    }
}
