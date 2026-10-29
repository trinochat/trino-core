//! The binary frame inside the ratchet (`diseno-vinculacion.md` §21.4, PB-07).
//!
//! The ratchet's plaintext stops being JSON alone: in base64 the compact
//! device list would not fit a type 2 handshake next to its KEM ciphertext.
//!
//! ```text
//! plaintext = 0x01 ‖ n u8 ‖ (kind u8 ‖ len u32 BE ‖ bytes[len])[n]
//! kinds: 1 JSON envelope (today's) · 2 compact DeviceList · 3 full DeviceList
//!        · 4 roster v3 · 5 `dl` echo · 6 seen · 7 Sync
//! ```
//!
//! - **An unknown kind is skipped**, so a later version can add parts that
//!   an older one ignores.
//! - **Refused:** another version byte, no parts, a part cut short, bytes
//!   after the last part, and the same kind twice (the reader would have to
//!   guess which one counts).

use thiserror::Error;

/// The frame version this code reads and writes.
pub const FRAME_VERSION: u8 = 1;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("unknown frame version {0}")]
    Version(u8),
    #[error("a frame needs 1 to 255 parts")]
    PartCount,
    #[error("part kind {0} appears twice")]
    Duplicate(u8),
    #[error("malformed frame")]
    Malformed,
}

/// The parts a frame can carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PartKind {
    /// Today's JSON envelope (`crate::envelope`).
    Envelope = 1,
    /// The device list with the classical signed prekeys (handshakes).
    DeviceListCompact = 2,
    /// The device list with the classical and post-quantum prekeys (16 KiB).
    DeviceListFull = 3,
    /// A version 3 group roster.
    RosterV3 = 4,
    /// The `dl` echo of both device lists (56 bytes).
    Echo = 5,
    /// Read receipts ("visto", §22).
    Seen = 6,
    /// A copy between your own devices (§7).
    Sync = 7,
}

impl PartKind {
    /// The kind a byte names, or `None` for one this version does not know.
    pub fn from_byte(b: u8) -> Option<PartKind> {
        Some(match b {
            1 => PartKind::Envelope,
            2 => PartKind::DeviceListCompact,
            3 => PartKind::DeviceListFull,
            4 => PartKind::RosterV3,
            5 => PartKind::Echo,
            6 => PartKind::Seen,
            7 => PartKind::Sync,
            _ => return None,
        })
    }
}

/// Encodes the parts in the order given.
pub fn encode(parts: &[(PartKind, &[u8])]) -> Result<Vec<u8>, FrameError> {
    let n = u8::try_from(parts.len()).map_err(|_| FrameError::PartCount)?;
    if n == 0 {
        return Err(FrameError::PartCount);
    }
    let mut seen = [false; 256];
    let mut out = vec![FRAME_VERSION, n];
    for (kind, bytes) in parts {
        let k = *kind as u8;
        if std::mem::replace(&mut seen[usize::from(k)], true) {
            return Err(FrameError::Duplicate(k));
        }
        let len = u32::try_from(bytes.len()).map_err(|_| FrameError::Malformed)?;
        out.push(k);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(bytes);
    }
    Ok(out)
}

/// Decodes a frame; parts of unknown kinds are skipped.
pub fn decode(b: &[u8]) -> Result<Vec<(PartKind, Vec<u8>)>, FrameError> {
    let (&version, rest) = b.split_first().ok_or(FrameError::Malformed)?;
    if version != FRAME_VERSION {
        return Err(FrameError::Version(version));
    }
    let (&n, mut rest) = rest.split_first().ok_or(FrameError::Malformed)?;
    if n == 0 {
        return Err(FrameError::PartCount);
    }
    let mut seen = [false; 256];
    let mut parts = Vec::with_capacity(usize::from(n));
    for _ in 0..n {
        if rest.len() < 5 {
            return Err(FrameError::Malformed);
        }
        let k = rest[0];
        let len = u32::from_be_bytes(rest[1..5].try_into().expect("4 bytes")) as usize;
        // checked_add: on a 32-bit target 5 + u32::MAX wraps.
        let end = len.checked_add(5).ok_or(FrameError::Malformed)?;
        let body = rest.get(5..end).ok_or(FrameError::Malformed)?;
        if std::mem::replace(&mut seen[usize::from(k)], true) {
            return Err(FrameError::Duplicate(k));
        }
        if let Some(kind) = PartKind::from_byte(k) {
            parts.push((kind, body.to_vec()));
        }
        rest = &rest[end..];
    }
    if !rest.is_empty() {
        return Err(FrameError::Malformed);
    }
    Ok(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_layout_written_by_hand() {
        // 0x01, two parts: kind 1 with "{}", kind 5 with one byte 0xaa.
        let want =
            hex::decode("0102".to_owned() + "01" + "00000002" + "7b7d" + "05" + "00000001" + "aa")
                .unwrap();
        let got = encode(&[(PartKind::Envelope, b"{}"), (PartKind::Echo, &[0xaa])]).unwrap();
        assert_eq!(got, want);
        assert_eq!(
            decode(&want).unwrap(),
            vec![
                (PartKind::Envelope, b"{}".to_vec()),
                (PartKind::Echo, vec![0xaa])
            ]
        );
    }

    #[test]
    fn every_kind_round_trips_in_order() {
        let kinds = [
            PartKind::Sync,
            PartKind::Envelope,
            PartKind::DeviceListCompact,
            PartKind::DeviceListFull,
            PartKind::RosterV3,
            PartKind::Echo,
            PartKind::Seen,
        ];
        let bodies: Vec<Vec<u8>> = (0..kinds.len()).map(|i| vec![i as u8; i * 3]).collect();
        let parts: Vec<(PartKind, &[u8])> = kinds
            .iter()
            .copied()
            .zip(bodies.iter().map(|b| &b[..]))
            .collect();
        let decoded = decode(&encode(&parts).unwrap()).unwrap();
        let want: Vec<(PartKind, Vec<u8>)> = kinds.iter().copied().zip(bodies).collect();
        assert_eq!(decoded, want);
        for k in kinds {
            assert_eq!(PartKind::from_byte(k as u8), Some(k));
        }
    }

    #[test]
    fn unknown_kinds_are_skipped() {
        let b = hex::decode(
            "0103".to_owned()
                + "09"
                + "00000003"
                + "010203"
                + "01"
                + "00000001"
                + "41"
                + "00"
                + "00000000",
        )
        .unwrap();
        assert_eq!(
            decode(&b).unwrap(),
            vec![(PartKind::Envelope, b"A".to_vec())]
        );
        assert_eq!(PartKind::from_byte(0), None);
        assert_eq!(PartKind::from_byte(8), None);
    }

    #[test]
    fn bad_frames_are_refused() {
        assert_eq!(decode(&[]).unwrap_err(), FrameError::Malformed);
        assert_eq!(
            decode(&[2, 1, 1, 0, 0, 0, 0]).unwrap_err(),
            FrameError::Version(2)
        );
        assert_eq!(decode(&[1, 0]).unwrap_err(), FrameError::PartCount);
        // Cut short: a header without its bytes, and a length past the end.
        assert_eq!(decode(&[1, 1, 1, 0, 0]).unwrap_err(), FrameError::Malformed);
        assert_eq!(
            decode(&[1, 1, 1, 0, 0, 0, 2, 0x41]).unwrap_err(),
            FrameError::Malformed
        );
        // Fewer parts than announced, and bytes after the last part.
        assert_eq!(
            decode(&[1, 2, 1, 0, 0, 0, 0]).unwrap_err(),
            FrameError::Malformed
        );
        assert_eq!(
            decode(&[1, 1, 1, 0, 0, 0, 0, 0xff]).unwrap_err(),
            FrameError::Malformed
        );
        // The same kind twice, known or not.
        assert_eq!(
            decode(&[1, 2, 6, 0, 0, 0, 0, 6, 0, 0, 0, 0]).unwrap_err(),
            FrameError::Duplicate(6)
        );
        assert_eq!(
            decode(&[1, 2, 9, 0, 0, 0, 0, 9, 0, 0, 0, 0]).unwrap_err(),
            FrameError::Duplicate(9)
        );
    }

    #[test]
    fn encode_refuses_what_decode_would() {
        assert_eq!(encode(&[]).unwrap_err(), FrameError::PartCount);
        assert_eq!(
            encode(&[(PartKind::Seen, b""), (PartKind::Seen, b"")]).unwrap_err(),
            FrameError::Duplicate(6)
        );
    }

    #[test]
    fn a_frame_with_a_compact_list_fits_a_type_2_with_text() {
        // §21.4: five devices give a 1912-byte compact list; with the 56-byte
        // echo and a short JSON envelope the frame still fits the 4 KiB step
        // next to the 1165-byte fixed part of a type 2.
        use crate::p1::wire::{Step, HANDSHAKE_FIXED};
        let list = vec![0u8; 367 + 309 * 5];
        let echo = [0u8; 56];
        let envelope = vec![b'x'; 600];
        let frame = encode(&[
            (PartKind::Envelope, &envelope),
            (PartKind::DeviceListCompact, &list),
            (PartKind::Echo, &echo),
        ])
        .unwrap();
        // The ratchet adds a 16-byte GCM tag; the type 1 body 52 bytes more.
        let body = HANDSHAKE_FIXED + 52 + frame.len() + 16;
        assert!(body <= Step::K4.capacity(), "{body}");
    }
}
