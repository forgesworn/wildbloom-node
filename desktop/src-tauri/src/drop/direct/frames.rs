//! The binary frames on the data channel (`docs/PROTOCOL.md`, "Data channel
//! and frames").  Drop's webview runs the frame logic with the page's
//! TypeScript (`src/direct/frames.ts` and `transfer.ts`); this is the same
//! reading in Rust, so the frame vectors are checked on both sides and the
//! sink's ACK points match the webview's exactly.

/// The largest frame.
pub const FRAME_BYTES: usize = 65_536;
/// The receiver ACKs at least this often, and when it reaches E.
pub const ACK_EVERY_BYTES: u64 = 1_048_576;
/// The most envelope bytes in flight beyond the last ACK.
pub const UNACKNOWLEDGED_BYTES: u64 = 8_388_608;
const DATA_HEADER_BYTES: usize = 9;
const END_FRAME_BYTES: usize = 41;
/// The highest the top 32 bits of an offset or size may be (2^53 - 1).
const MAX_HIGH: u32 = 0x1f_ffff;

/// Which role sent a frame.  In `to-drop` the page is the sender.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Sender,
    Receiver,
}

/// STOP's reason byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopCode {
    Cancelled = 1,
    Failed = 2,
    Storage = 3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Data { offset: u64, bytes: Vec<u8> },
    Ack { next: u64 },
    End { sha256: [u8; 32], size: u64 },
    Kept,
    Stop { code: StopCode },
}

/// A frame that is not allowed: the reader sends STOP 2 and closes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("a frame the protocol does not allow: {0}")]
pub struct FrameError(pub &'static str);

fn read_u64(bytes: &[u8]) -> Result<u64, FrameError> {
    let high = u32::from_be_bytes(bytes[..4].try_into().expect("4 bytes"));
    if high > MAX_HIGH {
        return Err(FrameError("an offset or size beyond 2^53 - 1"));
    }
    let low = u32::from_be_bytes(bytes[4..8].try_into().expect("4 bytes"));
    Ok((u64::from(high) << 32) | u64::from(low))
}

/// Reads one binary message sent by `from`.  DATA and END come only from
/// the sender, ACK and KEPT only from the receiver, STOP from either.  Type 6
/// is reserved, and an unknown STOP reason reads as 2.
pub fn decode(from: Role, frame: &[u8]) -> Result<Frame, FrameError> {
    let Some(&kind) = frame.first() else {
        return Err(FrameError("an empty message"));
    };
    match (kind, from) {
        (1, Role::Sender) => {
            if frame.len() <= DATA_HEADER_BYTES || frame.len() > FRAME_BYTES {
                return Err(FrameError("a DATA frame of the wrong length"));
            }
            Ok(Frame::Data {
                offset: read_u64(&frame[1..9])?,
                bytes: frame[DATA_HEADER_BYTES..].to_vec(),
            })
        }
        (2, Role::Receiver) if frame.len() == 9 => Ok(Frame::Ack {
            next: read_u64(&frame[1..9])?,
        }),
        (3, Role::Sender) if frame.len() == END_FRAME_BYTES => Ok(Frame::End {
            sha256: frame[1..33].try_into().expect("32 bytes"),
            size: read_u64(&frame[33..41])?,
        }),
        (4, Role::Receiver) if frame.len() == 1 => Ok(Frame::Kept),
        (5, _) if frame.len() == 2 => Ok(Frame::Stop {
            code: match frame[1] {
                1 => StopCode::Cancelled,
                3 => StopCode::Storage,
                _ => StopCode::Failed,
            },
        }),
        (1..=5, _) => Err(FrameError("a frame of the wrong length or direction")),
        _ => Err(FrameError("an unknown frame type")),
    }
}

/// The frame's bytes.  `None` for a DATA frame that is empty or too long.
pub fn encode(frame: &Frame) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    match frame {
        Frame::Data { offset, bytes } => {
            if bytes.is_empty() || DATA_HEADER_BYTES + bytes.len() > FRAME_BYTES {
                return None;
            }
            out.push(1);
            out.extend_from_slice(&offset.to_be_bytes());
            out.extend_from_slice(bytes);
        }
        Frame::Ack { next } => {
            out.push(2);
            out.extend_from_slice(&next.to_be_bytes());
        }
        Frame::End { sha256, size } => {
            out.push(3);
            out.extend_from_slice(sha256);
            out.extend_from_slice(&size.to_be_bytes());
        }
        Frame::Kept => out.push(4),
        Frame::Stop { code } => out.extend_from_slice(&[5, *code as u8]),
    }
    Some(out)
}

/// The receiver's ACK rule: after writing up to `written` with the last ACK
/// at `acked`, the `next` it sends now, if any.
pub fn ack_due(written: u64, acked: u64, total: u64) -> Option<u64> {
    (written > acked && (written - acked >= ACK_EVERY_BYTES || written == total)).then_some(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn role(side: &str) -> Role {
        match side {
            "page" => Role::Sender,
            "drop" => Role::Receiver,
            other => panic!("unknown side {other}"),
        }
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn vectors() -> Value {
        serde_json::from_str(include_str!(
            "../../../../../vectors/wildbloom-direct-v1.json"
        ))
        .unwrap()
    }

    #[test]
    fn every_frame_vector_reads_and_writes_back() {
        let fixture = vectors();
        assert_eq!(fixture["limits"]["frameBytes"], FRAME_BYTES);
        assert_eq!(
            fixture["limits"]["unacknowledgedBytes"],
            UNACKNOWLEDGED_BYTES
        );
        assert_eq!(fixture["limits"]["ackEveryBytes"], ACK_EVERY_BYTES);
        let frames = fixture["frames"].as_array().unwrap();
        assert!(frames.len() >= 8);
        for vector in frames {
            let name = vector["name"].as_str().unwrap();
            let bytes = unhex(vector["hex"].as_str().unwrap());
            let frame = decode(role(vector["from"].as_str().unwrap()), &bytes)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(encode(&frame).unwrap(), bytes, "{name}");
        }
    }

    #[test]
    fn every_refused_frame_vector_is_refused() {
        let fixture = vectors();
        let refusals = fixture["frameRefusals"].as_array().unwrap();
        assert!(refusals.len() >= 10);
        for vector in refusals {
            let name = vector["name"].as_str().unwrap();
            let bytes = unhex(vector["hex"].as_str().unwrap());
            assert!(
                decode(role(vector["from"].as_str().unwrap()), &bytes).is_err(),
                "{name}"
            );
        }
    }

    #[test]
    fn offsets_beyond_the_safe_range_and_unknown_stop_reasons() {
        let mut data = vec![1, 0, 0x20, 0, 0, 0, 0, 0, 0, 7];
        assert!(decode(Role::Sender, &data).is_err());
        data[2] = 0x1f;
        assert!(decode(Role::Sender, &data).is_ok());
        assert_eq!(
            decode(Role::Receiver, &[5, 9]).unwrap(),
            Frame::Stop {
                code: StopCode::Failed
            }
        );
        let mut largest = vec![0u8; FRAME_BYTES];
        largest[0] = 1;
        assert!(decode(Role::Sender, &largest).is_ok());
        largest.push(0);
        assert!(decode(Role::Sender, &largest).is_err());
        assert_eq!(
            encode(&Frame::Data {
                offset: 0,
                bytes: vec![]
            }),
            None
        );
    }

    #[test]
    fn the_ack_rule() {
        let total = 3 * ACK_EVERY_BYTES + 10;
        assert_eq!(ack_due(65_536, 0, total), None);
        assert_eq!(ack_due(ACK_EVERY_BYTES, 0, total), Some(ACK_EVERY_BYTES));
        assert_eq!(ack_due(ACK_EVERY_BYTES + 5, ACK_EVERY_BYTES, total), None);
        assert_eq!(ack_due(total, 3 * ACK_EVERY_BYTES, total), Some(total));
        assert_eq!(ack_due(10, 0, 10), Some(10));
        assert_eq!(ack_due(0, 0, 0), None);
    }
}
