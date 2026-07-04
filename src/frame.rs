use crate::checksum::{ascii_score, crc16_x25, rolling_tag};
use crate::error::{IronfleetError, Result};
use crate::reader::ByteReader;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Metadata,
    Route,
    Sensor,
    Alert,
    Session,
    Unknown(u8),
}

impl FrameKind {
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            1 => FrameKind::Metadata,
            2 => FrameKind::Route,
            3 => FrameKind::Sensor,
            4 => FrameKind::Alert,
            5 => FrameKind::Session,
            other => FrameKind::Unknown(other),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            FrameKind::Metadata => "metadata",
            FrameKind::Route => "route",
            FrameKind::Sensor => "sensor",
            FrameKind::Alert => "alert",
            FrameKind::Session => "session",
            FrameKind::Unknown(_) => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: FrameKind,
    pub flags: u8,
    pub sequence: u32,
    pub payload: Vec<u8>,
    pub checksum_valid: bool,
    pub ascii_score: u8,
    pub routing_tag: u32,
}

pub fn decode_frame_stream(data: &[u8]) -> Result<Vec<Frame>> {
    if data.starts_with(b"IFTL/") || data.starts_with(b"IFSS/") {
        return decode_line_frames(data);
    }
    decode_binary_frames(data)
}

fn decode_binary_frames(data: &[u8]) -> Result<Vec<Frame>> {
    let mut reader = ByteReader::new(data);
    let mut frames = Vec::new();
    while reader.remaining() >= 10 {
        let sync = reader.take(2)?;
        if sync != b"IF" {
            return Err(IronfleetError::medium("frame sync mismatch").at(reader.position().saturating_sub(2)));
        }
        let kind = FrameKind::from_byte(reader.take_u8()?);
        let flags = reader.take_u8()?;
        let sequence = reader.take_le_u32()?;
        let len = reader.take_le_u16()? as usize;
        let payload = reader.take(len)?.to_vec();
        let expected = reader.take_le_u16()?;
        let actual = crc16_x25(&payload);
        frames.push(Frame {
            kind,
            flags,
            sequence,
            ascii_score: ascii_score(&payload),
            routing_tag: rolling_tag(sequence, &payload),
            checksum_valid: expected == actual,
            payload,
        });
        if frames.len() > 4096 {
            return Err(IronfleetError::medium("too many frames in stream"));
        }
    }
    if !reader.is_empty() {
        return Err(IronfleetError::low("trailing partial frame").at(reader.position()));
    }
    Ok(frames)
}

fn decode_line_frames(data: &[u8]) -> Result<Vec<Frame>> {
    let text = String::from_utf8_lossy(data);
    let mut frames = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("IFTL/") || line.starts_with("IFSS/") {
            continue;
        }
        let (kind, flags) = if line.starts_with("meta ") {
            (FrameKind::Metadata, 0)
        } else if line.starts_with("route ") || line.starts_with("waypoint ") {
            (FrameKind::Route, 0)
        } else if line.starts_with("sensor ") {
            (FrameKind::Sensor, 0)
        } else if line.starts_with("alert ") {
            (FrameKind::Alert, 0)
        } else if line.starts_with("flow ") || line.starts_with("data ") || line.starts_with("defer ") || line.starts_with("ack ") || line.starts_with("close ") || line.starts_with("inspect ") || line.starts_with("config ") {
            (FrameKind::Session, 1)
        } else {
            (FrameKind::Unknown(0xff), 0)
        };
        let payload = line.as_bytes().to_vec();
        frames.push(Frame {
            kind,
            flags,
            sequence: idx as u32,
            ascii_score: ascii_score(&payload),
            routing_tag: rolling_tag(idx as u32, &payload),
            checksum_valid: true,
            payload,
        });
    }
    Ok(frames)
}