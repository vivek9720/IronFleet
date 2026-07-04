use crate::alert::{parse_alert_line, parse_alert_program, parse_sensor_line, AlertProgram};
use crate::checksum::rolling_tag;
use crate::error::{Diagnostics, IronfleetError, Result};
use crate::frame::{decode_frame_stream, FrameKind};
use crate::model::{DecodeReport, MetadataEntry, SensorSample};
use crate::route::{parse_route_line, parse_route_manifest, parse_waypoint_line, RouteBook};
use crate::session::{replay_session_tape, SessionReport};
use crate::text::{as_lossy_text, find_pair, parse_pairs, split_record, unquote};

#[derive(Debug, Clone, Default)]
pub struct FleetDocument {
    pub metadata: Vec<MetadataEntry>,
    pub routes: RouteBook,
    pub sensors: Vec<SensorSample>,
    pub alerts: AlertProgram,
    pub sessions: Vec<SessionReport>,
    pub diagnostics: Diagnostics,
}

impl FleetDocument {
    pub fn report(&self) -> DecodeReport {
        let mut report = DecodeReport::default();
        report.metadata_count = self.metadata.len();
        report.route_count = self.routes.routes.len();
        report.waypoint_count = self.routes.waypoints.len();
        report.sensor_count = self.sensors.len();
        report.alert_count = self.alerts.rules.len();
        report.flow_count = self.sessions.iter().map(|session| session.flows.len()).sum();
        for entry in &self.metadata {
            report.checksum ^= rolling_tag(report.checksum, entry.key.as_bytes());
            report.checksum = report.checksum.rotate_left(3) ^ rolling_tag(report.checksum, entry.value.as_bytes());
        }
        report.diagnostics.extend(self.diagnostics.clone().into_vec());
        report.diagnostics.extend(self.routes.diagnostics.clone().into_vec());
        report.diagnostics.extend(self.alerts.diagnostics.clone().into_vec());
        for session in &self.sessions {
            report.diagnostics.extend(session.diagnostics.clone().into_vec());
            report.checksum ^= session.inspection_score as u32;
        }
        report
    }
}

pub fn decode_archive(data: &[u8]) -> Result<FleetDocument> {
    let text = as_lossy_text(data);
    let mut doc = FleetDocument::default();
    let mut session_lines = String::new();
    let mut saw_header = false;

    for (line_no, raw) in text.lines().enumerate() {
        let Some((kind, rest)) = split_record(raw) else { continue; };
        match kind.to_ascii_lowercase().as_str() {
            "iftl/1" => saw_header = true,
            "meta" => match parse_metadata(rest) {
                Some(entry) => doc.metadata.push(entry),
                None => doc.diagnostics.push(IronfleetError::low("metadata record has no pairs").at(line_no)),
            },
            "route" => match parse_route_line(rest) {
                Ok(route) => doc.routes.routes.push(route),
                Err(err) => doc.diagnostics.push(err.at(line_no)),
            },
            "waypoint" => match parse_waypoint_line(rest) {
                Ok(point) => doc.routes.waypoints.push(point),
                Err(err) => doc.diagnostics.push(err.at(line_no)),
            },
            "sensor" => match parse_sensor_line(rest) {
                Ok(sample) => doc.sensors.push(sample),
                Err(err) => doc.diagnostics.push(err.at(line_no)),
            },
            "alert" => match parse_alert_line(rest) {
                Ok(rule) => doc.alerts.rules.push(rule),
                Err(err) => doc.diagnostics.push(err.at(line_no)),
            },
            "flow" | "data" | "defer" | "ack" | "close" | "inspect" | "config" => {
                session_lines.push_str(raw);
                session_lines.push('\n');
            }
            "frame" => {
                let pairs = parse_pairs(rest);
                if let Some(payload) = find_pair(&pairs, "payload") {
                    let nested = payload.as_bytes();
                    if let Ok(frames) = decode_frame_stream(nested) {
                        for frame in frames {
                            if frame.kind == FrameKind::Session {
                                session_lines.push_str(&String::from_utf8_lossy(&frame.payload));
                                session_lines.push('\n');
                            }
                        }
                    }
                }
            }
            _ => {
                if saw_header {
                    doc.diagnostics.push(IronfleetError::info("unknown archive record").at(line_no).with_context(kind.to_string()));
                }
            }
        }
        if doc.metadata.len() > 4096 || doc.sensors.len() > 16384 || doc.alerts.rules.len() > 4096 {
            return Err(IronfleetError::medium("archive exceeds decoder limits").at(line_no));
        }
    }

    if !saw_header && data.len() > 8 {
        doc.diagnostics.push(IronfleetError::low("archive header not present"));
    }
    if !session_lines.is_empty() {
        let session = replay_session_tape(session_lines.as_bytes())?;
        doc.sessions.push(session);
    }
    doc.routes.validate();
    doc.alerts.validate();
    Ok(doc)
}

fn parse_metadata(rest: &str) -> Option<MetadataEntry> {
    let pairs = parse_pairs(rest);
    if let Some((key, value)) = pairs.first() {
        Some(MetadataEntry { key: (*key).to_string(), value: unquote(value) })
    } else {
        None
    }
}

pub fn decode_any(data: &[u8]) -> Result<DecodeReport> {
    if data.starts_with(b"IFTL/1") {
        return decode_archive(data).map(|doc| doc.report());
    }
    if data.starts_with(b"IFSS/1") || data.windows(5).any(|w| w == b"flow ") {
        let session = replay_session_tape(data)?;
        let mut report = DecodeReport::default();
        report.flow_count = session.flows.len();
        report.checksum = session.inspection_score as u32;
        report.diagnostics.extend(session.diagnostics.into_vec());
        return Ok(report);
    }
    if data.windows(6).any(|w| w == b"route ") || data.windows(9).any(|w| w == b"waypoint ") {
        let route = parse_route_manifest(data)?;
        let mut report = DecodeReport::default();
        report.route_count = route.routes.len();
        report.waypoint_count = route.waypoints.len();
        report.checksum = route.score;
        report.diagnostics.extend(route.diagnostics.into_vec());
        return Ok(report);
    }
    if data.windows(6).any(|w| w == b"alert ") {
        let alerts = parse_alert_program(data)?;
        let mut report = DecodeReport::default();
        report.alert_count = alerts.rules.len();
        report.diagnostics.extend(alerts.diagnostics.into_vec());
        return Ok(report);
    }
    let frames = decode_frame_stream(data)?;
    let mut report = DecodeReport::default();
    for frame in frames {
        report.checksum ^= frame.routing_tag;
        match frame.kind {
            FrameKind::Metadata => report.metadata_count += 1,
            FrameKind::Route => report.route_count += 1,
            FrameKind::Sensor => report.sensor_count += 1,
            FrameKind::Alert => report.alert_count += 1,
            FrameKind::Session => report.flow_count += 1,
            FrameKind::Unknown(_) => report.diagnostics.push(IronfleetError::info("unknown frame kind")),
        }
        if !frame.checksum_valid {
            report.diagnostics.push(IronfleetError::low("frame checksum mismatch"));
        }
    }
    Ok(report)
}