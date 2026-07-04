pub mod alert;
pub mod archive;
pub mod catalog;
pub mod checksum;
pub mod error;
pub mod frame;
pub mod model;
pub mod reader;
pub mod route;
pub mod session;
pub mod text;

pub use alert::{parse_alert_program, AlertProgram};
pub use archive::{decode_archive, decode_any, FleetDocument};
pub use error::{Diagnostics, IronfleetError, Result, Severity};
pub use frame::{decode_frame_stream, Frame, FrameKind};
pub use route::{parse_route_manifest, RouteBook};
pub use session::{replay_session_tape, SessionReport};

pub fn analyze_bytes(data: &[u8]) -> Diagnostics {
    let mut diagnostics = Diagnostics::new();
    match decode_any(data) {
        Ok(report) => diagnostics.extend(report.diagnostics),
        Err(err) => diagnostics.push(err),
    }
    diagnostics
}