use crate::error::IronfleetError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataEntry {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SensorSample {
    pub id: String,
    pub value: f64,
    pub unit: String,
    pub timestamp: u64,
    pub quality: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportProto {
    Tcp,
    Udp,
    Can,
    Mqtt,
    Unknown(String),
}

impl TransportProto {
    pub fn parse(input: &str) -> Self {
        match input.to_ascii_lowercase().as_str() {
            "tcp" => TransportProto::Tcp,
            "udp" => TransportProto::Udp,
            "can" => TransportProto::Can,
            "mqtt" => TransportProto::Mqtt,
            other => TransportProto::Unknown(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            TransportProto::Tcp => "tcp",
            TransportProto::Udp => "udp",
            TransportProto::Can => "can",
            TransportProto::Mqtt => "mqtt",
            TransportProto::Unknown(value) => value.as_str(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    pub fn parse(input: &str) -> Self {
        if let Some((host, port)) = input.rsplit_once(':') {
            let parsed = port.parse::<u16>().unwrap_or(0);
            Self { host: host.to_string(), port: parsed }
        } else {
            Self { host: input.to_string(), port: 0 }
        }
    }

    pub fn render(&self) -> String { format!("{}:{}", self.host, self.port) }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteLeg {
    pub id: String,
    pub origin: String,
    pub destination: String,
    pub distance_m: u32,
    pub risk: u8,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Waypoint {
    pub route: String,
    pub index: u32,
    pub lat: f64,
    pub lon: f64,
    pub dwell_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComparisonOp {
    Less,
    LessEqual,
    Equal,
    NotEqual,
    GreaterEqual,
    Greater,
    Contains,
}

impl ComparisonOp {
    pub fn parse(input: &str) -> Option<Self> {
        match input {
            "<" | "lt" => Some(ComparisonOp::Less),
            "<=" | "le" => Some(ComparisonOp::LessEqual),
            "=" | "==" | "eq" => Some(ComparisonOp::Equal),
            "!=" | "ne" => Some(ComparisonOp::NotEqual),
            ">=" | "ge" => Some(ComparisonOp::GreaterEqual),
            ">" | "gt" => Some(ComparisonOp::Greater),
            "contains" | "has" => Some(ComparisonOp::Contains),
            _ => None,
        }
    }

    pub fn evaluate(&self, left: f64, right: f64) -> bool {
        match self {
            ComparisonOp::Less => left < right,
            ComparisonOp::LessEqual => left <= right,
            ComparisonOp::Equal => (left - right).abs() < f64::EPSILON,
            ComparisonOp::NotEqual => (left - right).abs() >= f64::EPSILON,
            ComparisonOp::GreaterEqual => left >= right,
            ComparisonOp::Greater => left > right,
            ComparisonOp::Contains => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AlertRule {
    pub id: String,
    pub signal: String,
    pub op: ComparisonOp,
    pub threshold: f64,
    pub severity: crate::error::Severity,
    pub hold_seconds: u32,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowKey {
    pub id: u32,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub protocol: TransportProto,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowSummary {
    pub id: u32,
    pub chunks: usize,
    pub bytes: usize,
    pub deferred: usize,
    pub closed: bool,
    pub inspection_score: u64,
}

#[derive(Debug, Clone, Default)]
pub struct DecodeReport {
    pub diagnostics: Vec<IronfleetError>,
    pub metadata_count: usize,
    pub route_count: usize,
    pub waypoint_count: usize,
    pub sensor_count: usize,
    pub alert_count: usize,
    pub flow_count: usize,
    pub checksum: u32,
}

impl DecodeReport {
    pub fn merge(&mut self, other: DecodeReport) {
        self.diagnostics.extend(other.diagnostics);
        self.metadata_count += other.metadata_count;
        self.route_count += other.route_count;
        self.waypoint_count += other.waypoint_count;
        self.sensor_count += other.sensor_count;
        self.alert_count += other.alert_count;
        self.flow_count += other.flow_count;
        self.checksum = self.checksum.rotate_left(5) ^ other.checksum;
    }
}