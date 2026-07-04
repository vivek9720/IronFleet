use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "info" | "note" => Some(Severity::Info),
            "low" | "minor" => Some(Severity::Low),
            "medium" | "moderate" => Some(Severity::Medium),
            "high" | "major" => Some(Severity::High),
            "critical" | "crit" | "emergency" => Some(Severity::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IronfleetError {
    pub severity: Severity,
    pub message: String,
    pub offset: Option<usize>,
    pub context: Option<String>,
}

impl IronfleetError {
    pub fn new(severity: Severity, message: impl Into<String>) -> Self {
        Self { severity, message: message.into(), offset: None, context: None }
    }

    pub fn info(message: impl Into<String>) -> Self { Self::new(Severity::Info, message) }
    pub fn low(message: impl Into<String>) -> Self { Self::new(Severity::Low, message) }
    pub fn medium(message: impl Into<String>) -> Self { Self::new(Severity::Medium, message) }
    pub fn high(message: impl Into<String>) -> Self { Self::new(Severity::High, message) }
    pub fn critical(message: impl Into<String>) -> Self { Self::new(Severity::Critical, message) }

    pub fn at(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }
}

impl fmt::Display for IronfleetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.offset, self.context.as_ref()) {
            (Some(offset), Some(context)) => write!(f, "{} at {}: {} ({})", self.severity.as_str(), offset, self.message, context),
            (Some(offset), None) => write!(f, "{} at {}: {}", self.severity.as_str(), offset, self.message),
            (None, Some(context)) => write!(f, "{}: {} ({})", self.severity.as_str(), self.message, context),
            (None, None) => write!(f, "{}: {}", self.severity.as_str(), self.message),
        }
    }
}

impl Error for IronfleetError {}

pub type Result<T> = std::result::Result<T, IronfleetError>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diagnostics {
    entries: Vec<IronfleetError>,
}

impl Diagnostics {
    pub fn new() -> Self { Self { entries: Vec::new() } }
    pub fn push(&mut self, error: IronfleetError) { self.entries.push(error); }
    pub fn extend<I: IntoIterator<Item = IronfleetError>>(&mut self, iter: I) { self.entries.extend(iter); }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
    pub fn len(&self) -> usize { self.entries.len() }
    pub fn iter(&self) -> impl Iterator<Item = &IronfleetError> { self.entries.iter() }
    pub fn into_vec(self) -> Vec<IronfleetError> { self.entries }
    pub fn highest(&self) -> Option<Severity> { self.entries.iter().map(|entry| entry.severity).max() }
    pub fn render_lines(&self) -> Vec<String> { self.entries.iter().map(|entry| entry.to_string()).collect() }
}