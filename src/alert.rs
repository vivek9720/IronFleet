use crate::catalog::{fault_by_code, signal_by_name};
use crate::error::{Diagnostics, IronfleetError, Result, Severity};
use crate::model::{AlertRule, ComparisonOp, SensorSample};
use crate::text::{as_lossy_text, find_pair, parse_f64, parse_pairs, parse_u32, split_record};

#[derive(Debug, Clone, Default)]
pub struct AlertProgram {
    pub rules: Vec<AlertRule>,
    pub diagnostics: Diagnostics,
}

impl AlertProgram {
    pub fn evaluate(&self, samples: &[SensorSample]) -> Vec<String> {
        let mut fired = Vec::new();
        for rule in &self.rules {
            for sample in samples.iter().filter(|sample| sample.id == rule.signal) {
                if rule.op.evaluate(sample.value, rule.threshold) {
                    fired.push(rule.id.clone());
                    break;
                }
            }
        }
        fired
    }

    pub fn validate(&mut self) {
        for rule in &self.rules {
            if signal_by_name(&rule.signal).is_none() {
                self.diagnostics.push(IronfleetError::low("alert references unknown signal").with_context(rule.signal.clone()));
            }
            if rule.hold_seconds > 86_400 {
                self.diagnostics.push(IronfleetError::medium("alert hold period exceeds one day").with_context(rule.id.clone()));
            }
        }
    }
}

pub fn parse_alert_program(data: &[u8]) -> Result<AlertProgram> {
    let text = as_lossy_text(data);
    let mut program = AlertProgram::default();
    for (line_no, raw) in text.lines().enumerate() {
        let Some((kind, rest)) = split_record(raw) else { continue; };
        match kind.to_ascii_lowercase().as_str() {
            "alert" => match parse_alert_line(rest) {
                Ok(rule) => program.rules.push(rule),
                Err(err) => program.diagnostics.push(err.at(line_no)),
            },
            "fault" => {
                let pairs = parse_pairs(rest);
                if let Some(code) = find_pair(&pairs, "code").and_then(|value| parse_u32(value).ok()) {
                    if fault_by_code(code as u16).is_none() {
                        program.diagnostics.push(IronfleetError::low("unknown fault code in alert program").at(line_no));
                    }
                }
            }
            "iftl/1" | "ifss/1" => {}
            _ => {}
        }
        if program.rules.len() > 4096 {
            return Err(IronfleetError::medium("alert program exceeds decoder limits"));
        }
    }
    program.validate();
    Ok(program)
}

pub fn parse_alert_line(rest: &str) -> Result<AlertRule> {
    let pairs = parse_pairs(rest);
    let id = find_pair(&pairs, "id").unwrap_or("alert-unknown").to_string();
    let signal = find_pair(&pairs, "when").or_else(|| find_pair(&pairs, "signal")).unwrap_or("unknown.signal").to_string();
    let op = find_pair(&pairs, "op").and_then(ComparisonOp::parse).unwrap_or(ComparisonOp::Greater);
    let threshold = find_pair(&pairs, "value").or_else(|| find_pair(&pairs, "threshold")).map(parse_f64).transpose()?.unwrap_or(0.0);
    let severity = find_pair(&pairs, "severity").and_then(Severity::parse).unwrap_or(Severity::Medium);
    let hold_seconds = find_pair(&pairs, "for").or_else(|| find_pair(&pairs, "hold")).map(parse_u32).transpose()?.unwrap_or(0);
    let tags = find_pair(&pairs, "tags")
        .unwrap_or("")
        .split('|')
        .filter(|tag| !tag.is_empty())
        .map(|tag| tag.to_ascii_lowercase())
        .collect();
    Ok(AlertRule { id, signal, op, threshold, severity, hold_seconds, tags })
}

pub fn parse_sensor_line(rest: &str) -> Result<SensorSample> {
    let pairs = parse_pairs(rest);
    let id = find_pair(&pairs, "id").unwrap_or("unknown.signal").to_string();
    let value = find_pair(&pairs, "value").map(parse_f64).transpose()?.unwrap_or(0.0);
    let unit = find_pair(&pairs, "unit").unwrap_or("").to_string();
    let timestamp = find_pair(&pairs, "ts").or_else(|| find_pair(&pairs, "time")).map(parse_u32).transpose()?.unwrap_or(0) as u64;
    let quality = find_pair(&pairs, "quality").map(parse_u32).transpose()?.unwrap_or(100).min(100) as u8;
    Ok(SensorSample { id, value, unit, timestamp, quality })
}
