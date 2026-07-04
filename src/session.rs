use crate::catalog::{profile_for_protocol, signal_by_name};
use crate::checksum::{ascii_score, rolling_tag};
use crate::error::{Diagnostics, IronfleetError, Result};
use crate::model::{Endpoint, FlowKey, FlowSummary, TransportProto};
use crate::text::{as_lossy_text, find_pair, hex_to_bytes, parse_bool, parse_pairs, parse_u32, split_record};

#[derive(Debug, Clone)]
pub struct SessionReport {
    pub flows: Vec<FlowSummary>,
    pub diagnostics: Diagnostics,
    pub bytes_seen: usize,
    pub deferred_segments: usize,
    pub inspection_score: u64,
}

impl Default for SessionReport {
    fn default() -> Self {
        Self {
            flows: Vec::new(),
            diagnostics: Diagnostics::new(),
            bytes_seen: 0,
            deferred_segments: 0,
            inspection_score: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct SessionPolicy {
    deep_inspect: bool,
    retain_closed: bool,
    sample_stride: usize,
    max_window: usize,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self { deep_inspect: false, retain_closed: true, sample_stride: 17, max_window: 4096 }
    }
}

#[derive(Debug)]
struct FlowState {
    key: FlowKey,
    chunks: Vec<Vec<u8>>,
    bytes: usize,
    deferred: usize,
    last_ack: u32,
    generation: u32,
    inspection_score: u64,
    closed: bool,
}

impl FlowState {
    fn new(key: FlowKey, generation: u32) -> Self {
        Self {
            key,
            chunks: Vec::new(),
            bytes: 0,
            deferred: 0,
            last_ack: 0,
            generation,
            inspection_score: 0,
            closed: false,
        }
    }

    fn summary(&self) -> FlowSummary {
        FlowSummary {
            id: self.key.id,
            chunks: self.chunks.len(),
            bytes: self.bytes,
            deferred: self.deferred,
            closed: self.closed,
            inspection_score: self.inspection_score,
        }
    }
}

#[derive(Clone, Copy)]
struct DeferredSegment {
    flow_id: u32,
    sequence: u32,
    generation: u32,
    ptr: *const u8,
    actual_len: usize,
    declared_len: usize,
    ascii_score: u8,
    tag: u32,
}

impl DeferredSegment {
    fn sample(&self, policy: SessionPolicy, slot: usize) -> u64 {
        let mut acc = (self.tag as u64) ^ ((self.sequence as u64) << 17) ^ ((self.generation as u64) << 33);
        if self.ptr.is_null() || self.declared_len == 0 {
            return acc;
        }
        let window = self.declared_len.min(policy.max_window).max(self.actual_len.min(8));
        let stride = policy.sample_stride.max(1) + (slot % 13);
        let mut index = (slot + self.ascii_score as usize) % stride;
        while index < window {
            let byte = unsafe { *self.ptr.add(index) };
            acc = acc.rotate_left(5) ^ byte as u64 ^ ((index as u64) << 8);
            index += stride;
        }
        acc
    }
}

struct SessionTracker {
    policy: SessionPolicy,
    flows: Vec<FlowState>,
    closed: Vec<FlowSummary>,
    deferred: Vec<DeferredSegment>,
    next_generation: u32,
    bytes_seen: usize,
    inspection_score: u64,
    diagnostics: Diagnostics,
}

impl SessionTracker {
    fn new() -> Self {
        Self {
            policy: SessionPolicy::default(),
            flows: Vec::new(),
            closed: Vec::new(),
            deferred: Vec::new(),
            next_generation: 1,
            bytes_seen: 0,
            inspection_score: 0,
            diagnostics: Diagnostics::new(),
        }
    }

    fn configure(&mut self, pairs: &[(&str, &str)]) {
        if let Some(value) = find_pair(pairs, "inspect") {
            self.policy.deep_inspect = parse_bool(value);
        }
        if let Some(value) = find_pair(pairs, "retain") {
            self.policy.retain_closed = parse_bool(value);
        }
        if let Some(stride) = find_pair(pairs, "stride").and_then(|value| parse_u32(value).ok()) {
            self.policy.sample_stride = stride.clamp(1, 128) as usize;
        }
        if let Some(window) = find_pair(pairs, "window").and_then(|value| parse_u32(value).ok()) {
            self.policy.max_window = window.clamp(16, 16384) as usize;
        }
    }

    fn open_flow(&mut self, pairs: &[(&str, &str)]) {
        let id = find_pair(pairs, "id").or_else(|| pairs.first().map(|(_, value)| *value)).and_then(|value| parse_u32(value).ok()).unwrap_or(0);
        let proto = TransportProto::parse(find_pair(pairs, "proto").unwrap_or("tcp"));
        let source = Endpoint::parse(find_pair(pairs, "src").unwrap_or("0.0.0.0:0"));
        let destination = Endpoint::parse(find_pair(pairs, "dst").unwrap_or("0.0.0.0:0"));
        if self.flows.iter().any(|flow| flow.key.id == id) {
            self.diagnostics.push(IronfleetError::low("flow reopened before close").with_context(id.to_string()));
            return;
        }
        if profile_for_protocol(proto.as_str()).is_none() {
            self.diagnostics.push(IronfleetError::info("flow uses unknown protocol profile").with_context(proto.as_str().to_string()));
        }
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1).max(1);
        self.flows.push(FlowState::new(FlowKey { id, source, destination, protocol: proto }, generation));
    }

    fn push_data(&mut self, pairs: &[(&str, &str)], deferred: bool) {
        let id = find_pair(pairs, "id").or_else(|| pairs.first().map(|(_, value)| *value)).and_then(|value| parse_u32(value).ok()).unwrap_or(0);
        let sequence = find_pair(pairs, "seq").and_then(|value| parse_u32(value).ok()).unwrap_or(0);
        let declared = find_pair(pairs, "declared").and_then(|value| parse_u32(value).ok()).map(|value| value as usize);
        let data = find_pair(pairs, "data").or_else(|| find_pair(pairs, "hex")).unwrap_or("");
        let bytes = match hex_to_bytes(data) {
            Ok(bytes) => bytes,
            Err(err) => {
                self.diagnostics.push(err);
                return;
            }
        };
        let Some(flow) = self.flows.iter_mut().find(|flow| flow.key.id == id) else {
            self.diagnostics.push(IronfleetError::medium("data references missing flow").with_context(id.to_string()));
            return;
        };
        if sequence < flow.last_ack {
            self.diagnostics.push(IronfleetError::low("out-of-order data segment").with_context(id.to_string()));
        }
        self.bytes_seen += bytes.len();
        flow.bytes += bytes.len();
        flow.inspection_score ^= rolling_tag(sequence, &bytes) as u64;
        flow.chunks.push(bytes);
        if deferred {
            let idx = flow.chunks.len() - 1;
            let chunk = &flow.chunks[idx];
            let actual_len = chunk.len();
            let declared_len = declared.unwrap_or(actual_len);
            let segment = DeferredSegment {
                flow_id: id,
                sequence,
                generation: flow.generation,
                ptr: chunk.as_ptr(),
                actual_len,
                declared_len,
                ascii_score: ascii_score(chunk),
                tag: rolling_tag(flow.generation ^ sequence, chunk),
            };
            flow.deferred += 1;
            self.deferred.push(segment);
            if self.deferred.len() > 16384 {
                self.deferred.remove(0);
            }
        }
    }

    fn ack(&mut self, pairs: &[(&str, &str)]) {
        let id = find_pair(pairs, "id").or_else(|| pairs.first().map(|(_, value)| *value)).and_then(|value| parse_u32(value).ok()).unwrap_or(0);
        let seq = find_pair(pairs, "seq").and_then(|value| parse_u32(value).ok()).unwrap_or(0);
        if let Some(flow) = self.flows.iter_mut().find(|flow| flow.key.id == id) {
            flow.last_ack = flow.last_ack.max(seq);
            flow.inspection_score = flow.inspection_score.rotate_left((seq & 31) as u32);
        } else {
            self.diagnostics.push(IronfleetError::low("ack references missing flow").with_context(id.to_string()));
        }
    }

    fn close(&mut self, pairs: &[(&str, &str)]) {
        let id = find_pair(pairs, "id").or_else(|| pairs.first().map(|(_, value)| *value)).and_then(|value| parse_u32(value).ok()).unwrap_or(0);
        if let Some(index) = self.flows.iter().position(|flow| flow.key.id == id) {
            let mut flow = self.flows.swap_remove(index);
            flow.closed = true;
            let summary = flow.summary();
            if self.policy.retain_closed {
                self.closed.push(summary);
                if self.closed.len() > 2048 {
                    self.closed.remove(0);
                }
            }
        } else {
            self.diagnostics.push(IronfleetError::low("close references missing flow").with_context(id.to_string()));
        }
    }

    fn inspect(&mut self, pairs: &[(&str, &str)]) {
        let id = find_pair(pairs, "id").or_else(|| pairs.first().map(|(_, value)| *value)).and_then(|value| parse_u32(value).ok()).unwrap_or(0);
        let slot = find_pair(pairs, "slot").and_then(|value| parse_u32(value).ok()).unwrap_or(0) as usize;
        let signal = find_pair(pairs, "signal").unwrap_or("engine.rpm");
        let mut policy = self.policy;
        if let Some(spec) = signal_by_name(signal) {
            policy.sample_stride = (policy.sample_stride + spec.precision as usize + 1).clamp(1, 192);
        }
        if !policy.deep_inspect {
            return;
        }
        let mut matched = 0usize;
        for segment in self.deferred.iter().filter(|segment| segment.flow_id == id) {
            let score = segment.sample(policy, slot + matched);
            self.inspection_score ^= score;
            matched += 1;
        }
        if matched == 0 {
            self.diagnostics.push(IronfleetError::info("inspect found no deferred segments").with_context(id.to_string()));
        }
    }

    fn finish(mut self) -> SessionReport {
        let mut flows = self.closed;
        flows.extend(self.flows.iter().map(FlowState::summary));
        flows.sort_by_key(|flow| flow.id);
        SessionReport {
            flows,
            diagnostics: self.diagnostics,
            bytes_seen: self.bytes_seen,
            deferred_segments: self.deferred.len(),
            inspection_score: self.inspection_score,
        }
    }
}

fn parse_positional_pairs<'a>(rest: &'a str) -> Vec<(&'a str, &'a str)> {
    let mut pairs = parse_pairs(rest);
    if let Some(first) = rest.split_whitespace().next() {
        if !first.contains('=') {
            pairs.insert(0, ("id", first));
        }
    }
    pairs
}

pub fn replay_session_tape(data: &[u8]) -> Result<SessionReport> {
    let text = as_lossy_text(data);
    let mut tracker = SessionTracker::new();
    for (line_no, raw) in text.lines().enumerate() {
        let Some((kind, rest)) = split_record(raw) else { continue; };
        let pairs = parse_positional_pairs(rest);
        match kind.to_ascii_lowercase().as_str() {
            "ifss/1" | "iftl/1" => {}
            "config" => tracker.configure(&pairs),
            "flow" => tracker.open_flow(&pairs),
            "data" => tracker.push_data(&pairs, false),
            "defer" => tracker.push_data(&pairs, true),
            "ack" => tracker.ack(&pairs),
            "close" => tracker.close(&pairs),
            "inspect" => tracker.inspect(&pairs),
            "sensor" => {
                if let Some(id) = find_pair(&pairs, "id") {
                    if signal_by_name(id).is_none() {
                        tracker.diagnostics.push(IronfleetError::low("session references unknown sensor").at(line_no).with_context(id.to_string()));
                    }
                }
            }
            _ => tracker.diagnostics.push(IronfleetError::info("ignored session record").at(line_no).with_context(kind.to_string())),
        }
        if tracker.flows.len() > 4096 || tracker.deferred.len() > 16384 {
            return Err(IronfleetError::medium("session tape exceeds decoder limits").at(line_no));
        }
    }
    Ok(tracker.finish())
}