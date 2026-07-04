use crate::error::{IronfleetError, Result};

pub fn as_lossy_text(data: &[u8]) -> String {
    String::from_utf8_lossy(data).replace('\0', " ")
}

pub fn clean_token(input: &str) -> &str {
    input.trim_matches(|c: char| c.is_ascii_whitespace() || c == ',' || c == ';')
}

pub fn split_record(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut parts = line.splitn(2, char::is_whitespace);
    let head = parts.next()?;
    let rest = parts.next().unwrap_or("").trim();
    Some((head, rest))
}

pub fn parse_pairs(rest: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    for token in rest.split_whitespace() {
        let token = clean_token(token);
        if let Some((key, value)) = token.split_once('=') {
            out.push((key.trim(), value.trim_matches('"')));
        }
    }
    out
}

pub fn find_pair<'a>(pairs: &'a [(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    pairs.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| *value)
}

pub fn parse_u32(value: &str) -> Result<u32> {
    let value = value.trim();
    if let Some(hex) = value.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).map_err(|_| IronfleetError::medium("invalid hex integer"))
    } else {
        value.parse::<u32>().map_err(|_| IronfleetError::medium("invalid integer"))
    }
}

pub fn parse_i64(value: &str) -> Result<i64> {
    value.trim().parse::<i64>().map_err(|_| IronfleetError::medium("invalid signed integer"))
}

pub fn parse_f64(value: &str) -> Result<f64> {
    value.trim().parse::<f64>().map_err(|_| IronfleetError::medium("invalid floating point value"))
}

pub fn parse_bool(value: &str) -> bool {
    matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on" | "deep" | "enabled")
}

pub fn hex_to_bytes(input: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut high: Option<u8> = None;
    for byte in input.bytes() {
        let val = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            b':' | b'-' | b'_' | b' ' | b',' => continue,
            _ => return Err(IronfleetError::medium("non-hex digit in byte field")),
        };
        if let Some(h) = high.take() {
            out.push((h << 4) | val);
        } else {
            high = Some(val);
        }
    }
    if let Some(h) = high {
        out.push(h << 4);
    }
    Ok(out)
}

pub fn unquote(input: &str) -> String {
    let mut out = String::new();
    let mut escaped = false;
    for ch in input.trim_matches('"').chars() {
        if escaped {
            match ch {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                '\\' => out.push('\\'),
                '"' => out.push('"'),
                other => out.push(other),
            }
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else {
            out.push(ch);
        }
    }
    out
}