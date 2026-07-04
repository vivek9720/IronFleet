use crate::error::{IronfleetError, Result};

#[derive(Debug, Clone)]
pub struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    pub fn new(data: &'a [u8]) -> Self { Self { data, pos: 0 } }
    pub fn len(&self) -> usize { self.data.len() }
    pub fn position(&self) -> usize { self.pos }
    pub fn remaining(&self) -> usize { self.data.len().saturating_sub(self.pos) }
    pub fn is_empty(&self) -> bool { self.remaining() == 0 }
    pub fn original(&self) -> &'a [u8] { self.data }

    pub fn set_position(&mut self, pos: usize) -> Result<()> {
        if pos > self.data.len() {
            return Err(IronfleetError::medium("reader seek outside input").at(pos));
        }
        self.pos = pos;
        Ok(())
    }

    pub fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(count).ok_or_else(|| IronfleetError::medium("reader offset overflow"))?;
        if end > self.data.len() {
            return Err(IronfleetError::medium("truncated input")
                .at(self.pos)
                .with_context(format!("need {} bytes, have {}", count, self.remaining())));
        }
        let start = self.pos;
        self.pos = end;
        Ok(&self.data[start..end])
    }

    pub fn peek(&self, count: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(count).ok_or_else(|| IronfleetError::medium("reader offset overflow"))?;
        if end > self.data.len() {
            return Err(IronfleetError::medium("truncated input").at(self.pos));
        }
        Ok(&self.data[self.pos..end])
    }

    pub fn take_rest(&mut self) -> &'a [u8] {
        let start = self.pos;
        self.pos = self.data.len();
        &self.data[start..]
    }

    pub fn skip(&mut self, count: usize) -> Result<()> { self.take(count).map(|_| ()) }
    pub fn take_u8(&mut self) -> Result<u8> { Ok(self.take(1)?[0]) }
    pub fn take_le_u16(&mut self) -> Result<u16> { let b = self.take(2)?; Ok(u16::from_le_bytes([b[0], b[1]])) }
    pub fn take_le_u32(&mut self) -> Result<u32> { let b = self.take(4)?; Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]])) }
    pub fn take_be_u16(&mut self) -> Result<u16> { let b = self.take(2)?; Ok(u16::from_be_bytes([b[0], b[1]])) }
    pub fn take_be_u32(&mut self) -> Result<u32> { let b = self.take(4)?; Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]])) }

    pub fn take_varint(&mut self) -> Result<u64> {
        let mut shift = 0u32;
        let mut value = 0u64;
        for _ in 0..10 {
            let byte = self.take_u8()?;
            value |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
        Err(IronfleetError::medium("varint exceeds 10 bytes").at(self.pos))
    }

    pub fn take_line(&mut self) -> Option<(usize, &'a [u8])> {
        if self.is_empty() {
            return None;
        }
        let start = self.pos;
        let mut end = self.pos;
        while end < self.data.len() && self.data[end] != b'\n' {
            end += 1;
        }
        self.pos = if end < self.data.len() { end + 1 } else { end };
        let mut line_end = end;
        if line_end > start && self.data[line_end - 1] == b'\r' {
            line_end -= 1;
        }
        Some((start, &self.data[start..line_end]))
    }
}

pub fn bounded_slice(data: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    let end = offset.checked_add(len).ok_or_else(|| IronfleetError::medium("slice offset overflow"))?;
    if end > data.len() {
        return Err(IronfleetError::medium("slice outside input").at(offset));
    }
    Ok(&data[offset..end])
}