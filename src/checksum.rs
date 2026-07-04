pub fn crc16_x25(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xffff;
    for &byte in data {
        crc ^= byte as u16;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

pub fn rolling_tag(seed: u32, data: &[u8]) -> u32 {
    let mut acc = seed ^ 0x9e37_79b9;
    for (idx, &byte) in data.iter().enumerate() {
        let rot = ((idx as u32) & 15) + 5;
        acc = acc.rotate_left(rot) ^ (byte as u32).wrapping_mul(0x45d9_f3b);
        acc = acc.wrapping_add((idx as u32).wrapping_mul(0x27d4_eb2d));
    }
    acc
}

pub fn ascii_score(data: &[u8]) -> u8 {
    if data.is_empty() {
        return 0;
    }
    let printable = data.iter().filter(|b| b.is_ascii_graphic() || b.is_ascii_whitespace()).count();
    ((printable * 100) / data.len()).min(100) as u8
}