#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = ironfleet::decode_archive(data);
    let _ = ironfleet::decode_any(data);
    let _ = ironfleet::decode_frame_stream(data);
});