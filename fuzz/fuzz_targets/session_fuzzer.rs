#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = ironfleet::replay_session_tape(data);
    let _ = ironfleet::decode_any(data);
});