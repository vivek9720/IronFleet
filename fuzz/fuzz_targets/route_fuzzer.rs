#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = ironfleet::parse_route_manifest(data);
    let _ = ironfleet::parse_alert_program(data);
    let _ = ironfleet::decode_any(data);
});