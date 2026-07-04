use ironfleet::{decode_archive, parse_route_manifest, replay_session_tape};

#[test]
fn parses_archive_seed() {
    let input = b"IFTL/1\nmeta fleet=demo\nroute id=R1 from=A to=B distance=10 risk=1\n";
    let doc = decode_archive(input).expect("archive should parse");
    assert_eq!(doc.metadata.len(), 1);
    assert_eq!(doc.routes.routes.len(), 1);
}

#[test]
fn parses_session_seed() {
    let input = b"IFSS/1\nflow id=1 src=a:1 dst=b:2 proto=tcp\ndata id=1 seq=1 data=4142\nclose id=1\n";
    let report = replay_session_tape(input).expect("session should parse");
    assert_eq!(report.flows.len(), 1);
}

#[test]
fn parses_route_seed() {
    let input = b"route id=R2 from=A to=C distance=100 risk=4 profile=urban\nwaypoint route=R2 index=1 lat=1 lon=2 dwell=3\n";
    let book = parse_route_manifest(input).expect("route should parse");
    assert_eq!(book.routes.len(), 1);
    assert_eq!(book.waypoints.len(), 1);
}