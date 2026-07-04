# IronFleet

IronFleet is an offline Rust decoder for a fictional but realistic fleet telemetry exchange format. It parses length-aware telemetry archives, route manifests, alert rules, and stateful session tapes used by vehicle gateways that batch sensor readings before forwarding them to a command center.

The project is intentionally dependency-free so fuzzing builds can run hermetically. The decoder exposes independent entry points for archive ingestion, route-book parsing, alert rule parsing, and session replay. Fuzz targets live under `fuzz/fuzz_targets` and are built by `.clusterfuzzlite/build.sh` into `$OUT` without network access.

## Format Overview

An IronFleet archive starts with `IFTL/1` followed by line-oriented records:

- `meta key=value ...` stores fleet metadata.
- `route id=... from=... to=... distance=...` defines route legs.
- `waypoint route=... index=... lat=... lon=... dwell=...` adds route geometry.
- `sensor id=... value=... unit=... ts=...` records sensor observations.
- `alert id=... when=... op=... value=... severity=...` defines alert rules.
- `flow`, `data`, `defer`, `ack`, `close`, and `inspect` records form a stateful session tape.

The session decoder exercises lifecycle-heavy state: flows accumulate chunks, deferred payloads are tracked across inspection windows, and route/profile metadata influences sampling decisions.

## Fuzzing

```bash
.clusterfuzzlite/build.sh
```

The build script expects ClusterFuzzLite/OSS-Fuzz style environment variables (`SRC`, `OUT`, and `LIB_FUZZING_ENGINE` or `/usr/lib/libFuzzingEngine.a`). It uses Cargo in offline locked mode and copies every harness binary into `$OUT`.