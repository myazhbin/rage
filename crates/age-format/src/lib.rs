//! Wire-format core of the age Rust port.
//!
//! Faithful port of Go age v1.3.2 (the behavioral oracle; product decision
//! 2026-10-09). Owned here, mirroring the Go tree:
//!
//! - root-package glue (`age.go`) — header/payload framing around the
//!   `Identity`/`Recipient` interface pair
//! - `internal/format` — stanza/header wire format, header MAC, strict
//!   field validation
//! - `internal/stream` — ChaCha20-Poly1305 STREAM payload encryption
//! - `internal/bech32` — key-string encoding for every HRP: `age1`,
//!   `AGE-SECRET-KEY-1`, `age1pq`, `AGE-SECRET-KEY-PQ-1`, `age1tag`,
//!   `AGE-PLUGIN-`
//!
//! Empty in Stage S0: dependencies are wired and pinned; implementation
//! begins in S1, judged by the full CCTV conformance suite.
//!
//! Faithful-port rule: where the Go code is stricter than the public
//! `age-encryption.org/v1` spec, the Go code wins — and the difference is
//! recorded, never "fixed".
