//! ASCII armor for the age Rust port.
//!
//! Faithful port of Go age v1.3.2 `armor/` (the behavioral oracle; product
//! decision 2026-10-09): the PEM-style wrapper around a header/footer pair,
//! including its strict CRLF / carriage-return validation — the strictness
//! cases are part of the observable behavior and are ported, not relaxed.
//!
//! Empty in Stage S0: implementation arrives with the standard recipients in
//! S2, covered by the armor strictness fixtures.
