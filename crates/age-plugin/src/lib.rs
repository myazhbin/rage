//! Plugin protocol for the age Rust port.
//!
//! Faithful port of Go age v1.3.2 `plugin/` (the behavioral oracle; product
//! decision 2026-10-09): both halves of the age plugin protocol — the client
//! side that drives external plugins, and the framework side they link —
//! plus stanza encode/decode over the v1 plugin protocol and the TUI
//! helpers the reference plugins share.
//!
//! Empty in Stage S0: implementation arrives with the plugin recipient in
//! S3, verified by a round-trip against the reference plugins.
