//! Recipient and identity implementations for the age Rust port.
//!
//! Faithful port of Go age v1.3.2 (the behavioral oracle; product decision
//! 2026-10-09). One module per recipient type, mirroring the Go tree:
//!
//! - `x25519.go` — X25519 recipient/identity (Stage S2)
//! - `scrypt.go` — scrypt passphrase recipient, including Go's work-factor
//!   handling and the wordlist auto-generation flow (Stage S2)
//! - `pq.go` — the post-quantum recipient: ML-KEM-768 + X25519 hybrid over
//!   HPKE, HPKE label `age-encryption.org/mlkem768x25519` (Stage S3). This
//!   is a faithful port: `pq.go` and `filippo.io/hpke` v0.4.0 are the
//!   contract; no other implementation's design is a reference.
//! - `agessh/` — ssh-rsa and ssh-ed25519, including passphrase-encrypted
//!   keys (Stage S3)
//! - `tag/` — tagged P-256 and tagged hybrid P-256 + ML-KEM-768 (Stage S3)
//!
//! Empty in Stage S0: dependencies are wired and pinned. Each recipient
//! lands only when its two-directional interop fixtures against the Go
//! v1.3.2 binary pass — stanza layout byte-exact for the PQ port.
