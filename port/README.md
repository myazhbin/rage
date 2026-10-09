# Rust port — Stage S0 notes

Status: S0 complete — wired-but-empty Cargo workspace, pinned toolchain, CI
gates, and the pinned dependency selection. The Go implementation is
untouched and remains the shipped implementation until the S5 gate (product
decision, 2026-10-09). Plan of record: _age: Go → Rust — Product Review &
Migration Plan_ (`art_0aGiKVHb`); Go v1.3.2 is the behavioral oracle.

## What S0 delivers

| Piece               | Choice                                                                   |
| ------------------- | ------------------------------------------------------------------------ |
| Workspace           | `crates/age-format`, `age-recipients`, `age-plugin`, `age-armor` — empty libs with crate docs mapping each Go unit to its landing stage; CLI binaries arrive in S4 |
| Toolchain           | Rust `1.99.0`, pinned patch-exact in `rust-toolchain.toml` (`rustfmt` + `clippy` components) |
| Formatting          | rustfmt defaults, no style overrides (`rustfmt.toml` documents the intent) |
| Safety lint         | `unsafe_code = "forbid"` for all workspace crates via `[workspace.lints]` — the port writes protocol and glue only |
| CI (`rust.yml`)     | `cargo fmt --all --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace` on ubuntu/macos/windows; `cargo-deny` (advisories + licenses enforced); `cargo-audit` (RustSec DB) |
| Publishing          | `publish = false` everywhere — naming/publishing is open question Q3 |

## Dependency selection (pin time: 2026-10-09)

All pins are exact (`=x.y.z`) so a rebuild can never silently pull new
cryptographic code; bumps are deliberate reviewed commits. Versions are the
latest stable releases on crates.io at pin time (verified via the crates.io
API).

| Crate                | Pin        | Ports (Go v1.3.2)                        | Why this crate                                                                 |
| -------------------- | ---------- | ---------------------------------------- | ------------------------------------------------------------------------------ |
| `chacha20poly1305`   | `=0.11.0`  | `internal/stream` — payload cipher       | RustCrypto; ecosystem standard, constant-time, own test suites                 |
| `hkdf`               | `=0.13.0`  | header MAC + stream key derivation       | RustCrypto; the spec's HKDF-SHA256 (`sha2` becomes a direct pin when S1 wires it) |
| `bech32`             | `=0.12.0`  | `internal/bech32` — all key encodings    | Canonical bech32 crate; owned by `age-format`, consumed by recipients          |
| `curve25519-dalek`   | `=5.0.0`   | `x25519.go`                              | The most-reviewed X25519 implementation in Rust                                 |
| `scrypt`             | `=0.12.0`  | `scrypt.go` — passphrase recipient       | RustCrypto; Go's work-factor handling and strictness are ported above it        |
| `libcrux-ml-kem`     | `=0.0.11`  | `pq.go` — ML-KEM-768 primitive (FIPS 203)| Formally verified, audited `mlkem768` API; current release published 2026-10-07 |

Not used, by locked product decision (2026-10-09): `rage` and the Rust
`age` crate are neither the implementation base nor a design reference;
`libcrux-ml-kem` supplies the KEM **primitive** only — `pq.go` and
`filippo.io/hpke` v0.4.0 remain the normative reference for all protocol
behavior.

## Dependency-graph facts at pin time

Observed via `cargo metadata` on the resolved lockfile (111 packages):

- License terms in the graph: `MIT`, `Apache-2.0`, `BSD-3-Clause`, `ISC`,
  `Unicode-3.0` — plus `Unlicense`, `BSD-1-Clause`, `LGPL-2.1-or-later`
  appearing only inside OR-expressions already covered. `deny.toml`
  allow-lists exactly these; new terms require a deliberate list bump.
- `libcrux-ml-kem` carries the widest subtree (build tooling: `bindgen`,
  `cc`, `wasm-bindgen`; formal-methods annotations: `hax-lib`). That is the
  cost of a verified ML-KEM-768 and is watched by the advisory/audit gates.
- Accepted advisory: RUSTSEC-2026-0173 (unmaintained `proc-macro-error2`)
  arrives transitively via `libcrux-ml-kem` 0.0.11's hax annotations; no
  fixed version exists, and it is compile-time tooling, not runtime
  crypto. Recorded as a dated, reasoned `ignore` in `deny.toml`
  (2026-10-09); drop it when libcrux stops pulling hax-lib 0.3.7.
- Duplicate versions in the graph (warn-level in `deny.toml` until the
  surface stabilizes): `hax-lib` 0.3/0.4, `syn` 2/3, `shlex` 1/2.
- Deliberately **not** pinned yet: `ssh-key` (S3, SSH recipients), a base64
  crate (S2, armor), `sha2`/`hmac` as direct pins (S1, HKDF wiring). Each
  lands with the stage that uses it.

## CI gates vs. review-plan evidence

| Gate               | Enforces                                  | Plan reference          |
| ------------------ | ----------------------------------------- | ----------------------- |
| `cargo-deny`       | Advisories + licenses (deny); bans/sources (warn) | supply-chain discipline |
| `cargo-audit`      | RustSec advisory DB                        | supply-chain discipline |
| clippy `-D warnings` | zero-warning bar on all targets          | code-quality bar        |
| 3-OS test matrix   | empty in S0; grows into the port's tests   | 8-target matrix arrives in S4 |

The heavier evidence layers (CCTV conformance, two-directional Go interop,
differential CLI, fuzzing, external review) attach in S1-S5 per the plan.
