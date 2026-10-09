//! Shared helpers for the age-format integration tests: the vendored CCTV
//! vector loader (a mirror of Go's `parseVector` in testkit_test.go) and a
//! deterministic PRNG for the property tests.
//!
//! The files under `tests/cctv/` are copied verbatim from c2sp.org/CCTV/age
//! at the version the Go module graph pins
//! (v0.0.0-20260829155415-4448f2097b2d, per go.mod) — the same corpus the Go
//! test suite consumes through `agetest.Vectors`.
#![allow(dead_code)]

use std::fmt;

/// Go: the accepted `expect` values of `parseVector`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expect {
    Success,
    HmacFailure,
    HeaderFailure,
    ArmorFailure,
    PayloadFailure,
    NoMatch,
}

impl fmt::Display for Expect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Success => "success",
            Self::HmacFailure => "HMAC failure",
            Self::HeaderFailure => "header failure",
            Self::ArmorFailure => "armor failure",
            Self::PayloadFailure => "payload failure",
            Self::NoMatch => "no match",
        })
    }
}

/// Go: the `vector` struct of testkit_test.go.
pub struct Vector {
    pub name: String,
    pub expect: Expect,
    pub payload_hash: Option<[u8; 32]>,
    /// Go: `(*[16]byte)(h)` view of the hex value — the first 16 bytes.
    pub file_key: Option<Vec<u8>>,
    pub identities: Vec<String>,
    pub passphrases: Vec<String>,
    pub armored: bool,
    /// The age file bytes, zlib-inflated when the vector says `compressed`.
    pub file: Vec<u8>,
}

pub const VECTOR_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/cctv");

fn vector_names() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(VECTOR_DIR)
        .expect("CCTV vector directory is vendored")
        .map(|entry| {
            entry
                .expect("vector directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// The parsed corpus, sorted by name for deterministic runs.
/// Go: `forEachVector` + `parseVector`, fused.
pub fn load_all() -> Vec<Vector> {
    vector_names()
        .into_iter()
        .map(|name| {
            let contents =
                std::fs::read(format!("{VECTOR_DIR}/{name}")).expect("vector file is readable");
            parse_vector(&name, &contents)
        })
        .collect()
}

/// Raw (still-compressed) vector bytes, sorted by name. Go's
/// `FuzzMalleability` seeds are cut from the raw bytes.
pub fn load_raw() -> Vec<(String, Vec<u8>)> {
    vector_names()
        .into_iter()
        .map(|name| {
            let contents =
                std::fs::read(format!("{VECTOR_DIR}/{name}")).expect("vector file is readable");
            (name, contents)
        })
        .collect()
}

/// Go: `parseVector`.
fn parse_vector(name: &str, contents: &[u8]) -> Vector {
    let mut v = Vector {
        name: name.to_string(),
        expect: Expect::Success,
        payload_hash: None,
        file_key: None,
        identities: Vec::new(),
        passphrases: Vec::new(),
        armored: false,
        file: Vec::new(),
    };
    let mut rest = contents;
    let mut compressed = false;
    loop {
        let Some(nl) = rest.iter().position(|&b| b == b'\n') else {
            panic!("invalid test file: no payload: {name}");
        };
        let line = &rest[..nl];
        rest = &rest[nl + 1..];
        if line.is_empty() {
            break;
        }
        let (key, value) = match line.windows(2).position(|w| w == b": ") {
            Some(i) => (
                std::str::from_utf8(&line[..i]).expect("header key is UTF-8"),
                std::str::from_utf8(&line[i + 2..]).expect("header value is UTF-8"),
            ),
            None => (std::str::from_utf8(line).expect("header key is UTF-8"), ""),
        };
        match key {
            "expect" => {
                v.expect = match value {
                    "success" => Expect::Success,
                    "HMAC failure" => Expect::HmacFailure,
                    "header failure" => Expect::HeaderFailure,
                    "armor failure" => Expect::ArmorFailure,
                    "payload failure" => Expect::PayloadFailure,
                    "no match" => Expect::NoMatch,
                    other => panic!("invalid test file: unknown expect value: {other}"),
                };
            }
            "payload" => {
                let hash = hex(value);
                let hash: [u8; 32] = hash
                    .try_into()
                    .expect("invalid test file: payload hash is 32 bytes");
                v.payload_hash = Some(hash);
            }
            "file key" => v.file_key = Some(hex(value)),
            "identity" => v.identities.push(value.to_string()),
            "passphrase" => v.passphrases.push(value.to_string()),
            "armored" => v.armored = true,
            "compressed" => {
                assert!(
                    value == "zlib",
                    "invalid test file: unknown compression: {value}"
                );
                compressed = true;
            }
            "comment" => {} // Go logs it.
            other => panic!("invalid test file: unknown header key: {other}"),
        }
    }
    v.file = if compressed {
        let mut out = Vec::new();
        let mut decoder = flate2::read::ZlibDecoder::new(rest);
        std::io::Read::read_to_end(&mut decoder, &mut out)
            .expect("invalid test file: bad zlib payload");
        out
    } else {
        rest.to_vec()
    };
    v
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex vector value"))
        .collect()
}

/// xorshift64* — deterministic, dependency-free pseudo-random data for the
/// property tests. Seeded by mixing bytes into a fixed constant.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: &[u8]) -> Self {
        let mut s = 0x9E37_79B9_7F4A_7C15;
        for &b in seed {
            s ^= u64::from(b).wrapping_mul(0x2545_F491_4F6C_DD1D);
            s = s.rotate_left(27) ^ 0x2545_F491_4F6C_DD1D;
        }
        Self(s | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform value in `0..n` (n > 0).
    pub fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0);
        self.next_u64() % n
    }

    pub fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }

    pub fn vec(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }
}
