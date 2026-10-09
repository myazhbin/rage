//! Faithful port of Go v1.3.2 `internal/bech32` — a modified version of the
//! reference implementation of BIP173.
//!
//! Divergences from BIP173 that Go keeps deliberately and this port
//! preserves (Go wins over the public spec wherever it is stricter or
//! looser):
//!
//! - **No length limit.** BIP173 caps Bech32 strings at 90 characters; age
//!   must encode 32-byte payload keys (X25519 identities are 62 chars, and
//!   `AGE-PLUGIN-` strings grow with each stanza argument), so the cap is
//!   dropped entirely. Upstream reference: age issue 453.
//! - **ASCII folding only.** Data-part characters are uppercased with an
//!   explicit ASCII fold, never Unicode case folding: Unicode folding could
//!   turn a non-ASCII rune into a shorter valid charset member.
//!
//! The port iterates the data part by Unicode scalar values exactly like
//! Go's `range` over a string, so the error positions are byte offsets and
//! the character errors carry rune values. Go strings can hold arbitrary
//! bytes where Rust `str` cannot: a Go byte like `0xFF` iterates as
//! `U+FFFD`, while a Rust `&str` holds `U+00FF` — both are rejected by the
//! charset lookup, so every observable outcome matches.

use crate::quote::go_quote;

/// Go: `charset`.
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Go: `generator`.
const GENERATOR: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

/// Errors of [`encode`] and [`decode`]: every Go `fmt.Errorf` of the
/// package, with Display strings matching Go's exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bech32Error {
    /// Go: `fmt.Errorf("invalid data range: data[%d]=%d (frombits=%d)", idx, value, frombits)`.
    InvalidDataRange {
        /// Zero-based index into the input data.
        index: usize,
        /// The out-of-range value.
        value: u8,
        /// The configured input bit width.
        from_bits: u8,
    },
    /// Go: `fmt.Errorf("illegal zero padding")`.
    IllegalZeroPadding,
    /// Go: `fmt.Errorf("non-zero padding")`.
    NonZeroPadding,
    /// Go: `fmt.Errorf("invalid HRP: %q", hrp)`.
    InvalidHrp(String),
    /// Go: `fmt.Errorf("invalid HRP character: hrp[%d]=%d", p, c)`.
    InvalidHrpCharacter {
        /// Byte offset of the offending character.
        index: usize,
        /// The offending character.
        char: char,
    },
    /// Go: `fmt.Errorf("mixed case HRP: %q", hrp)`.
    MixedCaseHrp(String),
    /// Go: `fmt.Errorf("mixed case")`.
    MixedCase,
    /// Go: `fmt.Errorf("separator '1' at invalid position: pos=%d, len=%d", pos, len(s))`.
    /// `pos` is -1 when no separator is present (Go: `strings.LastIndex`).
    InvalidSeparatorPosition {
        /// Byte position of the last separator, -1 if absent.
        pos: i64,
        /// Byte length of the whole string.
        len: usize,
    },
    /// Go: `fmt.Errorf("invalid character human-readable part: s[%d]=%d", p, c)`.
    InvalidCharacterHrp {
        /// Byte offset of the offending character.
        index: usize,
        /// The offending character.
        char: char,
    },
    /// Go: `fmt.Errorf("invalid character data part: s[%d]=%v", p, c)` —
    /// Go's `%v` prints the rune's numeric value.
    InvalidCharacterData {
        /// Byte offset of the offending character within the data part.
        index: usize,
        /// The offending character.
        char: char,
    },
    /// Go: `fmt.Errorf("data part too short")`.
    DataPartTooShort,
    /// Go: `fmt.Errorf("invalid checksum")`.
    InvalidChecksum,
}

impl std::fmt::Display for Bech32Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Bech32Error::InvalidDataRange {
                index,
                value,
                from_bits,
            } => write!(
                f,
                "invalid data range: data[{index}]={value} (frombits={from_bits})"
            ),
            Bech32Error::IllegalZeroPadding => write!(f, "illegal zero padding"),
            Bech32Error::NonZeroPadding => write!(f, "non-zero padding"),
            Bech32Error::InvalidHrp(hrp) => write!(f, "invalid HRP: {}", go_quote(hrp.as_bytes())),
            Bech32Error::InvalidHrpCharacter { index, char } => {
                write!(f, "invalid HRP character: hrp[{index}]={}", *char as u32)
            }
            Bech32Error::MixedCaseHrp(hrp) => {
                write!(f, "mixed case HRP: {}", go_quote(hrp.as_bytes()))
            }
            Bech32Error::MixedCase => write!(f, "mixed case"),
            Bech32Error::InvalidSeparatorPosition { pos, len } => {
                write!(f, "separator '1' at invalid position: pos={pos}, len={len}")
            }
            Bech32Error::InvalidCharacterHrp { index, char } => write!(
                f,
                "invalid character human-readable part: s[{index}]={}",
                *char as u32
            ),
            // Go: `%v` of a rune prints its numeric value.
            Bech32Error::InvalidCharacterData { index, char } => {
                write!(
                    f,
                    "invalid character data part: s[{index}]={}",
                    *char as u32
                )
            }
            Bech32Error::DataPartTooShort => write!(f, "data part too short"),
            Bech32Error::InvalidChecksum => write!(f, "invalid checksum"),
        }
    }
}

impl std::error::Error for Bech32Error {}

/// Go: `polymod`.
fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = (chk & 0x1ff_ffff) << 5;
        chk ^= u32::from(v);
        for (i, &generator) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= generator;
            }
        }
    }
    chk
}

/// Go: `hrpExpand`.
fn hrp_expand(hrp: &str) -> Vec<u8> {
    let h = hrp.to_lowercase();
    let mut ret = Vec::with_capacity(h.len() * 2 + 1);
    for &c in h.as_bytes() {
        ret.push(c >> 5);
    }
    ret.push(0);
    for &c in h.as_bytes() {
        ret.push(c & 31);
    }
    ret
}

/// Go: `verifyChecksum`.
fn verify_checksum(hrp: &str, data: &[u8]) -> bool {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    polymod(&values) == 1
}

/// Go: `createChecksum`.
fn create_checksum(hrp: &str, data: &[u8]) -> Vec<u8> {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let modulus = polymod(&values) ^ 1;
    (0..6)
        .map(|p| u8::try_from((modulus >> (5 * (5 - p))) & 31).expect("masked to five bits"))
        .collect()
}

/// Go: `convertBits`.
fn convert_bits(
    data: &[u8],
    from_bits: u8,
    to_bits: u8,
    pad: bool,
) -> Result<Vec<u8>, Bech32Error> {
    let mut ret = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u8 = 0;
    // Go: maxv := byte(1<<tobits) - 1; to_bits is 5 or 8, so it fits a u8.
    let maxv = u8::try_from((1u32 << to_bits).wrapping_sub(1)).expect("maxv fits u8");
    for (idx, &value) in data.iter().enumerate() {
        // Go shifts the byte by frombits in untyped arithmetic; a u8 shift
        // by 8 would panic in Rust, so the shift happens on u32.
        if u32::from(value) >> from_bits != 0 {
            return Err(Bech32Error::InvalidDataRange {
                index: idx,
                value,
                from_bits,
            });
        }
        acc = (acc << from_bits) | u32::from(value);
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            ret.push(u8::try_from((acc >> bits) & u32::from(maxv)).expect("masked by maxv"));
        }
    }
    if pad {
        if bits > 0 {
            ret.push(
                u8::try_from((acc << (to_bits - bits)) & u32::from(maxv)).expect("masked by maxv"),
            );
        }
    } else if bits >= from_bits {
        return Err(Bech32Error::IllegalZeroPadding);
    } else if (acc << (to_bits - bits)) & u32::from(maxv) != 0 {
        return Err(Bech32Error::NonZeroPadding);
    }
    Ok(ret)
}

/// Go: `Encode` — encodes the HRP and a bytes slice to Bech32. If the HRP is
/// uppercase, the output will be uppercase.
///
/// # Errors
///
/// [`Bech32Error::InvalidDataRange`] when the data is not 8-bit; Go checks
/// the data before the HRP, and so does this port. [`Bech32Error::InvalidHrp`]
/// for an empty HRP, [`Bech32Error::InvalidHrpCharacter`] for a character
/// outside the printable ASCII range 33..=126, and
/// [`Bech32Error::MixedCaseHrp`] for a mixed-case HRP.
pub fn encode(hrp: &str, data: &[u8]) -> Result<String, Bech32Error> {
    let values = convert_bits(data, 8, 5, true)?;
    if hrp.is_empty() {
        return Err(Bech32Error::InvalidHrp(hrp.to_string()));
    }
    for (p, c) in hrp.char_indices() {
        if !(33..=126).contains(&(c as u32)) {
            return Err(Bech32Error::InvalidHrpCharacter { index: p, char: c });
        }
    }
    if hrp.to_uppercase() != hrp && hrp.to_lowercase() != hrp {
        return Err(Bech32Error::MixedCaseHrp(hrp.to_string()));
    }
    let lower = hrp.to_lowercase() == hrp;
    let hrp = hrp.to_lowercase();
    let mut ret = String::with_capacity(hrp.len() + 1 + values.len() + 6);
    ret.push_str(&hrp);
    ret.push('1');
    for &p in &values {
        ret.push(CHARSET[usize::from(p)] as char);
    }
    for &p in &create_checksum(&hrp, &values) {
        ret.push(CHARSET[usize::from(p)] as char);
    }
    if lower {
        return Ok(ret);
    }
    Ok(ret.to_uppercase())
}

/// Go: `Decode` — decodes a Bech32 string. If the string is uppercase, the
/// HRP will be uppercase.
///
/// # Errors
///
/// [`Bech32Error::MixedCase`] for mixed-case input;
/// [`Bech32Error::InvalidSeparatorPosition`] when the last `1` is missing or
/// leaves a data part shorter than the 6-value checksum plus one value;
/// [`Bech32Error::InvalidCharacterHrp`] and
/// [`Bech32Error::InvalidCharacterData`] for characters outside their
/// respective alphabets; [`Bech32Error::DataPartTooShort`] when fewer than
/// six data values follow the separator; [`Bech32Error::InvalidChecksum`]
/// when the checksum does not verify; and the [`convert_bits`] errors for
/// padding problems in the payload regrouping.
///
/// # Panics
///
/// Only if a `try_from` invariant is violated, which cannot happen: charset
/// positions are below 32, and separator positions are bounded by the input
/// length, which fits an `i64`.
pub fn decode(s: &str) -> Result<(String, Vec<u8>), Bech32Error> {
    if s.to_lowercase() != s && s.to_uppercase() != s {
        return Err(Bech32Error::MixedCase);
    }
    // Go: pos := strings.LastIndexByte(s, '1'); -1 when there is no '1'.
    let pos = match s.rfind('1') {
        Some(p) if p >= 1 && p + 7 <= s.len() => p,
        found => {
            return Err(Bech32Error::InvalidSeparatorPosition {
                pos: found.map_or(-1, |p| i64::try_from(p).expect("position fits i64")),
                len: s.len(),
            });
        }
    };
    let hrp = &s[..pos];
    for (p, c) in hrp.char_indices() {
        if !(33..=126).contains(&(c as u32)) {
            return Err(Bech32Error::InvalidCharacterHrp { index: p, char: c });
        }
    }
    let mut data: Vec<u8> = Vec::new();
    for (p, c) in s[pos + 1..].char_indices() {
        // Fold ASCII explicitly. Unicode case folding can turn a non-ASCII
        // rune into a shorter valid charset member.
        let c = if c.is_ascii_uppercase() {
            c.to_ascii_lowercase()
        } else {
            c
        };
        match CHARSET
            .iter()
            .position(|&charset_char| u32::from(charset_char) == u32::from(c))
        {
            Some(d) => data.push(u8::try_from(d).expect("charset index fits u8")),
            None => return Err(Bech32Error::InvalidCharacterData { index: p, char: c }),
        }
    }
    if data.len() < 6 {
        return Err(Bech32Error::DataPartTooShort);
    }
    if !verify_checksum(hrp, &data) {
        return Err(Bech32Error::InvalidChecksum);
    }
    let data = convert_bits(&data[..data.len() - 6], 5, 8, false)?;
    Ok((hrp.to_string(), data))
}

#[cfg(test)]
mod tests;
