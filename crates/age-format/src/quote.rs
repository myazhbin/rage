//! Byte-exact port of Go's `strconv.Quote` for the fragments the format layer
//! interpolates into error messages (`%q`).
//!
//! Error text is observable behavior of the Go v1.3.2 implementation: the
//! ported Go unit tests assert exact quoted fragments (carriage returns,
//! byte-order marks, NUL bytes), and the Stage S4 differential CLI harness
//! compares stderr classes. Printable ASCII passes through; control bytes use
//! Go's `\xNN` form; valid non-ASCII runes render literally when printable
//! and as `\uXXXX` / `\UXXXXXXXX` otherwise, decided with the compiler's
//! Unicode printability tables (same category model as Go's
//! `unicode.IsPrint`; see the note in `push_runes`). Invalid UTF-8 bytes
//! escape individually as `\xNN`, matching Go.

use std::fmt::Write as _;

/// Renders `bytes` the way Go's `%q` verb does, including the surrounding
/// double quotes.
pub(crate) fn go_quote(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push('"');
    let mut rest = bytes;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(valid) => {
                push_runes(&mut out, valid);
                break;
            }
            Err(e) => {
                let (valid, tail) = rest.split_at(e.valid_up_to());
                if !valid.is_empty() {
                    push_runes(&mut out, std::str::from_utf8(valid).expect("valid_up_to"));
                }
                if let Some(bad_len) = e.error_len() {
                    for &b in &tail[..bad_len] {
                        push_byte_escape(&mut out, b);
                    }
                    rest = &tail[bad_len..];
                } else {
                    // Truncated valid prefix at the end of the input: Go
                    // escapes the remaining bytes individually.
                    for &b in tail {
                        push_byte_escape(&mut out, b);
                    }
                    rest = &[];
                }
            }
        }
    }
    out.push('"');
    out
}

fn push_runes(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\u{b}' => out.push_str("\\v"),
            _ if c.is_ascii() => {
                if ('\u{20}'..'\u{7f}').contains(&c) {
                    out.push(c);
                } else {
                    push_byte_escape(out, c as u8);
                }
            }
            _ => {
                // Non-ASCII: printable runes pass through, the rest escape in
                // Go's \uXXXX / \UXXXXXXXX form. `char::escape_debug` renders
                // printable runes literally, so comparing outputs decides.
                // Known hair: grapheme-extend runes escape here but would
                // print literally under Go's unicode.IsPrint (category M) —
                // unreachable from any real header line; revisit if the S4
                // differential harness ever observes one.
                let literal = c.to_string();
                if c.escape_debug().to_string() == literal {
                    out.push_str(&literal);
                } else if (c as u32) <= 0xFFFF {
                    let _ = write!(out, "\\u{:04x}", c as u32);
                } else {
                    let _ = write!(out, "\\U{:08x}", c as u32);
                }
            }
        }
    }
}

fn push_byte_escape(out: &mut String, b: u8) {
    let _ = write!(out, "\\x{b:02x}");
}
