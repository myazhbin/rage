//! Faithful port of Go age v1.3.2 `internal/format`: the age file format's
//! header — intro line, recipient stanzas, MAC footer — with Go's strict
//! field validation.
//!
//! Normative reference: `internal/format/format.go` at v1.3.2. Where the Go
//! code is stricter than the public `age-encryption.org/v1` spec, the Go code
//! wins and the difference is recorded in comments, never "fixed". Error
//! messages are byte-equal to the Go strings: they are observable behavior
//! (the ported Go unit tests assert exact fragments; the S4 differential CLI
//! harness compares stderr classes).

use std::fmt;
use std::io;

use base64::Engine as _;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

use crate::quote::go_quote;

/// Port of Go's `base64.RawStdEncoding.Strict()`: unpadded standard alphabet,
/// padding rejected, non-canonical trailing bits rejected.
const B64: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone),
);

/// Port of Go's `Header`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// Go: `Recipients`.
    pub recipients: Vec<Stanza>,
    /// Go: `MAC` (32 bytes in every valid file).
    pub mac: Vec<u8>,
}

/// Port of Go's `Stanza`. The Go source notes `age.Stanza` is assignable to
/// this type and would become an alias of it if the package went public —
/// the port re-exports this type at the crate root instead.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stanza {
    /// Go: `Type`.
    pub r#type: String,
    /// Go: `Args`.
    pub args: Vec<String>,
    /// Go: `Body`.
    pub body: Vec<u8>,
}

/// Error from the format layer, mirroring Go's two error classes:
///
/// - errors built with Go's `errorf` carry the `"parsing age header: "`
///   prefix (Go: `*ParseError`) and report malformed input;
/// - plain `fmt.Errorf` wrappers have no prefix and report I/O-shaped
///   failures (e.g. `"failed to read line: EOF"`).
///
/// [`Error::is_parse_error`] mirrors Go's `errors.As(err, &parseError)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    message: String,
    parse_error: bool,
}

impl Error {
    fn plain(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            parse_error: false,
        }
    }

    fn parse(message: impl Into<String>) -> Self {
        Self {
            message: format!("parsing age header: {}", message.into()),
            parse_error: true,
        }
    }

    /// The full message, prefix included (Go: `Error()`).
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Whether this is a Go `*ParseError`-class error (malformed input, not
    /// an I/O-shaped failure).
    #[must_use]
    pub fn is_parse_error(&self) -> bool {
        self.parse_error
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

/// Go's `io.EOF` rendered as the error text the format layer wraps into
/// messages ("failed to read line: EOF").
const GO_EOF: &str = "EOF";

fn io_error(e: &io::Error) -> Error {
    // Go's Marshal functions return raw io errors. In this codebase the only
    // writers are a Vec and the HMAC hasher (infallible), so wrapping the
    // message loses nothing observable; S4's file sinks revisit this.
    Error::plain(e.to_string())
}

/// Port of Go's `format.DecodeString`: strict raw-standard base64, with an
/// explicit newline rejection the format layer adds for malleability over
/// the base64 decoder's own behavior.
///
/// # Errors
///
/// Errors on embedded LF or CR bytes ("unexpected newline character") and
/// on any invalid strict raw-standard base64 content (Go:
/// `CorruptInputError`).
pub fn decode_string(s: &[u8]) -> Result<Vec<u8>, Error> {
    // CR and LF are ignored by DecodeString, but we don't want any malleability.
    if s.contains(&b'\n') || s.contains(&b'\r') {
        return Err(Error::plain("unexpected newline character"));
    }
    B64.decode(s).map_err(|e| go_base64_error(&e))
}

/// Port of Go's `var EncodeToString = b64.EncodeToString`.
#[must_use]
pub fn encode_string(data: &[u8]) -> String {
    B64.encode(data)
}

fn go_base64_error(e: &base64::DecodeError) -> Error {
    match &e {
        // Go's CorruptInputError reports the offending byte offset; the
        // crate surfaces the same offset for invalid bytes.
        base64::DecodeError::InvalidByte(offset, _) => {
            Error::plain(format!("illegal base64 data at input byte {offset}"))
        }
        // Structural length/padding cases: the crate reports an encoded
        // length or padding position instead of Go's truncated offset. The
        // offset-exact case above is the one realistic stanza bodies
        // exercise; keep the crate's message for the rest (documented hair).
        _ => Error::plain(format!("illegal base64 data: {e}")),
    }
}

pub const COLUMNS_PER_LINE: usize = 64;

pub const BYTES_PER_LINE: usize = COLUMNS_PER_LINE / 4 * 3;

/// Standard base64 encoder that inserts an LF character every
/// [`COLUMNS_PER_LINE`] bytes. It does not insert a newline neither at the
/// beginning nor at the end of the stream, but it ensures the last line is
/// shorter than [`COLUMNS_PER_LINE`], which means it might be empty.
///
/// Port of Go's `format.WrappedBase64Encoder`. Like the Go type, the base64
/// engine is a parameter (armor passes a padded strict engine; the format
/// passes the raw strict one).
pub struct WrappedBase64Encoder<'e, W: io::Write> {
    enc: &'e GeneralPurpose,
    dst: W,
    written: usize,
    /// 0–2 input bytes awaiting a full base64 quantum (the Go type keeps
    /// this state inside base64.NewEncoder; Close flushes it).
    pending: Vec<u8>,
}

impl<'e, W: io::Write> WrappedBase64Encoder<'e, W> {
    /// Port of Go's `NewWrappedBase64Encoder`.
    pub fn new(enc: &'e GeneralPurpose, dst: W) -> Self {
        Self {
            enc,
            dst,
            written: 0,
            pending: Vec::new(),
        }
    }

    /// Encodes `p` and writes the wrapped base64 text to the destination.
    /// Returns the number of input bytes consumed (Go's `io.Writer` shape).
    ///
    /// # Errors
    ///
    /// Errors when the destination writer errors.
    pub fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(p);
        let full = self.pending.len() - self.pending.len() % 3;
        // Encoding complete 3-byte groups chunkwise is byte-identical to
        // encoding their concatenation: base64 aligns on 3-byte groups.
        let groups = self.enc.encode(&self.pending[..full]);
        self.pending.drain(..full);
        if !groups.is_empty() {
            self.write_wrapped(groups.as_bytes())?;
        }
        Ok(p.len())
    }

    /// Flushes any pending partial quantum as an unpadded tail. Port of the
    /// Go type's internal base64 encoder Close.
    ///
    /// # Errors
    ///
    /// Errors when the destination writer errors.
    pub fn close(&mut self) -> io::Result<()> {
        if !self.pending.is_empty() {
            let tail = self.enc.encode(&self.pending);
            self.pending.clear();
            self.write_wrapped(tail.as_bytes())?;
        }
        Ok(())
    }

    /// Returns whether the last output line was empty, either because no
    /// input was written, or because a multiple of [`BYTES_PER_LINE`] was.
    ///
    /// Calling this before [`close`](Self::close) is meaningless
    /// (Go: `LastLineIsEmpty`).
    pub fn last_line_is_empty(&self) -> bool {
        self.written.is_multiple_of(COLUMNS_PER_LINE)
    }

    fn write_wrapped(&mut self, mut p: &[u8]) -> io::Result<()> {
        while !p.is_empty() {
            let to_write = (COLUMNS_PER_LINE - self.written % COLUMNS_PER_LINE).min(p.len());
            let chunk = &p[..to_write];
            self.dst.write_all(chunk)?;
            self.written += to_write;
            p = &p[to_write..];
            if self.written.is_multiple_of(COLUMNS_PER_LINE) {
                self.dst.write_all(b"\n")?;
            }
        }
        Ok(())
    }
}

const INTRO: &str = "age-encryption.org/v1\n";

const STANZA_PREFIX: &[u8] = b"->";
const FOOTER_PREFIX: &[u8] = b"---";

const MAX_HEADER_BYTES: usize = 2 << 20;
const MAX_RECIPIENT_STANZAS: usize = 1024;
const MAX_STANZA_ARGS: usize = 128;

impl Stanza {
    /// Port of Go's `(*Stanza).Marshal`.
    ///
    /// # Errors
    ///
    /// Errors when a stanza field fails Go's validation, or when the
    /// destination writer errors (Go's `Marshal` returns raw `io` errors).
    pub fn marshal_into<W: io::Write>(&self, w: &mut W) -> Result<(), Error> {
        if !is_valid_string(self.r#type.as_bytes()) {
            return Err(Error::plain(format!(
                "invalid stanza type: {}",
                go_quote(self.r#type.as_bytes())
            )));
        }
        for a in &self.args {
            if !is_valid_string(a.as_bytes()) {
                return Err(Error::plain(format!(
                    "invalid stanza argument: {}",
                    go_quote(a.as_bytes())
                )));
            }
        }
        w.write_all(STANZA_PREFIX).map_err(|e| io_error(&e))?;
        w.write_all(b" ")
            .and_then(|()| w.write_all(self.r#type.as_bytes()))
            .map_err(|e| io_error(&e))?;
        for a in &self.args {
            w.write_all(b" ")
                .and_then(|()| w.write_all(a.as_bytes()))
                .map_err(|e| io_error(&e))?;
        }
        w.write_all(b"\n").map_err(|e| io_error(&e))?;
        {
            let mut ww = WrappedBase64Encoder::new(&B64, &mut *w);
            ww.write(&self.body).map_err(|e| io_error(&e))?;
            ww.close().map_err(|e| io_error(&e))?;
        }
        w.write_all(b"\n").map_err(|e| io_error(&e))?;
        Ok(())
    }

    /// Convenience for in-memory marshalling (Go marshals into buffers via
    /// the same code path).
    ///
    /// # Errors
    ///
    /// Same conditions as [`marshal_into`](Self::marshal_into); the writer
    /// is a `Vec` and cannot fail.
    pub fn marshal(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        self.marshal_into(&mut buf)?;
        Ok(buf)
    }
}

impl Header {
    /// Port of Go's `(*Header).MarshalWithoutMAC`.
    ///
    /// # Errors
    ///
    /// Errors when the header has no recipients, when a stanza fails
    /// validation, or when the destination writer errors.
    pub fn marshal_without_mac_into<W: io::Write>(&self, w: &mut W) -> Result<(), Error> {
        if self.recipients.is_empty() {
            return Err(Error::plain("no recipient stanzas"));
        }
        w.write_all(INTRO.as_bytes()).map_err(|e| io_error(&e))?;
        for r in &self.recipients {
            r.marshal_into(w)?;
        }
        w.write_all(FOOTER_PREFIX).map_err(|e| io_error(&e))?;
        Ok(())
    }

    /// Port of Go's `(*Header).MarshalWithoutMAC` over a `Vec`.
    ///
    /// # Errors
    ///
    /// Same conditions as
    /// [`marshal_without_mac_into`](Self::marshal_without_mac_into); the
    /// writer is a `Vec` and cannot fail.
    pub fn marshal_without_mac(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        self.marshal_without_mac_into(&mut buf)?;
        Ok(buf)
    }

    /// Port of Go's `(*Header).Marshal`.
    ///
    /// # Errors
    ///
    /// Errors under the conditions of
    /// [`marshal_without_mac_into`](Self::marshal_without_mac_into); the
    /// MAC encoding itself cannot fail.
    pub fn marshal_into<W: io::Write>(&self, w: &mut W) -> Result<(), Error> {
        self.marshal_without_mac_into(w)?;
        let mac = encode_string(&self.mac);
        w.write_all(format!(" {mac}\n").as_bytes())
            .map_err(|e| io_error(&e))?;
        Ok(())
    }

    /// Port of Go's `(*Header).Marshal` over a `Vec`.
    ///
    /// # Errors
    ///
    /// Same conditions as [`marshal_into`](Self::marshal_into).
    pub fn marshal(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        self.marshal_into(&mut buf)?;
        Ok(buf)
    }
}

/// A parsed header plus the remaining payload bytes. Go's `Parse` returns
/// `(*Header, io.Reader)`; over an in-memory input the payload is simply the
/// input after the header — no byte is copied or lost, mirroring the
/// bufio-unwind semantics.
pub struct ParsedFile<'a> {
    pub header: Header,
    pub payload: &'a [u8],
}

/// Port of Go's `headerReader` (bounded over a byte slice). Limit errors are
/// Go's `errorf` `ParseErrors` and propagate as [`Error`] directly; clean EOF
/// is a value alongside the partial line, never an error (Go's `ReadBytes`
/// contract).
struct HeaderReader<'a> {
    input: &'a [u8],
    pos: usize,
    /// Go: `r.n` — bytes returned through the reader.
    n: usize,
}

impl<'a> HeaderReader<'a> {
    /// Port of `ReadBytes(delim)`: the line including the delimiter, plus
    /// whether input ended before the delimiter (Go: partial line + io.EOF).
    fn read_bytes(&mut self, delim: u8) -> Result<(&'a [u8], bool), Error> {
        let rest = &self.input[self.pos..];
        let end = rest
            .iter()
            .position(|&b| b == delim)
            .map_or(rest.len(), |i| i + 1);
        let line = &rest[..end];
        // Go checks each 4096-byte fragment; the cumulative bound is the
        // same: no line may push the consumed total past MAX_HEADER_BYTES.
        if self.n + line.len() > MAX_HEADER_BYTES {
            return Err(Error::parse("header exceeds 2 MiB"));
        }
        self.pos += end;
        self.n += end;
        let eof = !rest[..end].contains(&delim);
        Ok((line, eof))
    }

    /// Port of `Peek(n)`: up to `n` bytes without consuming, plus whether
    /// fewer than `n` were available (Go: partial + io.EOF).
    fn peek(&self, n: usize) -> Result<(&'a [u8], bool), Error> {
        if self.n + n > MAX_HEADER_BYTES {
            return Err(Error::parse("header exceeds 2 MiB"));
        }
        let rest = &self.input[self.pos..];
        Ok((&rest[..rest.len().min(n)], rest.len() < n))
    }
}

/// Port of Go's `StanzaReader.ReadStanza`. The sticky `r.err` of the Go type
/// is elided: `Parse` aborts on the first read error, so "read errors are
/// unrecoverable" is structural here.
fn read_stanza(hr: &mut HeaderReader<'_>) -> Result<Stanza, Error> {
    let (line, eof) = hr.read_bytes(b'\n')?;
    if eof {
        return Err(Error::plain(format!("failed to read line: {GO_EOF}")));
    }
    if !line.starts_with(STANZA_PREFIX) {
        return Err(Error::plain(format!(
            "malformed stanza opening line: {}",
            go_quote(line)
        )));
    }
    let (prefix, args) = split_args(line);
    if prefix != STANZA_PREFIX || args.is_empty() {
        return Err(Error::plain(format!(
            "malformed stanza: {}",
            go_quote(line)
        )));
    }
    let mut stanza = Stanza {
        r#type: ascii_string(args[0]),
        args: args[1..].iter().map(|a| ascii_string(a)).collect(),
        body: Vec::new(),
    };

    loop {
        let (line, eof) = hr.read_bytes(b'\n')?;
        if eof {
            return Err(Error::plain(format!("failed to read line: {GO_EOF}")));
        }

        let trimmed = &line[..line.len() - 1]; // one trailing LF, as in Go
        let b = match decode_string(trimmed) {
            Ok(b) => b,
            Err(e) => {
                if line.starts_with(FOOTER_PREFIX) || line.starts_with(STANZA_PREFIX) {
                    return Err(Error::plain(format!(
                        "malformed body line {}: stanza ended without a short line\nnote: this might be a file encrypted with an old beta version of age or rage; use age v1.0.0-beta6 or rage to decrypt it",
                        go_quote(line)
                    )));
                }
                // Go: errorf — a ParseError.
                return Err(Error::parse(format!(
                    "malformed body line {}: {e}",
                    go_quote(line)
                )));
            }
        };
        if b.len() > BYTES_PER_LINE {
            return Err(Error::parse(format!(
                "malformed body line {}: too long",
                go_quote(line)
            )));
        }
        stanza.body.extend_from_slice(&b);
        if b.len() < BYTES_PER_LINE {
            // A stanza body always ends with a short line.
            return Ok(stanza);
        }
    }
}

/// Port of Go's `describeIntro`: a quoted description of a bad intro line, or
/// an empty string if the line contains recognizable private key material.
fn describe_intro(line: &[u8]) -> String {
    for prefix in ["AGE-SECRET-KEY-", "AGE-PLUGIN-"] {
        if line.starts_with(prefix.as_bytes()) {
            return String::new();
        }
    }
    // Preserve enough context to diagnose a mangled intro without echoing an
    // arbitrarily long first line.
    let cut = line.len().min(INTRO.len());
    go_quote(&line[..cut])
}

/// Port of Go's `format.Parse` over an in-memory input.
///
/// # Errors
///
/// Errors with a ParseError-class [`Error`] (Go: `*ParseError`) on malformed
/// input — bad intro, stanza, or closing line, size limits, overlong lines —
/// and with a plain [`Error`] on truncated input where Go wraps `io.EOF`
/// without the parse prefix.
pub fn parse(input: &[u8]) -> Result<ParsedFile<'_>, Error> {
    let mut hr = HeaderReader {
        input,
        pos: 0,
        n: 0,
    };

    let (line, eof) = hr.read_bytes(b'\n')?;
    if eof {
        if line.is_empty() {
            return Err(Error::parse("file is empty"));
        }
        let description = describe_intro(line);
        if !description.is_empty() {
            return Err(Error::parse(format!(
                "unexpected EOF reading intro: {description}"
            )));
        }
        return Err(Error::parse(format!(
            "unexpected EOF reading intro, expected {}",
            go_quote(INTRO.as_bytes())
        )));
    }
    if line != INTRO.as_bytes() {
        let description = describe_intro(line);
        if !description.is_empty() {
            return Err(Error::parse(format!("unexpected intro: {description}")));
        }
        return Err(Error::parse(format!(
            "unexpected intro, expected {}",
            go_quote(INTRO.as_bytes())
        )));
    }

    let mut recipients = Vec::new();
    let mac = loop {
        let (peeked, short) = hr.peek(FOOTER_PREFIX.len())?;
        if short {
            // Go: the underlying Peek returned io.EOF, wrapped with
            // errorf (a ParseError).
            return Err(Error::parse(format!("failed to read header: {GO_EOF}")));
        }

        if peeked == FOOTER_PREFIX {
            let (line, eof) = hr.read_bytes(b'\n')?;
            if eof {
                // Go: fmt.Errorf — a plain error, not a ParseError.
                return Err(Error::plain(format!("failed to read header: {GO_EOF}")));
            }

            let (prefix, args) = split_args(line);
            if prefix != FOOTER_PREFIX || args.len() != 1 {
                return Err(Error::parse(format!(
                    "malformed closing line: {}",
                    go_quote(line)
                )));
            }
            break match decode_string(args[0]) {
                Ok(mac) if mac.len() == 32 => mac,
                // Go prints %v of a nil error as "<nil>" for the length case.
                Ok(_) => {
                    return Err(Error::parse(format!(
                        "malformed closing line {}: <nil>",
                        go_quote(line)
                    )));
                }
                Err(e) => {
                    return Err(Error::parse(format!(
                        "malformed closing line {}: {e}",
                        go_quote(line)
                    )));
                }
            };
        }
        if recipients.len() == MAX_RECIPIENT_STANZAS {
            return Err(Error::parse(format!(
                "header contains more than {MAX_RECIPIENT_STANZAS} recipient stanzas"
            )));
        }

        // Go: fmt.Errorf("failed to parse header: %w", err) — a plain wrap;
        // the inner ParseError's prefix stays in the message.
        let stanza = read_stanza(&mut hr)
            .map_err(|e| Error::plain(format!("failed to parse header: {e}")))?;
        recipients.push(stanza);
    };
    if recipients.is_empty() {
        return Err(Error::parse("no recipient stanzas"));
    }

    let payload = &input[hr.pos..];
    Ok(ParsedFile {
        header: Header { recipients, mac },
        payload,
    })
}

/// Port of Go's `splitArgs`: trims the trailing LF, splits at the first
/// space, and returns the prefix plus the arguments — or the whole line as
/// the prefix with no args when any argument is invalid or the count would
/// exceed [`MAX_STANZA_ARGS`].
fn split_args(line: &[u8]) -> (&[u8], Vec<&[u8]>) {
    let l = strip_line_suffix(line);
    let Some(space) = l.iter().position(|&b| b == b' ') else {
        return (l, Vec::new());
    };
    let (prefix, rest) = (&l[..space], &l[space + 1..]);

    let mut args = Vec::new();
    for arg in rest.split(|&c| c == b' ') {
        if !is_valid_string(arg) || args.len() > MAX_STANZA_ARGS {
            return (l, Vec::new());
        }
        args.push(arg);
    }
    (prefix, args)
}

/// `strings.TrimSuffix(line, "\n")`.
fn strip_line_suffix(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\n").unwrap_or(line)
}

/// Port of Go's `isValidString`. Go ranges over runes — any byte outside
/// 33..=126 is rejected either directly or as part of a multi-byte rune
/// (every lead/continuation byte is >= 128), so the byte-level check is
/// equivalent for all inputs.
fn is_valid_string(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(|&c| (33..=126).contains(&c))
}

/// Converts a validated argument to a String. `split_args` only returns args
/// that passed [`is_valid_string`] (printable ASCII), so this is lossless.
fn ascii_string(b: &[u8]) -> String {
    String::from_utf8(b.to_vec()).expect("isValidString guarantees printable ASCII")
}
