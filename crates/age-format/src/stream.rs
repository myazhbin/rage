//! Port of Go age v1.3.2 `internal/stream` — a variant of the STREAM chunked
//! encryption scheme (ChaCha20-Poly1305 over 64 KiB plaintext chunks, each
//! with its own nonce counter and a flag byte marking the last chunk).
//!
//! Normative reference: `internal/stream/stream.go` at v1.3.2. Error strings
//! are byte-identical to Go's, including their wrapper structure, because the
//! CLI surfaces them and the Go test battery asserts on them.
//!
//! Port note: the Go `EncryptReader` over-reads one plaintext byte per chunk
//! to detect the last chunk, encrypts in place over `bytes.Buffer`'s backing
//! array, then re-stitches the buffer so the served ciphertext is exactly
//! ct||tag and the over-read tail byte becomes the next chunk's first
//! plaintext byte (verified against instrumented Go — see `GoBuffer` below).
//! The Rust port transcribes that dance with the same observable buffer
//! semantics rather than "simplifying" it.

use std::io;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

/// Go: `ChunkSize` — the plaintext size of a non-final chunk.
pub const CHUNK_SIZE: usize = 64 * 1024;
/// Go's `ChunkSize` where Go's `int` arithmetic needs it; kept in step with
/// [`CHUNK_SIZE`] by construction (same literal, asserted below).
const CHUNK_SIZE_I: i64 = 64 * 1024;

/// Go: `encChunkSize` — ciphertext size of a full chunk (Poly1305 tag
/// included).
const ENC_CHUNK_SIZE: usize = CHUNK_SIZE + AEAD_OVERHEAD;
/// Go's `encChunkSize` as an `i64`.
const ENC_CHUNK_SIZE_I: i64 = CHUNK_SIZE_I + AEAD_OVERHEAD_I;

/// Go: `lastChunkFlag` — the nonce's last byte marks the final chunk.
const LAST_CHUNK_FLAG: u8 = 0x01;

/// Go: `chacha20poly1305.Overhead` — the Poly1305 tag length.
const AEAD_OVERHEAD: usize = 16;
/// Go's Poly1305 overhead as an `i64`.
const AEAD_OVERHEAD_I: i64 = 16;

/// Errors from the STREAM layer. Display strings are Go's, byte for byte.
///
/// `StreamError::UnexpectedEof` mirrors `io.ErrUnexpectedEOF` for the
/// `errors.Is` checks the Go battery performs; the compound wrappers
/// (`FinalChunkRead`, `ReadChunkAt`) preserve the inner class the same way
/// Go's `%w` wrapping does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    /// Go: `io.ErrUnexpectedEOF`.
    UnexpectedEof,
    /// Go: `errorf("unexpected tweak: %v", u)`.
    UnexpectedTweak(u64),
    /// Go: `fmt.Errorf("invalid encrypted payload size: %d", encryptedSize)`.
    InvalidEncryptedSize(i64),
    /// Go: the beta-file special case in `readChunk`.
    LastChunkEmpty,
    /// Go: `errors.New("failed to decrypt and authenticate payload chunk, …")`.
    DecryptChunk,
    /// Go: `errors.New("trailing data after end of encrypted file")`.
    TrailingData,
    /// Go: `fmt.Errorf("non-EOF error reading after end of encrypted file: %w", err)`.
    NonEofAfterEnd(String),
    /// Go: `errors.New("stream.Writer is already closed")`.
    WriterClosed,
    /// Go: a raw `io` error from the underlying reader or writer, carried by
    /// its display string.
    Io(String),
    /// Go: `fmt.Errorf("failed to read chunk at offset %d: %w", chunkOff, err)`.
    ReadChunkAt {
        offset: i64,
        source: Box<StreamError>,
    },
    /// Go: `fmt.Errorf("failed to decrypt and authenticate chunk at offset %d: %w", chunkOff, err)`.
    DecryptChunkAt { offset: i64, source: String },
    /// Go: `fmt.Errorf("failed to read final chunk: %w", err)`.
    FinalChunkRead(Box<StreamError>),
    /// Go: `fmt.Errorf("failed to decrypt and authenticate final chunk: %w", err)`.
    FinalChunkDecrypt(String),
    /// Go: `fmt.Errorf("offset out of range [0:%d]: %d", r.size, off)`.
    OffsetOutOfRange { size: i64, offset: i64 },
}

impl StreamError {
    /// Go: `errors.Is(err, io.ErrUnexpectedEOF)` — walks the `%w` wrappers.
    #[must_use]
    pub fn is_unexpected_eof(&self) -> bool {
        match self {
            StreamError::UnexpectedEof => true,
            StreamError::ReadChunkAt { source, .. } | StreamError::FinalChunkRead(source) => {
                source.is_unexpected_eof()
            }
            _ => false,
        }
    }

    /// The Go text of the ChaCha20-Poly1305 authentication failure, used
    /// verbatim where Go wraps the AEAD error into a larger message.
    fn auth_failed() -> String {
        "chacha20poly1305: message authentication failed".to_string()
    }
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::UnexpectedEof => write!(f, "unexpected EOF"),
            StreamError::UnexpectedTweak(v) => write!(f, "unexpected tweak: {v}"),
            StreamError::InvalidEncryptedSize(s) => {
                write!(f, "invalid encrypted payload size: {s}")
            }
            StreamError::LastChunkEmpty => write!(
                f,
                "last chunk is empty, try age v1.0.0, and please consider reporting this"
            ),
            StreamError::DecryptChunk => write!(
                f,
                "failed to decrypt and authenticate payload chunk, file may be corrupted or tampered with"
            ),
            StreamError::TrailingData => {
                write!(f, "trailing data after end of encrypted file")
            }
            StreamError::NonEofAfterEnd(e) => {
                write!(f, "non-EOF error reading after end of encrypted file: {e}")
            }
            StreamError::WriterClosed => write!(f, "stream.Writer is already closed"),
            StreamError::Io(e) => write!(f, "{e}"),
            StreamError::ReadChunkAt { offset, source } => {
                write!(f, "failed to read chunk at offset {offset}: {source}")
            }
            StreamError::DecryptChunkAt { offset, source } => write!(
                f,
                "failed to decrypt and authenticate chunk at offset {offset}: {source}"
            ),
            StreamError::FinalChunkRead(source) => {
                write!(f, "failed to read final chunk: {source}")
            }
            StreamError::FinalChunkDecrypt(source) => write!(
                f,
                "failed to decrypt and authenticate final chunk: {source}"
            ),
            StreamError::OffsetOutOfRange { size, offset } => {
                write!(f, "offset out of range [0:{size}]: {offset}")
            }
        }
    }
}

impl std::error::Error for StreamError {}

/// Terminal conditions of [`DecryptReader::read`]: Go returns `io.EOF` as the
/// sticky end-of-message marker, distinct from any error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptReadError {
    /// Go: `io.EOF`.
    Eof,
    /// Go: any other error value.
    Stream(StreamError),
}

/// Terminal conditions of [`EncryptReader::read`]: Go stores `io.EOF` in the
/// reader after feeding the last chunk, and raw source errors otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptReadError {
    /// Go: `io.EOF`.
    Eof,
    /// Go: a raw `io` error from the source reader, carried by its display
    /// string.
    Source(String),
}

/// Terminal condition of [`DecryptReaderAt::read_at`]: Go's `io.ReaderAt`
/// returns `(n, err)` pairs where `err` may be `io.EOF` alongside a positive
/// `n`, so the count and the condition travel together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadAtError {
    /// Go: `io.EOF`.
    Eof,
    /// Go: any other error value.
    Stream(StreamError),
}

/// Go: `EncryptedChunkCount`.
///
/// # Errors
///
/// [`StreamError::InvalidEncryptedSize`] when the size is negative, past the
/// overflow bound (`MaxInt64 - encChunkSize + 1`), or inconsistent with an
/// integral chunk count (Go's exact checks).
pub fn encrypted_chunk_count(encrypted_size: i64) -> Result<i64, StreamError> {
    if !(0..=i64::MAX - ENC_CHUNK_SIZE_I + 1).contains(&encrypted_size) {
        return Err(StreamError::InvalidEncryptedSize(encrypted_size));
    }
    let chunks = (encrypted_size + ENC_CHUNK_SIZE_I - 1) / ENC_CHUNK_SIZE_I;

    let plaintext_size = encrypted_size - chunks * AEAD_OVERHEAD_I;
    let mut exp_chunks = (plaintext_size + CHUNK_SIZE_I - 1) / CHUNK_SIZE_I;
    // Empty plaintext, the only case that allows (and requires) an empty chunk.
    if plaintext_size == 0 {
        exp_chunks = 1;
    }
    if exp_chunks != chunks {
        return Err(StreamError::InvalidEncryptedSize(encrypted_size));
    }

    Ok(chunks)
}

/// Go: `PlaintextSize`.
///
/// # Errors
///
/// Whatever [`encrypted_chunk_count`] reports for the size.
pub fn plaintext_size(encrypted_size: i64) -> Result<i64, StreamError> {
    let chunks = encrypted_chunk_count(encrypted_size)?;
    let plaintext_size = encrypted_size - chunks * AEAD_OVERHEAD_I;
    Ok(plaintext_size)
}

/// Go: `incNonce` — big-endian counter over the nonce's first 11 bytes.
fn inc_nonce(nonce: &mut [u8; 12]) {
    for i in (0..nonce.len() - 1).rev() {
        nonce[i] = nonce[i].wrapping_add(1);
        if nonce[i] != 0 {
            return;
        }
    }
    // The counter is 88 bits, this is unreachable.
    panic!("stream: chunk counter wrapped around");
}

/// Go: `nonceForChunk` — the chunk counter as a big-endian `uint64` at
/// `nonce[3:11]`.
#[must_use]
fn nonce_for_chunk(chunk_index: i64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[3..11].copy_from_slice(&chunk_index.cast_unsigned().to_be_bytes());
    nonce
}

/// Go: `setLastChunkFlag`.
fn set_last_chunk_flag(nonce: &mut [u8; 12]) {
    nonce[nonce.len() - 1] = LAST_CHUNK_FLAG;
}

/// Go: `nonceIsZero`.
fn nonce_is_zero(nonce: &[u8; 12]) -> bool {
    *nonce == [0u8; 12]
}

/// The observable semantics of Go's `bytes.Buffer` as `stream.go` uses them:
/// a backing `Vec` plus a read offset, with `Read` serving from the offset,
/// `Write` appending at the logical end, and a lazy reset when fully
/// consumed. The `EncryptReader` in-place seal relies on the split between
/// the backing length and the logical length, so this helper transcribes
/// those semantics exactly.
struct GoBuffer {
    buf: Vec<u8>,
    off: usize,
}

impl GoBuffer {
    fn new() -> Self {
        GoBuffer {
            buf: Vec::new(),
            off: 0,
        }
    }

    /// Go: `Len`.
    fn len(&self) -> usize {
        self.buf.len() - self.off
    }

    /// Go: `Bytes` — the unread portion.
    fn bytes(&self) -> &[u8] {
        &self.buf[self.off..]
    }

    /// Go: `Write` / `WriteByte` — appends at the logical end.
    fn write(&mut self, p: &[u8]) {
        self.buf.extend_from_slice(p);
    }

    fn write_byte(&mut self, b: u8) {
        self.buf.push(b);
    }

    /// Go: `Reset`.
    fn reset(&mut self) {
        self.off = 0;
        self.buf.clear();
    }

    /// Go: `Read` — serves from the offset; resets once fully drained.
    /// Returns the number of bytes served (never `io.EOF` at this call site:
    /// the caller caps the request at the available bytes).
    fn read(&mut self, p: &mut [u8]) -> usize {
        if self.off == self.buf.len() {
            self.reset();
            return 0;
        }
        let avail = &self.buf[self.off..];
        let n = p.len().min(avail.len());
        p[..n].copy_from_slice(&avail[..n]);
        self.off += n;
        if self.off == self.buf.len() {
            self.reset();
        }
        n
    }
}

/// Go: `io.ReadFull` outcome — the count and condition travel together.
enum ReadFull {
    /// Exactly `buf.len()` bytes read.
    Full,
    /// Zero bytes read, clean EOF.
    Eof,
    /// A short read before EOF, with the byte count.
    UnexpectedEof(usize),
    /// Any other error.
    Io(io::Error),
}

/// Go: `io.ReadFull` over a Rust reader (Go's `io.ReadAtLeast` semantics).
fn read_full<R: io::Read>(src: &mut R, buf: &mut [u8]) -> ReadFull {
    let mut n = 0;
    while n < buf.len() {
        match src.read(&mut buf[n..]) {
            Ok(0) => {
                return if n == 0 {
                    ReadFull::Eof
                } else {
                    ReadFull::UnexpectedEof(n)
                };
            }
            Ok(m) => n += m,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return ReadFull::Io(e),
        }
    }
    ReadFull::Full
}

/// Go: `DecryptReader`.
pub struct DecryptReader<R: io::Read> {
    aead: ChaCha20Poly1305,
    src: R,

    /// Decrypted but unread data, in `buf[..unread_end]` from `unread_start`.
    /// Go: `unread []byte` backed by `buf`.
    buf: Box<[u8; ENC_CHUNK_SIZE]>,
    unread_start: usize,
    unread_end: usize,

    err: Option<DecryptReadError>,
    nonce: [u8; 12],
}

/// Go: `NewDecryptReader`. The key length is enforced by the type system
/// (Go's `chacha20poly1305.New` checks it at runtime).
///
/// # Panics
///
/// Only if the internal buffer conversion fails, which cannot happen: the
/// allocation length is `encChunkSize` by construction.
pub fn new_decrypt_reader<R: io::Read>(key: &[u8; 32], src: R) -> DecryptReader<R> {
    DecryptReader {
        aead: ChaCha20Poly1305::new(key.into()),
        src,
        buf: vec![0u8; ENC_CHUNK_SIZE]
            .into_boxed_slice()
            .try_into()
            .expect("buffer length is encChunkSize"),
        unread_start: 0,
        unread_end: 0,
        err: None,
        nonce: [0u8; 12],
    }
}

impl<R: io::Read> DecryptReader<R> {
    /// Go: `(*DecryptReader).Read`. The sticky terminal is
    /// [`DecryptReadError::Eof`] (Go: `(0, io.EOF)`), set by the trailing-data
    /// check once the marked last chunk has been served. `Ok(0)` occurs only
    /// for zero-length `p` and once for an empty message, whose empty final
    /// chunk is served as `Ok(0)` (Go: `(0, nil)`) before the terminal.
    ///
    /// # Errors
    ///
    /// [`DecryptReadError::Eof`] once the marked last chunk has been served;
    /// [`DecryptReadError::Stream`] for truncation, corruption, and source
    /// errors, re-raised on every later call.
    pub fn read(&mut self, p: &mut [u8]) -> Result<usize, DecryptReadError> {
        if self.unread_start < self.unread_end {
            let n = p.len().min(self.unread_end - self.unread_start);
            p[..n].copy_from_slice(&self.buf[self.unread_start..self.unread_start + n]);
            self.unread_start += n;
            return Ok(n);
        }
        if let Some(e) = &self.err {
            return Err(e.clone());
        }
        if p.is_empty() {
            return Ok(0);
        }

        let last = self.read_chunk()?;

        let n = p.len().min(self.unread_end - self.unread_start);
        p[..n].copy_from_slice(&self.buf[self.unread_start..self.unread_start + n]);
        self.unread_start += n;

        if last {
            // Ensure there is an EOF after the last chunk as expected. In other
            // words, check for trailing data after a full-length final chunk.
            // Hopefully, the underlying reader supports returning EOF even if it
            // had previously returned an EOF to ReadFull.
            let mut tail = [0u8; 1];
            self.err = Some(match read_full(&mut self.src, &mut tail) {
                ReadFull::Full => DecryptReadError::Stream(StreamError::TrailingData),
                ReadFull::Eof | ReadFull::UnexpectedEof(0) => DecryptReadError::Eof,
                // Unreachable for a one-byte read (short == EOF), but Go
                // would wrap whatever error surfaced.
                ReadFull::UnexpectedEof(_) => DecryptReadError::Stream(
                    StreamError::NonEofAfterEnd("unexpected EOF".to_string()),
                ),
                ReadFull::Io(e) => {
                    DecryptReadError::Stream(StreamError::NonEofAfterEnd(e.to_string()))
                }
            });
        }

        Ok(n)
    }

    /// Go: `readChunk` — reads the next chunk of ciphertext and makes it
    /// available in the unread buffer. Returns whether the chunk was marked
    /// as the end of the message. Must not be called again after returning a
    /// last chunk or an error.
    fn read_chunk(&mut self) -> Result<bool, DecryptReadError> {
        assert!(
            self.unread_start >= self.unread_end,
            "stream: internal error: readChunk called with dirty buffer"
        );

        let mut in_len = ENC_CHUNK_SIZE;
        let mut last = false;
        match read_full(&mut self.src, self.buf.as_mut()) {
            ReadFull::Full => {}
            // A message can't end without a marked chunk. This message is truncated.
            ReadFull::Eof => {
                return Err(DecryptReadError::Stream(StreamError::UnexpectedEof));
            }
            // The last chunk can be short, but not empty unless it's the first and
            // only chunk.
            ReadFull::UnexpectedEof(n) => {
                if !nonce_is_zero(&self.nonce) && n == AEAD_OVERHEAD {
                    return Err(DecryptReadError::Stream(StreamError::LastChunkEmpty));
                }
                in_len = n;
                last = true;
                set_last_chunk_flag(&mut self.nonce);
            }
            ReadFull::Io(e) => {
                return Err(DecryptReadError::Stream(StreamError::Io(e.to_string())));
            }
        }

        let out = self
            .aead
            .decrypt(&Nonce::from(self.nonce), &self.buf[..in_len]);
        let out = match out {
            Ok(out) => out,
            Err(_) if !last => {
                // Check if this was a full-length final chunk.
                last = true;
                set_last_chunk_flag(&mut self.nonce);
                match self
                    .aead
                    .decrypt(&Nonce::from(self.nonce), &self.buf[..in_len])
                {
                    Ok(out) => out,
                    Err(_) => {
                        return Err(DecryptReadError::Stream(StreamError::DecryptChunk));
                    }
                }
            }
            Err(_) => {
                return Err(DecryptReadError::Stream(StreamError::DecryptChunk));
            }
        };

        inc_nonce(&mut self.nonce);
        self.buf[..out.len()].copy_from_slice(&out);
        self.unread_start = 0;
        self.unread_end = out.len();
        Ok(last)
    }
}

/// Go: `EncryptWriter` — writes ciphertext chunks to the destination as they
/// fill. `close` flushes the (possibly empty) last chunk; it does not close
/// the underlying writer.
pub struct EncryptWriter<W: io::Write> {
    aead: ChaCha20Poly1305,
    dst: W,
    buf: GoBuffer,
    nonce: [u8; 12],
    err: Option<StreamError>,
}

/// Go: `NewEncryptWriter`.
pub fn new_encrypt_writer<W: io::Write>(key: &[u8; 32], dst: W) -> EncryptWriter<W> {
    EncryptWriter {
        aead: ChaCha20Poly1305::new(key.into()),
        dst,
        buf: GoBuffer::new(),
        nonce: [0u8; 12],
        err: None,
    }
}

impl<W: io::Write> EncryptWriter<W> {
    /// Go: `(*EncryptWriter).Write`.
    ///
    /// # Errors
    ///
    /// The sticky previous error, a chunk-flush failure (field validation or
    /// destination `io` error), or nothing. Per Go, a flush error reports zero
    /// bytes written even though the input has been consumed.
    pub fn write(&mut self, mut p: &[u8]) -> Result<usize, StreamError> {
        if let Some(e) = &self.err {
            return Err(e.clone());
        }
        if p.is_empty() {
            return Ok(0);
        }

        let total = p.len();
        while !p.is_empty() {
            let n = p.len().min(CHUNK_SIZE - self.buf.len());
            self.buf.write(&p[..n]);
            p = &p[n..];

            // Only flush if there's a full chunk with bytes still to write, or we
            // can't know if this is the last chunk yet.
            if self.buf.len() == CHUNK_SIZE
                && !p.is_empty()
                && let Err(e) = self.flush_chunk(false)
            {
                self.err = Some(e.clone());
                return Err(e);
            }
        }
        Ok(total)
    }

    /// Go: `Close` — flushes the last chunk. Does not close the underlying
    /// writer.
    ///
    /// # Errors
    ///
    /// The sticky previous error, the last-chunk flush failure, or (on any
    /// later call) [`StreamError::WriterClosed`].
    pub fn close(&mut self) -> Result<(), StreamError> {
        if let Some(e) = &self.err {
            return Err(e.clone());
        }

        if let Err(e) = self.flush_chunk(true) {
            self.err = Some(e.clone());
            return Err(e);
        }

        self.err = Some(StreamError::WriterClosed);
        Ok(())
    }

    /// Go: `flushChunk`.
    fn flush_chunk(&mut self, last: bool) -> Result<(), StreamError> {
        assert!(
            last || self.buf.len() == CHUNK_SIZE,
            "stream: internal error: flush called with partial chunk"
        );

        if last {
            set_last_chunk_flag(&mut self.nonce);
        }
        let plaintext = self.buf.bytes().to_vec();
        let ciphertext = self
            .aead
            .encrypt(&Nonce::from(self.nonce), plaintext.as_slice())
            .expect("ChaCha20-Poly1305 encryption cannot fail");
        // Go writes with a single Write and ignores the count.
        self.dst
            .write(&ciphertext)
            .map_err(|e| StreamError::Io(e.to_string()))?;
        inc_nonce(&mut self.nonce);
        self.buf.reset();
        Ok(())
    }
}

/// Go: `EncryptReader` — encrypts on the fly, over-reading one plaintext byte
/// per chunk to detect the last chunk.
pub struct EncryptReader<R: io::Read> {
    aead: ChaCha20Poly1305,
    src: R,

    /// Go: `ready` — the number of encrypted bytes at the front of `buf`.
    ready: usize,
    buf: GoBuffer,

    nonce: [u8; 12],
    err: Option<EncryptReadError>,
}

/// Go: `NewEncryptReader`.
pub fn new_encrypt_reader<R: io::Read>(key: &[u8; 32], src: R) -> EncryptReader<R> {
    EncryptReader {
        aead: ChaCha20Poly1305::new(key.into()),
        src,
        ready: 0,
        buf: GoBuffer::new(),
        nonce: [0u8; 12],
        err: None,
    }
}

impl<R: io::Read> EncryptReader<R> {
    /// Go: `(*EncryptReader).Read` — `Ok(0)` is the sticky EOF.
    ///
    /// # Errors
    ///
    /// [`EncryptReadError::Eof`] after the last chunk has been served;
    /// [`EncryptReadError::Source`] for source reader errors, re-raised on
    /// every later call.
    pub fn read(&mut self, p: &mut [u8]) -> Result<usize, EncryptReadError> {
        if self.ready > 0 {
            let cap = p.len().min(self.ready);
            let n = self.buf.read(&mut p[..cap]);
            self.ready -= n;
            return Ok(n);
        }
        if let Some(e) = &self.err {
            return Err(e.clone());
        }
        if p.is_empty() {
            return Ok(0);
        }

        self.feed_buffer()?;

        let cap = p.len().min(self.ready);
        let n = self.buf.read(&mut p[..cap]);
        self.ready -= n;
        Ok(n)
    }

    /// Go: `feedBuffer` — reads and encrypts the next chunk from the source
    /// and appends it to the buffer; sets `ready` to the number of newly
    /// available bytes.
    fn feed_buffer(&mut self) -> Result<(), EncryptReadError> {
        assert!(
            self.ready == 0,
            "stream: internal error: feedBuffer called with dirty buffer"
        );

        // Go: io.CopyN(&r.buf, r.src, int64(ChunkSize-r.buf.Len()+1)) — the
        // +1 over-read is what decides whether this is the last chunk.
        // CopyN's EOF is expected and swallowed; other errors are terminal.
        let want = CHUNK_SIZE - self.buf.len() + 1;
        copy_n(&mut self.buf, &mut self.src, want)
            .map_err(|e| EncryptReadError::Source(e.to_string()))?;

        if self.buf.len() <= CHUNK_SIZE {
            set_last_chunk_flag(&mut self.nonce);

            let n = self.buf.len();
            let off = self.buf.off;
            // Go seals in place over the buffer's backing array; the Rust
            // transcription extends the backing, writes ct||tag, then restores
            // Go's logical length so the tag append below lands where Go's
            // self-copy lands.
            let plaintext = self.buf.buf[off..off + n].to_vec();
            let ciphertext = self
                .aead
                .encrypt(&Nonce::from(self.nonce), plaintext.as_slice())
                .expect("ChaCha20-Poly1305 encryption cannot fail");
            self.buf.buf.resize(off + n + AEAD_OVERHEAD, 0);
            self.buf.buf[off..off + n + AEAD_OVERHEAD].copy_from_slice(&ciphertext);
            self.buf.buf.truncate(off + n);
            // Go: r.buf.Write(plaintext[len : len+Overhead]) — the full tag.
            self.buf.write(&ciphertext[n..n + AEAD_OVERHEAD]);
            inc_nonce(&mut self.nonce);
            self.ready = self.buf.len();

            self.err = Some(EncryptReadError::Eof);
            return Ok(());
        }

        // Same, but accounting for the tail byte which will remain unencrypted and
        // needs to be shifted past the overhead.
        assert!(
            self.buf.len() == CHUNK_SIZE + 1,
            "stream: internal error: unexpected buffer length"
        );
        let tail_byte = self.buf.bytes()[CHUNK_SIZE];
        let off = self.buf.off;
        let plaintext = self.buf.buf[off..off + CHUNK_SIZE].to_vec();
        let ciphertext = self
            .aead
            .encrypt(&Nonce::from(self.nonce), plaintext.as_slice())
            .expect("ChaCha20-Poly1305 encryption cannot fail");
        self.buf.buf.resize(off + CHUNK_SIZE + AEAD_OVERHEAD, 0);
        self.buf.buf[off..off + CHUNK_SIZE + AEAD_OVERHEAD].copy_from_slice(&ciphertext);
        // Go's logical length after the in-place seal is still pt+tail
        // (CHUNK_SIZE+1); the byte at off+CHUNK_SIZE now holds tag[0], same
        // as Go's backing.
        self.buf.buf.truncate(off + CHUNK_SIZE + 1);
        // Go: r.buf.Write(plaintext[len+1 : len+Overhead]) — tag[1..16],
        // fifteen bytes, appended at the logical end (over itself).
        self.buf
            .write(&ciphertext[CHUNK_SIZE + 1..CHUNK_SIZE + AEAD_OVERHEAD]);
        // Go: r.buf.WriteByte(tailByte) — restores the tail byte past the
        // overhead; it becomes the next chunk's first plaintext byte.
        self.buf.write_byte(tail_byte);
        inc_nonce(&mut self.nonce);
        self.ready = CHUNK_SIZE + AEAD_OVERHEAD;

        Ok(())
    }
}

/// Go: `io.CopyN` into a [`GoBuffer`], reduced to what `feedBuffer` needs:
/// exactly `n` bytes appended, stopping early at EOF (no error) and
/// propagating any other error after appending what was read.
fn copy_n(dst: &mut GoBuffer, src: &mut impl io::Read, mut n: usize) -> Result<(), io::Error> {
    let mut tmp = [0u8; 8192];
    while n > 0 {
        let want = tmp.len().min(n);
        match read_full(src, &mut tmp[..want]) {
            ReadFull::Full => {
                dst.write(&tmp[..want]);
                n -= want;
            }
            ReadFull::Eof => return Ok(()),
            ReadFull::UnexpectedEof(m) => {
                dst.write(&tmp[..m]);
                return Ok(());
            }
            ReadFull::Io(e) => return Err(e),
        }
    }
    Ok(())
}

/// Go: `io.ReaderAt` — positional reads that leave the source unmoved.
pub trait ReaderAt {
    /// Go: `ReadAt`. Returns the number of bytes read; implementations
    /// surface a short read as an EOF-kind `io::Error`, matching
    /// `bytes.Reader.ReadAt`.
    ///
    /// # Errors
    ///
    /// An EOF-kind `io::Error` for a short read or an out-of-range offset;
    /// implementation-defined errors otherwise.
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize>;
}

impl ReaderAt for [u8] {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let off =
            usize::try_from(offset).map_err(|_| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        if off >= self.len() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        let n = buf.len().min(self.len() - off);
        buf[..n].copy_from_slice(&self[off..off + n]);
        if n < buf.len() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        Ok(n)
    }
}

impl ReaderAt for Vec<u8> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        self.as_slice().read_at(buf, offset)
    }
}

impl<T: AsRef<[u8]>> ReaderAt for std::io::Cursor<T> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        self.get_ref().as_ref().read_at(buf, offset)
    }
}

/// Go method sets: a pointer to a `ReaderAt` is itself a `ReaderAt`, so
/// callers can hand `&src` where Go passes `src` by interface value.
impl<R: ReaderAt + ?Sized> ReaderAt for &R {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        (**self).read_at(buf, offset)
    }
}

/// Go: `readFullAt` — normalizes a positional read to exactly `p.len()`
/// bytes or `ErrUnexpectedEOF`.
///
/// # Errors
///
/// [`StreamError::UnexpectedEof`] when the source is short (or reports an
/// EOF-kind error), [`StreamError::Io`] for any other reader error.
fn read_full_at(r: &impl ReaderAt, p: &mut [u8], off: u64) -> Result<(), StreamError> {
    r.read_at(p, off)
        .map_err(|e| match e.kind() {
            io::ErrorKind::UnexpectedEof => StreamError::UnexpectedEof,
            _ => StreamError::Io(e.to_string()),
        })
        .and_then(|n| {
            if n == p.len() {
                Ok(())
            } else {
                // Incorrect io.ReaderAt implementation, or the source is short.
                Err(StreamError::UnexpectedEof)
            }
        })
}

/// Go: `cachedChunk` + the constructor-prefilled cache.
struct CachedChunk {
    off: i64,
    data: Vec<u8>,
}

/// Go: `DecryptReaderAt` — random-access decryption over an in-memory or
/// file-like source, with a one-chunk cache.
pub struct DecryptReaderAt<R: ReaderAt> {
    aead: ChaCha20Poly1305,
    src: R,
    /// Go: `size` — the plaintext size.
    size: i64,
    chunks: i64,
    cache: Option<CachedChunk>,
}

impl<R: ReaderAt> std::fmt::Debug for DecryptReaderAt<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose cached plaintext or key material.
        f.debug_struct("DecryptReaderAt").finish_non_exhaustive()
    }
}

impl<R: ReaderAt> DecryptReaderAt<R> {
    /// Go: `NewDecryptReaderAt` — checks that `size` is valid by decrypting
    /// the final chunk before returning.
    ///
    /// # Errors
    ///
    /// [`StreamError::InvalidEncryptedSize`] from the chunk-count check,
    /// [`StreamError::FinalChunkRead`] wrapping a short read of the final
    /// chunk, and [`StreamError::FinalChunkDecrypt`] wrapping an
    /// authentication failure.
    ///
    /// # Panics
    ///
    /// Only if the final chunk size does not fit in `usize`, which cannot
    /// happen for any `size` that passes the chunk-count check on a 64-bit
    /// target.
    pub fn new(key: &[u8; 32], src: R, size: i64) -> Result<Self, StreamError> {
        // Check that size is valid by decrypting the final chunk.
        let chunks = encrypted_chunk_count(size)?;
        let final_chunk_index = chunks - 1;
        let final_chunk_off = final_chunk_index * ENC_CHUNK_SIZE_I;
        let final_chunk_size = size - final_chunk_off;
        let mut final_chunk =
            vec![0u8; usize::try_from(final_chunk_size).expect("final chunk size fits in usize")];
        if let Err(e) = read_full_at(&src, &mut final_chunk, final_chunk_off.cast_unsigned()) {
            return Err(StreamError::FinalChunkRead(Box::new(e)));
        }
        let mut nonce = nonce_for_chunk(final_chunk_index);
        set_last_chunk_flag(&mut nonce);
        let Ok(plaintext) =
            ChaCha20Poly1305::new(key.into()).decrypt(&Nonce::from(nonce), &final_chunk[..])
        else {
            return Err(StreamError::FinalChunkDecrypt(StreamError::auth_failed()));
        };
        let cache = CachedChunk {
            off: final_chunk_off,
            data: plaintext,
        };

        let plaintext_size = size - chunks * AEAD_OVERHEAD_I;
        Ok(DecryptReaderAt {
            aead: ChaCha20Poly1305::new(key.into()),
            src,
            size: plaintext_size,
            chunks,
            cache: Some(cache),
        })
    }

    /// Go: `ReadAt` — returns the byte count plus an optional terminal
    /// condition (`None` on success, [`ReadAtError::Eof`] when the read ends
    /// at the plaintext end, [`ReadAtError::Stream`] on failure). The count
    /// is meaningful even alongside an error, mirroring Go.
    ///
    /// # Panics
    ///
    /// Only if an in-loop size conversion fails, which cannot happen: chunk
    /// offsets and sizes are bounded by the validated `size`.
    pub fn read_at(&mut self, mut p: &mut [u8], mut off: i64) -> (usize, Option<ReadAtError>) {
        if off < 0 || off > self.size {
            return (
                0,
                Some(ReadAtError::Stream(StreamError::OffsetOutOfRange {
                    size: self.size,
                    offset: off,
                })),
            );
        }
        if p.is_empty() {
            return (0, None);
        }
        let mut n = 0usize;
        let mut cache_update: Option<CachedChunk> = None;
        let mut chunk = vec![0u8; ENC_CHUNK_SIZE];
        while !p.is_empty() && off < self.size {
            let chunk_index = off / CHUNK_SIZE_I;
            let chunk_off = chunk_index * ENC_CHUNK_SIZE_I;
            let enc_size = self.size + self.chunks * AEAD_OVERHEAD_I;
            let chunk_size = usize::try_from((enc_size - chunk_off).min(ENC_CHUNK_SIZE_I))
                .expect("chunk size fits in usize");

            let plaintext = if self.cache.as_ref().is_some_and(|c| c.off == chunk_off) {
                cache_update = None;
                self.cache
                    .as_ref()
                    .map_or_else(Vec::new, |c| c.data.clone())
            } else {
                if let Err(e) = read_full_at(
                    &self.src,
                    &mut chunk[..chunk_size],
                    chunk_off.cast_unsigned(),
                ) {
                    return (
                        n,
                        Some(ReadAtError::Stream(StreamError::ReadChunkAt {
                            offset: chunk_off,
                            source: Box::new(e),
                        })),
                    );
                }
                let mut nonce = nonce_for_chunk(chunk_index);
                if chunk_index == self.chunks - 1 {
                    set_last_chunk_flag(&mut nonce);
                }
                let Ok(pt) = self.aead.decrypt(&Nonce::from(nonce), &chunk[..chunk_size]) else {
                    return (
                        n,
                        Some(ReadAtError::Stream(StreamError::DecryptChunkAt {
                            offset: chunk_off,
                            source: StreamError::auth_failed(),
                        })),
                    );
                };
                cache_update = Some(CachedChunk {
                    off: chunk_off,
                    data: pt.clone(),
                });
                pt
            };

            let plain_chunk_off = usize::try_from(off - chunk_index * CHUNK_SIZE_I)
                .expect("offset within chunk fits in usize");
            let copy_size = (plaintext.len() - plain_chunk_off).min(p.len());
            p[..copy_size]
                .copy_from_slice(&plaintext[plain_chunk_off..plain_chunk_off + copy_size]);
            p = &mut p[copy_size..];
            off += i64::try_from(copy_size).expect("copy size fits in i64");
            n += copy_size;
        }
        if let Some(update) = cache_update {
            self.cache = Some(update);
        }
        if off == self.size {
            return (n, Some(ReadAtError::Eof));
        }
        (n, None)
    }
}
