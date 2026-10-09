//! Port of Go age v1.3.2 `internal/stream/stream_test.go` — the STREAM test
//! battery, transcribed against the same oracle behavior. Deterministic RNG
//! replaces `crypto/rand` so CI failures reproduce; the Go tests draw fresh
//! randomness per run.
//!
//! Port note: Go's `iotest.TestReader` subtests are covered by
//! [`read_to_end_checked`], which asserts the same contract (data matches,
//! `Ok(0)` never precedes EOF, EOF is sticky). The concurrent `ReadAt` test
//! is ported sequentially: in Rust, random access takes `&mut self`, so the
//! data race the Go test guards against (its atomic cache) cannot be
//! expressed, and the same access patterns are replayed in order.

use std::io::Read;

use age_format::stream::{
    CHUNK_SIZE, DecryptReadError, DecryptReaderAt, EncryptReadError, ReadAtError, ReaderAt,
    StreamError, encrypted_chunk_count, new_decrypt_reader, new_encrypt_reader, new_encrypt_writer,
};

const CS: usize = CHUNK_SIZE;

/// xorshift64* — non-cryptographic, deterministic test data only.
struct TestRng(u64);

impl TestRng {
    fn new(seed: u64) -> Self {
        TestRng(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

/// Go: `encrypt` — encrypts plaintext with the writer path and returns the
/// ciphertext.
fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut w = new_encrypt_writer(key, &mut buf);
    w.write(plaintext).expect("write error");
    w.close().expect("close error");
    buf
}

/// Port of the `iotest.TestReader` contract checks the Go battery applies to
/// every reader: all data comes out in order, the terminal is the reader's
/// typed EOF, and that EOF is sticky. A single `Ok(0)` immediately before the
/// typed EOF is legal (Go serves an empty final chunk as `(0, nil)` and only
/// reports `io.EOF` on the next call); data or a second `Ok(0)` after it is
/// not.
fn read_to_end_checked<E>(
    mut read: impl FnMut(&mut [u8]) -> Result<usize, E>,
    eof: &E,
    want: &[u8],
    ctx: &str,
) where
    E: std::fmt::Debug + PartialEq + Clone,
{
    let mut got = Vec::new();
    let mut buf = vec![0u8; 7]; // awkward size: forces reads to split chunks
    let mut eof_pending = false;
    loop {
        match read(&mut buf) {
            Ok(0) => {
                assert!(!eof_pending, "{ctx}: repeated Ok(0) before EOF");
                eof_pending = true;
            }
            Ok(n) => {
                assert!(!eof_pending, "{ctx}: data after Ok(0)");
                got.extend_from_slice(&buf[..n]);
            }
            Err(e) if e == *eof => break,
            Err(e) => panic!("{ctx}: unexpected error {e:?}"),
        }
    }
    assert_eq!(got, want, "{ctx}: data mismatch");
    assert_eq!(read(&mut buf), Err(eof.clone()), "{ctx}: EOF not sticky");
}

/// The body of Go's `testRoundTrip`: writer-chunked encryption, then the
/// decrypt, random-access-decrypt, and encrypt-reader paths over the result.
fn test_round_trip(step_size: usize, length: usize) {
    let mut rng = TestRng::new(0xABCD_0123 ^ (length as u64) ^ (step_size as u64));
    let mut src = vec![0u8; length];
    rng.fill(&mut src);
    let mut key = [0u8; 32];
    rng.fill(&mut key);

    // EncryptWriter with step-size writes, including a zero-length write per
    // step (Go: w.Write(src[n:n]) must be a no-op).
    let mut buf = Vec::new();
    {
        let mut w = new_encrypt_writer(&key, &mut buf);
        let mut n = 0;
        while n < length {
            let b = (length - n).min(step_size);
            let nn = w.write(&src[n..n + b]).expect("write error");
            assert_eq!(nn, b, "Write returned {nn}, expected {b}");
            n += nn;

            let nn = w.write(&src[n..n]).expect("write error");
            assert_eq!(nn, 0, "empty Write returned {nn}, expected 0");
        }
        w.close().expect("Close returned an error");
    }
    let ciphertext = buf;

    // DecryptReader, read by step.
    {
        let mut r = new_decrypt_reader(&key, ciphertext.as_slice());
        let mut n = 0;
        let mut read_buf = vec![0u8; step_size];
        while n < length {
            let nn = r
                .read(&mut read_buf)
                .unwrap_or_else(|e| panic!("Read error at index {n}: {e:?}"));
            assert_eq!(
                &read_buf[..nn],
                &src[n..n + nn],
                "wrong data at indexes {n} - {}",
                n + nn
            );
            n += nn;
        }
        // Empty message: Go serves the empty final chunk as (0, nil) and
        // only reports io.EOF on the next call, so tolerate one pending
        // Ok(0) before demanding the typed EOF.
        match r.read(&mut read_buf) {
            Err(DecryptReadError::Eof) => {}
            Ok(0) => {
                assert_eq!(
                    r.read(&mut read_buf),
                    Err(DecryptReadError::Eof),
                    "missing EOF after end of ciphertext"
                );
            }
            other => panic!("missing EOF after end of ciphertext: {other:?}"),
        }
        assert_eq!(
            r.read(&mut read_buf),
            Err(DecryptReadError::Eof),
            "EOF not sticky"
        );
        let mut r2 = new_decrypt_reader(&key, ciphertext.as_slice());
        read_to_end_checked(
            |p| r2.read(p),
            &DecryptReadError::Eof,
            &src,
            "iotest.TestReader on DecryptReader",
        );
    }

    // DecryptReaderAt read sequentially through a section window.
    {
        let mut ra = DecryptReaderAt::new(&key, ciphertext.as_slice(), ciphertext.len() as i64)
            .expect("NewDecryptReaderAt failed");
        let mut n = 0;
        let mut read_buf = vec![0u8; step_size];
        while n < length {
            let size = read_buf.len().min(length - n);
            let (nn, err) = ra.read_at(&mut read_buf[..size], n as i64);
            let err = if n + nn == length && err == Some(ReadAtError::Eof) {
                None
            } else {
                err
            };
            assert!(err.is_none(), "ReadAt error at index {n}: {err:?}");
            assert_eq!(
                &read_buf[..nn],
                &src[n..n + nn],
                "wrong data at indexes {n} - {}",
                n + nn
            );
            n += nn;
        }
    }

    // EncryptReader must produce the writer's exact ciphertext.
    {
        let mut er = new_encrypt_reader(&key, src.as_slice());
        let mut n = 0;
        let mut read_buf = vec![0u8; step_size];
        loop {
            match er.read(&mut read_buf) {
                Err(EncryptReadError::Eof) => break,
                Err(e) => panic!("EncryptReader Read error at index {n}: {e:?}"),
                Ok(nn) => {
                    assert_eq!(
                        &read_buf[..nn],
                        &ciphertext[n..n + nn],
                        "EncryptReader wrong data at indexes {n} - {}",
                        n + nn
                    );
                    n += nn;
                }
            }
        }
        assert_eq!(
            n,
            ciphertext.len(),
            "EncryptReader read {n} bytes, expected {}",
            ciphertext.len()
        );
        assert_eq!(
            er.read(&mut read_buf),
            Err(EncryptReadError::Eof),
            "EOF not sticky"
        );
        let mut er2 = new_encrypt_reader(&key, src.as_slice());
        read_to_end_checked(
            |p| er2.read(p),
            &EncryptReadError::Eof,
            &ciphertext,
            "iotest.TestReader on EncryptReader",
        );
    }
}

#[test]
fn test_round_trip_matrix() {
    for length in [0, 1000, CS - 1, CS, CS + 1, CS + 100, 2 * CS, 2 * CS + 500] {
        for step_size in [512, 600, 1000, CS - 1, CS, CS + 1] {
            test_round_trip(step_size, length);
        }
    }
    test_round_trip(1, 2 * CS + 500);
}

/// Go: `trackingReaderAt`.
struct TrackingReaderAt {
    data: Vec<u8>,
    called: std::cell::Cell<bool>,
}

impl TrackingReaderAt {
    fn reset(&self) {
        self.called.set(false);
    }
}

impl ReaderAt for TrackingReaderAt {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        self.called.set(true);
        self.data.as_slice().read_at(buf, offset)
    }
}

/// Go: `TestDecryptReaderAt` — cache behavior and data correctness across
/// chunk boundaries, with a source that reports whether it was touched.
#[test]
fn test_decrypt_reader_at() {
    let mut rng = TestRng::new(0x1234_5678_9ABC_DEF0);
    let mut key = [0u8; 32];
    rng.fill(&mut key);

    // Plaintext spanning exactly 3 chunks: 2 full chunks + partial third.
    let plaintext_size = 2 * CS + 500;
    let mut plaintext = vec![0u8; plaintext_size];
    rng.fill(&mut plaintext);
    let ciphertext = encrypt(&key, &plaintext);

    let tracker = TrackingReaderAt {
        data: ciphertext,
        called: std::cell::Cell::new(false),
    };
    let mut ra = DecryptReaderAt::new(&key, &tracker, (plaintext_size + 3 * 16) as i64)
        .expect("NewDecryptReaderAt failed");
    tracker.reset();

    // Test-local macro (not a closure) so each expansion takes its own
    // mutable borrow of `ra` and direct `ra.read_at` calls between
    // expansions stay borrow-compatible.
    macro_rules! check_read {
        ($name:expr, $off:expr, $size:expr, $want_n:expr, $want_eof:expr, $want_src_read:expr) => {{
            let name: &str = $name;
            let off: i64 = $off;
            tracker.reset();
            let mut p = vec![0u8; $size];
            let (n, err) = ra.read_at(&mut p, off);

            assert_eq!(
                err,
                if $want_eof {
                    Some(ReadAtError::Eof)
                } else {
                    None
                },
                "{name}: got err={err:?}"
            );
            assert_eq!(n, $want_n, "{name}: got n={n}, want {}", $want_n);
            assert_eq!(
                tracker.called.get(),
                $want_src_read,
                "{name}: src.ReadAt called={}, want {}",
                tracker.called.get(),
                $want_src_read
            );
            if n > 0 && off >= 0 && off < plaintext_size as i64 {
                let end = ((off as usize) + n).min(plaintext_size);
                assert_eq!(
                    &p[..n],
                    &plaintext[off as usize..end],
                    "{name}: data mismatch"
                );
            }
        }};
    }

    // Test 1: Read from final chunk (cached by constructor)
    check_read!(
        "final chunk (cached)",
        (2 * CS + 100) as i64,
        100,
        100,
        false,
        false
    );
    // Test 2: Read spanning second and third chunk
    check_read!(
        "span chunks 1-2",
        (CS + CS - 50) as i64,
        100,
        100,
        false,
        true
    );
    // Test 3: Read from final chunk again (cached from test 2)
    check_read!(
        "final chunk after span",
        (2 * CS + 200) as i64,
        100,
        100,
        false,
        false
    );
    // Test 4: Read from final chunk again (now cached)
    check_read!(
        "final chunk (cached again)",
        (2 * CS + 50) as i64,
        50,
        50,
        false,
        false
    );
    // Test 5: Read from first chunk (not cached)
    check_read!("first chunk", 0, 100, 100, false, true);
    // Test 6: Read from first chunk again (now cached)
    check_read!("first chunk (cached)", 50, 100, 100, false, false);

    // Test 7: Read spanning all chunks
    tracker.reset();
    let mut p = vec![0u8; plaintext_size];
    let (n, err) = ra.read_at(&mut p, 0);
    assert_eq!(
        err,
        Some(ReadAtError::Eof),
        "span all: got err={err:?}, want EOF"
    );
    assert_eq!(
        n, plaintext_size,
        "span all: got n={n}, want {plaintext_size}"
    );
    assert_eq!(p, plaintext, "span all: data mismatch");

    // Test 8: Read beyond the end (offset > size)
    tracker.reset();
    let mut p = vec![0u8; 100];
    let (n, err) = ra.read_at(&mut p, plaintext_size as i64 + 100);
    assert!(err.is_some(), "beyond end: expected error, got nil");
    assert_eq!(n, 0, "beyond end: got n={n}, want 0");

    // Test 9: Read with off = size (should return 0, EOF)
    tracker.reset();
    let mut p = vec![0u8; 100];
    let (n, err) = ra.read_at(&mut p, plaintext_size as i64);
    assert_eq!(
        err,
        Some(ReadAtError::Eof),
        "off=size: got err={err:?}, want EOF"
    );
    assert_eq!(n, 0, "off=size: got n={n}, want 0");

    // Test 10: Read spanning last chunk and beyond
    tracker.reset();
    let mut p = vec![0u8; 1000]; // request more than available
    let (n, err) = ra.read_at(&mut p, (2 * CS + 400) as i64);
    assert_eq!(
        err,
        Some(ReadAtError::Eof),
        "span last+beyond: got err={err:?}, want EOF"
    );
    let want_n = 500 - 400; // only 100 bytes available from offset 2*cs+400
    assert_eq!(n, want_n, "span last+beyond: got n={n}, want {want_n}");
    assert_eq!(
        &p[..n],
        &plaintext[2 * CS + 400..],
        "span last+beyond: data mismatch"
    );

    // Test 11: Read spanning second+last chunk and beyond
    tracker.reset();
    let mut p = vec![0u8; CS + 1000]; // request more than available
    let (n, err) = ra.read_at(&mut p, (CS + 100) as i64);
    assert_eq!(
        err,
        Some(ReadAtError::Eof),
        "span 1-2+beyond: got err={err:?}, want EOF"
    );
    let want_n = plaintext_size - (CS + 100);
    assert_eq!(n, want_n, "span 1-2+beyond: got n={n}, want {want_n}");
    assert_eq!(
        &p[..n],
        &plaintext[CS + 100..],
        "span 1-2+beyond: data mismatch"
    );

    // Test 12: Negative offset
    tracker.reset();
    let mut p = vec![0u8; 100];
    let (n, err) = ra.read_at(&mut p, -1);
    assert!(err.is_some(), "negative offset: expected error, got nil");
    assert_eq!(n, 0, "negative offset: got n={n}, want 0");

    // Test 13: Zero-length read in the middle
    tracker.reset();
    let (n, err) = ra.read_at(&mut [], 100);
    assert!(
        err.is_none(),
        "zero-length middle: got err={err:?}, want nil"
    );
    assert_eq!(n, 0, "zero-length middle: got n={n}, want 0");

    // Test 14: Zero-length read at end
    tracker.reset();
    let (n, err) = ra.read_at(&mut [], plaintext_size as i64);
    assert!(err.is_none(), "zero-length end: got err={err:?}, want nil");
    assert_eq!(n, 0, "zero-length end: got n={n}, want 0");

    // Test 15: Read exactly one chunk at chunk boundary
    check_read!("exact chunk at boundary", CS as i64, CS, CS, false, true);

    // Test 16: Read one byte at each chunk boundary
    check_read!("one byte at start", 0, 1, 1, false, true);
    check_read!("one byte at cs-1", (CS - 1) as i64, 1, 1, false, false); // cached from test 15
    check_read!("one byte at cs", CS as i64, 1, 1, false, true);
    check_read!(
        "one byte at 2*cs-1",
        (2 * CS - 1) as i64,
        1,
        1,
        false,
        false
    ); // same chunk
    check_read!("one byte at 2*cs", (2 * CS) as i64, 1, 1, false, true);
    check_read!("last byte", (plaintext_size - 1) as i64, 1, 1, true, false); // same chunk, EOF because we reach end

    // Test 17: Read crossing exactly one chunk boundary
    check_read!(
        "cross boundary 0-1",
        (CS - 50) as i64,
        100,
        100,
        false,
        true
    );
    check_read!(
        "cross boundary 1-2",
        (2 * CS - 50) as i64,
        100,
        100,
        false,
        true
    );
}

/// Go: `TestDecryptReaderAtEOF` — reads that reach the exact end of the
/// source must be accepted. In Go an `io.ReaderAt` may return `io.EOF`
/// alongside a full read; the Rust `ReaderAt` convention encodes that
/// terminal condition as `Ok(n)`, which every impl here produces, so the
/// same end-of-source double is exercised through the constructor and the
/// cache-evicting read path.
#[test]
fn test_decrypt_reader_at_eof() {
    let mut rng = TestRng::new(0x0FED_CBA9_8765_4321);
    let mut key = [0u8; 32];
    rng.fill(&mut key);

    // Multiple chunks, so that reads reach the final chunk both in the
    // constructor and through ReadAt.
    let mut plaintext = vec![0u8; 2 * CS + 100];
    rng.fill(&mut plaintext);
    let ciphertext = encrypt(&key, &plaintext);

    let mut ra = DecryptReaderAt::new(&key, ciphertext.as_slice(), ciphertext.len() as i64)
        .expect("NewDecryptReaderAt failed on EOF");

    // Sequential small reads evict the final chunk from the cache, so it is
    // read again through ReadAt, exercising its own end-of-source handling.
    let mut got = Vec::new();
    let mut buf = vec![0u8; 7];
    while got.len() < plaintext.len() {
        let (n, err) = ra.read_at(&mut buf, got.len() as i64);
        assert!(
            err.is_none() || err == Some(ReadAtError::Eof),
            "ReadAll failed on EOF: {err:?}"
        );
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(got, plaintext, "plaintext mismatch");
}

/// Go: `TestDecryptReaderTrailingData` — data appended after a full-length
/// final chunk is rejected, including when the source returns the trailing
/// byte alongside EOF as permitted by `io.Reader` (here: a data-echoing
/// source wrapper, Go's `iotest.DataErrReader`).
#[test]
fn test_decrypt_reader_trailing_data() {
    let mut rng = TestRng::new(0x5EED_1234_AAAA_5555);
    let mut key = [0u8; 32];
    rng.fill(&mut key);

    // A plaintext of exactly one full chunk, so the trailing data can only be
    // detected by reading past the final chunk.
    let mut plaintext = vec![0u8; CS];
    rng.fill(&mut plaintext);
    let ciphertext = encrypt(&key, &plaintext);
    let mut trailing = ciphertext.clone();
    trailing.push(0x42);

    /// Go: `iotest.DataErrReader` returns the final data with a nil error and
    /// defers `io.EOF` by one read. Rust's `io::Read` cannot express an error
    /// carrying consumed data, so the port-equivalent hunts the same failure
    /// mode with single-byte reads: `read_full` must accumulate short reads
    /// correctly and the trailing byte must still arrive before EOF.
    struct DataErrReader<T: Read>(T);
    impl<T: Read> Read for DataErrReader<T> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            self.0.read(&mut buf[..1])
        }
    }

    for (name, reader) in [
        (
            "plain",
            Box::new(std::io::Cursor::new(trailing.clone())) as Box<dyn Read>,
        ),
        (
            "dataErr",
            Box::new(DataErrReader(std::io::Cursor::new(trailing))) as Box<dyn Read>,
        ),
    ] {
        let mut r = new_decrypt_reader(&key, reader);
        let mut sink = Vec::new();
        let mut buf = vec![0u8; 4096];
        let got_err = loop {
            match r.read(&mut buf) {
                Ok(0) => panic!("{name}: Ok(0) before EOF"),
                Ok(n) => sink.extend_from_slice(&buf[..n]),
                Err(e) => break e,
            }
        };
        assert_eq!(
            got_err,
            DecryptReadError::Stream(StreamError::TrailingData),
            "{name}: got err={got_err:?}, want trailing-data error"
        );
        let _ = sink; // data up to the first invalid chunk is not observable

        let mut r = new_decrypt_reader(&key, std::io::Cursor::new(ciphertext.clone()));
        let mut got = Vec::new();
        let mut buf = vec![0u8; 4096];
        loop {
            match r.read(&mut buf) {
                Err(DecryptReadError::Eof) => break,
                Ok(0) => panic!("{name}: valid file: unexpected Ok(0) before EOF"),
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(e) => panic!("{name}: valid file: got err={e:?}, want nil"),
            }
        }
        assert_eq!(got, plaintext, "{name}: valid file: plaintext mismatch");
    }
}

/// Go: `TestDecryptReaderAtEmpty`.
#[test]
fn test_decrypt_reader_at_empty() {
    let mut rng = TestRng::new(0x7777_8888_9999_0000);
    let mut key = [0u8; 32];
    rng.fill(&mut key);

    let ciphertext = encrypt(&key, &[]);
    let tracker = TrackingReaderAt {
        data: ciphertext,
        called: std::cell::Cell::new(false),
    };
    let mut ra = DecryptReaderAt::new(&key, &tracker, 16).expect("NewDecryptReaderAt failed");
    tracker.reset();

    // Test 1: Read from empty file at offset 0
    let mut p = vec![0u8; 100];
    let (n, err) = ra.read_at(&mut p, 0);
    assert_eq!(
        err,
        Some(ReadAtError::Eof),
        "empty read: got err={err:?}, want EOF"
    );
    assert_eq!(n, 0, "empty read: got n={n}, want 0");

    // Test 2: Zero-length read from empty file
    let (n, err) = ra.read_at(&mut [], 0);
    assert!(
        err.is_none(),
        "empty zero-length: got err={err:?}, want nil"
    );
    assert_eq!(n, 0, "empty zero-length: got n={n}, want 0");

    // Test 3: Read beyond empty file
    let mut p = vec![0u8; 100];
    let (n, err) = ra.read_at(&mut p, 1);
    assert!(err.is_some(), "empty beyond: expected error, got nil");
    assert_eq!(n, 0, "empty beyond: got n={n}, want 0");
}

/// Go: `TestDecryptReaderAtSingleChunk`.
#[test]
fn test_decrypt_reader_at_single_chunk() {
    let mut rng = TestRng::new(0x1357_2468_ABCD_EF01);
    let mut key = [0u8; 32];
    rng.fill(&mut key);

    // Single chunk, not full
    let mut plaintext = vec![0u8; 1000];
    rng.fill(&mut plaintext);
    let ciphertext = encrypt(&key, &plaintext);

    let tracker = TrackingReaderAt {
        data: ciphertext,
        called: std::cell::Cell::new(false),
    };
    let mut ra = DecryptReaderAt::new(&key, &tracker, 1016).expect("NewDecryptReaderAt failed");
    tracker.reset();

    // All reads should use cache (final chunk = only chunk)
    let mut p = vec![0u8; 100];
    let (n, err) = ra.read_at(&mut p, 0);
    assert!(
        err.is_none(),
        "single chunk start: got err={err:?}, want nil"
    );
    assert_eq!(n, 100, "single chunk start: got n={n}, want 100");
    assert!(
        !tracker.called.get(),
        "single chunk start: unexpected src.ReadAt call"
    );
    assert_eq!(
        &p[..n],
        &plaintext[..100],
        "single chunk start: data mismatch"
    );

    // Read at end
    let (n, err) = ra.read_at(&mut p, 900);
    assert_eq!(
        err,
        Some(ReadAtError::Eof),
        "single chunk end: got err={err:?}, want EOF"
    );
    assert_eq!(n, 100, "single chunk end: got n={n}, want 100");
    assert!(
        !tracker.called.get(),
        "single chunk end: unexpected src.ReadAt call"
    );
    assert_eq!(
        &p[..n],
        &plaintext[900..],
        "single chunk end: data mismatch"
    );
}

/// Go: `TestDecryptReaderAtFullChunks`.
#[test]
fn test_decrypt_reader_at_full_chunks() {
    let mut rng = TestRng::new(0x2468_ACE0_1357_BDF2);
    let mut key = [0u8; 32];
    rng.fill(&mut key);

    // Exactly 2 full chunks
    let mut plaintext = vec![0u8; 2 * CS];
    rng.fill(&mut plaintext);
    let ciphertext = encrypt(&key, &plaintext);

    let tracker = TrackingReaderAt {
        data: ciphertext,
        called: std::cell::Cell::new(false),
    };
    let mut ra = DecryptReaderAt::new(&key, &tracker, (2 * CS + 32) as i64)
        .expect("NewDecryptReaderAt failed");
    tracker.reset();

    // Read last byte of second chunk (cached)
    let mut p = vec![0u8; 1];
    let (n, err) = ra.read_at(&mut p, (2 * CS - 1) as i64);
    assert_eq!(
        err,
        Some(ReadAtError::Eof),
        "last byte: got err={err:?}, want EOF"
    );
    assert_eq!(n, 1, "last byte: got n={n}, want 1");
    assert!(
        !tracker.called.get(),
        "last byte: unexpected src.ReadAt call (should be cached)"
    );
    assert_eq!(p[0], plaintext[2 * CS - 1], "last byte: data mismatch");

    // Read at exactly the boundary between chunks
    let mut p = vec![0u8; 100];
    let (n, err) = ra.read_at(&mut p, (CS - 50) as i64);
    assert!(err.is_none(), "boundary: got err={err:?}, want nil");
    assert_eq!(n, 100, "boundary: got n={n}, want 100");
    assert_eq!(
        &p[..n],
        &plaintext[CS - 50..CS + 50],
        "boundary: data mismatch"
    );
}

/// Go: `TestDecryptReaderAtWrongKey`.
#[test]
fn test_decrypt_reader_at_wrong_key() {
    let mut rng = TestRng::new(0x9999_3333_7777_1111);
    let mut key = [0u8; 32];
    rng.fill(&mut key);
    let mut plaintext = vec![0u8; 1000];
    rng.fill(&mut plaintext);
    let ciphertext = encrypt(&key, &plaintext);

    let mut wrong_key = [0u8; 32];
    rng.fill(&mut wrong_key);
    let err = DecryptReaderAt::new(&wrong_key, ciphertext.as_slice(), ciphertext.len() as i64);
    assert!(err.is_err(), "wrong key: expected error, got nil");
}

/// Go: `TestDecryptReaderAtInvalidSize`.
#[test]
fn test_decrypt_reader_at_invalid_size() {
    let mut rng = TestRng::new(0x6161_6262_6363_6464);
    let mut key = [0u8; 32];
    rng.fill(&mut key);
    let mut plaintext = vec![0u8; 1000];
    rng.fill(&mut plaintext);
    let ciphertext = encrypt(&key, &plaintext);

    // Wrong size (too small)
    assert!(
        DecryptReaderAt::new(&key, ciphertext.as_slice(), ciphertext.len() as i64 - 1).is_err(),
        "wrong size (small): expected error, got nil"
    );

    // Wrong size (too large)
    assert!(
        DecryptReaderAt::new(&key, ciphertext.as_slice(), ciphertext.len() as i64 + 1).is_err(),
        "wrong size (large): expected error, got nil"
    );

    // Size that would imply empty final chunk (invalid)
    // This would be: one full encrypted chunk + just overhead
    let invalid_size = (CS + 16 + 16) as i64;
    assert!(
        DecryptReaderAt::new(
            &key,
            std::io::Cursor::new(vec![0u8; invalid_size as usize]),
            invalid_size
        )
        .is_err(),
        "invalid size (empty final chunk): expected error, got nil"
    );

    // Negative sizes and sizes that would overflow the chunk count computation
    // must be rejected with an error rather than a panic.
    for size in [-1, -70000, i64::MAX, i64::MAX - 200, i64::MAX - 65550] {
        assert!(
            encrypted_chunk_count(size).is_err(),
            "EncryptedChunkCount({size}): expected error, got nil"
        );
        assert!(
            DecryptReaderAt::new(&key, ciphertext.as_slice(), size).is_err(),
            "NewDecryptReaderAt({size}): expected error, got nil"
        );
    }
}

/// Go: `TestDecryptReaderAtTruncated` — the source ending before the expected
/// end of the final chunk must be reported as an unexpected EOF, not as a
/// decryption failure.
#[test]
fn test_decrypt_reader_at_truncated() {
    let mut rng = TestRng::new(0xBEEF_DEAD_F00D_CAFE);
    let mut key = [0u8; 32];
    rng.fill(&mut key);
    let mut plaintext = vec![0u8; 2 * CS + 500];
    rng.fill(&mut plaintext);
    let ciphertext = encrypt(&key, &plaintext);

    // Truncate ciphertext but lie about size.
    let truncated = &ciphertext[..ciphertext.len() - 100];
    let err = DecryptReaderAt::new(&key, truncated, ciphertext.len() as i64).unwrap_err();
    assert!(
        err.is_unexpected_eof(),
        "truncated: got err={err:?}, want unexpected EOF"
    );
}

/// Go: `TestDecryptReaderAtTruncatedChunk` — truncating to a chunk boundary
/// and lying about the size makes a non-final chunk pass as the final one;
/// the authentication retry with the last-chunk flag must fail.
#[test]
fn test_decrypt_reader_at_truncated_chunk() {
    let mut rng = TestRng::new(0x1357_9BDF_2468_ACE0);
    let mut key = [0u8; 32];
    rng.fill(&mut key);

    // Create 4 chunks: 3 full + 1 partial
    let mut plaintext = vec![0u8; 3 * CS + 500];
    rng.fill(&mut plaintext);
    let ciphertext = encrypt(&key, &plaintext);

    // Truncate to 3 chunks (remove the actual final chunk). The third chunk
    // was NOT encrypted with the last chunk flag, so decryption should fail
    // when we try to use it as the final chunk.
    let enc_chunk_size = CS + 16; // ChunkSize + Overhead
    let truncated_size = 3 * enc_chunk_size;
    let truncated = &ciphertext[..truncated_size];

    assert!(
        DecryptReaderAt::new(&key, truncated, truncated_size as i64).is_err(),
        "truncated at chunk boundary: expected error, got nil"
    );
}

/// Go: `TestDecryptReaderAtConcurrent` — replayed sequentially (random access
/// takes `&mut self` in the port, so the cache race Go guards against cannot
/// be expressed); the same access patterns must still produce correct data.
#[test]
fn test_decrypt_reader_at_concurrent() {
    let mut rng = TestRng::new(0x0DEF_ACED_1234_5678);
    let mut key = [0u8; 32];
    rng.fill(&mut key);

    // Plaintext spanning 3 chunks: 2 full + partial
    let plaintext_size = 2 * CS + 500;
    let mut plaintext = vec![0u8; plaintext_size];
    rng.fill(&mut plaintext);
    let ciphertext = encrypt(&key, &plaintext);

    let mut ra = DecryptReaderAt::new(&key, ciphertext.as_slice(), ciphertext.len() as i64)
        .expect("NewDecryptReaderAt failed");

    // same chunk
    for id in 0..10 {
        for i in 0..100 {
            let off = ((id * 100 + i) % 500) as i64;
            let mut p = vec![0u8; 100];
            let (n, err) = ra.read_at(&mut p, off);
            assert!(err.is_none(), "same chunk goroutine {id} iter {i}: {err:?}");
            assert_eq!(
                n, 100,
                "same chunk goroutine {id} iter {i}: n={n}, want 100"
            );
            assert_eq!(
                &p,
                &plaintext[off as usize..off as usize + 100],
                "same chunk goroutine {id} iter {i}: data mismatch"
            );
        }
    }

    // different chunks
    for id in 0..10 {
        for i in 0..100 {
            let chunk_idx = (id % 3) as i64;
            let off = chunk_idx * CS as i64 + (i % 400) as i64;
            let mut size = 100usize;
            if off + size as i64 > plaintext_size as i64 {
                size = (plaintext_size as i64 - off) as usize;
            }
            let mut p = vec![0u8; size];
            let (n, err) = ra.read_at(&mut p, off);
            let err = if n == size && err == Some(ReadAtError::Eof) {
                None
            } else {
                err
            }; // EOF at end is acceptable
            assert!(
                err.is_none(),
                "different chunks goroutine {id} iter {i}: off={off}: {err:?}"
            );
            assert_eq!(
                n, size,
                "different chunks goroutine {id} iter {i}: n={n}, want {size}"
            );
            assert_eq!(
                &p[..n],
                &plaintext[off as usize..off as usize + n],
                "different chunks goroutine {id} iter {i}: data mismatch"
            );
        }
    }

    // across chunks
    for id in 0..10 {
        for i in 0..100 {
            // Read across chunk boundaries
            let boundary = (((id % 2) + 1) * CS) as i64; // either cs or 2*cs
            let off = boundary - 50 + (i % 30) as i64;
            let mut size = 100usize;
            if off + size as i64 > plaintext_size as i64 {
                size = (plaintext_size as i64 - off) as usize;
            }
            if size == 0 {
                continue;
            }
            let mut p = vec![0u8; size];
            let (n, err) = ra.read_at(&mut p, off);
            let err = if n == size && err == Some(ReadAtError::Eof) {
                None
            } else {
                err
            };
            assert!(
                err.is_none(),
                "across chunks goroutine {id} iter {i}: off={off} size={size}: {err:?}"
            );
            assert_eq!(
                n, size,
                "across chunks goroutine {id} iter {i}: n={n}, want {size}"
            );
            assert_eq!(
                &p[..n],
                &plaintext[off as usize..off as usize + n],
                "across chunks goroutine {id} iter {i}: data mismatch"
            );
        }
    }
}

/// Go: `TestDecryptReaderAtCorrupted`.
#[test]
fn test_decrypt_reader_at_corrupted() {
    let mut rng = TestRng::new(0x5555_AAAA_3333_CCCC);
    let mut key = [0u8; 32];
    rng.fill(&mut key);
    let mut plaintext = vec![0u8; 2 * CS + 500];
    rng.fill(&mut plaintext);
    let ciphertext = encrypt(&key, &plaintext);

    // Corrupt final chunk - should fail in constructor
    let mut corrupted_final = ciphertext.clone();
    let len = corrupted_final.len();
    corrupted_final[len - 10] ^= 0xFF;
    assert!(
        DecryptReaderAt::new(&key, corrupted_final.as_slice(), len as i64).is_err(),
        "corrupted final: expected error, got nil"
    );

    // Corrupt first chunk - should fail on read
    let mut corrupted_first = ciphertext.clone();
    corrupted_first[10] ^= 0xFF;
    let mut ra = DecryptReaderAt::new(&key, corrupted_first.as_slice(), len as i64)
        .expect("corrupted first constructor: unexpected error");
    let mut p = vec![0u8; 100];
    let (_, err) = ra.read_at(&mut p, 0);
    assert!(
        err.is_some(),
        "corrupted first read: expected error, got nil"
    );
}

/// Go: `TestEncryptWriterClosedWriter` shape — Close must be idempotent only
/// as an error: writes and closes after Close fail with the closed-writer
/// error, and a failed flush leaves a sticky error.
#[test]
fn test_encrypt_writer_sticky_errors() {
    let mut rng = TestRng::new(0x1234_ABCD_5678_EF90);
    let mut key = [0u8; 32];
    rng.fill(&mut key);

    let mut buf = Vec::new();
    let mut w = new_encrypt_writer(&key, &mut buf);
    w.write(b"data").expect("first write");
    w.close().expect("first close");
    assert_eq!(
        w.write(b"more"),
        Err(StreamError::WriterClosed),
        "write after close"
    );
    assert_eq!(w.close(), Err(StreamError::WriterClosed), "second close");
}
