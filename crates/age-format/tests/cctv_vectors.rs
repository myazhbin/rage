//! CCTV conformance runner — the S1 subset of Go's testkit_test.go.
//!
//! Per vector: parse the header, verify `Marshal(Parse(file))` re-encodes
//! byte-exactly (Go: testVectorRoundTrip "header"), verify the header MAC
//! against the vector's published file key (Go: testDecrypt's "bad header
//! MAC" classification), and for `success` vectors round-trip the STREAM
//! payload end-to-end (Go: testVectorRoundTrip "STREAM"). Recipient-layer
//! outcomes (`no match` dispatch) are S2/S3 surface and only assert the
//! header-level properties here.

mod common;

use age_format::{FileKey, format, header_mac, mac_equal, stream, stream_key};
use common::{Expect, Vector, load_all};
use sha2::{Digest, Sha256};

#[test]
fn test_vectors() {
    let vectors = load_all();
    assert_eq!(
        vectors.len(),
        147,
        "the vendored CCTV corpus must be complete"
    );

    let mut failures: Vec<String> = Vec::new();
    let mut armored = 0usize;
    for v in &vectors {
        if v.armored {
            // Armor decode/encode is S2 surface (age-armor crate); the
            // non-armor vectors below still cover header + payload.
            armored += 1;
            continue;
        }
        if let Err(e) = run_vector(v) {
            failures.push(format!("{}: {e}", v.name));
        }
    }
    assert!(armored > 0, "expected armor vectors in the corpus");
    assert!(
        failures.is_empty(),
        "{} vector failure(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn run_vector(v: &Vector) -> Result<(), String> {
    let pf = match format::parse(&v.file) {
        Err(e) => {
            // Go skips "header failure" vectors in testVectorRoundTrip:
            // some fail in format.Parse (as ParseErrors), others only in
            // ReadStanza (as plain "failed to parse header" wraps) or later
            // in age.Decrypt. The Go error class varies by failure site and
            // is not part of the vector contract — only that the failure
            // happens before the payload.
            if v.expect != Expect::HeaderFailure {
                return Err(format!("expected {}, got parse error: {e}", v.expect));
            }
            return Ok(());
        }
        Ok(pf) => pf,
    };

    if v.expect == Expect::HeaderFailure {
        // Accepted by the generic format layer, rejected later in
        // age.Decrypt: only the malleability property applies here (Go:
        // FuzzMalleability asserts exactly this for accepted inputs).
        return malleability(&v.file, &pf);
    }

    // Go: testVectorRoundTrip "header" — re-encode byte-exactly.
    malleability(&v.file, &pf)?;

    // MAC verification with the vector's published file key.
    let Some(fk_bytes) = &v.file_key else {
        return Err("vector without a file key".to_string());
    };
    // Go's (*[16]byte)(h) view: the first 16 bytes.
    let fk = FileKey::from_slice(fk_bytes.get(..16).ok_or("file key shorter than 16 bytes")?)
        .ok_or("invalid file key length")?;
    let computed = header_mac(&fk, &pf.header).map_err(|e| e.to_string())?;
    let mac_ok = mac_equal(&computed, &pf.header.mac);

    match v.expect {
        Expect::HmacFailure => {
            if mac_ok {
                return Err("expected HMAC failure, MAC verified".to_string());
            }
            Ok(())
        }
        Expect::PayloadFailure => {
            if !mac_ok {
                return Err("expected payload failure, got MAC failure".to_string());
            }
            stream_payload_failure(v, &fk, pf.payload)
        }
        Expect::Success => {
            if !mac_ok {
                return Err("expected success, got MAC failure".to_string());
            }
            stream_round_trip(v, &fk, pf.payload)
        }
        // Identity dispatch is S2/S3 surface; the header + MAC checks above
        // cover the S1 scope (Go skips the STREAM subtest for non-success).
        Expect::NoMatch | Expect::ArmorFailure => Ok(()),
        Expect::HeaderFailure => unreachable!("handled above"),
    }
}

/// Go: `Marshal(h) + payload` must reproduce the input exactly.
fn malleability(file: &[u8], pf: &format::ParsedFile<'_>) -> Result<(), String> {
    let mut re = pf.header.marshal().map_err(|e| e.to_string())?;
    re.extend_from_slice(pf.payload);
    if re != file {
        return Err("got a different header+payload encoding".to_string());
    }
    Ok(())
}

/// Go: testVectorRoundTrip "STREAM" — decrypt, hash, re-encrypt via writer
/// and reader, and decrypt again through ReaderAt.
fn stream_round_trip(v: &Vector, fk: &FileKey, payload: &[u8]) -> Result<(), String> {
    let (key, ciphertext) = stream_key_and_ct(fk, payload)?;

    // Go: stream.NewDecryptReader + io.ReadAll.
    let plaintext = {
        let mut r = stream::new_decrypt_reader(&key, ciphertext);
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match r.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                // Eof is the reader's normal end-of-stream signal (Go:
                // io.EOF); any other error is a decrypt failure.
                Err(stream::DecryptReadError::Eof) => break,
                Err(e) => return Err(format!("expected success, got decrypt error: {e:?}")),
            }
        }
        out
    };

    // Go: sha256.Sum256(out) != *v.payloadHash.
    if let Some(hash) = &v.payload_hash {
        let got: [u8; 32] = Sha256::digest(&plaintext).into();
        if got != *hash {
            return Err("payload hash mismatch".to_string());
        }
    }

    // Go: stream.NewEncryptWriter + Write + Close must reproduce the
    // ciphertext.
    {
        let mut buf = Vec::new();
        {
            let mut w = stream::new_encrypt_writer(&key, &mut buf);
            let n = w
                .write(&plaintext)
                .map_err(|e| format!("EncryptWriter.Write: {e:?}"))?;
            if n != plaintext.len() {
                return Err(format!(
                    "EncryptWriter: short write ({n} of {})",
                    plaintext.len()
                ));
            }
            w.close()
                .map_err(|e| format!("EncryptWriter.Close: {e:?}"))?;
        }
        if buf != ciphertext {
            return Err("got a different STREAM ciphertext".to_string());
        }
    }

    // Go: stream.NewEncryptReader + io.ReadAll.
    {
        let mut er = stream::new_encrypt_reader(&key, &plaintext[..]);
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match er.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(stream::EncryptReadError::Eof) => break,
                Err(e) => return Err(format!("EncryptReader error: {e:?}")),
            }
        }
        if out != ciphertext {
            return Err("got a different STREAM ciphertext from EncryptReader".to_string());
        }
    }

    // Go: stream.NewDecryptReaderAt + SectionReader read.
    {
        let size = i64::try_from(ciphertext.len()).expect("vector ciphertext fits i64");
        let mut ra = stream::DecryptReaderAt::new(&key, ciphertext, size)
            .map_err(|e| format!("NewDecryptReaderAt failed: {e:?}"))?;
        let mut out = Vec::new();
        let mut buf = vec![0u8; 8192];
        let mut off = 0i64;
        loop {
            let (n, err) = ra.read_at(&mut buf, off);
            out.extend_from_slice(&buf[..n]);
            off += i64::try_from(n).expect("read count fits i64");
            if err.is_some() || n == 0 {
                // EOF (or any error) ends the section; the equality check
                // below catches real failures by truncation.
                break;
            }
        }
        if out != plaintext {
            return Err("got a different plaintext from DecryptReaderAt".to_string());
        }
    }

    Ok(())
}

/// Go: testDecrypt's payload-read phase for `payload failure` vectors —
/// decryption must error, with the published partial-output hash if present.
fn stream_payload_failure(v: &Vector, fk: &FileKey, payload: &[u8]) -> Result<(), String> {
    let (key, ciphertext) = stream_key_and_ct(fk, payload)?;
    let mut r = stream::new_decrypt_reader(&key, ciphertext);
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    let mut got_error = false;
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => {
                got_error = true;
                break;
            }
        }
    }
    if !got_error {
        return Err("expected payload failure, got success".to_string());
    }
    if let Some(hash) = &v.payload_hash {
        let got: [u8; 32] = Sha256::digest(&out).into();
        if got != *hash {
            return Err(format!(
                "partial payload hash mismatch, read {} bytes",
                out.len()
            ));
        }
    }
    Ok(())
}

fn stream_key_and_ct<'a>(fk: &FileKey, payload: &'a [u8]) -> Result<([u8; 32], &'a [u8]), String> {
    if payload.len() < 16 {
        return Err("payload shorter than the 16-byte nonce".to_string());
    }
    let nonce: [u8; 16] = payload[..16].try_into().expect("16-byte nonce");
    Ok((stream_key(fk, &nonce), &payload[16..]))
}
