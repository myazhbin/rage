//! Round-trip and tamper-rejection property tests over deterministic
//! pseudo-random data (the S1 acceptance gate), anchored to a real CCTV
//! vector for the single-byte tamper matrices.

mod common;

use age_format::{FileKey, format, header_mac, mac_equal, stream, stream_key};
use common::load_all;

/// Plaintext sizes straddling every STREAM chunk boundary.
const SIZES: [usize; 13] = [
    0, 1, 63, 64, 65, 1000, 65535, 65536, 65537, 131071, 131072, 131073, 200001,
];

#[test]
fn round_trip_decrypt_encrypt() {
    for size in SIZES {
        let mut rng = common::Rng::new(&size.to_le_bytes());
        let key: [u8; 32] = rng.vec(32).try_into().expect("32-byte key");
        let plaintext = rng.vec(size);

        // EncryptWriter → ciphertext.
        let mut ct = Vec::new();
        {
            let mut w = stream::new_encrypt_writer(&key, &mut ct);
            let n = w.write(&plaintext).expect("EncryptWriter.Write");
            assert_eq!(n, plaintext.len(), "size {size}: short write");
            w.close().expect("EncryptWriter.Close");
        }

        // DecryptReader → plaintext'.
        let back = decrypt_all(&key, &ct).unwrap_or_else(|e| panic!("size {size}: {e}"));
        assert_eq!(back, plaintext, "size {size}: round trip mismatch");

        // EncryptReader parity with EncryptWriter.
        let mut er = stream::new_encrypt_reader(&key, &plaintext[..]);
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match er.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(stream::EncryptReadError::Eof) => break,
                Err(e) => panic!("size {size}: EncryptReader error: {e:?}"),
            }
        }
        assert_eq!(
            out, ct,
            "size {size}: EncryptReader diverged from EncryptWriter"
        );
    }
}

#[test]
fn tamper_rejection() {
    // Anchor: the CCTV `x25519` vector — a real header, MAC, and payload.
    let vectors = load_all();
    let v = vectors
        .iter()
        .find(|v| v.name == "x25519")
        .expect("x25519 vector");
    assert_eq!(v.expect, common::Expect::Success);
    let pf = format::parse(&v.file).expect("x25519 vector parses");
    let fk_bytes = v.file_key.as_ref().expect("x25519 vector has a file key");
    let fk = FileKey::from_slice(fk_bytes.get(..16).expect("file key is 16 bytes"))
        .expect("valid file key");

    let header_len = v.file.len() - pf.payload.len();

    // Sanity: the untampered payload decrypts.
    let (key, ciphertext) = {
        let nonce: [u8; 16] = pf.payload[..16].try_into().expect("16-byte nonce");
        (stream_key(&fk, &nonce), &pf.payload[16..])
    };
    let plaintext = decrypt_all(&key, ciphertext).expect("untampered payload decrypts");

    // Header: every single-byte bit flip must be rejected by parse or yield
    // a MAC mismatch.
    for i in 0..header_len {
        let mut flipped = v.file.clone();
        flipped[i] ^= 1;
        match format::parse(&flipped) {
            Err(_) => {}
            Ok(pf) => {
                let computed = header_mac(&fk, &pf.header).expect("header MAC");
                if mac_equal(&computed, &pf.header.mac) {
                    panic!("tampered header byte {i} accepted with a valid MAC");
                }
            }
        }
    }

    // Payload: every single-byte bit flip must fail decryption.
    for i in header_len..v.file.len() {
        let mut flipped = v.file.clone();
        flipped[i] ^= 1;
        let pf = format::parse(&flipped).expect("payload tamper must not affect header parsing");
        let nonce: [u8; 16] = pf.payload[..16].try_into().expect("16-byte nonce");
        let key = stream_key(&fk, &nonce);
        if decrypt_all(&key, &pf.payload[16..]).is_ok() {
            panic!("tampered payload byte {i} decrypted");
        }
    }

    // Truncations: any proper prefix must fail to parse (short header) or
    // fail payload authentication (truncated ciphertext).
    let mut cuts: Vec<usize> = vec![0, 1, 10, header_len / 2, header_len - 1];
    cuts.push(header_len); // nonce only, no ciphertext
    cuts.push(v.file.len() - 1); // half a tag
    for cut in cuts {
        match format::parse(&v.file[..cut]) {
            Err(_) => {}
            Ok(pf) => {
                if pf.payload.len() < 16 {
                    // Header parsed but no full nonce present: nothing is
                    // decryptable — rejected by construction.
                    continue;
                }
                let nonce: [u8; 16] = pf.payload[..16].try_into().expect("16-byte nonce");
                let key = stream_key(&fk, &nonce);
                assert!(
                    decrypt_all(&key, &pf.payload[16..]).is_err(),
                    "truncation at byte {cut} decrypted"
                );
            }
        }
    }

    // The tamper target is real: the anchor plaintext is non-trivial.
    assert!(!plaintext.is_empty());
}

/// Full `DecryptReader` drain; errors surface as Err.
fn decrypt_all(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let mut r = stream::new_decrypt_reader(key, ciphertext);
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf) {
            Ok(0) => return Ok(out),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            // Eof is the reader's normal end-of-stream signal (Go: io.EOF).
            Err(stream::DecryptReadError::Eof) => return Ok(out),
            Err(e) => return Err(format!("decrypt error: {e:?}")),
        }
    }
}
