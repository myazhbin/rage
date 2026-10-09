//! Byte-level differential tests against the Go v1.3.2 oracle
//! (`myazhbin/age` at `b74dce4`). The ciphertext hashes and the embedded
//! 1000-byte ciphertext were produced by a probe running the actual Go
//! `internal/stream` package with the same deterministic inputs used here:
//! `plaintext[i] = (i*7 + 13) mod 256`, `key[i] = i`. Both Go encryption
//! paths (writer and reader) produced identical hashes per length, so one
//! hash pins each length.
//!
//! Byte-for-byte equality with Go's output is the strongest statement of
//! payload-faithfulness available without a shared test binary: same chunk
//! framing, same nonce sequence, same tag bytes.

use age_format::stream::{
    DecryptReadError, EncryptReadError, new_decrypt_reader, new_encrypt_reader, new_encrypt_writer,
};
use sha2::{Digest, Sha256};

fn plaintext(length: usize) -> Vec<u8> {
    (0..length).map(|i| ((i * 7 + 13) % 256) as u8).collect()
}

fn key() -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = i as u8;
    }
    k
}

/// Go oracle: sha256 of the ciphertext for the writer path (== reader path).
const GO_HASHES: &[(usize, &str)] = &[
    (
        0,
        "98082ff61f1317c757770e0ee5ec26bbe8f1d4d7c3f91e4755eb0622f630b8a7",
    ),
    (
        1,
        "9c803d005e05fd7e0a1ce4c660e0571b8f71e43461aac74a46ff3be303a742d0",
    ),
    (
        1000,
        "1979731dbd5998285e0a7efeeea59a892ccfed86d3a179cf119f3d6d7268234e",
    ),
    (
        65535,
        "ffedc1e3c2839c06eeb7201a167528a9f1ebd4cbdb4bf096f7403efb1b20982e",
    ),
    (
        65536,
        "2731a224806de15b01f56552e24cfdc1b1089f1d148caf54183cef7e0e459c82",
    ),
    (
        65537,
        "190c520724937cf776833958f931caca42fa38464ee2a6665807b4a4feaa8701",
    ),
    (
        131036,
        "6dc6fd856334574dd3c720b0551d23cf2438381d19d7492da57f8dce9e649f6f",
    ),
];

pub static GO_CIPHERTEXT_1000: [u8; 1016] = [
    100, 72, 103, 251, 24, 58, 143, 68, 104, 61, 45, 117, 210, 124, 120, 100, 109, 117, 180, 210,
    87, 17, 91, 219, 240, 134, 118, 226, 248, 54, 64, 236, 62, 217, 23, 8, 186, 235, 185, 157, 4,
    100, 216, 30, 231, 171, 229, 152, 152, 154, 46, 1, 240, 235, 211, 187, 241, 167, 179, 228, 222,
    175, 144, 191, 210, 6, 187, 88, 43, 202, 126, 211, 120, 124, 54, 215, 144, 175, 120, 32, 181,
    68, 51, 228, 105, 246, 193, 167, 156, 205, 59, 245, 0, 174, 31, 12, 155, 117, 170, 96, 142,
    177, 156, 151, 134, 6, 113, 243, 154, 69, 65, 89, 1, 163, 202, 185, 11, 111, 3, 90, 39, 97,
    148, 75, 102, 125, 143, 58, 9, 138, 25, 43, 5, 206, 231, 177, 45, 3, 230, 77, 69, 63, 251, 225,
    66, 197, 101, 173, 246, 219, 12, 120, 236, 70, 110, 168, 208, 238, 79, 186, 200, 65, 158, 68,
    158, 195, 182, 90, 195, 24, 197, 199, 199, 170, 228, 206, 208, 50, 112, 143, 49, 173, 228, 68,
    9, 38, 116, 63, 239, 237, 86, 142, 87, 111, 168, 27, 101, 95, 37, 49, 237, 23, 163, 193, 123,
    99, 115, 2, 45, 239, 164, 225, 16, 113, 41, 158, 42, 105, 40, 31, 33, 218, 69, 204, 44, 212,
    224, 126, 97, 169, 219, 86, 187, 134, 97, 137, 13, 116, 44, 213, 18, 3, 89, 217, 63, 0, 203,
    37, 125, 179, 83, 25, 123, 137, 99, 79, 112, 232, 236, 27, 124, 160, 222, 24, 167, 167, 212,
    126, 48, 174, 201, 35, 202, 101, 171, 127, 3, 244, 7, 219, 181, 255, 163, 44, 4, 28, 17, 154,
    78, 111, 151, 180, 247, 26, 31, 198, 0, 136, 9, 40, 17, 135, 165, 169, 30, 171, 68, 4, 160, 66,
    222, 27, 102, 10, 142, 231, 48, 136, 201, 209, 199, 94, 211, 125, 51, 224, 101, 102, 40, 136,
    151, 147, 187, 95, 210, 81, 216, 117, 5, 61, 193, 226, 147, 42, 219, 185, 134, 66, 106, 53, 36,
    173, 248, 18, 37, 48, 63, 23, 252, 181, 241, 143, 165, 151, 243, 67, 162, 11, 15, 138, 198,
    109, 6, 57, 135, 137, 198, 107, 22, 5, 207, 204, 11, 245, 5, 147, 179, 151, 51, 209, 48, 25,
    85, 96, 48, 100, 41, 89, 166, 36, 199, 251, 161, 69, 171, 233, 138, 162, 112, 148, 127, 109,
    189, 213, 216, 77, 109, 73, 128, 25, 249, 187, 228, 95, 15, 195, 143, 213, 149, 189, 116, 104,
    215, 17, 183, 232, 99, 92, 151, 183, 146, 136, 249, 24, 157, 242, 193, 134, 239, 10, 198, 140,
    26, 229, 137, 89, 159, 81, 93, 157, 161, 81, 166, 184, 33, 127, 155, 34, 28, 208, 211, 198,
    117, 107, 15, 37, 79, 13, 3, 235, 224, 101, 7, 250, 141, 175, 211, 142, 96, 57, 238, 211, 169,
    36, 226, 74, 60, 132, 112, 29, 178, 241, 245, 127, 241, 232, 73, 129, 218, 237, 53, 147, 154,
    222, 254, 111, 40, 226, 117, 68, 160, 146, 233, 235, 130, 247, 46, 72, 255, 27, 133, 244, 203,
    120, 11, 237, 255, 204, 127, 146, 63, 181, 213, 163, 136, 140, 197, 56, 8, 11, 228, 68, 157,
    12, 14, 240, 17, 74, 154, 34, 38, 7, 206, 152, 126, 5, 105, 133, 249, 12, 218, 46, 164, 16, 2,
    249, 104, 13, 160, 187, 48, 168, 115, 36, 169, 76, 148, 214, 100, 178, 55, 224, 70, 252, 18,
    105, 32, 60, 95, 234, 87, 87, 90, 136, 32, 216, 158, 164, 212, 173, 129, 238, 69, 114, 138,
    207, 124, 24, 180, 40, 253, 125, 198, 87, 31, 18, 25, 109, 54, 65, 164, 142, 254, 40, 101, 10,
    54, 205, 2, 100, 248, 17, 57, 239, 80, 181, 122, 73, 179, 186, 168, 33, 176, 11, 181, 12, 238,
    152, 90, 152, 45, 57, 59, 120, 206, 87, 72, 253, 218, 160, 125, 128, 50, 85, 49, 190, 222, 152,
    60, 120, 95, 209, 12, 165, 111, 235, 90, 122, 166, 213, 215, 0, 46, 54, 175, 246, 128, 46, 254,
    85, 113, 45, 235, 120, 145, 164, 180, 195, 188, 171, 149, 64, 129, 50, 56, 140, 166, 49, 52,
    55, 97, 145, 238, 247, 12, 196, 136, 168, 133, 199, 102, 183, 105, 63, 162, 10, 8, 182, 168,
    42, 106, 65, 203, 73, 89, 87, 228, 167, 79, 153, 82, 75, 201, 37, 158, 172, 148, 9, 51, 216,
    130, 116, 3, 247, 26, 96, 122, 193, 123, 179, 117, 56, 84, 67, 175, 51, 227, 71, 86, 67, 217,
    253, 237, 63, 61, 9, 2, 131, 37, 73, 80, 228, 238, 62, 198, 206, 18, 150, 52, 34, 83, 201, 48,
    164, 95, 95, 15, 107, 83, 176, 236, 96, 100, 82, 14, 124, 212, 40, 82, 113, 135, 51, 192, 220,
    167, 126, 194, 229, 167, 53, 3, 170, 109, 216, 221, 240, 146, 241, 43, 204, 185, 64, 110, 211,
    86, 118, 70, 209, 97, 23, 185, 73, 5, 187, 123, 228, 169, 154, 95, 230, 223, 90, 156, 136, 220,
    192, 151, 208, 35, 21, 64, 45, 224, 15, 22, 0, 207, 10, 122, 78, 200, 152, 243, 58, 140, 48,
    108, 7, 78, 75, 133, 106, 1, 134, 27, 203, 148, 23, 199, 71, 157, 5, 112, 66, 113, 59, 23, 37,
    166, 26, 157, 240, 128, 244, 252, 65, 181, 157, 220, 201, 165, 17, 159, 233, 16, 199, 223, 10,
    238, 46, 131, 4, 185, 170, 13, 105, 122, 153, 163, 37, 136, 155, 247, 142, 23, 7, 53, 94, 222,
    55, 167, 81, 52, 7, 139, 88, 31, 57, 182, 216, 11, 254, 42, 28, 146, 99, 183, 225, 43, 40, 171,
    57, 149, 118, 106, 87, 195, 13, 175, 142, 57, 23, 47, 35, 89, 153, 129, 114, 246, 172, 148,
    152, 99, 87, 128, 93, 164, 66, 5, 60, 60, 176, 29, 32, 242, 178, 69, 197, 71, 151, 146, 8, 7,
    115, 105, 55,
];

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// The writer path must reproduce Go's exact ciphertext bytes.
#[test]
fn encrypt_writer_matches_go() {
    for (length, want) in GO_HASHES {
        let mut buf = Vec::new();
        let mut w = new_encrypt_writer(&key(), &mut buf);
        w.write(&plaintext(*length)).expect("write error");
        w.close().expect("close error");
        assert_eq!(sha256_hex(&buf), *want, "writer path, length {length}");
    }
}

/// The reader path must reproduce Go's exact ciphertext bytes.
#[test]
fn encrypt_reader_matches_go() {
    for (length, want) in GO_HASHES {
        let src = plaintext(*length);
        let mut er = new_encrypt_reader(&key(), src.as_slice());
        let mut got = Vec::new();
        let mut buf = vec![0u8; 8192];
        loop {
            match er.read(&mut buf) {
                Err(EncryptReadError::Eof) => break,
                Err(e) => panic!("encrypt reader error at length {length}: {e:?}"),
                Ok(0) => panic!("unexpected Ok(0) before EOF"),
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
        assert_eq!(sha256_hex(&got), *want, "reader path, length {length}");
    }
}

/// The port must decrypt a Go-produced ciphertext exactly, and re-encrypting
/// the plaintext must reproduce the Go ciphertext byte-for-byte.
#[test]
fn decrypts_go_ciphertext_and_round_trips() {
    let ct: &[u8] = &GO_CIPHERTEXT_1000;

    let mut r = new_decrypt_reader(&key(), ct);
    let mut got = Vec::new();
    let mut buf = vec![0u8; 4096];
    loop {
        match r.read(&mut buf) {
            Err(DecryptReadError::Eof) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) => panic!("decrypt of Go ciphertext failed: {e:?}"),
        }
    }
    assert_eq!(got, plaintext(1000), "decrypted plaintext mismatch");
    assert_eq!(
        r.read(&mut buf),
        Err(DecryptReadError::Eof),
        "EOF not sticky"
    );

    let mut buf2 = Vec::new();
    let mut w = new_encrypt_writer(&key(), &mut buf2);
    w.write(&got).expect("write error");
    w.close().expect("close error");
    assert_eq!(buf2, ct, "re-encryption does not match the Go ciphertext");
}
