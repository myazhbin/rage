//! Port of Go v1.3.2 `internal/bech32/bech32_test.go`.

use super::{decode, encode};

/// The long vector Go accepts despite the spec (age issue 453), transcribed
/// verbatim from the Go v1.3.2 test table.
const LONG_VECTOR: &str = "long10pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7qfcsvr0";

/// Go: `TestBech32` — the valid/invalid vector table. Valid vectors must
/// round-trip through decode/encode to the exact original string (including
/// the uppercase `A12UEL5L`), and flipping one bit after the last `1` must
/// always fail decoding. The long accepted vectors are age issue 453.
#[test]
fn test_bech32() {
    let valid: Vec<String> = vec![
        "A12UEL5L".to_string(), // empty data part
        "a12uel5l".to_string(),
        "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs"
            .to_string(),
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw".to_string(),
        "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j"
            .to_string(),
        "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w".to_string(),
        // long vector we accept despite the spec, see Issue 453
        LONG_VECTOR.to_string(),
        "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx"
            .to_string(),
    ];
    let invalid: [&str; 14] = [
        // invalid checksum
        "split1checkupstagehandshakeupstreamerranterredcaperred2y9e2w",
        // invalid character (space) in hrp
        "s lit1checkupstagehandshakeupstreamerranterredcaperredp8hs2p",
        // invalid character (o) in data part
        "split1cheo2y9e2w",
        // too short data part
        "split1a2y9w",
        // empty hrp
        "1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        // invalid character (DEL) in hrp
        "spl\u{7F}t1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        // BIP 173 invalid vectors.
        "pzry9x0s0muk",
        "1pzry9x0s0muk",
        "x1b4n0q5v",
        "li1dgmt3",
        "de1lg7wt\u{00FF}",
        "A1G7SGD8",
        "10a06t8",
        "1qzzfhee",
    ];

    for s in &valid {
        let (hrp, decoded) =
            decode(s).unwrap_or_else(|e| panic!("decoded {s:?}: unexpected error: {e}"));

        // Check that it encodes to the same string.
        let encoded = encode(&hrp, &decoded).unwrap_or_else(|e| panic!("encoding failed: {e}"));
        assert_eq!(
            encoded, *s,
            "expected data to encode to {s:?}, but got {encoded:?}"
        );

        // Flip a bit in the string and make sure it is caught.
        let pos = s.rfind('1').expect("valid vector contains a separator");
        let mut flipped = s.as_bytes().to_vec();
        flipped[pos + 1] ^= 1;
        let flipped = std::str::from_utf8(&flipped).expect("flipped vector is valid UTF-8");
        assert!(
            decode(flipped).is_err(),
            "expected decoding to fail for {flipped:?}"
        );
    }

    for s in &invalid {
        assert!(
            decode(s).is_err(),
            "expected decoding to fail for invalid string {s:?}"
        );
    }
}

/// Go: `TestDecodeShortDataPart` — data parts shorter than the 6-checksum
/// values must error (not panic) even when multi-byte runes such as the
/// Kelvin sign shift the byte offsets.
#[test]
fn test_decode_short_data_part() {
    let kelvin = '\u{212A}'.to_string();
    for s in [
        format!("AA3100AC{kelvin}"),
        format!("BK1{kelvin}0JFM"),
        "AQM1KZCML".to_string(),
    ] {
        assert!(decode(&s).is_err(), "Decode({s:?}) = Ok, want error");
    }
}
