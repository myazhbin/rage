//! Port of Go v1.3.2 internal/format/format_test.go (minus FuzzMalleability,
//! which lives in fuzz_seeds.rs with the CCTV-derived seeds).

use age_format::format;

#[test]
fn test_stanza_marshal() {
    let mut s = format::Stanza {
        r#type: "test".to_string(),
        args: vec!["1".to_string(), "2".to_string(), "3".to_string()],
        body: Vec::new(),
    };
    assert_eq!(s.marshal().expect("valid stanza"), b"-> test 1 2 3\n\n");

    s.body = b"AAA".to_vec();
    assert_eq!(s.marshal().expect("valid stanza"), b"-> test 1 2 3\nQUFB\n");

    // Exactly one line of body columns (Go: format.BytesPerLine bytes).
    s.body = vec![b'A'; format::BYTES_PER_LINE];
    assert_eq!(
        s.marshal().expect("valid stanza"),
        format!("-> test 1 2 3\n{}\n\n", "QUFB".repeat(16)).into_bytes()
    );

    for (t, args) in [
        ("", Vec::new()),
        ("test", vec![String::new()]),
        ("test", vec!["a b".to_string()]),
        ("test", vec!["a\nb".to_string()]),
        ("test", vec!["café".to_string()]),
    ] {
        let s = format::Stanza {
            r#type: t.to_string(),
            args,
            body: Vec::new(),
        };
        let mut buf = Vec::new();
        assert!(
            s.marshal_into(&mut buf).is_err(),
            "Marshal accepted type {t:?}, args {:?}",
            s.args
        );
        assert!(buf.is_empty(), "Marshal wrote {} bytes", buf.len());
    }
}

#[test]
fn test_header_marshal_no_stanzas() {
    let h = format::Header {
        recipients: Vec::new(),
        mac: Vec::new(),
    };
    let mut buf = Vec::new();
    assert!(
        h.marshal_into(&mut buf).is_err(),
        "Marshal accepted no stanzas"
    );
    assert!(buf.is_empty(), "Marshal wrote {} bytes", buf.len());
}

#[test]
fn test_parse_limits() {
    const INTRO: &str = "age-encryption.org/v1\n";
    const MAX_HEADER_BYTES: usize = 2 << 20;
    let footer = format!("--- {}\n", format::encode_string(&[0u8; 32]));

    // Header size limit: a max-size header is accepted, one byte over is a
    // single-prefixed ParseError mentioning the 2 MiB bound.
    {
        const OPENING: &str = "-> test ";
        let make_header = |size: usize| {
            let fixed = INTRO.len() + OPENING.len() + "\n\n".len() + footer.len();
            format!("{INTRO}{OPENING}{}\n\n{footer}", "a".repeat(size - fixed))
        };
        let max = make_header(MAX_HEADER_BYTES);
        assert_eq!(
            max.len(),
            MAX_HEADER_BYTES,
            "makeHeader must span exactly the limit"
        );
        assert!(
            format::parse(max.as_bytes()).is_ok(),
            "maximum-size header was rejected"
        );

        let over = make_header(MAX_HEADER_BYTES + 1);
        match format::parse(over.as_bytes()) {
            Err(e) => {
                assert!(
                    e.message().contains("header exceeds 2 MiB"),
                    "unexpected oversized-header error: {e}"
                );
                assert!(
                    e.is_parse_error(),
                    "oversized-header error is not a ParseError"
                );
                assert_eq!(
                    e.message().matches("parsing age header").count(),
                    1,
                    "oversized-header error nests ParseError prefixes: {e}"
                );
            }
            Ok(_) => panic!("expected an oversized-header error"),
        }

        // A first line longer than the limit without a newline.
        let big_intro = vec![b'a'; MAX_HEADER_BYTES + 1];
        match format::parse(&big_intro) {
            Err(e) => {
                assert!(
                    e.message().contains("header exceeds 2 MiB"),
                    "unexpected oversized-intro error: {e}"
                );
                assert_eq!(
                    e.message().matches("parsing age header").count(),
                    1,
                    "oversized-intro error nests ParseError prefixes: {e}"
                );
            }
            Ok(_) => panic!("expected an oversized-intro error"),
        }
    }

    // Recipient stanza count limit.
    {
        let make_header =
            |stanzas: usize| format!("{INTRO}{}{footer}", "-> test\n\n".repeat(stanzas));
        match format::parse(make_header(0).as_bytes()) {
            Err(e) => assert!(
                e.message().contains("no recipient stanzas"),
                "unexpected zero-stanza error: {e}"
            ),
            Ok(_) => panic!("expected a zero-stanza error"),
        }
        assert!(
            format::parse(make_header(1024).as_bytes()).is_ok(),
            "1024-stanza header was rejected"
        );
        match format::parse(make_header(1025).as_bytes()) {
            Err(e) => assert!(
                e.message().contains("more than 1024 recipient stanzas"),
                "unexpected stanza-count error: {e}"
            ),
            Ok(_) => panic!("expected a stanza-count error"),
        }
    }

    // Recipient stanza argument count limit.
    {
        let make_header = |args: usize| format!("{INTRO}-> test{}\n\n{footer}", " a".repeat(args));
        assert!(
            format::parse(make_header(128).as_bytes()).is_ok(),
            "128-argument stanza was rejected"
        );
        assert!(
            format::parse(make_header(129).as_bytes()).is_err(),
            "129-argument stanza was accepted"
        );
    }

    // The payload size is not limited.
    {
        let header = format!("{INTRO}-> test\n\n{footer}");
        let want = vec![b'p'; MAX_HEADER_BYTES + 1];
        let mut input = header.into_bytes();
        input.extend_from_slice(&want);
        let pf = format::parse(&input).expect("payload is not limited");
        assert_eq!(pf.payload, &want[..]);
    }

    // Go asserts its bufio.Reader is rewound to the payload start; over an
    // in-memory input the payload IS the input remainder (see ParsedFile).
    {
        let header = format!("{INTRO}-> test\n\n{footer}");
        let mut input = header.into_bytes();
        input.extend_from_slice(b"payload");
        let pf = format::parse(&input).expect("small payload parses");
        assert_eq!(pf.payload, b"payload");
    }
}

#[test]
fn test_parse_intro_error_is_not_secret() {
    const SECRET: &str =
        "AGE-SECRET-KEY-1NOTAREALKEYNOTAREALKEYNOTAREALKEYNOTAREALKEYNOTAREALKEYNOTA";
    const PLUGIN_SECRET: &str =
        "AGE-PLUGIN-PQ-1NOTAREALKEYNOTAREALKEYNOTAREALKEYNOTAREALKEYNOTAREALKEYNOTA";
    for (name, input, secret) in [
        ("identity", format!("{SECRET}\n"), true),
        ("identity, no newline", SECRET.to_string(), true),
        ("plugin identity", format!("{PLUGIN_SECRET}\n"), true),
        (
            "plugin identity, no newline",
            PLUGIN_SECRET.to_string(),
            true,
        ),
        (
            "truncated intro",
            "age-encryption.org/v1".to_string(),
            false,
        ),
        ("binary", "\x00\x01\x02".to_string(), false),
    ] {
        match format::parse(input.as_bytes()) {
            Ok(_) => panic!("{name}: expected an error"),
            Err(e) => {
                assert!(
                    !e.message().contains("file is empty"),
                    "{name}: error says the file is empty, but it is {} bytes: {e}",
                    input.len()
                );
                if secret {
                    let key = input.trim_end_matches('\n');
                    for i in 0..=key.len() - 17 {
                        assert!(
                            !e.message().contains(&key[i..i + 17]),
                            "{name}: error includes a private-key run: {e}"
                        );
                    }
                }
            }
        }
    }

    match format::parse(b"") {
        Err(e) => assert!(
            e.message().contains("file is empty"),
            "expected an empty file error, got: {e}"
        ),
        Ok(_) => panic!("empty: expected an error"),
    }
}

#[test]
fn test_parse_intro_error_shows_mangling() {
    for (name, input, want) in [
        ("crlf", "age-encryption.org/v1\r\n", "\\r"),
        ("utf8 bom", "\u{feff}age-encryption.org/v1\n", "\\ufeff"),
        (
            "utf16be",
            "\x00a\x00g\x00e\x00-\x00e\x00n\x00c\x00r\x00y\x00p\x00",
            "\\x00a\\x00g\\x00e",
        ),
        ("trailing space", "age-encryption.org/v1 \n", "v1 "),
        ("wrong version", "age-encryption.org/v2\n", "v2"),
        ("leading blank line", "\nage-encryption.org/v1\n", "\"\\n\""),
    ] {
        match format::parse(input.as_bytes()) {
            Ok(_) => panic!("{name}: expected an error"),
            Err(e) => assert!(
                e.message().contains(want),
                "{name}: error does not show the mangling: got {e}, want it to contain {want:?}"
            ),
        }
    }
}
