//! Port of Go's FuzzMalleability (internal/format/format_test.go): every
//! CCTV vector, stripped of its metadata header, is a seed; any input that
//! parses must re-encode to exactly the input bytes. The seeds are
//! CCTV-derived per the S1 acceptance gate; a bounded deterministic mutation
//! sweep exercises nearby inputs in-process (a placeholder for continuous
//! go-fuzz coverage until the fuzzing stage of S5 wires a corpus importer).

mod common;

use age_format::format;
use common::load_raw;

const MUTATIONS_PER_SEED: usize = 16;

#[test]
fn fuzz_malleability_seeds() {
    let vectors = load_raw();
    assert!(!vectors.is_empty(), "no test vectors");
    let mut failures: Vec<String> = Vec::new();
    let mut seeds = 0usize;
    for (name, contents) in &vectors {
        // Go: test, contents, ok := bytes.Cut(test, []byte("\n\n")).
        let Some(idx) = contents.windows(2).position(|w| w == b"\n\n") else {
            failures.push(format!("{name}: testkit file without header"));
            continue;
        };
        let seed = &contents[idx + 2..];
        seeds += 1;
        check_seed(&format!("seed:{name}"), seed, &mut failures);

        // Bounded deterministic mutation sweep.
        let mut rng = common::Rng::new(seed);
        for m in 0..MUTATIONS_PER_SEED {
            let mutated = mutate(seed, &mut rng, m);
            check_seed(&format!("mut:{name}:{m}"), &mutated, &mut failures);
        }
    }
    assert!(
        failures.is_empty(),
        "{} failure(s) over {seeds} seeds:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Go: FuzzMalleability's body — parse must either fail or re-encode to the
/// exact input bytes.
fn check_seed(label: &str, data: &[u8], failures: &mut Vec<String>) {
    match format::parse(data) {
        Ok(pf) => {
            let mut re = pf
                .header
                .marshal()
                .expect("marshalling a parsed header cannot fail");
            re.extend_from_slice(pf.payload);
            if re != data {
                failures.push(format!("{label}: Marshal output different from input"));
            }
        }
        Err(e) => {
            // Go's fuzz skips failing inputs; the error class varies by
            // failure site (ParseError vs the plain "failed to parse
            // header" wraps around ReadStanza errors), matching Go.
            let _ = e;
        }
    }
}

fn mutate(seed: &[u8], rng: &mut common::Rng, m: usize) -> Vec<u8> {
    if seed.is_empty() {
        return vec![rng.byte()];
    }
    let len = u64::try_from(seed.len()).expect("seed length fits u64");
    match m % 3 {
        // Bit flip.
        0 => {
            let pos = usize::try_from(rng.below(len)).expect("index fits usize");
            let bit = u8::try_from(rng.below(8)).expect("bit index fits u8");
            let mut out = seed.to_vec();
            out[pos] ^= 1 << bit;
            out
        }
        // Truncation.
        1 => {
            let keep = usize::try_from(rng.below(len)).expect("index fits usize") + 1;
            seed[..keep].to_vec()
        }
        // Byte substitution with format-punctuation.
        _ => {
            let pos = usize::try_from(rng.below(len)).expect("index fits usize");
            let table = *b"-\n> 01a";
            let idx = usize::try_from(rng.below(table.len() as u64)).expect("index fits usize");
            let mut out = seed.to_vec();
            out[pos] = table[idx];
            out
        }
    }
}
