//! Faithful Rust port of the Go age v1.3.2 wire-format core.
//!
//! This crate mirrors the Go code's responsibilities with the Go source at
//! v1.3.2 as the normative reference for every byte and every error class:
//! the header/stanza wire format and header MAC (`internal/format`), the
//! ChaCha20-Poly1305 STREAM payload framing (`internal/stream`), bech32
//! (`internal/bech32`), and the root package's format glue (`age.go`,
//! `primitives.go`). Where the Go code is stricter than the public
//! `age-encryption.org/v1` spec, the Go code wins — the difference is
//! recorded in comments, never "fixed".
//!
//! # Porting map
//!
//! | Go (v1.3.2)                     | Rust (this crate)                    |
//! | ------------------------------- | ------------------------------------ |
//! | `age.go` glue                   | crate root (this file)               |
//! | `internal/format`               | [`format`]                           |
//! | `internal/stream`               | [`stream`]                           |
//! | `internal/bech32`               | [`bech32`]                           |
//! | `strconv.Quote` in error text   | `quote` (private)                    |
#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]

mod quote;

pub mod bech32;
pub mod format;
pub mod stream;

// --- Root-package glue (Go: age.go) -------------------------------------

/// Go: `fileKeySize` — `fileKey` is `[16]byte` (sized by the format spec;
/// the port asserts the size against the vectors).
pub const FILE_KEY_LEN: usize = 16;

/// Go: `streamNonceSize`.
pub const STREAM_NONCE_SIZE: usize = 16;

pub use format::Stanza;

/// Go: `fileKey []byte` — an opaque 16-byte file key.
///
/// Debug output is redacted: key material never lands in logs or panic
/// messages.
#[derive(Clone, PartialEq, Eq)]
pub struct FileKey([u8; FILE_KEY_LEN]);

impl FileKey {
    /// Port of `generateFileKey`'s output type.
    #[must_use]
    pub fn new(bytes: [u8; FILE_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Go passes file keys around as `[]byte`; returns None on any other
    /// length (Go's slice indexing would panic; the port reports it).
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(Self)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for FileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FileKey(***)")
    }
}

/// Go: `WrapError` (from `unwrap.go`) — wrapping a file key to a recipient
/// failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WrapError {
    /// Go: `errIncorrectRecipients` — "failed to wrap key to recipient".
    IncorrectRecipients,
    /// Implementation-specific failure (Go's recipient Wrap returns any
    /// error; the port carries its message).
    Other(String),
}

impl std::fmt::Display for WrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IncorrectRecipients => f.write_str("failed to wrap key to recipient"),
            Self::Other(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for WrapError {}

/// Go: `UnwrapError` (from `unwrap.go`) — unwrapping the file key failed.
///
/// In Go this is a plain error whose message is
/// "no identity matched any of the recipients"; the `IncorrectIdentity`
/// variant exists so the decrypt path can distinguish "not for me" from
/// other failures, mirroring Go's `errors.Is` checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnwrapError {
    /// Go: `ErrIncorrectIdentity` — "no identity matched any of the
    /// recipients".
    IncorrectIdentity,
    /// Any other failure (Go's Unwrap returns any error; the port carries
    /// its message).
    Other(String),
}

impl std::fmt::Display for UnwrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IncorrectIdentity => f.write_str("no identity matched any of the recipients"),
            Self::Other(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for UnwrapError {}

/// Go: `Recipient` interface (`age.go:82`) — wraps a file key into recipient
/// stanzas.
///
/// The port keeps Go's shape so each Go recipient translates in isolation
/// and the format core stays generic over recipient types.
pub trait Recipient {
    /// Go: `Wrap`.
    ///
    /// # Errors
    ///
    /// Errors with [`WrapError::IncorrectRecipients`] when the recipient
    /// cannot wrap the key, or [`WrapError::Other`] for implementation
    /// failures.
    fn wrap(&self, file_key: &FileKey) -> Result<Vec<Stanza>, WrapError>;
}

/// Go: `Identity` interface (`age.go:65`) — unwraps the file key from the
/// header's recipient stanzas, or reports that this identity does not match.
pub trait Identity {
    /// Go: `Unwrap`. Any [`UnwrapError::Other`] result makes the decrypt
    /// operation fail; [`UnwrapError::IncorrectIdentity`] means "not for
    /// me" and other identities are tried.
    ///
    /// # Errors
    ///
    /// Errors per the variant semantics above.
    fn unwrap_stanzas(&self, stanzas: &[Stanza]) -> Result<FileKey, UnwrapError>;
}

/// Go: `RecipientWithLabels` (`recipient_with_labels.go`). Implementations
/// must also implement [`Recipient`]; the encrypt path dispatches on the
/// interface dynamically (Go: type assertion).
pub trait RecipientWithLabels: Recipient {
    /// Go: `WrapWithLabels`.
    ///
    /// # Errors
    ///
    /// Same conditions as [`Recipient::wrap`]; labels are advisory
    /// metadata for the encrypt path.
    fn wrap_with_labels(&self, file_key: &FileKey)
    -> Result<(Vec<Stanza>, Vec<String>), WrapError>;
}

// --- Root-package glue (Go: primitives.go) ------------------------------

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// Go: `headerMAC` — HKDF-SHA256(fileKey, salt=nil, info="header") derives
/// an HMAC-SHA256 key, which authenticates the header without the MAC line.
///
/// # Errors
///
/// Errors when marshalling the header fails (field validation), which is
/// impossible for a parsed or correctly built header.
///
/// # Panics
///
/// Never: the HKDF output length and HMAC key length are statically valid.
pub fn header_mac(file_key: &FileKey, hdr: &format::Header) -> Result<[u8; 32], format::Error> {
    let hk = Hkdf::<Sha256>::new(None, file_key.as_bytes());
    let mut hmac_key = [0u8; 32];
    hk.expand(b"header", &mut hmac_key)
        .expect("32-byte output is a valid HKDF-SHA256 length");
    let mut hh = Hmac::<Sha256>::new_from_slice(&hmac_key).expect("HMAC accepts any key length");
    hh.update(&hdr.marshal_without_mac()?);
    Ok(hh.finalize().into_bytes().into())
}

/// Go: `streamKey` — HKDF-SHA256(fileKey, salt=nonce, info="payload").
///
/// # Panics
///
/// Never: the HKDF output length is statically valid.
#[must_use]
pub fn stream_key(file_key: &FileKey, nonce: &[u8; STREAM_NONCE_SIZE]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(nonce), file_key.as_bytes());
    let mut out = [0u8; 32];
    hk.expand(b"payload", &mut out)
        .expect("32-byte output is a valid HKDF-SHA256 length");
    out
}

/// Error from [`aead_decrypt`] — the Go path surfaces two cases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AeadDecryptError {
    /// Go: `errIncorrectCiphertextSize`.
    IncorrectCiphertextSize,
    /// Go: the `cipher.Open` authentication failure.
    AuthFailed,
}

impl std::fmt::Display for AeadDecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IncorrectCiphertextSize => f.write_str("incorrect ciphertext size"),
            Self::AuthFailed => f.write_str("chacha20poly1305: message authentication failed"),
        }
    }
}

impl std::error::Error for AeadDecryptError {}

/// Go: `aeadEncrypt` — encrypts with a one-time key under the all-zero
/// nonce (the key schedule guarantees single use per derived key).
///
/// # Panics
///
/// Never for a 32-byte key: ChaCha20-Poly1305 encryption cannot fail.
#[must_use]
pub fn aead_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
    let aead =
        ChaCha20Poly1305::new_from_slice(key).expect("32-byte key is valid for ChaCha20-Poly1305");
    aead.encrypt(&Nonce::default(), plaintext)
        .expect("ChaCha20-Poly1305 encryption cannot fail")
}

/// Go: `aeadDecrypt`.
///
/// # Errors
///
/// [`AeadDecryptError::IncorrectCiphertextSize`] when the ciphertext is not
/// `size` plus the 16-byte Poly1305 tag; [`AeadDecryptError::AuthFailed`]
/// when tag verification fails.
///
/// # Panics
///
/// Never for a 32-byte key.
pub fn aead_decrypt(
    key: &[u8; 32],
    size: usize,
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeadDecryptError> {
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
    let aead =
        ChaCha20Poly1305::new_from_slice(key).expect("32-byte key is valid for ChaCha20-Poly1305");
    if ciphertext.len() != size + 16 {
        // chacha20poly1305::Overhead.
        return Err(AeadDecryptError::IncorrectCiphertextSize);
    }
    aead.decrypt(&Nonce::default(), ciphertext)
        .map_err(|_| AeadDecryptError::AuthFailed)
}

/// Constant-time MAC comparison (Go: `mac_equal`, from `hmac.Equal`).
#[must_use]
pub fn mac_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}
