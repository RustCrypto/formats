//! Support for OpenSSH-formatted private keys.
//!
//! These keys are PEM-encoded and begin with the following:
//!
//! ```text
//! -----BEGIN OPENSSH PRIVATE KEY-----
//! ```

use crate::{Error, Result};

/// Carriage return
pub(crate) const CHAR_CR: u8 = 0x0d;

/// Line feed
pub(crate) const CHAR_LF: u8 = 0x0a;

/// Pre-encapsulation boundary.
const PRE_ENCAPSULATION_BOUNDARY: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----";

/// Post-encapsulation boundary.
const POST_ENCAPSULATION_BOUNDARY: &[u8] = b"-----END OPENSSH PRIVATE KEY-----";

/// OpenSSH private key encapsulation parser.
pub(super) struct Encapsulation<'a> {
    /// Base64-encoded key data
    pub(super) base64_data: &'a [u8],
}

impl<'a> Encapsulation<'a> {
    /// Width at which the Base64 is line wrapped.
    pub(super) const LINE_WIDTH: usize = 70;

    /// Parse the given PEM-encapsulated data.
    pub(super) fn decode(input: &'a [u8]) -> Result<Self> {
        // Parse pre-encapsulation boundary (including label)
        let input = strip_leading_eol(input)
            .unwrap_or(input)
            .strip_prefix(PRE_ENCAPSULATION_BOUNDARY)
            .ok_or(Error::Pem)
            .and_then(strip_leading_eol)?;

        // Parse post-encapsulation boundary and optional trailing newline
        let base64_data = strip_trailing_eol(input)
            .strip_suffix(POST_ENCAPSULATION_BOUNDARY)
            .ok_or(Error::Pem)?;

        Ok(Self { base64_data })
    }
}

/// Strip a newline (`eol`) from the beginning of the provided byte slice.
///
/// The newline is considered mandatory and a decoding error will occur if it
/// is not present.
pub(crate) fn strip_leading_eol(bytes: &[u8]) -> Result<&[u8]> {
    match bytes {
        [CHAR_LF, rest @ ..] => Ok(rest),
        [CHAR_CR, CHAR_LF, rest @ ..] => Ok(rest),
        [CHAR_CR, rest @ ..] => Ok(rest),
        _ => Err(Error::Pem),
    }
}

/// Strip a newline (`eol`) from the end of the provided byte slice if present.
///
/// Returns the original slice if there is no newline.
pub(crate) fn strip_trailing_eol(bytes: &[u8]) -> &[u8] {
    match bytes {
        [head @ .., CHAR_CR, CHAR_LF] => head,
        [head @ .., CHAR_LF] => head,
        [head @ .., CHAR_CR] => head,
        _ => bytes,
    }
}
