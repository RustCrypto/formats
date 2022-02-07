//! Support for OpenSSH-formatted public keys.
//!
//! These keys have the form:
//!
//! ```text
//! <algorithm id> <base64 data> <comment>
//! ```
//!
//! ## Example
//!
//! ```text
//! ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti user@example.com
//! ```

use crate::{base64, Error, Result};
use core::str;

/// OpenSSH public key encapsulation parser.
pub(crate) struct Encapsulation<'a> {
    /// Algorithm identifier
    pub(super) algorithm_id: &'a str,

    /// Base64-encoded key data
    pub(super) base64_data: &'a [u8],

    /// Comment
    #[cfg_attr(not(feature = "alloc"), allow(dead_code))]
    pub(super) comment: &'a str,
}

impl<'a> Encapsulation<'a> {
    /// Parse the given binary data.
    pub(super) fn decode(mut bytes: &'a [u8]) -> Result<Self> {
        let algorithm_id = decode_segment_str(&mut bytes)?;
        let base64_data = decode_segment(&mut bytes)?;
        let comment = str::from_utf8(bytes)
            .map_err(|_| Error::CharacterEncoding)?
            .trim_end();

        if algorithm_id.is_empty() || base64_data.is_empty() || comment.is_empty() {
            // TODO(tarcieri): better errors for these cases?
            return Err(Error::Length);
        }

        Ok(Self {
            algorithm_id,
            base64_data,
            comment,
        })
    }

    /// Encode data with OpenSSH public key encapsulation.
    pub(super) fn encode<'o, F>(
        out: &'o mut [u8],
        algorithm_id: &str,
        comment: &str,
        f: F,
    ) -> Result<&'o str>
    where
        F: FnOnce(&mut base64::Encoder<'_>) -> Result<()>,
    {
        let mut offset = 0;
        encode_str(out, &mut offset, algorithm_id)?;
        encode_str(out, &mut offset, " ")?;

        let mut encoder = base64::Encoder::new(&mut out[offset..])?;
        f(&mut encoder)?;
        let base64_len = encoder.finish()?.len();

        offset += base64_len;
        encode_str(out, &mut offset, " ")?;
        encode_str(out, &mut offset, comment)?;
        Ok(str::from_utf8(&out[..offset])?)
    }
}

/// Parse a segment of the public key.
fn decode_segment<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8]> {
    let start = *bytes;
    let mut len = 0;

    loop {
        match *bytes {
            [b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'-' | b'/' | b'=', rest @ ..] => {
                // Valid character; continue
                *bytes = rest;
                len += 1;
            }
            [b' ', rest @ ..] => {
                // Encountered space; we're done
                *bytes = rest;
                return start.get(..len).ok_or(Error::Length);
            }
            [_, ..] => {
                // Invalid character
                // TODO(tarcieri): better error?
                return Err(Error::CharacterEncoding);
            }
            [] => {
                // Truncated public key
                return Err(Error::Length);
            }
        }
    }
}

/// Parse a segment of the public key as a `&str`.
fn decode_segment_str<'a>(bytes: &mut &'a [u8]) -> Result<&'a str> {
    str::from_utf8(decode_segment(bytes)?).map_err(|_| Error::CharacterEncoding)
}

/// Encode a segment of the public key.
fn encode_str(out: &mut [u8], offset: &mut usize, s: &str) -> Result<()> {
    let bytes = s.as_bytes();

    if *offset + bytes.len() > out.len() {
        return Err(Error::Length);
    }

    out[*offset..][..bytes.len()].copy_from_slice(bytes);
    *offset += bytes.len();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Encapsulation;

    const EXAMPLE_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti user@example.com";

    #[test]
    fn decode() {
        let encapsulation = Encapsulation::decode(EXAMPLE_KEY.as_bytes()).unwrap();
        assert_eq!(encapsulation.algorithm_id, "ssh-ed25519");
        assert_eq!(
            encapsulation.base64_data,
            b"AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti"
        );
        assert_eq!(encapsulation.comment, "user@example.com");
    }
}
