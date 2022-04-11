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

use crate::{writer::Base64Writer, Error, Result};
use core::str;

/// OpenSSH public key encapsulation parser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Encapsulation<'a> {
    /// Algorithm identifier
    pub(crate) algorithm_id: &'a str,

    /// Base64-encoded key data
    pub(crate) base64_data: &'a [u8],

    /// Comment
    #[cfg_attr(not(feature = "alloc"), allow(dead_code))]
    pub(crate) comment: &'a str,
}

impl<'a> Encapsulation<'a> {
    /// Parse the given binary data.
    pub(crate) fn decode(mut bytes: &'a [u8]) -> Result<Self> {
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
    pub(crate) fn encode<'o, F>(
        out: &'o mut [u8],
        algorithm_id: &str,
        comment: &str,
        f: F,
    ) -> Result<&'o str>
    where
        F: FnOnce(&mut Base64Writer<'_>) -> Result<()>,
    {
        let mut offset = 0;
        encode_str(out, &mut offset, algorithm_id)?;
        encode_str(out, &mut offset, " ")?;

        let mut writer = Base64Writer::new(&mut out[offset..])?;
        f(&mut writer)?;
        let base64_len = writer.finish()?.len();

        offset = offset.checked_add(base64_len).ok_or(Error::Length)?;
        encode_str(out, &mut offset, " ")?;
        encode_str(out, &mut offset, comment)?;
        Ok(str::from_utf8(&out[..offset])?)
    }
}

/// Parse a segment of the public key.
fn decode_segment<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8]> {
    let start = *bytes;
    let mut len = 0usize;

    loop {
        match *bytes {
            [b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'-' | b'/' | b'=' | b'@' | b'.', rest @ ..] =>
            {
                // Valid character; continue
                *bytes = rest;
                len = len.checked_add(1).ok_or(Error::Length)?;
            }
            [b' ', rest @ ..] => {
                // Encountered space; we're done
                *bytes = rest;
                return start.get(..len).ok_or(Error::Length);
            }
            [_, ..] => {
                // Invalid character
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

    if out.len() < offset.checked_add(bytes.len()).ok_or(Error::Length)? {
        return Err(Error::Length);
    }

    out[*offset..][..bytes.len()].copy_from_slice(bytes);
    *offset = offset.checked_add(bytes.len()).ok_or(Error::Length)?;
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
