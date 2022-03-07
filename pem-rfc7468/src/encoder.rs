//! PEM encoder.

use crate::{
    grammar, Base64Encoder, Error, LineEnding, Result, BASE64_WRAP_WIDTH,
    ENCAPSULATION_BOUNDARY_DELIMITER, POST_ENCAPSULATION_BOUNDARY, PRE_ENCAPSULATION_BOUNDARY,
};
use base64ct::{Base64, Encoding};

#[cfg(feature = "alloc")]
use alloc::string::String;

#[cfg(feature = "std")]
use std::io;

/// Encode a PEM document according to RFC 7468's "Strict" grammar.
pub fn encode<'o>(
    type_label: &str,
    line_ending: LineEnding,
    input: &[u8],
    buf: &'o mut [u8],
) -> Result<&'o [u8]> {
    let mut encoder = Encoder::new(type_label, line_ending, buf)?;
    encoder.encode(input)?;
    let encoded_len = encoder.finish()?;
    Ok(&buf[..encoded_len])
}

/// Get the length of a PEM encoded document with the given bytes and label.
pub fn encoded_len(label: &str, line_ending: LineEnding, input: &[u8]) -> usize {
    // TODO(tarcieri): use checked arithmetic
    let base64_len = input
        .chunks((BASE64_WRAP_WIDTH * 3) / 4)
        .fold(0, |acc, chunk| {
            acc + Base64::encoded_len(chunk) + line_ending.len()
        });

    encoded_len_inner(label, line_ending, base64_len)
}

/// Encode a PEM document according to RFC 7468's "Strict" grammar, returning
/// the result as a [`String`].
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub fn encode_string(label: &str, line_ending: LineEnding, input: &[u8]) -> Result<String> {
    let mut buf = vec![0u8; encoded_len(label, line_ending, input)];
    encode(label, line_ending, input, &mut buf)?;
    String::from_utf8(buf).map_err(|_| Error::CharacterEncoding)
}

/// Buffered PEM encoder.
///
/// Stateful buffered encoder type which encodes an input PEM document according
/// to RFC 7468's "Strict" grammar.
pub struct Encoder<'l, 'o> {
    /// PEM type label.
    type_label: &'l str,

    /// Line ending used to wrap Base64.
    line_ending: LineEnding,

    /// Buffered Base64 encoder.
    base64: Base64Encoder<'o>,
}

impl<'l, 'o> Encoder<'l, 'o> {
    /// Create a new PEM [`Encoder`] with the default options which
    /// writes output into the provided buffer.
    ///
    /// Uses the default 64-character line wrapping.
    pub fn new(type_label: &'l str, line_ending: LineEnding, out: &'o mut [u8]) -> Result<Self> {
        Self::new_wrapped(type_label, BASE64_WRAP_WIDTH, line_ending, out)
    }

    /// Create a new PEM [`Encoder`] which wraps at the given line width.
    pub fn new_wrapped(
        type_label: &'l str,
        line_width: usize,
        line_ending: LineEnding,
        mut out: &'o mut [u8],
    ) -> Result<Self> {
        grammar::validate_label(type_label.as_bytes())?;

        for boundary_part in [
            PRE_ENCAPSULATION_BOUNDARY,
            type_label.as_bytes(),
            ENCAPSULATION_BOUNDARY_DELIMITER,
            line_ending.as_bytes(),
        ] {
            if out.len() < boundary_part.len() {
                return Err(Error::Length);
            }

            let (part, rest) = out.split_at_mut(boundary_part.len());
            out = rest;

            part.copy_from_slice(boundary_part);
        }

        let base64 = Base64Encoder::new_wrapped(out, line_width, line_ending)?;

        Ok(Self {
            type_label,
            line_ending,
            base64,
        })
    }

    /// Get the PEM type label used for this document.
    pub fn type_label(&self) -> &'l str {
        self.type_label
    }

    /// Encode the provided input data.
    ///
    /// This method can be called as many times as needed with any sized input
    /// to write data encoded data into the output buffer, so long as there is
    /// sufficient space in the buffer to handle the resulting Base64 encoded
    /// data.
    pub fn encode(&mut self, input: &[u8]) -> Result<()> {
        self.base64.encode(input)?;
        Ok(())
    }

    /// Borrow the inner [`Base64Encoder`].
    pub fn base64_encoder(&mut self) -> &mut Base64Encoder<'o> {
        &mut self.base64
    }

    /// Finish encoding PEM, writing the post-encapsulation boundary.
    ///
    /// On success, returns the total number of bytes written to the output
    /// buffer.
    pub fn finish(self) -> Result<usize> {
        let (base64, mut out) = self.base64.finish_with_remaining()?;

        for boundary_part in [
            self.line_ending.as_bytes(),
            POST_ENCAPSULATION_BOUNDARY,
            self.type_label.as_bytes(),
            ENCAPSULATION_BOUNDARY_DELIMITER,
            self.line_ending.as_bytes(),
        ] {
            if out.len() < boundary_part.len() {
                return Err(Error::Length);
            }

            let (part, rest) = out.split_at_mut(boundary_part.len());
            out = rest;

            part.copy_from_slice(boundary_part);
        }

        Ok(encoded_len_inner(
            self.type_label,
            self.line_ending,
            base64.len() + self.line_ending.len(),
        ))
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<'l, 'o> io::Write for Encoder<'l, 'o> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.encode(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // TODO(tarcieri): return an error if there's still data remaining in the buffer?
        Ok(())
    }
}

/// Compute the length of a PEM encoded document with a Base64-encoded body of
/// the given length.
fn encoded_len_inner(label: &str, line_ending: LineEnding, base64_len: usize) -> usize {
    // TODO(tarcieri): use checked arithmetic
    PRE_ENCAPSULATION_BOUNDARY.len()
        + label.as_bytes().len()
        + ENCAPSULATION_BOUNDARY_DELIMITER.len()
        + line_ending.len()
        + base64_len
        + POST_ENCAPSULATION_BOUNDARY.len()
        + label.as_bytes().len()
        + ENCAPSULATION_BOUNDARY_DELIMITER.len()
        + line_ending.len()
}
