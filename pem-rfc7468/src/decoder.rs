//! Decoder for PEM encapsulated data.
//!
//! From RFC 7468 Section 2:
//!
//! > Textual encoding begins with a line comprising "-----BEGIN ", a
//! > label, and "-----", and ends with a line comprising "-----END ", a
//! > label, and "-----".  Between these lines, or "encapsulation
//! > boundaries", are base64-encoded data according to Section 4 of
//! > [RFC 4648].
//!
//! [RFC 4648]: https://datatracker.ietf.org/doc/html/rfc4648

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::{
    grammar, Error, Result, BASE64_WRAP_WIDTH, POST_ENCAPSULATION_BOUNDARY,
    PRE_ENCAPSULATION_BOUNDARY,
};
use base64ct::{Base64, Encoding};
use core::{convert::TryFrom, str};

/// Decode a PEM document according to RFC 7468's "Strict" grammar.
///
/// On success, writes the decoded document into the provided buffer, returning
/// the decoded label and the portion of the provided buffer containing the
/// decoded message.
pub fn decode<'i, 'o>(pem: &'i [u8], buf: &'o mut [u8]) -> Result<(&'i str, &'o [u8])> {
    let encapsulation = Encapsulation::try_from(pem)?;
    let label = encapsulation.label();
    let mut out_len = 0;
    decode_encapsulated_text(&encapsulation, buf, &mut out_len)?;
    Ok((label, &buf[..out_len]))
}

/// Decode a PEM document according to RFC 7468's "Strict" grammar, returning
/// the result as a [`Vec`] upon success.
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub fn decode_vec(pem: &[u8]) -> Result<(&str, Vec<u8>)> {
    let encapsulation = Encapsulation::try_from(pem)?;
    let label = encapsulation.label();
    // count all chars (gives over-estimation, due to whitespace)
    let max_len = encapsulation.encapsulated_text.len() * 3 / 4;
    let mut result = vec![0u8; max_len];
    let mut actual_len = 0;

    decode_encapsulated_text(&encapsulation, &mut result, &mut actual_len)?;

    // Actual encoded length can be slightly shorter than estimated
    // TODO(tarcieri): more reliable length estimation
    result.truncate(actual_len);
    Ok((label, result))
}

/// Decode the encapsulation boundaries of a PEM document according to RFC 7468's "Strict" grammar.
///
/// On success, returning the decoded label.
pub fn decode_label(pem: &[u8]) -> Result<&str> {
    Ok(Encapsulation::try_from(pem)?.label())
}

fn decode_encapsulated_text<'i, 'o>(
    encapsulation: &Encapsulation<'i>,
    buf: &'o mut [u8],
    out_len: &mut usize,
) -> Result<()> {
    for line in encapsulation.encapsulated_text() {
        let line = line?;

        match Base64::decode(line, &mut buf[*out_len..]) {
            Err(error) => {
                // in the case that we are decoding the first line
                // and we error, then attribute the error to an unsupported header
                // if a colon char is present in the line
                if *out_len == 0 && line.iter().any(|&b| b == grammar::CHAR_COLON) {
                    return Err(Error::HeaderDisallowed);
                } else {
                    return Err(error.into());
                }
            }
            Ok(out) => *out_len += out.len(),
        }
    }
    Ok(())
}

/// PEM encapsulation parser.
///
/// This parser performs an initial pass over the data, locating the
/// pre-encapsulation (`---BEGIN [...]---`) and post-encapsulation
/// (`---END [...]`) boundaries while attempting to avoid branching
/// on the potentially secret Base64-encoded data encapsulated between
/// the two boundaries.
///
/// It only supports a single encapsulated message at present. Future work
/// could potentially include extending it provide an iterator over a series
/// of encapsulated messages.
#[derive(Copy, Clone, Debug)]
struct Encapsulation<'a> {
    /// Type label extracted from the pre/post-encapsulation boundaries.
    ///
    /// From RFC 7468 Section 2:
    ///
    /// > The type of data encoded is labeled depending on the type label in
    /// > the "-----BEGIN " line (pre-encapsulation boundary).  For example,
    /// > the line may be "-----BEGIN CERTIFICATE-----" to indicate that the
    /// > content is a PKIX certificate (see further below).  Generators MUST
    /// > put the same label on the "-----END " line (post-encapsulation
    /// > boundary) as the corresponding "-----BEGIN " line.  Labels are
    /// > formally case-sensitive, uppercase, and comprised of zero or more
    /// > characters; they do not contain consecutive spaces or hyphen-minuses,
    /// > nor do they contain spaces or hyphen-minuses at either end.  Parsers
    /// > MAY disregard the label in the post-encapsulation boundary instead of
    /// > signaling an error if there is a label mismatch: some extant
    /// > implementations require the labels to match; others do not.
    label: &'a str,

    /// Encapsulated text portion contained between the boundaries.
    ///
    /// This data should be encoded as Base64, however this type performs no
    /// validation of it so it can be handled in constant-time.
    encapsulated_text: &'a [u8],
}

impl<'a> Encapsulation<'a> {
    /// Adapted from:
    /// https://en.wikipedia.org/wiki/Boyer%E2%80%93Moore%E2%80%93Horspool_algorithm#Description
    /// https://github.com/peterjoel/needle/blob/master/src/skip_search.rs#L36-L47 (MIT LICENSE)
    const fn generate_bad_char_table() -> [usize; 256] {
        let needle = PRE_ENCAPSULATION_BOUNDARY;
        let mut table = [needle.len(); 256];
        let mut i = 0;

        while i < needle.len() - 1 {
            let c = needle[i] as usize;
            table[c] = needle.len() - i - 1;
            i += 1;
        }

        table
    }

    const PRE_ENCAPSULATION_BOUNDARY_BAD_CHARS_TABLE: [usize; 256] =
        Self::generate_bad_char_table();

    /// Adapted from:
    /// https://en.wikipedia.org/wiki/Boyer%E2%80%93Moore%E2%80%93Horspool_algorithm#Description
    /// https://github.com/peterjoel/needle/blob/f40693aff55a932eeca16e6b921ad4619a1f3b42/src/skip_search.rs#L14-L33 (MIT LICENSE)
    fn boyer_moore_horspool(haystack: &[u8]) -> Option<usize> {
        let needle = PRE_ENCAPSULATION_BOUNDARY;
        let mut position = 0;
        let max_position = haystack.len() - needle.len();
        let mut res = None;

        'outer: while position <= max_position {
            let mut needle_position = needle.len() - 1;
            while haystack[position + needle_position] == needle[needle_position] {
                if needle_position == 0 {
                    res = Some(position);
                    break 'outer;
                } else {
                    needle_position -= 1;
                }
            }
            let bad_char = haystack[position + needle.len() - 1];
            let jump = Self::PRE_ENCAPSULATION_BOUNDARY_BAD_CHARS_TABLE[bad_char as usize];
            position += jump;
        }

        res
    }

    /// Parse the type label and encapsulated text from between the
    /// pre/post-encapsulation boundaries.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        // search for position of PRE_ENCAPSULATION_BOUNDARY
        let position = Self::boyer_moore_horspool(data).ok_or(Error::PreEncapsulationBoundary)?;
        // drop everything before the expected start of the label
        let data = &data[position + PRE_ENCAPSULATION_BOUNDARY.len()..];

        let (label, body) = grammar::split_label(data).ok_or(Error::Label)?;

        let mut body = match grammar::strip_trailing_eol(body).unwrap_or(body) {
            [head @ .., b'-', b'-', b'-', b'-', b'-'] => head,
            _ => return Err(Error::PreEncapsulationBoundary),
        };

        // Ensure body ends with a properly labeled post-encapsulation boundary
        for &slice in [POST_ENCAPSULATION_BOUNDARY, label.as_bytes()].iter().rev() {
            // Ensure the input ends with the post encapsulation boundary as
            // well as a matching label
            if !body.ends_with(slice) {
                return Err(Error::PostEncapsulationBoundary);
            }

            body = body
                .get(..(body.len() - slice.len()))
                .ok_or(Error::PostEncapsulationBoundary)?;
        }

        let encapsulated_text =
            grammar::strip_trailing_eol(body).ok_or(Error::PostEncapsulationBoundary)?;

        Ok(Self {
            label,
            encapsulated_text,
        })
    }

    /// Get the label parsed from the encapsulation boundaries.
    pub fn label(self) -> &'a str {
        self.label
    }

    /// Get an iterator over the (allegedly) Base64-encoded lines of the
    /// encapsulated text.
    pub fn encapsulated_text(self) -> Lines<'a> {
        Lines {
            is_start: true,
            bytes: self.encapsulated_text,
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for Encapsulation<'a> {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Self::parse(bytes)
    }
}

/// Iterator over the lines in the encapsulated text.
struct Lines<'a> {
    /// true if no lines have been read
    is_start: bool,
    /// Remaining data being iterated over.
    bytes: &'a [u8],
}

impl<'a> Iterator for Lines<'a> {
    type Item = Result<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.len() > BASE64_WRAP_WIDTH {
            let (line, rest) = self.bytes.split_at(BASE64_WRAP_WIDTH);
            if let Some(rest) = grammar::strip_leading_eol(rest) {
                self.is_start = false;
                self.bytes = rest;
                Some(Ok(line))
            } else {
                // if bytes remaining does not split at BASE64_WRAP_WIDTH such
                // that the next char(s) in the rest is vertical whitespace
                // then attribute the error generically as `EncapsulatedText`
                // unless we are at the first line and the line contains a colon
                // then it may be a unsupported header
                Some(Err(
                    if self.is_start && line.iter().any(|&b| b == grammar::CHAR_COLON) {
                        Error::HeaderDisallowed
                    } else {
                        Error::EncapsulatedText
                    },
                ))
            }
        } else if !self.bytes.is_empty() {
            let line = self.bytes;
            self.bytes = &[];
            Some(Ok(line))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Encapsulation;

    #[test]
    fn pkcs8_example() {
        let pem = include_bytes!("../tests/examples/pkcs8.pem");
        let result = Encapsulation::parse(pem).unwrap();
        assert_eq!(result.label, "PRIVATE KEY");

        let mut lines = result.encapsulated_text();
        assert_eq!(
            lines.next().unwrap().unwrap(),
            &[
                77, 67, 52, 67, 65, 81, 65, 119, 66, 81, 89, 68, 75, 50, 86, 119, 66, 67, 73, 69,
                73, 66, 102, 116, 110, 72, 80, 112, 50, 50, 83, 101, 119, 89, 109, 109, 69, 111,
                77, 99, 88, 56, 86, 119, 73, 52, 73, 72, 119, 97, 113, 100, 43, 57, 76, 70, 80,
                106, 47, 49, 53, 101, 113, 70
            ]
        );
        assert_eq!(lines.next(), None);
    }
}
