//! Stateful Base64 decoder.

use crate::{
    encoding::decode_padding,
    variant::Variant,
    Encoding,
    Error::{self, InvalidLength},
};
use core::{cmp, marker::PhantomData};

#[cfg(docsrs)]
use crate::{Base64, Base64Unpadded};

/// Carriage return
const CHAR_CR: u8 = 0x0d;

/// Line feed
const CHAR_LF: u8 = 0x0a;

/// Stateful Base64 decoder with support for buffered, incremental decoding.
///
/// The `E` type parameter can be any type which impls [`Encoding`] such as
/// [`Base64`] or [`Base64Unpadded`].
///
/// Internally it uses a sealed `Variant` trait which is an implementation
/// detail of this crate, and leverages a [blanket impl] of [`Encoding`].
///
/// [blanket impl]: ./trait.Encoding.html#impl-Encoding
#[derive(Clone)]
pub struct Decoder<'i, E: Variant> {
    /// Current line being processed.
    line: Line<'i>,

    /// Base64 input data reader.
    line_reader: LineReader<'i>,

    /// Block buffer used for non-block-aligned data.
    block_buffer: BlockBuffer,

    /// Phantom parameter for the Base64 encoding in use.
    encoding: PhantomData<E>,
}

impl<'i, E: Variant> Decoder<'i, E> {
    /// Create a new decoder for a byte slice containing contiguous
    /// (non-newline-delimited) Base64-encoded data.
    pub fn new(input: &'i [u8]) -> Result<Self, Error> {
        Ok(Self {
            line: Line::new(Self::unpad_input(input)?),
            line_reader: LineReader::default(),
            block_buffer: BlockBuffer::default(),
            encoding: PhantomData,
        })
    }

    /// Create a new decoder for a byte slice containing Base64 which
    /// line wraps at the given line length.
    ///
    /// Trailing newlines are not supported and must be removed in advance.
    ///
    /// Newlines are handled according to what are roughly [RFC7468] conventions:
    ///
    /// ```text
    /// [parsers] MUST handle different newline conventions
    /// ```
    ///
    /// RFC7468 allows any of the following as newlines, and allows a mixture
    /// of different types of newlines:
    ///
    /// ```text
    /// eol        = CRLF / CR / LF
    /// ```
    ///
    /// [RFC7468]: https://datatracker.ietf.org/doc/html/rfc7468
    pub fn new_wrapped(input: &'i [u8], line_width: usize) -> Result<Self, Error> {
        Ok(Self {
            line: Line::default(),
            line_reader: LineReader::new(Self::unpad_input(input)?, line_width)?,
            block_buffer: BlockBuffer::default(),
            encoding: PhantomData,
        })
    }

    /// Fill the provided buffer with data decoded from Base64.
    ///
    /// Enough Base64 input data must remain to fill the entire buffer.
    ///
    /// # Returns
    /// - `Ok(bytes)` if the expected amount of data was read
    /// - `Err(Error::InvalidLength)` if the exact amount of data couldn't be read
    pub fn decode<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8], Error> {
        if self.is_finished() {
            return Err(Error::InvalidLength);
        }

        let mut out_pos = 0;

        while out_pos < out.len() {
            // If there's data in the block buffer, use it
            if !self.block_buffer.is_empty() {
                let out_rem = out.len().checked_sub(out_pos).ok_or(InvalidLength)?;
                let bytes = self.block_buffer.take(out_rem);
                out[out_pos..][..bytes.len()].copy_from_slice(bytes);
                out_pos = out_pos.checked_add(bytes.len()).ok_or(InvalidLength)?;
            }

            // Advance the line reader if necessary
            if self.line.is_empty() && !self.line_reader.is_empty() {
                self.advance_line()?;
            }

            // Attempt to decode a stride of block-aligned data
            let in_blocks = self.line.len() / 4;
            let out_rem = out.len().checked_sub(out_pos).ok_or(InvalidLength)?;
            let out_blocks = out_rem / 3;
            let blocks = cmp::min(in_blocks, out_blocks);
            let in_aligned = self.line.take(blocks * 4);

            if !in_aligned.is_empty() {
                let out_buf = &mut out[out_pos..][..(blocks * 3)];
                let decoded_len = E::Unpadded::decode(in_aligned, out_buf)?.len();
                out_pos = out_pos.checked_add(decoded_len).ok_or(InvalidLength)?;
            }

            if out_pos < out.len() {
                // If we still haven't filled the output slice, we're in a
                // situation where either the input or output isn't
                // block-aligned, so fill the internal block buffer
                self.fill_block_buffer()?;
            }
        }

        Ok(out)
    }

    /// Has all of the input data been decoded?
    pub fn is_finished(&self) -> bool {
        self.line.is_empty() && self.line_reader.is_empty() && self.block_buffer.is_empty()
    }

    /// Fill the block buffer with data.
    fn fill_block_buffer(&mut self) -> Result<(), Error> {
        if self.line.len() < 4 && !self.line_reader.is_empty() {
            // Handle input block which is split across lines
            let mut tmp = [0u8; 4];

            // Copy remaining data in the line into tmp
            let line_end = self.line.take(4);
            tmp[..line_end.len()].copy_from_slice(line_end);

            // Advance the line and attempt to fill tmp
            self.advance_line()?;
            let line_begin = self.line.take(4 - line_end.len());
            tmp[line_end.len()..][..line_begin.len()].copy_from_slice(line_begin);

            let tmp_len = line_begin
                .len()
                .checked_add(line_end.len())
                .ok_or(InvalidLength)?;

            self.block_buffer.fill::<E::Unpadded>(&tmp[..tmp_len])
        } else {
            let block = self.line.take(4);
            self.block_buffer.fill::<E::Unpadded>(block)
        }
    }

    /// Advance the internal buffer to the next line.
    fn advance_line(&mut self) -> Result<(), Error> {
        debug_assert!(self.line.is_empty(), "expected line buffer to be empty");

        if let Some(line) = self.line_reader.next().transpose()? {
            self.line = line;
            Ok(())
        } else {
            Err(Error::InvalidLength)
        }
    }

    /// Remove padding from an input buffer.
    // TODO(tarcieri): instead of this, process the last Base64 block as padded?
    // This approach may not cover all cases with linewrapped Base64
    fn unpad_input(input: &[u8]) -> Result<&[u8], Error> {
        if E::PADDED {
            // TODO(tarcieri): validate that padding is well-formed with `validate_padding`
            // ...or switch to processing the last block as padded, leaning on
            // the existing padding validation code
            let (unpadded_len, err) = decode_padding(input)?;
            if err != 0 {
                return Err(Error::InvalidEncoding);
            }

            Ok(&input[..unpadded_len])
        } else {
            Ok(input)
        }
    }
}

/// Base64 decode buffer for a 1-block input.
///
/// This handles a partially decoded block of data, i.e. data which has been
/// decoded but not read.
#[derive(Clone, Default)]
struct BlockBuffer {
    /// 3 decoded bytes from a 4-byte Base64-encoded input.
    decoded: [u8; 3],

    /// Length of the buffer.
    length: usize,

    /// Position within the buffer.
    position: usize,
}

impl BlockBuffer {
    /// Fill the buffer by decoding up to 4 bytes of Base64 input
    fn fill<E: Variant>(&mut self, base64_input: &[u8]) -> Result<(), Error> {
        debug_assert!(self.is_empty());
        debug_assert!(base64_input.len() <= 4);
        self.length = E::decode(base64_input, &mut self.decoded)?.len();
        self.position = 0;
        Ok(())
    }

    /// Take a specified number of bytes from the buffer.
    ///
    /// Returns as many bytes as possible, or an empty slice if the buffer has
    /// already been read to completion.
    fn take(&mut self, mut nbytes: usize) -> &[u8] {
        debug_assert!(self.position <= self.length);
        let start_pos = self.position;
        let remaining_len = self.length - start_pos;

        if nbytes > remaining_len {
            nbytes = remaining_len;
        }

        self.position += nbytes;
        &self.decoded[start_pos..][..nbytes]
    }

    /// Have all of the bytes in this buffer been consumed?
    fn is_empty(&self) -> bool {
        self.position == self.length
    }
}

/// A single line of linewrapped data, providing a read buffer.
#[derive(Clone)]
pub struct Line<'i> {
    /// Remaining data in the line
    remaining: &'i [u8],
}

impl<'i> Default for Line<'i> {
    fn default() -> Self {
        Self::new(&[])
    }
}

impl<'i> Line<'i> {
    /// Create a new line which wraps the given input data
    pub fn new(bytes: &'i [u8]) -> Self {
        Self { remaining: bytes }
    }

    /// Take up to `nbytes` from this line buffer.
    fn take(&mut self, nbytes: usize) -> &'i [u8] {
        let (bytes, rest) = if nbytes < self.remaining.len() {
            self.remaining.split_at(nbytes)
        } else {
            (self.remaining, [].as_ref())
        };

        self.remaining = rest;
        bytes
    }

    /// Get the number of bytes remaining in this line.
    fn len(&self) -> usize {
        self.remaining.len()
    }

    /// Is the buffer for this line empty?
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Iterator over multi-line Base64 input.
#[derive(Clone, Default)]
struct LineReader<'i> {
    /// Remaining linewrapped data to be processed.
    remaining: &'i [u8],

    /// Line width.
    line_width: Option<usize>,
}

impl<'i> LineReader<'i> {
    /// Create a new reader which operates over linewrapped data.
    fn new(bytes: &'i [u8], line_width: usize) -> Result<Self, Error> {
        if line_width == 0 {
            return Err(Error::InvalidLength);
        }

        Ok(Self {
            remaining: bytes,
            line_width: Some(line_width),
        })
    }

    /// Is this line reader empty?
    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

impl<'i> Iterator for LineReader<'i> {
    type Item = Result<Line<'i>, Error>;

    fn next(&mut self) -> Option<Result<Line<'i>, Error>> {
        if let Some(line_width) = self.line_width {
            let rest = match self.remaining.get(line_width..) {
                None => {
                    if self.remaining.is_empty() {
                        return None;
                    } else {
                        let line = Line::new(self.remaining);
                        self.remaining = &[];
                        return Some(Ok(line));
                    }
                }
                Some([CHAR_CR, CHAR_LF, rest @ ..]) => rest,
                Some([CHAR_CR, rest @ ..]) => rest,
                Some([CHAR_LF, rest @ ..]) => rest,
                _ => return Some(Err(Error::InvalidEncoding)),
            };

            let line = Line::new(&self.remaining[..line_width]);
            self.remaining = rest;
            Some(Ok(line))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{variant::Variant, Base64, Base64Unpadded, Decoder};

    /// Padded Base64-encoded example
    const PADDED_BASE64: &str =
         "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHwf2HMM5TRXvo2SQJjsNkiDD5KqiiNjrGVv3UUh+mMT5RHxiRtOnlqvjhQtBq0VpmpCV/PwUdhOig4vkbqAcEc=";
    const PADDED_BIN: &[u8] = &[
        0, 0, 0, 19, 101, 99, 100, 115, 97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 50,
        53, 54, 0, 0, 0, 8, 110, 105, 115, 116, 112, 50, 53, 54, 0, 0, 0, 65, 4, 124, 31, 216, 115,
        12, 229, 52, 87, 190, 141, 146, 64, 152, 236, 54, 72, 131, 15, 146, 170, 138, 35, 99, 172,
        101, 111, 221, 69, 33, 250, 99, 19, 229, 17, 241, 137, 27, 78, 158, 90, 175, 142, 20, 45,
        6, 173, 21, 166, 106, 66, 87, 243, 240, 81, 216, 78, 138, 14, 47, 145, 186, 128, 112, 71,
    ];

    /// Unpadded Base64-encoded example
    const UNPADDED_BASE64: &str =
        "AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti";
    const UNPADDED_BIN: &[u8] = &[
        0, 0, 0, 11, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 32, 179, 62, 174,
        243, 126, 162, 223, 124, 170, 1, 13, 239, 222, 163, 78, 36, 31, 101, 241, 181, 41, 164,
        244, 62, 209, 67, 39, 245, 197, 74, 171, 98,
    ];

    /// Padded multi-line Base64 example (from the `ssh-key` crate's `id_ed25519`)
    const MULTILINE_PADDED_BASE64: &str =
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
         QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM\n\
         XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg\n\
         AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf\n\
         ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==";
    const MULTILINE_PADDED_BIN: &[u8] = &[
        111, 112, 101, 110, 115, 115, 104, 45, 107, 101, 121, 45, 118, 49, 0, 0, 0, 0, 4, 110, 111,
        110, 101, 0, 0, 0, 4, 110, 111, 110, 101, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 51, 0, 0, 0, 11,
        115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 32, 179, 62, 174, 243, 126, 162,
        223, 124, 170, 1, 13, 239, 222, 163, 78, 36, 31, 101, 241, 181, 41, 164, 244, 62, 209, 67,
        39, 245, 197, 74, 171, 98, 0, 0, 0, 152, 0, 32, 12, 93, 0, 32, 12, 93, 0, 0, 0, 11, 115,
        115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 32, 179, 62, 174, 243, 126, 162, 223,
        124, 170, 1, 13, 239, 222, 163, 78, 36, 31, 101, 241, 181, 41, 164, 244, 62, 209, 67, 39,
        245, 197, 74, 171, 98, 0, 0, 0, 64, 182, 6, 194, 34, 209, 12, 22, 218, 225, 108, 112, 164,
        212, 81, 115, 71, 46, 198, 23, 224, 92, 101, 105, 32, 210, 110, 86, 192, 143, 181, 145,
        237, 179, 62, 174, 243, 126, 162, 223, 124, 170, 1, 13, 239, 222, 163, 78, 36, 31, 101,
        241, 181, 41, 164, 244, 62, 209, 67, 39, 245, 197, 74, 171, 98, 0, 0, 0, 16, 117, 115, 101,
        114, 64, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 1, 2, 3, 4, 5,
    ];

    /// Unpadded multi-line Base64 example (from the `ssh-key` crate's `id_ecdsa_p256`).
    const MULTILINE_UNPADDED_BASE64: &str =
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS\n\
         1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQR8H9hzDOU0V76NkkCY7DZIgw+Sqooj\n\
         Y6xlb91FIfpjE+UR8YkbTp5ar44ULQatFaZqQlfz8FHYTooOL5G6gHBHAAAAsB8RBhUfEQ\n\
         YVAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHwf2HMM5TRXvo2S\n\
         QJjsNkiDD5KqiiNjrGVv3UUh+mMT5RHxiRtOnlqvjhQtBq0VpmpCV/PwUdhOig4vkbqAcE\n\
         cAAAAhAMp4pkd0v643EjIkk38DmJYBiXB6ygqGRc60NZxCO6B5AAAAEHVzZXJAZXhhbXBs\n\
         ZS5jb20BAgMEBQYH";
    const MULTILINE_UNPADDED_BIN: &[u8] = &[
        111, 112, 101, 110, 115, 115, 104, 45, 107, 101, 121, 45, 118, 49, 0, 0, 0, 0, 4, 110, 111,
        110, 101, 0, 0, 0, 4, 110, 111, 110, 101, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 104, 0, 0, 0,
        19, 101, 99, 100, 115, 97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 50, 53, 54,
        0, 0, 0, 8, 110, 105, 115, 116, 112, 50, 53, 54, 0, 0, 0, 65, 4, 124, 31, 216, 115, 12,
        229, 52, 87, 190, 141, 146, 64, 152, 236, 54, 72, 131, 15, 146, 170, 138, 35, 99, 172, 101,
        111, 221, 69, 33, 250, 99, 19, 229, 17, 241, 137, 27, 78, 158, 90, 175, 142, 20, 45, 6,
        173, 21, 166, 106, 66, 87, 243, 240, 81, 216, 78, 138, 14, 47, 145, 186, 128, 112, 71, 0,
        0, 0, 176, 31, 17, 6, 21, 31, 17, 6, 21, 0, 0, 0, 19, 101, 99, 100, 115, 97, 45, 115, 104,
        97, 50, 45, 110, 105, 115, 116, 112, 50, 53, 54, 0, 0, 0, 8, 110, 105, 115, 116, 112, 50,
        53, 54, 0, 0, 0, 65, 4, 124, 31, 216, 115, 12, 229, 52, 87, 190, 141, 146, 64, 152, 236,
        54, 72, 131, 15, 146, 170, 138, 35, 99, 172, 101, 111, 221, 69, 33, 250, 99, 19, 229, 17,
        241, 137, 27, 78, 158, 90, 175, 142, 20, 45, 6, 173, 21, 166, 106, 66, 87, 243, 240, 81,
        216, 78, 138, 14, 47, 145, 186, 128, 112, 71, 0, 0, 0, 33, 0, 202, 120, 166, 71, 116, 191,
        174, 55, 18, 50, 36, 147, 127, 3, 152, 150, 1, 137, 112, 122, 202, 10, 134, 69, 206, 180,
        53, 156, 66, 59, 160, 121, 0, 0, 0, 16, 117, 115, 101, 114, 64, 101, 120, 97, 109, 112,
        108, 101, 46, 99, 111, 109, 1, 2, 3, 4, 5, 6, 7,
    ];

    #[test]
    fn decode_padded() {
        decode_test(PADDED_BIN, || {
            Decoder::<Base64>::new(PADDED_BASE64.as_bytes()).unwrap()
        })
    }

    #[test]
    fn decode_unpadded() {
        decode_test(UNPADDED_BIN, || {
            Decoder::<Base64Unpadded>::new(UNPADDED_BASE64.as_bytes()).unwrap()
        })
    }

    #[test]
    fn decode_multiline_padded() {
        decode_test(MULTILINE_PADDED_BIN, || {
            Decoder::<Base64>::new_wrapped(MULTILINE_PADDED_BASE64.as_bytes(), 70).unwrap()
        })
    }

    #[test]
    fn decode_multiline_unpadded() {
        decode_test(MULTILINE_UNPADDED_BIN, || {
            Decoder::<Base64Unpadded>::new_wrapped(MULTILINE_UNPADDED_BASE64.as_bytes(), 70)
                .unwrap()
        })
    }

    /// Core functionality of a decoding test
    fn decode_test<'a, F, V>(expected: &[u8], f: F)
    where
        F: Fn() -> Decoder<'a, V>,
        V: Variant,
    {
        for chunk_size in 1..expected.len() {
            let mut decoder = f();
            let mut buffer = [0u8; 1024];

            for chunk in expected.chunks(chunk_size) {
                assert!(!decoder.is_finished());
                let decoded = decoder.decode(&mut buffer[..chunk.len()]).unwrap();
                assert_eq!(chunk, decoded);
            }

            assert!(decoder.is_finished());
        }
    }
}
