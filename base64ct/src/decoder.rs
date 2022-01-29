//! Buffered Base64 decoder.

use crate::{
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
    ///
    /// # Returns
    /// - `Ok(decoder)` on success.
    /// - `Err(Error::InvalidLength)` if the input buffer is empty.
    pub fn new(input: &'i [u8]) -> Result<Self, Error> {
        if input.is_empty() {
            return Err(InvalidLength);
        }

        Ok(Self {
            line: Line::new(input),
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
    /// # Returns
    /// - `Ok(decoder)` on success.
    /// - `Err(Error::InvalidLength)` if the input buffer is empty or the line
    ///   width is zero.
    ///
    /// [RFC7468]: https://datatracker.ietf.org/doc/html/rfc7468
    pub fn new_wrapped(input: &'i [u8], line_width: usize) -> Result<Self, Error> {
        if input.is_empty() {
            return Err(InvalidLength);
        }

        Ok(Self {
            line: Line::default(),
            line_reader: LineReader::new(input, line_width)?,
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
            return Err(InvalidLength);
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
                let decoded_len = self.perform_decode(in_aligned, out_buf)?.len();
                out_pos = out_pos.checked_add(decoded_len).ok_or(InvalidLength)?;
            }

            if out_pos < out.len() {
                if self.is_finished() {
                    // If we're out of input then we've been requested to decode
                    // more data than is actually available.
                    return Err(InvalidLength);
                } else {
                    // If we still have data available but haven't completely
                    // filled the output slice, we're in a situation where
                    // either the input or output isn't block-aligned, so fill
                    // the internal block buffer.
                    self.fill_block_buffer()?;
                }
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
        let mut buf = [0u8; BlockBuffer::SIZE];

        let decoded = if self.line.len() < 4 && !self.line_reader.is_empty() {
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

            self.perform_decode(&tmp[..tmp_len], &mut buf)
        } else {
            let block = self.line.take(4);
            self.perform_decode(block, &mut buf)
        }?;

        self.block_buffer.fill(decoded)
    }

    /// Advance the internal buffer to the next line.
    fn advance_line(&mut self) -> Result<(), Error> {
        debug_assert!(self.line.is_empty(), "expected line buffer to be empty");

        if let Some(line) = self.line_reader.next().transpose()? {
            self.line = line;
            Ok(())
        } else {
            Err(InvalidLength)
        }
    }

    /// Perform Base64 decoding operation.
    fn perform_decode<'o>(&self, src: &[u8], dst: &'o mut [u8]) -> Result<&'o [u8], Error> {
        if self.is_finished() {
            E::decode(src, dst)
        } else {
            E::Unpadded::decode(src, dst)
        }
    }
}

/// Base64 decode buffer for a 1-block input.
///
/// This handles a partially decoded block of data, i.e. data which has been
/// decoded but not read.
#[derive(Clone, Default, Debug)]
struct BlockBuffer {
    /// 3 decoded bytes from a 4-byte Base64-encoded input.
    decoded: [u8; Self::SIZE],

    /// Length of the buffer.
    length: usize,

    /// Position within the buffer.
    position: usize,
}

impl BlockBuffer {
    /// Size of the buffer in bytes.
    const SIZE: usize = 3;

    /// Fill the buffer by decoding up to 3 bytes of decoded Base64 input.
    fn fill(&mut self, decoded_input: &[u8]) -> Result<(), Error> {
        debug_assert!(self.is_empty());

        if decoded_input.len() > Self::SIZE {
            return Err(InvalidLength);
        }

        self.position = 0;
        self.length = decoded_input.len();
        self.decoded[..decoded_input.len()].copy_from_slice(decoded_input);
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
#[derive(Clone, Debug)]
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
            return Err(InvalidLength);
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
                None | Some([]) => {
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
                _ => {
                    // Expected a leading newline
                    return Some(Err(Error::InvalidEncoding));
                }
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
    use crate::{test_vectors::*, variant::Variant, Base64, Base64Unpadded, Decoder};

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
