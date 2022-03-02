//! Buffered Base64 encoder.

use crate::{
    variant::Variant,
    Encoding,
    Error::{self, InvalidLength},
    LineEnding, MIN_LINE_WIDTH,
};
use core::{cmp, marker::PhantomData, str};

#[cfg(feature = "std")]
use std::io;

#[cfg(docsrs)]
use crate::{Base64, Base64Unpadded};

/// Stateful Base64 encoder with support for buffered, incremental encoding.
///
/// The `E` type parameter can be any type which impls [`Encoding`] such as
/// [`Base64`] or [`Base64Unpadded`].
///
/// Internally it uses a sealed `Variant` trait which is an implementation
/// detail of this crate, and leverages a [blanket impl] of [`Encoding`].
///
/// [blanket impl]: ./trait.Encoding.html#impl-Encoding
pub struct Encoder<'o, E: Variant> {
    /// Output buffer.
    output: &'o mut [u8],

    /// Cursor within the output buffer.
    position: usize,

    /// Block buffer used for non-block-aligned data.
    block_buffer: BlockBuffer,

    /// Configuration and state for line-wrapping the output at a specified
    /// column.
    line_wrapper: Option<LineWrapper>,

    /// Phantom parameter for the Base64 encoding in use.
    encoding: PhantomData<E>,
}

impl<'o, E: Variant> Encoder<'o, E> {
    /// Create a new encoder which writes output to the given byte slice.
    ///
    /// Output constructed using this method is not line-wrapped.
    pub fn new(output: &'o mut [u8]) -> Result<Self, Error> {
        if output.is_empty() {
            return Err(InvalidLength);
        }

        Ok(Self {
            output,
            position: 0,
            block_buffer: BlockBuffer::default(),
            line_wrapper: None,
            encoding: PhantomData,
        })
    }

    /// Create a new encoder which writes line-wrapped output to the given byte
    /// slice.
    ///
    /// Output will be wrapped at the specified interval, using the provided
    /// line ending. Use [`LineEnding::default()`] to use the conventional line
    /// ending for the target OS.
    ///
    /// Minimum allowed line width is 4.
    pub fn new_wrapped(
        output: &'o mut [u8],
        width: usize,
        ending: LineEnding,
    ) -> Result<Self, Error> {
        let mut encoder = Self::new(output)?;
        encoder.line_wrapper = Some(LineWrapper::new(width, ending)?);
        Ok(encoder)
    }

    /// Encode the provided buffer as Base64, writing it to the output buffer.
    ///
    /// # Returns
    /// - `Ok(bytes)` if the expected amount of data was read
    /// - `Err(Error::InvalidLength)` if there is insufficient space in the output buffer
    pub fn encode(&mut self, mut input: &[u8]) -> Result<(), Error> {
        // If there's data in the block buffer, fill it
        if !self.block_buffer.is_empty() {
            self.process_buffer(&mut input)?;
        }

        while !input.is_empty() {
            // Attempt to encode a stride of block-aligned data
            let in_blocks = input.len() / 3;
            let out_blocks = self.remaining().len() / 4;
            let mut blocks = cmp::min(in_blocks, out_blocks);

            // When line wrapping, cap the block-aligned stride at near/at line length
            if let Some(line_wrapper) = &self.line_wrapper {
                line_wrapper.wrap_blocks(&mut blocks);
            }

            if blocks > 0 {
                let (in_aligned, in_rem) = input.split_at(blocks * 3);
                input = in_rem;
                self.perform_encode(in_aligned)?;
            }

            // If there's remaining non-aligned data, fill the block buffer
            if !input.is_empty() {
                self.process_buffer(&mut input)?;
            }
        }

        Ok(())
    }

    /// Finish encoding data, returning the resulting Base64 as a `str`.
    pub fn finish(mut self) -> Result<&'o str, Error> {
        if !self.block_buffer.is_empty() {
            let buffer_len = self.block_buffer.position;
            let block = self.block_buffer.bytes;
            self.perform_encode(&block[..buffer_len])?;
        }

        Ok(str::from_utf8(&self.output[..self.position])?)
    }

    /// Borrow the remaining data in the buffer.
    fn remaining(&mut self) -> &mut [u8] {
        &mut self.output[self.position..]
    }

    /// Fill the block buffer with data, consuming and encoding it when the
    /// buffer is full.
    fn process_buffer(&mut self, input: &mut &[u8]) -> Result<(), Error> {
        self.block_buffer.fill(input);

        if self.block_buffer.is_full() {
            let block = self.block_buffer.take();
            self.perform_encode(&block)?;
        }

        Ok(())
    }

    /// Perform Base64 encoding operation.
    fn perform_encode(&mut self, input: &[u8]) -> Result<usize, Error> {
        let mut len = E::encode(input, self.remaining())?.as_bytes().len();

        // Insert newline characters into the output as needed
        if let Some(line_wrapper) = &mut self.line_wrapper {
            line_wrapper.insert_newlines(&mut self.output[self.position..], &mut len)?;
        }

        self.position = self.position.checked_add(len).ok_or(InvalidLength)?;
        Ok(len)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<'o, E: Variant> io::Write for Encoder<'o, E> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.encode(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // TODO(tarcieri): return an error if there's still data remaining in the buffer?
        Ok(())
    }
}

/// Base64 encode buffer for a 1-block output.
///
/// This handles a partial block of data, i.e. data which hasn't been
#[derive(Clone, Default, Debug)]
struct BlockBuffer {
    /// 3 decoded bytes to be encoded to a 4-byte Base64-encoded input.
    bytes: [u8; Self::SIZE],

    /// Position within the buffer.
    position: usize,
}

impl BlockBuffer {
    /// Size of the buffer in bytes: 3-bytes of unencoded input which
    /// Base64 encode to 4-bytes of output.
    const SIZE: usize = 3;

    /// Fill the remaining space in the buffer with the input data.
    fn fill(&mut self, input: &mut &[u8]) {
        let len = cmp::min(Self::SIZE - self.position, input.len());
        self.bytes[self.position..][..len].copy_from_slice(&input[..len]);
        self.position += len;
        *input = &input[len..];
    }

    /// Take the output buffer, resetting the position to 0.
    fn take(&mut self) -> [u8; Self::SIZE] {
        debug_assert!(self.is_full());
        let result = self.bytes;
        *self = Default::default();
        result
    }

    /// Is the buffer empty?
    fn is_empty(&self) -> bool {
        self.position == 0
    }

    /// Is the buffer full?
    fn is_full(&self) -> bool {
        self.position == Self::SIZE
    }
}

/// Helper for wrapping Base64 at a given line width.
#[derive(Debug)]
struct LineWrapper {
    /// Number of bytes remaining in the current line.
    remaining: usize,

    /// Column at which Base64 should be wrapped.
    width: usize,

    /// Newline characters to use at the end of each line.
    ending: LineEnding,
}

impl LineWrapper {
    /// Create a new linewrapper.
    fn new(width: usize, ending: LineEnding) -> Result<Self, Error> {
        if width < MIN_LINE_WIDTH {
            return Err(InvalidLength);
        }

        Ok(Self {
            remaining: width,
            width,
            ending,
        })
    }

    /// Wrap the number of blocks to encode near/at EOL.
    fn wrap_blocks(&self, blocks: &mut usize) {
        if (*blocks * 4) >= self.remaining {
            *blocks = self.remaining / 4;
        }
    }

    /// Insert newlines into the output buffer as needed.
    fn insert_newlines(&mut self, mut buffer: &mut [u8], len: &mut usize) -> Result<(), Error> {
        let mut buffer_len = *len;

        if buffer_len < self.remaining {
            self.remaining = self
                .remaining
                .checked_sub(buffer_len)
                .ok_or(InvalidLength)?;

            return Ok(());
        }

        buffer = &mut buffer[self.remaining..];
        buffer_len = buffer_len
            .checked_sub(self.remaining)
            .ok_or(InvalidLength)?;

        // The `wrap_blocks` function should ensure the buffer is smaller than a Base64 block
        debug_assert!(buffer_len < 4, "buffer exceeds 4-bytes");

        if buffer_len + self.ending.len() >= buffer.len() {
            // Not enough space in buffer to add newlines
            return Err(InvalidLength);
        }

        // Shift the buffer contents to make space for the line ending
        for i in (0..buffer_len).rev() {
            buffer[i + self.ending.len()] = buffer[i];
        }

        buffer[..self.ending.len()].copy_from_slice(self.ending.as_bytes());
        *len = (*len).checked_add(self.ending.len()).ok_or(InvalidLength)?;
        self.remaining = self.width.checked_sub(buffer_len).ok_or(InvalidLength)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{test_vectors::*, variant::Variant, Base64, Base64Unpadded, Encoder, LineEnding};

    #[test]
    fn encode_padded() {
        encode_test::<Base64>(PADDED_BIN, PADDED_BASE64, None);
    }

    #[test]
    fn encode_unpadded() {
        encode_test::<Base64Unpadded>(UNPADDED_BIN, UNPADDED_BASE64, None);
    }

    #[test]
    fn encode_multiline_padded() {
        encode_test::<Base64>(MULTILINE_PADDED_BIN, MULTILINE_PADDED_BASE64, Some(70));
    }

    #[test]
    fn encode_multiline_unpadded() {
        encode_test::<Base64Unpadded>(MULTILINE_UNPADDED_BIN, MULTILINE_UNPADDED_BASE64, Some(70));
    }

    /// Core functionality of an encoding test.
    fn encode_test<V: Variant>(input: &[u8], expected: &str, wrapped: Option<usize>) {
        let mut buffer = [0u8; 1024];

        for chunk_size in 1..input.len() {
            let mut encoder = match wrapped {
                Some(line_width) => {
                    Encoder::<V>::new_wrapped(&mut buffer, line_width, LineEnding::LF)
                }
                None => Encoder::<V>::new(&mut buffer),
            }
            .unwrap();

            for chunk in input.chunks(chunk_size) {
                encoder.encode(chunk).unwrap();
            }

            assert_eq!(expected, encoder.finish().unwrap());
        }
    }
}
