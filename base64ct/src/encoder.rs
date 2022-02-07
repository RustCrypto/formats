//! Buffered Base64 encoder.

use crate::{
    variant::Variant,
    Encoding,
    Error::{self, InvalidLength},
};
use core::{cmp, marker::PhantomData, str};

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

    /// Phantom parameter for the Base64 encoding in use.
    encoding: PhantomData<E>,
}

impl<'o, E: Variant> Encoder<'o, E> {
    /// Create a new decoder for a byte slice containing contiguous
    /// (non-newline-delimited) Base64-encoded data.
    pub fn new(output: &'o mut [u8]) -> Result<Self, Error> {
        if output.is_empty() {
            return Err(InvalidLength);
        }

        Ok(Self {
            output,
            position: 0,
            block_buffer: BlockBuffer::default(),
            encoding: PhantomData,
        })
    }

    /// Encode the provided buffer as Base64, writing it to the output buffer.
    ///
    /// # Returns
    /// - `Ok(bytes)` if the expected amount of data was read
    /// - `Err(Error::InvalidLength)` if there is insufficient space in the output buffer
    pub fn encode(&mut self, mut input: &[u8]) -> Result<(), Error> {
        // If there's data in the block buffer, fill it
        if !self.block_buffer.is_empty() {
            self.fill_block_buffer(&mut input)?;
        }

        // Attempt to decode a stride of block-aligned data
        let in_blocks = input.len() / 3;
        let out_blocks = self.remaining().len() / 4;
        let blocks = cmp::min(in_blocks, out_blocks);

        if blocks > 0 {
            let (in_aligned, in_rem) = input.split_at(blocks * 3);
            input = in_rem;
            self.perform_encode(in_aligned)?;
        }

        // If there's remaining non-aligned data, fill the block buffer
        if !input.is_empty() {
            self.fill_block_buffer(&mut input)?;
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
    fn fill_block_buffer(&mut self, input: &mut &[u8]) -> Result<(), Error> {
        self.block_buffer.fill(input);

        if self.block_buffer.is_full() {
            let block = self.block_buffer.take();
            self.perform_encode(&block)?;
        }

        Ok(())
    }

    /// Perform Base64 encoding operation.
    fn perform_encode(&mut self, input: &[u8]) -> Result<usize, Error> {
        let len = E::encode(input, self.remaining())?.as_bytes().len();
        self.position += len;
        Ok(len)
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

#[cfg(test)]
mod tests {
    use crate::{test_vectors::*, variant::Variant, Base64, Base64Unpadded, Encoder};

    #[test]
    fn encode_padded() {
        encode_test::<Base64>(PADDED_BIN, PADDED_BASE64);
    }

    #[test]
    fn encode_unpadded() {
        encode_test::<Base64Unpadded>(UNPADDED_BIN, UNPADDED_BASE64);
    }

    /// Core functionality of an encoding test.
    fn encode_test<V>(input: &[u8], expected: &str)
    where
        V: Variant,
    {
        for chunk_size in 1..input.len() {
            let mut buffer = [0u8; 1024];
            let mut encoder = Encoder::<V>::new(&mut buffer).unwrap();

            for chunk in input.chunks(chunk_size) {
                encoder.encode(chunk).unwrap();
            }

            assert_eq!(expected, encoder.finish().unwrap());
        }
    }
}
