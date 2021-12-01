//! Stateful Base64 decoder.

use crate::{
    encoding::decode_padding,
    variant::Variant,
    Encoding,
    Error::{self, InvalidLength},
};
use core::marker::PhantomData;

#[cfg(docsrs)]
use crate::{Base64, Base64Unpadded};

/// Stateful Base64 decoder with support for buffered, incremental decoding.
///
/// The `E` type parameter can be any type which impls [`Encoding`] such as
/// [`Base64`] or [`Base64Unpadded`].
///
/// Internally it uses a sealed `Variant` trait which is an implementation
/// detail of this crate, and leverages a [blanket impl] of [`Encoding`].
///
/// [blanket impl]: ./trait.Encoding.html#impl-Encoding
pub struct Decoder<'i, E: Variant> {
    /// Remaining data in the input buffer.
    remaining: &'i [u8],

    /// Block buffer used for non-block-aligned data.
    buffer: Option<BlockBuffer>,

    /// Phantom parameter for the Base64 encoding in use.
    encoding: PhantomData<E>,
}

impl<'i, E: Variant> Decoder<'i, E> {
    /// Create a new decoder for a byte slice containing contiguous
    /// (non-newline-delimited) Base64-encoded data.
    pub fn new(input: &'i [u8]) -> Result<Self, Error> {
        let remaining = if E::PADDED {
            let (unpadded_len, err) = decode_padding(input)?;
            if err != 0 {
                return Err(Error::InvalidEncoding);
            }

            &input[..unpadded_len]
        } else {
            input
        };

        Ok(Self {
            remaining,
            buffer: None,
            encoding: PhantomData,
        })
    }

    /// Write as many bytes of decoded data as possible into the provided
    /// buffer.
    ///
    /// If there is not sufficient input data to completely fill the buffer,
    /// it returns a partial result.
    ///
    /// # Returns
    /// - `Ok(Some(bytes))` if there was data available
    /// - `Ok(None)` if there is no remaining data
    /// - `Err(err)` if there was a Base64 decoding error
    pub fn decode_partial<'o>(&mut self, out: &'o mut [u8]) -> Result<Option<&'o [u8]>, Error> {
        if self.is_finished() {
            return Ok(None);
        }

        let mut out_offset = 0;

        let take_buffer = self
            .buffer
            .as_mut()
            .map(|buf| {
                let bytes = buf.take(out.len());
                out[..bytes.len()].copy_from_slice(bytes);
                out_offset += bytes.len();
                buf.is_empty()
            })
            .unwrap_or_default();

        if take_buffer {
            self.buffer = None;
        }

        let out_len = out.len().checked_sub(out_offset).ok_or(InvalidLength)?;
        let out_aligned = out_len.checked_sub(out_len % 3).ok_or(InvalidLength)?;

        let mut in_len = out_aligned
            .checked_mul(4)
            .and_then(|n| n.checked_div(3))
            .ok_or(InvalidLength)?;

        if in_len > self.remaining.len() {
            in_len = self
                .remaining
                .len()
                .checked_sub(self.remaining.len() % 4)
                .ok_or(InvalidLength)?;
        }

        if in_len < 4 {
            in_len = 0;
        }

        let (aligned, rest) = self.remaining.split_at(in_len);

        if in_len != 0 {
            let decoded_len =
                E::Unpadded::decode(aligned, &mut out[out_offset..][..out_aligned])?.len();

            out_offset = out_offset.checked_add(decoded_len).ok_or(InvalidLength)?;
            self.remaining = rest;
        }

        if out_offset < out.len() && !self.remaining.is_empty() {
            if self.remaining.len() < 4 {
                return Err(InvalidLength);
            }

            let (block, rest) = self.remaining.split_at(4);
            let mut buf =
                BlockBuffer::new::<E::Unpadded>(block.try_into().map_err(|_| InvalidLength)?)?;
            self.remaining = rest;

            let bytes = buf.take(out.len().checked_sub(out_offset).ok_or(InvalidLength)?);
            out[out_offset..][..bytes.len()].copy_from_slice(bytes);
            out_offset = out_offset.checked_add(bytes.len()).ok_or(InvalidLength)?;

            debug_assert!(!buf.is_empty());
            debug_assert!(self.buffer.is_none());
            self.buffer = Some(buf);
        }

        Ok(Some(&out[..out_offset]))
    }

    /// Write an exact amount of data to a buffer.
    ///
    /// # Returns
    /// - `Ok(bytes)` if the expected amount of data was read
    /// - `Err(Error::Length)` if the exact amount of data couldn't be read
    pub fn decode_exact<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8], Error> {
        let expected_len = out.len();

        if let Some(slice) = self.decode_partial(out)? {
            if slice.len() == expected_len {
                return Ok(slice);
            }
        }

        Err(InvalidLength)
    }

    /// Has all of the input data been decoded?
    pub fn is_finished(&self) -> bool {
        self.remaining.is_empty()
            && self
                .buffer
                .as_ref()
                .map(|buf| buf.is_empty())
                .unwrap_or(true)
    }
}

/// Base64 decode buffer for a 1-block input.
///
/// This handles a partially decoded block of data, i.e. data which has been
/// decoded but not read.
struct BlockBuffer {
    /// 3 decoded bytes from a 4-byte Base64-encoded input.
    decoded: [u8; 3],

    /// Length of the buffer.
    length: usize,

    /// Position within the buffer.
    position: usize,
}

impl BlockBuffer {
    /// Decode the provided 4-byte input as Base64.
    pub(crate) fn new<E: Variant>(input: &[u8; 4]) -> Result<Self, Error> {
        let mut decoded = [0u8; 3];
        let length = E::decode(input, &mut decoded)?.len();

        Ok(Self {
            decoded,
            length,
            position: 0,
        })
    }

    /// Take a specified number of bytes from the buffer.
    ///
    /// Returns as many bytes as possible, or an empty slice if the buffer has
    /// already been read to completion.
    pub(crate) fn take(&mut self, mut nbytes: usize) -> &[u8] {
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
    pub fn is_empty(&self) -> bool {
        self.position == self.length
    }
}

#[cfg(test)]
mod tests {
    use crate::{Base64Unpadded, Decoder};

    /// Unpadded Base64-encoded example
    // TODO(tarcieri): padded Base64 tests
    const UNPADDED_BASE64: &str =
        "AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti";
    const UNPADDED_BIN: &[u8] = &[
        0, 0, 0, 11, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 32, 179, 62, 174,
        243, 126, 162, 223, 124, 170, 1, 13, 239, 222, 163, 78, 36, 31, 101, 241, 181, 41, 164,
        244, 62, 209, 67, 39, 245, 197, 74, 171, 98,
    ];

    #[test]
    fn decode_unpadded() {
        for chunk_size in 1..UNPADDED_BIN.len() {
            let mut decoder = Decoder::<Base64Unpadded>::new(UNPADDED_BASE64.as_bytes()).unwrap();
            let mut buffer = [0u8; 64];

            for chunk in UNPADDED_BIN.chunks(chunk_size) {
                assert!(!decoder.is_finished());
                match decoder.decode_partial(&mut buffer[..chunk_size]) {
                    Ok(Some(decoded)) => assert_eq!(chunk, decoded),
                    other => panic!("decode failed: {:?}", other),
                }
            }

            assert!(decoder.is_finished());
        }
    }
}
