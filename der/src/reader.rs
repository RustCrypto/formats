//! Reader trait.

use crate::{ErrorKind, Header, Length, Result, Tag};

/// Reader trait which reads DER-encoded input.
pub trait Reader<'i>: Clone + Sized {
    /// Get the length of the input.
    fn input_len(&self) -> Result<Length>;

    /// Peek at the next byte of input without modifying the cursor.
    fn peek_byte(&self) -> Option<u8>;

    /// Peek forward in the input data, attempting to decode a [`Header`] from
    /// the data at the current position in the decoder.
    ///
    /// Does not modify the decoder's state.
    fn peek_header(&self) -> Result<Header>;

    /// Get the position within the buffer.
    fn position(&self) -> Length;

    /// Get the number of bytes still remaining in the buffer.
    fn remaining_len(&self) -> Result<Length>;

    /// Have we read all of the input data?
    fn is_finished(&self) -> bool {
        self.remaining_len() == Ok(Length::ZERO)
    }

    /// Peek at the next byte in the decoder and attempt to decode it as a
    /// [`Tag`] value.
    ///
    /// Does not modify the decoder's state.
    fn peek_tag(&self) -> Result<Tag> {
        match self.peek_byte() {
            Some(byte) => byte.try_into(),
            None => {
                let actual_len = self.input_len()?;
                let expected_len = (actual_len + Length::ONE)?;
                Err(ErrorKind::Incomplete {
                    expected_len,
                    actual_len,
                }
                .into())
            }
        }
    }

    /// Attempt to read data borrowed directly from the input as a slice,
    /// updating the internal cursor position.
    ///
    /// # Returns
    /// - `Ok(slice)` on success
    /// - `Err(ErrorKind::Incomplete)` if there is not enough data
    /// - `Err(ErrorKind::Reader)` if the reader can't borrow from the input
    fn read_slice(&mut self, len: impl TryInto<Length>) -> Result<&'i [u8]>;

    /// Attempt to read input data, writing it into the provided buffer, and
    /// returning a slice on success.
    ///
    /// # Returns
    /// - `Ok(slice)` if there is sufficient data
    /// - `Err(ErrorKind::Incomplete)` if there is not enough data
    fn read_into<'o>(&mut self, buf: &'o mut [u8]) -> Result<&'o [u8]> {
        let input = self.read_slice(buf.len())?;
        buf.copy_from_slice(input);
        Ok(buf)
    }

    /// Read a single byte.
    fn read_byte(&mut self) -> Result<u8> {
        let mut buf = [0];
        self.read_into(&mut buf)?;
        Ok(buf[0])
    }
}
