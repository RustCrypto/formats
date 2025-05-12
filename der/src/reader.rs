//! Reader trait.

#[cfg(feature = "pem")]
pub(crate) mod pem;
pub(crate) mod slice;

use crate::{
    Decode, DecodeValue, Encode, EncodingRules, Error, ErrorKind, FixedTag, Header, Length, Tag,
    TagMode, TagNumber, asn1::ContextSpecific,
};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// End of contents length
const EOC_LENGTH: Length = Length::new(2);
/// End of contents
const EOC_BYTES: [u8; 2] = [0x00, 0x00];

/// Reader trait which reads DER-encoded input.
pub trait Reader<'r>: Sized {
    /// Get the [`EncodingRules`] which should be applied when decoding the input.
    fn encoding_rules(&self) -> EncodingRules;

    /// Get the length of the input.
    fn input_len(&self) -> Length;

    /// Peek at the decoded PEM without updating the internal state, writing into the provided
    /// output buffer.
    ///
    /// Attempts to fill the entire buffer, returning an error if there is not enough data.
    fn peek_into(&self, buf: &mut [u8]) -> crate::Result<()>;

    /// Get the position within the buffer.
    fn position(&self) -> Length;

    /// Read nested data of the given length.
    fn read_nested<T, F, E>(&mut self, len: Length, f: F) -> Result<T, E>
    where
        E: From<Error>,
        F: FnOnce(&mut Self) -> Result<T, E>;

    /// Attempt to read data borrowed directly from the input as a slice,
    /// updating the internal cursor position.
    ///
    /// # Returns
    /// - `Ok(slice)` on success
    /// - `Err(ErrorKind::Incomplete)` if there is not enough data
    /// - `Err(ErrorKind::Reader)` if the reader can't borrow from the input
    fn read_slice(&mut self, len: Length) -> Result<&'r [u8], Error>;

    /// Attempt to decode an ASN.1 `CONTEXT-SPECIFIC` field with the
    /// provided [`TagNumber`].
    fn context_specific<T>(
        &mut self,
        tag_number: TagNumber,
        tag_mode: TagMode,
    ) -> Result<Option<T>, T::Error>
    where
        T: DecodeValue<'r> + FixedTag + 'r,
    {
        Ok(match tag_mode {
            TagMode::Explicit => ContextSpecific::<T>::decode_explicit(self, tag_number)?,
            TagMode::Implicit => ContextSpecific::<T>::decode_implicit(self, tag_number)?,
        }
        .map(|field| field.value))
    }

    /// Decode a value which impls the [`Decode`] trait.
    fn decode<T: Decode<'r>>(&mut self) -> Result<T, T::Error> {
        T::decode(self)
    }

    /// Return an error with the given [`ErrorKind`], annotating it with
    /// context about where the error occurred.
    fn error(&mut self, kind: ErrorKind) -> Error {
        kind.at(self.position())
    }

    /// Finish decoding, returning the given value if there is no
    /// remaining data, or an error otherwise
    fn finish<T>(self, value: T) -> Result<T, Error> {
        if !self.is_finished() {
            Err(ErrorKind::TrailingData {
                decoded: self.position(),
                remaining: self.remaining_len(),
            }
            .at(self.position()))
        } else {
            Ok(value)
        }
    }

    /// Have we read all of the input data?
    fn is_finished(&self) -> bool {
        self.remaining_len().is_zero()
    }

    /// Offset within the original input stream.
    ///
    /// This is used for error reporting, and doesn't need to be overridden
    /// by any reader implementations (except for the built-in `NestedReader`,
    /// which consumes nested input messages)
    fn offset(&self) -> Length {
        self.position()
    }

    /// Peek at the next byte of input without modifying the cursor.
    fn peek_byte(&self) -> Option<u8> {
        let mut byte = [0];
        self.peek_into(&mut byte).ok().map(|_| byte[0])
    }

    /// Peek forward in the input data, attempting to decode a [`Header`] from
    /// the data at the current position in the decoder.
    ///
    /// Does not modify the decoder's state.
    #[deprecated(since = "0.8.0-rc.1", note = "use `Header::peek` instead")]
    fn peek_header(&self) -> Result<Header, Error> {
        Header::peek(self)
    }

    /// Peek at the next tag in the reader.
    #[deprecated(since = "0.8.0-rc.1", note = "use `Tag::peek` instead")]
    fn peek_tag(&self) -> Result<Tag, Error> {
        Tag::peek(self)
    }

    /// Attempt to peek remaining bytes.
    fn peek_remaining(&mut self) -> Result<&'r [u8], Error>;

    /// Read a single byte.
    fn read_byte(&mut self) -> Result<u8, Error> {
        let mut buf = [0];
        self.read_into(&mut buf)?;
        Ok(buf[0])
    }

    /// Attempt to read input data, writing it into the provided buffer, and
    /// returning a slice on success.
    ///
    /// # Returns
    /// - `Ok(slice)` if there is sufficient data
    /// - `Err(ErrorKind::Incomplete)` if there is not enough data
    fn read_into<'o>(&mut self, buf: &'o mut [u8]) -> Result<&'o [u8], Error> {
        let input = self.read_slice(buf.len().try_into()?)?;
        buf.copy_from_slice(input);
        Ok(buf)
    }

    /// Read a byte vector of the given length.
    #[cfg(feature = "alloc")]
    fn read_vec(&mut self, len: Length) -> Result<Vec<u8>, Error> {
        let mut bytes = vec![0u8; usize::try_from(len)?];
        self.read_into(&mut bytes)?;
        Ok(bytes)
    }

    /// Get the number of bytes still remaining in the buffer.
    fn remaining_len(&self) -> Length {
        debug_assert!(self.position() <= self.input_len());
        self.input_len().saturating_sub(self.position())
    }

    /// Read an ASN.1 `SEQUENCE`, creating a nested [`Reader`] for the body and
    /// calling the provided closure with it.
    fn sequence<F, T, E>(&mut self, f: F) -> Result<T, E>
    where
        F: FnOnce(&mut Self) -> Result<T, E>,
        E: From<Error>,
    {
        let header = Header::decode(self)?;
        header.tag.assert_eq(Tag::Sequence)?;
        self.read_nested(header.length, f)
    }

    /// Obtain a slice of bytes contain a complete TLV production suitable for parsing later.
    fn tlv_bytes(&mut self) -> Result<&'r [u8], Error> {
        let header = Header::peek(self)?;
        let header_len = header.encoded_len()?;
        self.read_slice((header_len + header.length)?)
    }

    /// Returns length of current indefinite segment
    fn peek_indefinite_length(&mut self) -> Result<Length, Error> {
        let remaining_len = self.remaining_len();

        let slice = self.peek_remaining()?;
        if remaining_len < EOC_LENGTH {
            return Err(ErrorKind::Incomplete {
                expected_len: EOC_LENGTH,
                actual_len: remaining_len,
            }
            .into());
        }
        let content_len = (remaining_len - EOC_LENGTH)?;
        let content_usize = usize::try_from(content_len)?;
        if &slice[content_usize..] != &EOC_BYTES {
            return Err(ErrorKind::IndefiniteLength.into());
        }
        Ok(content_len)
    }
    /// Reads 2 end-of-contents bytes [0x00, 0x00]
    fn read_end_of_contents(&mut self) -> Result<(), Error> {
        let mut eoc_buf = [0u8; 2];
        self.read_into(&mut eoc_buf)?;
        if eoc_buf != EOC_BYTES {
            return Err(ErrorKind::IndefiniteLength.into());
        }
        Ok(())
    }
}
