//! DER decoder.

use crate::{
    asn1::*, Choice, Decodable, DecodeValue, Error, ErrorKind, Length, Result, Tag, TagMode,
    TagNumber, Tagged,
};

/// DER decoder.
#[derive(Debug)]
pub struct Decoder<'a> {
    /// Byte slice being decoded.
    ///
    /// In the event an error was previously encountered this will be set to
    /// `None` to prevent further decoding while in a bad state.
    bytes: Option<&'a [u8]>,

    /// Position within the decoded slice.
    position: Length,
}

impl<'a> Decoder<'a> {
    /// Create a new decoder for the given byte slice.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes: Some(bytes),
            position: Length::ZERO,
        }
    }

    /// Decode a value which impls the [`Decodable`] trait.
    pub fn decode<T: Decodable<'a>>(&mut self) -> Result<T> {
        if self.is_failed() {
            return Err(self.error(ErrorKind::Failed));
        }

        T::decode(self).map_err(|e| {
            self.bytes.take();
            e.nested(self.position)
        })
    }

    /// Return an error with the given [`ErrorKind`], annotating it with
    /// context about where the error occurred.
    pub fn error(&mut self, kind: ErrorKind) -> Error {
        self.bytes.take();
        kind.at(self.position)
    }

    /// Return an error for an invalid value with the given tag.
    pub fn value_error(&mut self, tag: Tag) -> Error {
        self.error(tag.value_error().kind())
    }

    /// Did the decoding operation fail due to an error?
    pub fn is_failed(&self) -> bool {
        self.bytes.is_none()
    }

    /// Get the position within the buffer.
    pub fn position(&self) -> Length {
        self.position
    }

    /// Peek at the next byte in the decoder without modifying the cursor.
    pub fn peek(&self) -> Option<u8> {
        self.remaining()
            .ok()
            .and_then(|bytes| bytes.get(0).cloned())
    }

    /// Finish decoding, returning the given value if there is no
    /// remaining data, or an error otherwise
    pub fn finish<T>(self, value: T) -> Result<T> {
        if self.is_failed() {
            Err(ErrorKind::Failed.at(self.position))
        } else if !self.is_finished() {
            Err(ErrorKind::TrailingData {
                decoded: self.position,
                remaining: self.remaining_len()?,
            }
            .at(self.position))
        } else {
            Ok(value)
        }
    }

    /// Have we decoded all of the bytes in this [`Decoder`]?
    ///
    /// Returns `false` if we're not finished decoding or if a fatal error
    /// has occurred.
    pub fn is_finished(&self) -> bool {
        self.remaining().map(|rem| rem.is_empty()).unwrap_or(false)
    }

    /// Attempt to decode an ASN.1 `ANY` value.
    pub fn any(&mut self) -> Result<Any<'a>> {
        self.decode()
    }

    /// Attempt to decode an `OPTIONAL` ASN.1 `ANY` value.
    pub fn any_optional(&mut self) -> Result<Option<Any<'a>>> {
        self.decode()
    }

    /// Attempt to decode ASN.1 `INTEGER` as `i8`
    pub fn int8(&mut self) -> Result<i8> {
        self.decode()
    }

    /// Attempt to decode ASN.1 `INTEGER` as `i16`
    pub fn int16(&mut self) -> Result<i16> {
        self.decode()
    }

    /// Attempt to decode unsigned ASN.1 `INTEGER` as `u8`
    pub fn uint8(&mut self) -> Result<u8> {
        self.decode()
    }

    /// Attempt to decode unsigned ASN.1 `INTEGER` as `u16`
    pub fn uint16(&mut self) -> Result<u16> {
        self.decode()
    }

    /// Attempt to decode an ASN.1 `INTEGER` as a [`UIntBytes`].
    #[cfg(feature = "bigint")]
    #[cfg_attr(docsrs, doc(cfg(feature = "bigint")))]
    pub fn uint_bytes(&mut self) -> Result<UIntBytes<'a>> {
        self.decode()
    }

    /// Attempt to decode an ASN.1 `BIT STRING`.
    pub fn bit_string(&mut self) -> Result<BitString<'a>> {
        self.decode()
    }

    /// Attempt to decode an ASN.1 `CONTEXT-SPECIFIC` field with the
    /// provided [`TagNumber`].
    pub fn context_specific<T>(
        &mut self,
        tag_number: TagNumber,
        tag_mode: TagMode,
    ) -> Result<Option<T>>
    where
        T: DecodeValue<'a> + Tagged,
    {
        Ok(match tag_mode {
            TagMode::Explicit => ContextSpecific::<T>::decode_explicit(self, tag_number)?,
            TagMode::Implicit => ContextSpecific::<T>::decode_implicit(self, tag_number)?,
        }
        .map(|field| field.value))
    }

    /// Attempt to decode an ASN.1 `GeneralizedTime`.
    pub fn generalized_time(&mut self) -> Result<GeneralizedTime> {
        self.decode()
    }

    /// Attempt to decode an ASN.1 `IA5String`.
    pub fn ia5_string(&mut self) -> Result<Ia5String<'a>> {
        self.decode()
    }

    /// Attempt to decode an ASN.1 `NULL` value.
    pub fn null(&mut self) -> Result<Null> {
        self.decode()
    }

    /// Attempt to decode an ASN.1 `OCTET STRING`.
    pub fn octet_string(&mut self) -> Result<OctetString<'a>> {
        self.decode()
    }

    /// Attempt to decode an ASN.1 `OBJECT IDENTIFIER`.
    #[cfg(feature = "oid")]
    #[cfg_attr(docsrs, doc(cfg(feature = "oid")))]
    pub fn oid(&mut self) -> Result<ObjectIdentifier> {
        self.decode()
    }

    /// Attempt to decode an ASN.1 `OPTIONAL` value.
    pub fn optional<T: Choice<'a>>(&mut self) -> Result<Option<T>> {
        self.decode()
    }

    /// Attempt to decode an ASN.1 `PrintableString`.
    pub fn printable_string(&mut self) -> Result<PrintableString<'a>> {
        self.decode()
    }

    /// Attempt to decode an ASN.1 `UTCTime`.
    pub fn utc_time(&mut self) -> Result<UtcTime> {
        self.decode()
    }

    /// Attempt to decode an ASN.1 `UTF8String`.
    pub fn utf8_string(&mut self) -> Result<Utf8String<'a>> {
        self.decode()
    }

    /// Attempt to decode an ASN.1 `SEQUENCE`, creating a new nested
    /// [`Decoder`] and calling the provided argument with it.
    pub fn sequence<F, T>(&mut self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Decoder<'a>) -> Result<T>,
    {
        Tag::try_from(self.byte()?)?.assert_eq(Tag::Sequence)?;
        let len = Length::decode(self)?;
        self.decode_nested(len, f)
    }

    /// Decode a single byte, updating the internal cursor.
    pub(crate) fn byte(&mut self) -> Result<u8> {
        match self.bytes(1u8)? {
            [byte] => Ok(*byte),
            _ => Err(self.error(ErrorKind::Truncated)),
        }
    }

    /// Obtain a slice of bytes of the given length from the current cursor
    /// position, or return an error if we have insufficient data.
    pub fn bytes(&mut self, len: impl TryInto<Length>) -> Result<&'a [u8]> {
        if self.is_failed() {
            return Err(self.error(ErrorKind::Failed));
        }

        let len = len
            .try_into()
            .map_err(|_| self.error(ErrorKind::Overflow))?;

        let result = self
            .remaining()?
            .get(..len.try_into()?)
            .ok_or_else(|| self.error(ErrorKind::Truncated))?;

        self.position = (self.position + len)?;
        Ok(result)
    }

    /// Obtain a slice of bytes contain a complete TLV production suitable for parsing later.
    pub fn tlv_slice(&mut self) -> Result<&'a [u8]> {
        if self.is_failed() {
            return Err(self.error(ErrorKind::Failed));
        }

        let pos = self.position();
        let tag = Tag::decode(self)?;

        let element_length = Length::decode(self).map_err(|e| {
            if e.kind() == ErrorKind::Overlength {
                ErrorKind::Length { tag }.into()
            } else {
                e
            }
        })?;
        // length of full TLV production includes tag and length (captured via current pos - orig)
        let length = ((self.position - pos)? + element_length)?;
        // reset position before invoking bytes (which will advance to first byte beyond value)
        self.position = pos;
        self.bytes(length)
    }

    /// Get the number of bytes still remaining in the buffer.
    pub(crate) fn remaining_len(&self) -> Result<Length> {
        self.remaining()?.len().try_into()
    }

    /// Create a nested decoder which operates over the provided [`Length`].
    ///
    /// The nested decoder is passed to the provided callback function which is
    /// expected to decode a value of type `T` with it.
    fn decode_nested<F, T>(&mut self, length: Length, f: F) -> Result<T>
    where
        F: FnOnce(&mut Self) -> Result<T>,
    {
        let start_pos = self.position();
        let end_pos = (start_pos + length)?;
        let bytes = match self.bytes {
            Some(slice) => slice
                .get(..end_pos.try_into()?)
                .ok_or(ErrorKind::Truncated)?,
            None => return Err(self.error(ErrorKind::Failed)),
        };

        let mut nested_decoder = Self {
            bytes: Some(bytes),
            position: start_pos,
        };
        self.position = end_pos;

        let result = f(&mut nested_decoder)?;
        nested_decoder.finish(result)
    }

    /// Obtain the remaining bytes in this decoder from the current cursor
    /// position.
    fn remaining(&self) -> Result<&'a [u8]> {
        let pos = usize::try_from(self.position)?;

        self.bytes
            .and_then(|b| b.get(pos..))
            .ok_or_else(|| ErrorKind::Truncated.at(self.position))
    }
}

impl<'a> From<&'a [u8]> for Decoder<'a> {
    fn from(bytes: &'a [u8]) -> Decoder<'a> {
        Decoder::new(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::Decoder;
    use crate::{Decodable, ErrorKind, Length};

    #[test]
    fn truncated_message() {
        let mut decoder = Decoder::new(&[]);
        let err = bool::decode(&mut decoder).err().unwrap();
        assert_eq!(ErrorKind::Truncated, err.kind());
        assert_eq!(Some(Length::ZERO), err.position());
    }

    #[test]
    fn invalid_field_length() {
        let mut decoder = Decoder::new(&[0x02, 0x01]);
        let err = i8::decode(&mut decoder).err().unwrap();
        assert_eq!(ErrorKind::Truncated, err.kind());
        assert_eq!(Some(Length::from(2u8)), err.position());
    }

    #[test]
    fn trailing_data() {
        let mut decoder = Decoder::new(&[0x02, 0x01, 0x2A, 0x00]);
        let x = decoder.decode().unwrap();
        assert_eq!(42i8, x);

        let err = decoder.finish(x).err().unwrap();
        assert_eq!(
            ErrorKind::TrailingData {
                decoded: 3u8.into(),
                remaining: 1u8.into()
            },
            err.kind()
        );
        assert_eq!(Some(Length::from(3u8)), err.position());
    }
}
