//! DER decoder.

use crate::{
    asn1::*, ByteSlice, Choice, Decode, DecodeValue, Encode, Error, ErrorKind, FixedTag, Header,
    Length, Reader, Result, Tag, TagMode, TagNumber,
};

/// DER decoder.
#[derive(Clone, Debug)]
pub struct Decoder<'a> {
    /// Byte slice being decoded.
    bytes: ByteSlice<'a>,

    /// Did the decoding operation fail?
    failed: bool,

    /// Position within the decoded slice.
    position: Length,

    /// Offset where `bytes` occurs in the original ASN.1 DER document.
    ///
    /// Used for nested decoding.
    offset: Length,
}

impl<'a> Decoder<'a> {
    /// Create a new decoder for the given byte slice.
    pub fn new(bytes: &'a [u8]) -> Result<Self> {
        Ok(Self::new_with_offset(ByteSlice::new(bytes)?, Length::ZERO))
    }

    /// Create a new decoder where `bytes` begins at a specified offset within
    /// an original ASN.1 DER document.
    ///
    /// This is used for calculating positions when decoding nested documents.
    pub(crate) fn new_with_offset(bytes: ByteSlice<'a>, offset: Length) -> Self {
        Self {
            bytes,
            failed: false,
            position: Length::ZERO,
            offset,
        }
    }

    /// Decode a value which impls the [`Decode`] trait.
    pub fn decode<T: Decode<'a>>(&mut self) -> Result<T> {
        if self.is_failed() {
            return Err(self.error(ErrorKind::Failed));
        }

        T::decode(self).map_err(|e| {
            self.failed = true;
            e.nested(self.position)
        })
    }

    /// Return an error with the given [`ErrorKind`], annotating it with
    /// context about where the error occurred.
    pub fn error(&mut self, kind: ErrorKind) -> Error {
        self.failed = true;
        kind.at(self.position)
    }

    /// Return an error for an invalid value with the given tag.
    pub fn value_error(&mut self, tag: Tag) -> Error {
        self.error(tag.value_error().kind())
    }

    /// Did the decoding operation fail due to an error?
    pub fn is_failed(&self) -> bool {
        self.failed
    }

    /// Finish decoding, returning the given value if there is no
    /// remaining data, or an error otherwise
    pub fn finish<T>(self, value: T) -> Result<T> {
        if self.is_failed() {
            Err(ErrorKind::Failed.at(self.position))
        } else if !self.is_finished() {
            Err(ErrorKind::TrailingData {
                decoded: self.position,
                remaining: self.remaining_len(),
            }
            .at(self.position))
        } else {
            Ok(value)
        }
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
        T: DecodeValue<'a> + FixedTag,
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
        SequenceRef::decode(self)?.decode_body(f)
    }

    /// Obtain a slice of bytes contain a complete TLV production suitable for parsing later.
    pub fn tlv_bytes(&mut self) -> Result<&'a [u8]> {
        let header = self.peek_header()?;
        let header_len = header.encoded_len()?;
        self.read_slice((header_len + header.length)?)
    }

    /// Obtain the remaining bytes in this decoder from the current cursor
    /// position.
    fn remaining(&self) -> Result<&'a [u8]> {
        if self.is_failed() {
            Err(ErrorKind::Failed.at(self.position))
        } else {
            self.bytes
                .as_slice()
                .get(self.position.try_into()?..)
                .ok_or_else(|| Error::incomplete(self.input_len()))
        }
    }
}

impl<'a> Reader<'a> for Decoder<'a> {
    fn input_len(&self) -> Length {
        self.bytes.len()
    }

    fn peek_byte(&self) -> Option<u8> {
        self.remaining()
            .ok()
            .and_then(|bytes| bytes.get(0).cloned())
    }

    fn peek_header(&self) -> Result<Header> {
        Header::decode(&mut self.clone())
    }

    fn position(&self) -> Length {
        self.position.saturating_add(self.offset)
    }

    fn read_slice(&mut self, len: impl TryInto<Length>) -> Result<&'a [u8]> {
        if self.is_failed() {
            return Err(self.error(ErrorKind::Failed));
        }

        let len = len
            .try_into()
            .map_err(|_| self.error(ErrorKind::Overflow))?;

        match self.remaining()?.get(..len.try_into()?) {
            Some(result) => {
                self.position = (self.position + len)?;
                Ok(result)
            }
            None => Err(self.error(ErrorKind::Incomplete {
                expected_len: (self.position + len)?,
                actual_len: self.input_len(),
            })),
        }
    }

    fn remaining_len(&self) -> Length {
        debug_assert!(self.position <= self.input_len());
        self.input_len().saturating_sub(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::Decoder;
    use crate::{Decode, ErrorKind, Length, Reader, Tag};
    use hex_literal::hex;

    // INTEGER: 42
    const EXAMPLE_MSG: &[u8] = &hex!("02012A00");

    #[test]
    fn empty_message() {
        let mut decoder = Decoder::new(&[]).unwrap();
        let err = bool::decode(&mut decoder).err().unwrap();
        assert_eq!(Some(Length::ZERO), err.position());

        match err.kind() {
            ErrorKind::Incomplete {
                expected_len,
                actual_len,
            } => {
                assert_eq!(actual_len, 0u8.into());
                assert_eq!(expected_len, 1u8.into());
            }
            other => panic!("unexpected error kind: {:?}", other),
        }
    }

    #[test]
    fn invalid_field_length() {
        const MSG_LEN: usize = 2;

        let mut decoder = Decoder::new(&EXAMPLE_MSG[..MSG_LEN]).unwrap();
        let err = i8::decode(&mut decoder).err().unwrap();
        assert_eq!(Some(Length::from(2u8)), err.position());

        match err.kind() {
            ErrorKind::Incomplete {
                expected_len,
                actual_len,
            } => {
                assert_eq!(actual_len, MSG_LEN.try_into().unwrap());
                assert_eq!(expected_len, (MSG_LEN + 1).try_into().unwrap());
            }
            other => panic!("unexpected error kind: {:?}", other),
        }
    }

    #[test]
    fn trailing_data() {
        let mut decoder = Decoder::new(EXAMPLE_MSG).unwrap();
        let x = decoder.decode().unwrap();
        assert_eq!(42i8, x);

        let err = decoder.finish(x).err().unwrap();
        assert_eq!(Some(Length::from(3u8)), err.position());

        assert_eq!(
            ErrorKind::TrailingData {
                decoded: 3u8.into(),
                remaining: 1u8.into()
            },
            err.kind()
        );
    }

    #[test]
    fn peek_tag() {
        let decoder = Decoder::new(EXAMPLE_MSG).unwrap();
        assert_eq!(decoder.position(), Length::ZERO);
        assert_eq!(decoder.peek_tag().unwrap(), Tag::Integer);
        assert_eq!(decoder.position(), Length::ZERO); // Position unchanged
    }

    #[test]
    fn peek_header() {
        let decoder = Decoder::new(EXAMPLE_MSG).unwrap();
        assert_eq!(decoder.position(), Length::ZERO);

        let header = decoder.peek_header().unwrap();
        assert_eq!(header.tag, Tag::Integer);
        assert_eq!(header.length, Length::ONE);
        assert_eq!(decoder.position(), Length::ZERO); // Position unchanged
    }
}
