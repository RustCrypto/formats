//! ASN.1 `NULL` support.

use crate::{
    asn1::Any, ord::OrdIsValueOrd, ByteSlice, DecodeValue, EncodeValue, Error, ErrorKind, FixedTag,
    Header, Length, Reader, Result, Tag, Writer,
};

/// ASN.1 `NULL` type.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Null;

impl<'a> DecodeValue<'a> for Null {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        if header.length.is_zero() {
            Ok(Null)
        } else {
            Err(reader.error(ErrorKind::Length { tag: Self::TAG }))
        }
    }
}

impl EncodeValue for Null {
    fn value_len(&self) -> Result<Length> {
        Ok(Length::ZERO)
    }

    fn encode_value(&self, _writer: &mut dyn Writer) -> Result<()> {
        Ok(())
    }
}

impl FixedTag for Null {
    const TAG: Tag = Tag::Null;
}

impl OrdIsValueOrd for Null {}

impl<'a> From<Null> for Any<'a> {
    fn from(_: Null) -> Any<'a> {
        Any::from_tag_and_value(Tag::Null, ByteSlice::default())
    }
}

impl TryFrom<Any<'_>> for Null {
    type Error = Error;

    fn try_from(any: Any<'_>) -> Result<Null> {
        any.decode_into()
    }
}

impl TryFrom<Any<'_>> for () {
    type Error = Error;

    fn try_from(any: Any<'_>) -> Result<()> {
        Null::try_from(any).map(|_| ())
    }
}

impl<'a> From<()> for Any<'a> {
    fn from(_: ()) -> Any<'a> {
        Null.into()
    }
}

impl<'a> DecodeValue<'a> for () {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        Null::decode_value(reader, header)?;
        Ok(())
    }
}

impl EncodeValue for () {
    fn value_len(&self) -> Result<Length> {
        Ok(Length::ZERO)
    }

    fn encode_value(&self, _writer: &mut dyn Writer) -> Result<()> {
        Ok(())
    }
}

impl FixedTag for () {
    const TAG: Tag = Tag::Null;
}

#[cfg(test)]
mod tests {
    use super::Null;
    use crate::{Decode, Encode};

    #[test]
    fn decode() {
        Null::from_der(&[0x05, 0x00]).unwrap();
    }

    #[test]
    fn encode() {
        let mut buffer = [0u8; 2];
        assert_eq!(&[0x05, 0x00], Null.encode_to_slice(&mut buffer).unwrap());
        assert_eq!(&[0x05, 0x00], ().encode_to_slice(&mut buffer).unwrap());
    }

    #[test]
    fn reject_non_canonical() {
        assert!(Null::from_der(&[0x05, 0x81, 0x00]).is_err());
    }
}
