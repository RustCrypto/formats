use crate::{DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Tag, Writer};

use super::OctetStringRef;

/// This is currently `OctetStringRef` as `GeneralString` is not part of the `der` crate
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GeneralStringRef<'a> {
    /// Raw contents, unchecked
    #[doc(hidden)]
    pub __contents: OctetStringRef<'a>,
}
impl FixedTag for GeneralStringRef<'_> {
    const TAG: Tag = Tag::GeneralString;
}
impl<'a> DecodeValue<'a> for GeneralStringRef<'a> {
    type Error = crate::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self, Self::Error> {
        Ok(Self {
            __contents: OctetStringRef::decode_value(reader, header)?,
        })
    }
}
impl EncodeValue for GeneralStringRef<'_> {
    fn value_len(&self) -> crate::Result<Length> {
        self.__contents.value_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> crate::Result<()> {
        self.__contents.encode_value(encoder)
    }
}
