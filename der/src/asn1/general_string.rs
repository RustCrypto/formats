use crate::{BytesRef, DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Tag, Writer};

/// This is currently `OctetStringRef` internally, as `GeneralString` is not fully implemented yet
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GeneralStringRef<'a> {
    /// Raw contents, unchecked
    #[doc(hidden)]
    pub __contents: &'a [u8],
}
impl FixedTag for GeneralStringRef<'_> {
    const TAG: Tag = Tag::GeneralString;
}
impl<'a> DecodeValue<'a> for GeneralStringRef<'a> {
    type Error = crate::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self, Self::Error> {
        Ok(Self {
            __contents: BytesRef::decode_value(reader, header)?.as_slice(),
        })
    }
}
impl EncodeValue for GeneralStringRef<'_> {
    fn value_len(&self) -> crate::Result<Length> {
        BytesRef::new(self.__contents)?.value_len()
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> crate::Result<()> {
        BytesRef::new(self.__contents)?.encode_value(encoder)
    }
}
