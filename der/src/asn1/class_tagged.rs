use crate::{
    Class, Decode, DecodeValue, Encode, EncodeValue, Error, FixedTag, Header, Length, Reader, Tag,
    TagMode, TagNumber, Writer,
};

/// `APPLICATION`, `CONTEXT-SPECIFIC` or `PRIVATE` reference, with const `EXPLICIT` encoding.
///
///
/// This type encodes a field which is specific to a particular context
/// and is identified by a [`TagNumber`].
///
/// Inner value might implement [`Encode`], [`Decode`] or both.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct ClassTaggedExplicit<const NUMBER: u32, T, const CLASS_BITS: u8> {
    /// Inner value might implement [`Encode`], [`Decode`] or both.
    pub value: T,
}

impl<const NUMBER: u32, T, const CLASS_BITS: u8> ClassTaggedExplicit<NUMBER, T, CLASS_BITS> {
    /// Returns const [`TagNumber`], associated with this `EXPLICIT` tag wrapper.
    pub const fn tag_number() -> TagNumber {
        TagNumber(NUMBER)
    }

    /// Returns const [`TagMode::Explicit`], associated with this `EXPLICIT` tag wrapper.
    pub const fn tag_mode() -> TagMode {
        TagMode::Explicit
    }
}

impl<const NUMBER: u32, T, const CLASS_BITS: u8> EncodeValue
    for ClassTaggedExplicit<NUMBER, T, CLASS_BITS>
where
    T: Encode,
{
    fn value_len(&self) -> Result<Length, Error> {
        self.value.encoded_len()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), Error> {
        // Encode EXPLICIT value (with tag and length)
        self.value.encode(writer)
    }
}

impl<'a, const NUMBER: u32, T, const CLASS_BITS: u8> DecodeValue<'a>
    for ClassTaggedExplicit<NUMBER, T, CLASS_BITS>
where
    T: Decode<'a>,
{
    type Error = T::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self, Self::Error> {
        // encoding shall be constructed
        if !header.tag().is_constructed() {
            return Err(reader.error(header.tag().non_canonical_error()).into());
        }
        Ok(Self {
            value: T::decode(reader)?,
        })
    }
}

impl<const NUMBER: u32, T, const CLASS_BITS: u8> FixedTag
    for ClassTaggedExplicit<NUMBER, T, CLASS_BITS>
{
    const TAG: Tag = Tag::new_non_universal(Class::from_bits(CLASS_BITS), TagNumber(NUMBER), true);
}
