use super::any_custom_class::{
    expected_tag_constructed, AnyCustomClassExplicit, AnyCustomClassImplicit,
};
use super::{AnyRef, Choice};
use crate::encode::Encode;
use crate::{
    Class, Decode, DecodeValue, DerOrd, EncodeValue, EncodeValueRef, Error, FixedTag, Header,
    Length, Reader, SliceReader, Tag, TagNumber, Tagged, ValueOrd, Writer,
};
use core::cmp::Ordering;

/// Application, Context-specific or Private class field which wraps an owned inner value.
///
/// This type decodes/encodes a field which is specific to a particular context
/// and is identified by a [`TagNumber`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct CustomClassExplicit<const TAG: u16, T, const CLASS: u8> {
    /// Value of the field.
    pub value: T,
}

/// Application, Context-specific or Private class field which wraps an owned inner value.
///
/// This type decodes/encodes a field which is specific to a particular context
/// and is identified by a [`TagNumber`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct CustomClassImplicit<const TAG: u16, T, const CLASS: u8> {
    /// Value of the field.
    pub value: T,
}

impl<const TAG: u16, T, const CLASS: u8> CustomClassExplicit<TAG, T, CLASS> {
    /// Attempt to decode an `EXPLICIT` ASN.1 custom-tagged field with the
    /// provided [`TagNumber`].
    ///
    /// This method has the following behavior:
    ///
    /// - Returns `Ok(None)` if a [`CustomClass`] field with a different tag
    ///   number is encountered. These fields are not consumed in this case,
    ///   allowing a field with a different tag number to be omitted, then the
    ///   matching field consumed as a follow-up.
    /// - Returns `Ok(None)` if anything other than a [`CustomClass`] field
    ///   is encountered.
    pub fn decode_skipping<'a, R: Reader<'a>>(reader: &mut R) -> Result<Option<Self>, T::Error>
    where
        T: Decode<'a>,
    {
        match AnyCustomClassExplicit::decode_skipping(Class::from(CLASS), TagNumber(TAG), reader) {
            Ok(Some(custom)) => Ok(Some(Self {
                value: custom.value,
            })),
            Ok(None) => Ok(None),
            Err(err) => Err(err),
        }
    }
}

impl<const TAG: u16, T, const CLASS: u8> CustomClassImplicit<TAG, T, CLASS> {
    /// Attempt to decode an `IMPLICIT` ASN.1 custom-tagged field with the
    /// provided [`TagNumber`].
    ///
    /// This method otherwise behaves the same as `decode_explicit`,
    /// but should be used in cases where the particular fields are `IMPLICIT`
    /// as opposed to `EXPLICIT`.
    pub fn decode_skipping<'a, R: Reader<'a>>(reader: &mut R) -> Result<Option<Self>, T::Error>
    where
        T: DecodeValue<'a> + Tagged + 'a,
    {
        match AnyCustomClassImplicit::decode_skipping(Class::from(CLASS), TagNumber(TAG), reader) {
            Ok(Some(custom)) => Ok(Some(Self {
                value: custom.value,
            })),
            Ok(None) => Ok(None),
            Err(err) => Err(err),
        }
    }
}

impl<'a, T, const TAG: u16, const CLASS: u8> Choice<'a> for CustomClassExplicit<TAG, T, CLASS>
where
    T: Decode<'a> + Tagged,
{
    fn can_decode(tag: Tag) -> bool {
        tag.class().bits() == CLASS && tag.number() == TagNumber(TAG)
    }
}

impl<'a, T, const TAG: u16, const CLASS: u8> Choice<'a> for CustomClassImplicit<TAG, T, CLASS>
where
    T: DecodeValue<'a> + FixedTag + 'a,
{
    fn can_decode(tag: Tag) -> bool {
        tag.class().bits() == CLASS
            && tag.number() == TagNumber(TAG)
            && tag.is_constructed() == <T as FixedTag>::TAG.is_constructed()
    }
}

impl<'a, T, const TAG: u16, const CLASS: u8> Decode<'a> for CustomClassExplicit<TAG, T, CLASS>
where
    T: Decode<'a>,
{
    type Error = T::Error;

    fn decode<R: Reader<'a>>(reader: &mut R) -> Result<Self, Self::Error> {
        match AnyCustomClassExplicit::<T>::decode_checked(
            Class::from(CLASS),
            TagNumber(TAG),
            reader,
        ) {
            Ok(custom) => Ok(Self {
                value: custom.value,
            }),
            Err(err) => Err(err),
        }
    }
}

impl<'a, T, const TAG: u16, const CLASS: u8> Decode<'a> for CustomClassImplicit<TAG, T, CLASS>
where
    T: Tagged + DecodeValue<'a> + 'a,
{
    type Error = T::Error;

    fn decode<R: Reader<'a>>(reader: &mut R) -> Result<Self, Self::Error> {
        match AnyCustomClassImplicit::<T>::decode_checked(
            Class::from(CLASS),
            TagNumber(TAG),
            reader,
        ) {
            Ok(custom) => Ok(Self {
                value: custom.value,
            }),
            Err(err) => Err(err),
        }
    }
}

impl<const TAG: u16, T, const CLASS: u8> EncodeValue for CustomClassExplicit<TAG, T, CLASS>
where
    T: EncodeValue + Tagged,
{
    fn value_len(&self) -> Result<Length, Error> {
        self.value.encoded_len()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), Error> {
        self.value.encode(writer)
    }
}

impl<const TAG: u16, T, const CLASS: u8> EncodeValue for CustomClassImplicit<TAG, T, CLASS>
where
    T: EncodeValue + Tagged,
{
    fn value_len(&self) -> Result<Length, Error> {
        self.value.value_len()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), Error> {
        self.value.encode_value(writer)
    }
}

impl<const TAG: u16, T, const CLASS: u8> Tagged for CustomClassExplicit<TAG, T, CLASS> {
    fn tag(&self) -> Tag {
        // ISO/IEC 8825-1:2021
        // 8.14.3 If implicit tagging (see Rec. ITU-T X.680 | ISO/IEC 8824-1, 31.2.7) was not used in the definition of the type, the
        // encoding shall be constructed and the contents octets shall be the complete base encoding [Encode].
        let constructed = true;
        expected_tag_constructed(Class::from(CLASS), TagNumber(TAG), constructed)
    }
}

impl<const TAG: u16, T, const CLASS: u8> Tagged for CustomClassImplicit<TAG, T, CLASS>
where
    T: FixedTag,
{
    fn tag(&self) -> Tag {
        // ISO/IEC 8825-1:2021
        // 8.14.4 If implicit tagging was used in the definition of the type, then:
        // a) the encoding shall be constructed if the base encoding is constructed, and shall be primitive otherwise; and
        // b) the contents octets shall be the same as the contents octets [EncodeValue] of the base encoding.
        let constructed = <T as FixedTag>::TAG.is_constructed();
        expected_tag_constructed(Class::from(CLASS), TagNumber(TAG), constructed)
    }
}

impl<'a, T, const TAG: u16, const CLASS: u8> TryFrom<AnyRef<'a>>
    for CustomClassExplicit<TAG, T, CLASS>
where
    T: Decode<'a>,
{
    type Error = T::Error;

    fn try_from(any: AnyRef<'a>) -> Result<Self, Self::Error> {
        let tag = any.tag();
        // currently accepts constructed and not constructed
        if tag.class().bits() == CLASS {
            Ok(Self {
                value: T::from_der(any.value())?,
            })
        } else {
            let expected = expected_tag_constructed(Class::from(CLASS), TagNumber(TAG), true);
            Err(tag.unexpected_error(Some(expected)).into())
        }
    }
}

impl<'a, T, const TAG: u16, const CLASS: u8> TryFrom<AnyRef<'a>>
    for CustomClassImplicit<TAG, T, CLASS>
where
    T: DecodeValue<'a>,
{
    type Error = T::Error;

    fn try_from(any: AnyRef<'a>) -> Result<Self, Self::Error> {
        let tag: Tag = any.tag();
        // currently accepts constructed and not constructed
        if tag.class().bits() == CLASS {
            let content = any.value();
            // TODO(dishmaker): test
            let mut reader = SliceReader::new(content)?;
            let value = T::decode_value(
                &mut reader,
                Header {
                    tag,
                    length: content.len().try_into()?,
                },
            )?;

            Ok(Self { value })
        } else {
            let expected = expected_tag_constructed(Class::from(CLASS), TagNumber(TAG), true);
            Err(tag.unexpected_error(Some(expected)).into())
        }
    }
}

impl<const TAG: u16, T, const CLASS: u8> ValueOrd for CustomClassExplicit<TAG, T, CLASS>
where
    T: DerOrd,
{
    fn value_cmp(&self, other: &Self) -> Result<Ordering, Error> {
        self.value.der_cmp(&other.value)
    }
}

impl<const TAG: u16, T, const CLASS: u8> ValueOrd for CustomClassImplicit<TAG, T, CLASS>
where
    T: ValueOrd,
{
    fn value_cmp(&self, other: &Self) -> Result<Ordering, Error> {
        self.value.value_cmp(&other.value)
    }
}

/// Custom class field reference.
///
/// This type encodes an `EXPLICIT` field with custom class tag, for example [`Class::ContextSpecific`]
/// and is identified by a [`TagNumber`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct CustomClassExplicitRef<'a, const TAG: u16, T, const CLASS: u8> {
    /// Value of the field.
    pub value: &'a T,
}

impl<'a, const TAG: u16, T, const CLASS: u8> CustomClassExplicitRef<'a, TAG, T, CLASS> {
    /// Convert to a [`CustomClassExplicit`].
    fn encoder(&self) -> CustomClassExplicit<TAG, EncodeValueRef<'a, T>, CLASS> {
        CustomClassExplicit {
            value: EncodeValueRef(self.value),
        }
    }
}

impl<'a, const TAG: u16, T, const CLASS: u8> EncodeValue
    for CustomClassExplicitRef<'a, TAG, T, CLASS>
where
    T: EncodeValue + Tagged,
{
    fn value_len(&self) -> Result<Length, Error> {
        self.encoder().value_len()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), Error> {
        self.encoder().encode_value(writer)
    }
}

impl<'a, const TAG: u16, T, const CLASS: u8> Tagged for CustomClassExplicitRef<'a, TAG, T, CLASS> {
    fn tag(&self) -> Tag {
        self.encoder().tag()
    }
}

/// Custom class field reference.
///
/// This type encodes an `EXPLICIT` field with custom class tag, for example [`Class::ContextSpecific`]
/// and is identified by a [`TagNumber`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct CustomClassImplicitRef<'a, const TAG: u16, T, const CLASS: u8> {
    /// Value of the field.
    pub value: &'a T,
}

impl<'a, const TAG: u16, T, const CLASS: u8> CustomClassImplicitRef<'a, TAG, T, CLASS> {
    /// Convert to a [`CustomClassImplicit`].
    fn encoder(&self) -> CustomClassImplicit<TAG, EncodeValueRef<'a, T>, CLASS> {
        CustomClassImplicit {
            value: EncodeValueRef(self.value),
        }
    }
}

impl<'a, const TAG: u16, T, const CLASS: u8> EncodeValue
    for CustomClassImplicitRef<'a, TAG, T, CLASS>
where
    T: EncodeValue + Tagged,
{
    fn value_len(&self) -> Result<Length, Error> {
        self.encoder().value_len()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), Error> {
        self.encoder().encode_value(writer)
    }
}

impl<'a, const TAG: u16, T, const CLASS: u8> Tagged for CustomClassImplicitRef<'a, TAG, T, CLASS>
where
    T: Tagged,
{
    fn tag(&self) -> Tag {
        let constructed = self.value.tag().is_constructed();
        expected_tag_constructed(Class::from(CLASS), TagNumber(TAG), constructed)
    }
}
