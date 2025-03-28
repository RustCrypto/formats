//! Less strict Context-specific, Application or Private field.

use crate::{
    Class, Decode, DecodeValue, Encode, EncodeValue, Error, Header, Length, Reader, Tag, TagNumber,
    Tagged, Writer,
};

use super::AnyRef;

/// `APPLICATION`, `CONTEXT-SPECIFIC` or `PRIVATE` tagged value.
///
/// `EXPLICIT` encoding - always constructed.
pub struct AnyCustomClassExplicit<T> {
    /// Value of the field. Should implement [`Decode`]
    pub value: T,

    /// Class of the field.
    ///
    /// Supported classes: [`Class::Application`], [`Class::ContextSpecific`], [`Class::Private`]
    pub class: Class,

    /// Tag number without the leading class bits `0b11000000`
    /// and without constructed `0b00100000` flag.
    pub tag_number: TagNumber,
}

/// `APPLICATION`, `CONTEXT-SPECIFIC` or `PRIVATE` tagged value.
///
/// `IMPLICIT` encoding - constructed bit should match inner value's tag.
pub struct AnyCustomClassImplicit<T> {
    /// Value of the field. Should implement [`DecodeValue`]
    pub value: T,

    /// Class of the field.
    ///
    /// Supported classes: [`Class::Application`], [`Class::ContextSpecific`], [`Class::Private`]
    pub class: Class,

    /// Tag number without the leading class bits `0b11000000`
    /// and without constructed `0b00100000` flag.
    pub tag_number: TagNumber,

    /// Constructed flag. Should match value's tag constructed flag.
    pub constructed: bool,
}

impl<'a, T> AnyCustomClassExplicit<T>
where
    T: Decode<'a>,
{
    /// Decodes `APPLICATION`, `CONTEXT-SPECIFIC` or `PRIVATE` tagged value.
    ///
    /// Returns Ok only if both [`Class`] and [`TagNumber`] match the decoded tag.
    ///
    /// Skips `CONTEXT-SPECIFIC` fields, lower than [`TagNumber`].
    pub fn peek_decode_optional<R: Reader<'a>>(
        class: Class,
        tag_number: TagNumber,
        reader: &mut R,
    ) -> Result<Option<Self>, T::Error> {
        peek_decode_optional(reader, class, tag_number, |reader| {
            Self::decode_checked(class, tag_number, reader)
        })
    }

    /// Decodes `APPLICATION`, `CONTEXT-SPECIFIC` or `PRIVATE` tagged value.
    ///
    /// Returns Ok only if both [`Class`] and [`TagNumber`] match the decoded tag.
    pub fn decode_checked<R: Reader<'a>>(
        class: Class,
        tag_number: TagNumber,
        reader: &mut R,
    ) -> Result<Self, T::Error> {
        let any_explicit = Self::decode(reader)?;

        if any_explicit.class == class && any_explicit.tag_number == tag_number {
            Ok(any_explicit)
        } else {
            let expected = tag_number.custom_class(class, true);
            Err(any_explicit.tag().unexpected_error(expected).into())
        }
    }
}

impl<'a, T> AnyCustomClassImplicit<T>
where
    T: Tagged + DecodeValue<'a> + 'a,
{
    /// Decodes `APPLICATION`, `CONTEXT-SPECIFIC` or `PRIVATE` tagged value.
    ///
    /// Returns Ok only if both [`Class`] and [`TagNumber`] match the decoded tag.
    ///
    /// Skips `CONTEXT-SPECIFIC` fields, lower than [`TagNumber`].
    pub fn peek_decode_optional<R: Reader<'a>>(
        class: Class,
        tag_number: TagNumber,
        constructed: bool,
        reader: &mut R,
    ) -> Result<Option<Self>, T::Error> {
        peek_decode_optional::<_, _, T::Error, _>(reader, class, tag_number, |reader| {
            Self::decode_checked(class, tag_number, constructed, reader)
        })
    }

    /// Decodes `APPLICATION`, `CONTEXT-SPECIFIC` or `PRIVATE` tagged value.
    ///
    /// Returns Ok only if both [`Class`] and [`TagNumber`] match the decoded tag.
    pub fn decode_checked<R: Reader<'a>>(
        class: Class,
        tag_number: TagNumber,
        constructed: bool,
        reader: &mut R,
    ) -> Result<Self, T::Error> {
        let any_implicit = Self::decode(reader)?;
        if any_implicit.class == class
            && any_implicit.tag_number == tag_number
            && any_implicit.constructed == constructed
        {
            Ok(any_implicit)
        } else {
            let expected = tag_number.custom_class(class, any_implicit.constructed);
            Err(any_implicit.tag().unexpected_error(expected).into())
        }
    }
}

impl<'a, T> Decode<'a> for AnyCustomClassExplicit<T>
where
    T: Decode<'a>,
{
    type Error = T::Error;

    fn decode<R: Reader<'a>>(reader: &mut R) -> Result<Self, Self::Error> {
        let header = Header::decode(reader)?;

        if !header.tag.is_constructed() {
            return Err(header.tag.non_canonical_error().into());
        }

        Ok(Self {
            value: reader.read_nested(header.length, |reader| T::decode(reader))?,
            class: header.tag.class(),
            tag_number: header.tag.number(),
        })
    }
}

impl<'a, T> Decode<'a> for AnyCustomClassImplicit<T>
where
    T: Tagged + DecodeValue<'a> + 'a,
{
    type Error = T::Error;

    fn decode<R: Reader<'a>>(reader: &mut R) -> Result<Self, Self::Error> {
        let header = Header::decode(reader)?;

        let value = reader.read_nested(header.length, |reader| T::decode_value(reader, header))?;

        if header.tag.is_constructed() != value.tag().is_constructed() {
            return Err(header.tag.non_canonical_error().into());
        }
        Ok(Self {
            value,
            class: header.tag.class(),
            tag_number: header.tag.number(),
            constructed: header.tag.is_constructed(),
        })
    }
}

impl<T> EncodeValue for AnyCustomClassExplicit<T>
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

impl<T> EncodeValue for AnyCustomClassImplicit<T>
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

impl<T> Tagged for AnyCustomClassExplicit<T> {
    fn tag(&self) -> Tag {
        self.tag_number
            .custom_class(self.class, true)
            .expect("class not to be Universal")
    }
}

impl<T> Tagged for AnyCustomClassImplicit<T> {
    fn tag(&self) -> Tag {
        self.tag_number
            .custom_class(self.class, self.constructed)
            .expect("class not to be Universal")
    }
}

/// Attempt to decode a custom class-tagged field with the given
/// helper callback.
fn peek_decode_optional<'a, F, R: Reader<'a>, E, T>(
    reader: &mut R,
    expected_class: Class,
    expected_number: TagNumber,
    f: F,
) -> Result<Option<T>, E>
where
    F: FnOnce(&mut R) -> Result<T, E>,
    E: From<Error>,
{
    while let Some(tag) = Tag::peek_optional(reader)? {
        if is_unskippable_tag(tag, expected_class, expected_number) {
            break;
        } else if tag.number() == expected_number {
            return Some(f(reader)).transpose();
        } else {
            AnyRef::decode(reader)?;
        }
    }

    Ok(None)
}

/// Returns if this tag is of different class than eg. CONTEXT-SPECIFIC
/// or tag number is higher than expected
fn is_unskippable_tag(tag: Tag, expected_class: Class, expected_number: TagNumber) -> bool {
    if expected_class != tag.class() {
        return true;
    }
    match expected_class {
        Class::Application => tag.number() > expected_number,
        Class::ContextSpecific => tag.number() > expected_number,
        Class::Private => tag.number() != expected_number,

        // probably unreachable
        Class::Universal => tag.number() != expected_number,
    }
}
