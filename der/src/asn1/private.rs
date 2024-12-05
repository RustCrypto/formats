//! Private field.

use crate::{
    asn1::AnyRef, Choice, Decode, DecodeValue, DerOrd, Encode, EncodeValue, EncodeValueRef, Error,
    Header, Length, Reader, Tag, TagMode, TagNumber, Tagged, ValueOrd, Writer,
};
use core::cmp::Ordering;

/// Private field which wraps an owned inner value.
///
/// This type encodes a field which is whose meaning is specific to a given
/// enterprise and is identified by a [`TagNumber`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Private<T> {
    /// Private tag number sans the leading `0b10000000` class
    /// identifier bit and `0b100000` constructed flag.
    pub tag_number: TagNumber,

    /// Tag mode: `EXPLICIT` VS `IMPLICIT`.
    pub tag_mode: TagMode,

    /// Value of the field.
    pub value: T,
}

impl<T> Private<T> {
    /// Attempt to decode an `EXPLICIT` ASN.1 `PRIVATE` field with the
    /// provided [`TagNumber`].
    ///
    /// This method has the following behavior:
    ///
    /// - Returns `Ok(None)` if a [`Private`] field with a different tag
    ///   number is encountered. These fields are not consumed in this case,
    ///   allowing a field with a different tag number to be omitted, then the
    ///   matching field consumed as a follow-up.
    /// - Returns `Ok(None)` if anything other than a [`Private`] field
    ///   is encountered.
    pub fn decode_explicit<'a, R: Reader<'a>>(
        reader: &mut R,
        tag_number: TagNumber,
    ) -> Result<Option<Self>, T::Error>
    where
        T: Decode<'a>,
    {
        Self::decode_with(reader, tag_number, |reader| Self::decode(reader))
    }

    /// Attempt to decode an `IMPLICIT` ASN.1 `PRIVATE` field with the
    /// provided [`TagNumber`].
    ///
    /// This method otherwise behaves the same as `decode_explicit`,
    /// but should be used in cases where the particular fields are `IMPLICIT`
    /// as opposed to `EXPLICIT`.
    pub fn decode_implicit<'a, R: Reader<'a>>(
        reader: &mut R,
        tag_number: TagNumber,
    ) -> Result<Option<Self>, T::Error>
    where
        T: DecodeValue<'a> + Tagged,
    {
        Self::decode_with::<_, _, T::Error>(reader, tag_number, |reader| {
            let header = Header::decode(reader)?;
            let value = T::decode_value(reader, header)?;

            if header.tag.is_constructed() != value.tag().is_constructed() {
                return Err(header.tag.non_canonical_error().into());
            }

            Ok(Self {
                tag_number,
                tag_mode: TagMode::Implicit,
                value,
            })
        })
    }

    /// Attempt to decode a private field with the given
    /// helper callback.
    fn decode_with<'a, F, R: Reader<'a>, E>(
        reader: &mut R,
        tag_number: TagNumber,
        f: F,
    ) -> Result<Option<Self>, E>
    where
        F: FnOnce(&mut R) -> Result<Self, E>,
        E: From<Error>,
    {
        while let Some(tag) = Tag::peek_optional(reader)? {
            if !tag.is_private() || (tag.number() != tag_number) {
                break;
            } else {
                return Some(f(reader)).transpose();
            }
        }

        Ok(None)
    }
}

impl<'a, T> Choice<'a> for Private<T>
where
    T: Decode<'a> + Tagged,
{
    fn can_decode(tag: Tag) -> bool {
        tag.is_private()
    }
}

impl<'a, T> Decode<'a> for Private<T>
where
    T: Decode<'a>,
{
    type Error = T::Error;

    fn decode<R: Reader<'a>>(reader: &mut R) -> Result<Self, Self::Error> {
        let header = Header::decode(reader)?;

        match header.tag {
            Tag::Private {
                number,
                constructed: true,
            } => Ok(Self {
                tag_number: number,
                tag_mode: TagMode::default(),
                value: reader.read_nested(header.length, |reader| T::decode(reader))?,
            }),
            tag => Err(tag.unexpected_error(None).into()),
        }
    }
}

impl<T> EncodeValue for Private<T>
where
    T: EncodeValue + Tagged,
{
    fn value_len(&self) -> Result<Length, Error> {
        match self.tag_mode {
            TagMode::Explicit => self.value.encoded_len(),
            TagMode::Implicit => self.value.value_len(),
        }
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), Error> {
        match self.tag_mode {
            TagMode::Explicit => self.value.encode(writer),
            TagMode::Implicit => self.value.encode_value(writer),
        }
    }
}

impl<T> Tagged for Private<T>
where
    T: Tagged,
{
    fn tag(&self) -> Tag {
        let constructed = match self.tag_mode {
            TagMode::Explicit => true,
            TagMode::Implicit => self.value.tag().is_constructed(),
        };

        Tag::Private {
            number: self.tag_number,
            constructed,
        }
    }
}

impl<'a, T> TryFrom<AnyRef<'a>> for Private<T>
where
    T: Decode<'a>,
{
    type Error = T::Error;

    fn try_from(any: AnyRef<'a>) -> Result<Private<T>, Self::Error> {
        match any.tag() {
            Tag::Private {
                number,
                constructed: true,
            } => Ok(Self {
                tag_number: number,
                tag_mode: TagMode::default(),
                value: T::from_der(any.value())?,
            }),
            tag => Err(tag.unexpected_error(None).into()),
        }
    }
}

impl<T> ValueOrd for Private<T>
where
    T: EncodeValue + ValueOrd + Tagged,
{
    fn value_cmp(&self, other: &Self) -> Result<Ordering, Error> {
        match self.tag_mode {
            TagMode::Explicit => self.der_cmp(other),
            TagMode::Implicit => self.value_cmp(other),
        }
    }
}

/// Private field reference.
///
/// This type encodes a field which is whose meaning is specific to a given
/// enterprise and is identified by a [`TagNumber`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct PrivateRef<'a, T> {
    /// Private tag number sans the leading `0b11000000` class
    /// identifier bit and `0b100000` constructed flag.
    pub tag_number: TagNumber,

    /// Tag mode: `EXPLICIT` VS `IMPLICIT`.
    pub tag_mode: TagMode,

    /// Value of the field.
    pub value: &'a T,
}

impl<'a, T> PrivateRef<'a, T> {
    /// Convert to a [`Private`].
    fn encoder(&self) -> Private<EncodeValueRef<'a, T>> {
        Private {
            tag_number: self.tag_number,
            tag_mode: self.tag_mode,
            value: EncodeValueRef(self.value),
        }
    }
}

impl<'a, T> EncodeValue for PrivateRef<'a, T>
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

impl<'a, T> Tagged for PrivateRef<'a, T>
where
    T: Tagged,
{
    fn tag(&self) -> Tag {
        self.encoder().tag()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::Private;
    use crate::{asn1::BitStringRef, Decode, Encode, SliceReader, TagMode, TagNumber};
    use hex_literal::hex;

    // Public key data from `pkcs8` crate's `ed25519-pkcs8-v2.der`
    const EXAMPLE_BYTES: &[u8] =
        &hex!("A123032100A3A7EAE3A8373830BC47E1167BC50E1DB551999651E0E2DC587623438EAC3F31");

    #[test]
    fn round_trip() {
        let field = Private::<BitStringRef<'_>>::from_der(EXAMPLE_BYTES).unwrap();
        assert_eq!(field.tag_number.value(), 1);
        assert_eq!(
            field.value,
            BitStringRef::from_bytes(&EXAMPLE_BYTES[5..]).unwrap()
        );

        let mut buf = [0u8; 128];
        let encoded = field.encode_to_slice(&mut buf).unwrap();
        assert_eq!(encoded, EXAMPLE_BYTES);
    }

    #[test]
    fn private_with_explicit_field() {
        let tag_number = TagNumber::new(0);

        // Empty message
        let mut reader = SliceReader::new(&[]).unwrap();
        assert_eq!(
            Private::<u8>::decode_explicit(&mut reader, tag_number).unwrap(),
            None
        );

        // Message containing a non-private type
        let mut reader = SliceReader::new(&hex!("020100")).unwrap();
        assert_eq!(
            Private::<u8>::decode_explicit(&mut reader, tag_number).unwrap(),
            None
        );

        // Message containing an EXPLICIT private field
        let mut reader = SliceReader::new(&hex!("A003020100")).unwrap();
        let field = Private::<u8>::decode_explicit(&mut reader, tag_number)
            .unwrap()
            .unwrap();

        assert_eq!(field.tag_number, tag_number);
        assert_eq!(field.tag_mode, TagMode::Explicit);
        assert_eq!(field.value, 0);
    }

    #[test]
    fn private_with_implicit_field() {
        // From RFC8410 Section 10.3:
        // <https://datatracker.ietf.org/doc/html/rfc8410#section-10.3>
        //
        //    81  33:   [1] 00 19 BF 44 09 69 84 CD FE 85 41 BA C1 67 DC 3B
        //                  96 C8 50 86 AA 30 B6 B6 CB 0C 5C 38 AD 70 31 66
        //                  E1
        let private_implicit_bytes =
            hex!("81210019BF44096984CDFE8541BAC167DC3B96C85086AA30B6B6CB0C5C38AD703166E1");

        let tag_number = TagNumber::new(1);

        let mut reader = SliceReader::new(&private_implicit_bytes).unwrap();
        let field = Private::<BitStringRef<'_>>::decode_implicit(&mut reader, tag_number)
            .unwrap()
            .unwrap();

        assert_eq!(field.tag_number, tag_number);
        assert_eq!(field.tag_mode, TagMode::Implicit);
        assert_eq!(
            field.value.as_bytes().unwrap(),
            &private_implicit_bytes[3..]
        );
    }

    #[test]
    fn private_skipping_unknown_field() {
        let tag = TagNumber::new(1);
        let mut reader = SliceReader::new(&hex!("A003020100A103020101")).unwrap();
        let field = Private::<u8>::decode_explicit(&mut reader, tag)
            .unwrap()
            .unwrap();
        assert_eq!(field.value, 1);
    }

    #[test]
    fn private_returns_none_on_greater_tag_number() {
        let tag = TagNumber::new(0);
        let mut reader = SliceReader::new(&hex!("A103020101")).unwrap();
        assert_eq!(
            Private::<u8>::decode_explicit(&mut reader, tag).unwrap(),
            None
        );
    }
}
