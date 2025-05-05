//! Context-specific field.

use crate::{
    Choice, Class, Decode, DecodeValue, DerOrd, Encode, EncodeValue, EncodeValueRef, Error, Header,
    Length, Reader, Tag, TagMode, TagNumber, Tagged, ValueOrd, Writer, asn1::AnyRef,
    tag::IsConstructed,
};
use core::cmp::Ordering;

/// Context-specific field which wraps an owned inner value.
///
/// This type decodes/encodes a field which is specific to a particular context
/// and is identified by a [`TagNumber`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct ContextSpecific<T> {
    /// Context-specific tag number sans the leading `0b10000000` class
    /// identifier bit and `0b100000` constructed flag.
    pub tag_number: TagNumber,

    /// Tag mode: `EXPLICIT` VS `IMPLICIT`.
    pub tag_mode: TagMode,

    /// Value of the field.
    pub value: T,
}

impl<T> ContextSpecific<T> {
    /// Attempt to decode an `EXPLICIT` ASN.1 `CONTEXT-SPECIFIC` field with the
    /// provided [`TagNumber`].
    ///
    /// This method has the following behavior which is designed to simplify
    /// handling of extension fields, which are denoted in an ASN.1 schema
    /// using the `...` ellipsis extension marker:
    ///
    /// - Skips over [`ContextSpecific`] fields with a tag number lower than
    ///   the current one, consuming and ignoring them.
    /// - Returns `Ok(None)` if a [`ContextSpecific`] field with a higher tag
    ///   number is encountered. These fields are not consumed in this case,
    ///   allowing a field with a lower tag number to be omitted, then the
    ///   higher numbered field consumed as a follow-up.
    /// - Returns `Ok(None)` if anything other than a [`ContextSpecific`] field
    ///   is encountered.
    pub fn decode_explicit<'a, R: Reader<'a>>(
        reader: &mut R,
        tag_number: TagNumber,
    ) -> Result<Option<Self>, T::Error>
    where
        T: Decode<'a>,
    {
        if !Tag::peek_matches(reader, Class::ContextSpecific, tag_number)? {
            return Ok(None);
        }
        Ok(Some(Self::decode(reader)?))
    }

    /// Attempt to decode an `IMPLICIT` ASN.1 `CONTEXT-SPECIFIC` field with the
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
        T: DecodeValue<'a> + IsConstructed,
    {
        // Peek tag number
        if !Tag::peek_matches(reader, Class::ContextSpecific, tag_number)? {
            return Ok(None);
        }
        // Decode IMPLICIT header
        let header = Header::decode(reader)?;

        // read_nested checks if header matches decoded length
        let value = reader.read_nested(header.length, |reader| {
            // Decode inner IMPLICIT value
            T::decode_value(reader, header)
        })?;

        // the encoding shall be constructed if the base encoding is constructed
        if header.tag.is_constructed() != T::CONSTRUCTED {
            return Err(header.tag.non_canonical_error().into());
        }

        Ok(Some(Self {
            tag_number,
            tag_mode: TagMode::Implicit,
            value,
        }))
    }
}

impl<'a, T> Choice<'a> for ContextSpecific<T>
where
    T: Decode<'a> + Tagged,
{
    fn can_decode(tag: Tag) -> bool {
        tag.is_context_specific()
    }
}

impl<'a, T> Decode<'a> for ContextSpecific<T>
where
    T: Decode<'a>,
{
    type Error = T::Error;

    fn decode<R: Reader<'a>>(reader: &mut R) -> Result<Self, Self::Error> {
        // Decode EXPLICIT header
        let header = Header::decode(reader)?;

        match header.tag {
            Tag::ContextSpecific {
                number,
                // encoding shall be constructed
                constructed: true,
            } => Ok(Self {
                tag_number: number,
                tag_mode: TagMode::default(),
                value: reader.read_nested(header.length, |reader| {
                    // Decode inner tag-length-value of EXPLICIT
                    T::decode(reader)
                })?,
            }),
            tag => Err(tag.unexpected_error(None).into()),
        }
    }
}

impl<T> EncodeValue for ContextSpecific<T>
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

impl<T> Tagged for ContextSpecific<T>
where
    T: Tagged,
{
    fn tag(&self) -> Tag {
        let constructed = match self.tag_mode {
            // ISO/IEC 8825-1:2021
            // 8.14.3 If implicit tagging (see Rec. ITU-T X.680 | ISO/IEC 8824-1, 31.2.7) was not used in the definition of the type, the
            // encoding shall be constructed and the contents octets shall be the complete base encoding [Encode].
            TagMode::Explicit => true,

            // ISO/IEC 8825-1:2021
            // 8.14.4 If implicit tagging was used in the definition of the type, then:
            // a) the encoding shall be constructed if the base encoding is constructed, and shall be primitive otherwise; and
            // b) the contents octets shall be the same as the contents octets [EncodeValue] of the base encoding.
            //
            // TODO(dishmaker): use IsConstructed trait for IMPLICIT
            TagMode::Implicit => self.value.tag().is_constructed(),
        };

        Tag::ContextSpecific {
            number: self.tag_number,
            constructed,
        }
    }
}

impl<'a, T> TryFrom<AnyRef<'a>> for ContextSpecific<T>
where
    T: Decode<'a>,
{
    type Error = T::Error;

    fn try_from(any: AnyRef<'a>) -> Result<ContextSpecific<T>, Self::Error> {
        match any.tag() {
            Tag::ContextSpecific {
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

impl<T> ValueOrd for ContextSpecific<T>
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

/// Context-specific field reference.
///
/// This type encodes a field which is specific to a particular context
/// and is identified by a [`TagNumber`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct ContextSpecificRef<'a, T> {
    /// Context-specific tag number sans the leading `0b10000000` class
    /// identifier bit and `0b100000` constructed flag.
    pub tag_number: TagNumber,

    /// Tag mode: `EXPLICIT` VS `IMPLICIT`.
    pub tag_mode: TagMode,

    /// Value of the field.
    pub value: &'a T,
}

impl<'a, T> ContextSpecificRef<'a, T> {
    /// Convert to a [`ContextSpecific`].
    fn encoder(&self) -> ContextSpecific<EncodeValueRef<'a, T>> {
        ContextSpecific {
            tag_number: self.tag_number,
            tag_mode: self.tag_mode,
            value: EncodeValueRef(self.value),
        }
    }
}

impl<T> EncodeValue for ContextSpecificRef<'_, T>
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

impl<T> Tagged for ContextSpecificRef<'_, T>
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
    use super::ContextSpecific;
    use crate::{
        Decode, Encode, SliceReader, TagMode, TagNumber,
        asn1::{BitStringRef, ContextSpecificRef, SetOf, Utf8StringRef},
    };
    use hex_literal::hex;

    // Public key data from `pkcs8` crate's `ed25519-pkcs8-v2.der`
    const EXAMPLE_BYTES: &[u8] =
        &hex!("A123032100A3A7EAE3A8373830BC47E1167BC50E1DB551999651E0E2DC587623438EAC3F31");

    #[test]
    fn round_trip() {
        let field = ContextSpecific::<BitStringRef<'_>>::from_der(EXAMPLE_BYTES).unwrap();
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
    fn context_specific_with_explicit_field() {
        let tag_number = TagNumber(0);

        // Empty message
        let mut reader = SliceReader::new(&[]).unwrap();
        assert_eq!(
            ContextSpecific::<u8>::decode_explicit(&mut reader, tag_number).unwrap(),
            None
        );

        // Message containing a non-context-specific type
        let mut reader = SliceReader::new(&hex!("020100")).unwrap();
        assert_eq!(
            ContextSpecific::<u8>::decode_explicit(&mut reader, tag_number).unwrap(),
            None
        );

        // Message containing an EXPLICIT context-specific field
        let mut reader = SliceReader::new(&hex!("A003020100")).unwrap();
        let field = ContextSpecific::<u8>::decode_explicit(&mut reader, tag_number)
            .unwrap()
            .unwrap();

        assert_eq!(field.tag_number, tag_number);
        assert_eq!(field.tag_mode, TagMode::Explicit);
        assert_eq!(field.value, 0);
    }

    #[test]
    fn context_specific_with_implicit_field() {
        // From RFC8410 Section 10.3:
        // <https://datatracker.ietf.org/doc/html/rfc8410#section-10.3>
        //
        //    81  33:   [1] 00 19 BF 44 09 69 84 CD FE 85 41 BA C1 67 DC 3B
        //                  96 C8 50 86 AA 30 B6 B6 CB 0C 5C 38 AD 70 31 66
        //                  E1
        let context_specific_implicit_bytes =
            hex!("81210019BF44096984CDFE8541BAC167DC3B96C85086AA30B6B6CB0C5C38AD703166E1");

        let tag_number = TagNumber(1);

        let mut reader = SliceReader::new(&context_specific_implicit_bytes).unwrap();
        let field = ContextSpecific::<BitStringRef<'_>>::decode_implicit(&mut reader, tag_number)
            .unwrap()
            .unwrap();

        assert_eq!(field.tag_number, tag_number);
        assert_eq!(field.tag_mode, TagMode::Implicit);
        assert_eq!(
            field.value.as_bytes().unwrap(),
            &context_specific_implicit_bytes[3..]
        );
    }

    #[test]
    fn context_specific_not_skipping_unknown_field() {
        let tag = TagNumber(1);
        let mut reader = SliceReader::new(&hex!("A003020100A103020101")).unwrap();
        let field = ContextSpecific::<u8>::decode_explicit(&mut reader, tag).unwrap();
        assert_eq!(field, None);
    }

    #[test]
    fn context_specific_returns_none_on_greater_tag_number() {
        let tag = TagNumber(0);
        let mut reader = SliceReader::new(&hex!("A103020101")).unwrap();
        assert_eq!(
            ContextSpecific::<u8>::decode_explicit(&mut reader, tag).unwrap(),
            None
        );
    }

    #[test]
    fn context_specific_explicit_ref() {
        let mut set = SetOf::new();
        set.insert(8u16).unwrap();
        set.insert(7u16).unwrap();

        let field = ContextSpecificRef::<SetOf<u16, 2>> {
            value: &set,
            tag_number: TagNumber(2),
            tag_mode: TagMode::Explicit,
        };

        let mut buf = [0u8; 16];
        let encoded = field.encode_to_slice(&mut buf).unwrap();
        assert_eq!(
            encoded,
            &[
                /* CONTEXT-SPECIFIC [2] */ 0xA2, 0x08, /* SET 0x11 | 0x20 */ 0x31, 0x06,
                /* INTEGER */ 0x02, 0x01, 0x07, /* INTEGER */ 0x02, 0x01, 0x08
            ]
        );

        let mut reader = SliceReader::new(encoded).unwrap();
        let field = ContextSpecific::<SetOf<u16, 2>>::decode_explicit(&mut reader, TagNumber(2))
            .unwrap()
            .unwrap();

        assert_eq!(field.value.len(), 2);
        assert_eq!(field.value.get(0).cloned(), Some(7));
        assert_eq!(field.value.get(1).cloned(), Some(8));
    }

    #[test]
    fn context_specific_implicit_ref() {
        let hello = Utf8StringRef::new("Hello").unwrap();
        let world = Utf8StringRef::new("world").unwrap();

        let mut set = SetOf::new();
        set.insert(hello).unwrap();
        set.insert(world).unwrap();

        let field = ContextSpecificRef::<SetOf<Utf8StringRef<'_>, 2>> {
            value: &set,
            tag_number: TagNumber(2),
            tag_mode: TagMode::Implicit,
        };

        let mut buf = [0u8; 16];
        let encoded = field.encode_to_slice(&mut buf).unwrap();
        assert_eq!(
            encoded,
            &[
                0xA2, 0x0E, // CONTEXT-SPECIFIC [2]
                0x0C, 0x05, b'H', b'e', b'l', b'l', b'o', // UTF8String "Hello"
                0x0C, 0x05, b'w', b'o', b'r', b'l', b'd', // UTF8String "world"
            ]
        );

        let mut reader = SliceReader::new(encoded).unwrap();
        let field = ContextSpecific::<SetOf<Utf8StringRef<'_>, 2>>::decode_implicit(
            &mut reader,
            TagNumber(2),
        )
        .unwrap()
        .unwrap();

        assert_eq!(field.value.len(), 2);
        assert_eq!(field.value.get(0).cloned(), Some(hello));
        assert_eq!(field.value.get(1).cloned(), Some(world));
    }
}
