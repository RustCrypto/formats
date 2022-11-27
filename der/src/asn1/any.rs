//! ASN.1 `ANY` type.

use crate::{
    asn1::*, ByteSlice, Choice, Decode, DecodeValue, DerOrd, EncodeValue, Error, ErrorKind,
    FixedTag, Header, Length, Reader, Result, SliceReader, Tag, Tagged, ValueOrd, Writer,
};
use core::cmp::Ordering;

#[cfg(feature = "alloc")]
use crate::Bytes;

#[cfg(feature = "oid")]
use crate::asn1::ObjectIdentifier;

/// ASN.1 `ANY`: represents any explicitly tagged ASN.1 value.
///
/// This is a zero-copy reference type which borrows from the input data.
///
/// Technically `ANY` hasn't been a recommended part of ASN.1 since the X.209
/// revision from 1988. It was deprecated and replaced by Information Object
/// Classes in X.680 in 1994, and X.690 no longer refers to it whatsoever.
///
/// Nevertheless, this crate defines an `ANY` type as it remains a familiar
/// and useful concept which is still extensively used in things like
/// PKI-related RFCs.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct AnyRef<'a> {
    /// Tag representing the type of the encoded value.
    tag: Tag,

    /// Inner value encoded as bytes.
    value: ByteSlice<'a>,
}

impl<'a> AnyRef<'a> {
    /// [`AnyRef`] representation of the ASN.1 `NULL` type.
    pub const NULL: Self = Self {
        tag: Tag::Null,
        value: ByteSlice::EMPTY,
    };

    /// Create a new [`AnyRef`] from the provided [`Tag`] and DER bytes.
    pub fn new(tag: Tag, bytes: &'a [u8]) -> Result<Self> {
        let value = ByteSlice::new(bytes).map_err(|_| ErrorKind::Length { tag })?;
        Ok(Self { tag, value })
    }

    /// Infallible creation of an [`AnyRef`] from a [`ByteSlice`].
    pub(crate) fn from_tag_and_value(tag: Tag, value: ByteSlice<'a>) -> Self {
        Self { tag, value }
    }

    /// Get the raw value for this [`AnyRef`] type as a byte slice.
    pub fn value(self) -> &'a [u8] {
        self.value.as_slice()
    }

    /// Attempt to decode this [`AnyRef`] type into the inner value.
    pub fn decode_into<T>(self) -> Result<T>
    where
        T: DecodeValue<'a> + FixedTag,
    {
        self.tag.assert_eq(T::TAG)?;
        let header = Header {
            tag: self.tag,
            length: self.value.len(),
        };

        let mut decoder = SliceReader::new(self.value())?;
        let result = T::decode_value(&mut decoder, header)?;
        decoder.finish(result)
    }

    /// Is this value an ASN.1 `NULL` value?
    pub fn is_null(self) -> bool {
        self == Self::NULL
    }

    /// Attempt to decode an ASN.1 `BIT STRING`.
    pub fn bit_string(self) -> Result<BitStringRef<'a>> {
        self.try_into()
    }

    /// Attempt to decode an ASN.1 `CONTEXT-SPECIFIC` field.
    pub fn context_specific<T>(self) -> Result<ContextSpecific<T>>
    where
        T: Decode<'a>,
    {
        self.try_into()
    }

    /// Attempt to decode an ASN.1 `GeneralizedTime`.
    pub fn generalized_time(self) -> Result<GeneralizedTime> {
        self.try_into()
    }

    /// Attempt to decode an ASN.1 `OCTET STRING`.
    pub fn octet_string(self) -> Result<OctetStringRef<'a>> {
        self.try_into()
    }

    /// Attempt to decode an ASN.1 `OBJECT IDENTIFIER`.
    #[cfg(feature = "oid")]
    #[cfg_attr(docsrs, doc(cfg(feature = "oid")))]
    pub fn oid(self) -> Result<ObjectIdentifier> {
        self.try_into()
    }

    /// Attempt to decode an ASN.1 `OPTIONAL` value.
    pub fn optional<T>(self) -> Result<Option<T>>
    where
        T: Choice<'a> + TryFrom<Self, Error = Error>,
    {
        if T::can_decode(self.tag) {
            T::try_from(self).map(Some)
        } else {
            Ok(None)
        }
    }

    /// Attempt to decode this value an ASN.1 `SEQUENCE`, creating a new
    /// nested reader and calling the provided argument with it.
    pub fn sequence<F, T>(self, f: F) -> Result<T>
    where
        F: FnOnce(&mut SliceReader<'a>) -> Result<T>,
    {
        self.tag.assert_eq(Tag::Sequence)?;
        let mut reader = SliceReader::new(self.value.as_slice())?;
        let result = f(&mut reader)?;
        reader.finish(result)
    }

    /// Attempt to decode an ASN.1 `UTCTime`.
    pub fn utc_time(self) -> Result<UtcTime> {
        self.try_into()
    }
}

impl<'a> Choice<'a> for AnyRef<'a> {
    fn can_decode(_: Tag) -> bool {
        true
    }
}

impl<'a> Decode<'a> for AnyRef<'a> {
    fn decode<R: Reader<'a>>(reader: &mut R) -> Result<AnyRef<'a>> {
        let header = Header::decode(reader)?;

        Ok(Self {
            tag: header.tag,
            value: ByteSlice::decode_value(reader, header)?,
        })
    }
}

impl EncodeValue for AnyRef<'_> {
    fn value_len(&self) -> Result<Length> {
        Ok(self.value.len())
    }

    fn encode_value(&self, writer: &mut dyn Writer) -> Result<()> {
        writer.write(self.value())
    }
}

impl Tagged for AnyRef<'_> {
    fn tag(&self) -> Tag {
        self.tag
    }
}

#[cfg(feature = "alloc")]
impl ValueOrd for Any {
    fn value_cmp(&self, other: &Self) -> Result<Ordering> {
        self.value.der_cmp(&other.value)
    }
}

impl ValueOrd for AnyRef<'_> {
    fn value_cmp(&self, other: &Self) -> Result<Ordering> {
        self.value.der_cmp(&other.value)
    }
}

impl<'a> From<AnyRef<'a>> for ByteSlice<'a> {
    fn from(any: AnyRef<'a>) -> ByteSlice<'a> {
        any.value
    }
}

impl<'a> TryFrom<&'a [u8]> for AnyRef<'a> {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<AnyRef<'a>> {
        AnyRef::from_der(bytes)
    }
}

/// ASN.1 `ANY`: represents any explicitly tagged ASN.1 value.
///
/// This type provides the same functionality as [`AnyRef`] but owns the
/// backing data.
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Any {
    /// Tag representing the type of the encoded value.
    tag: Tag,

    /// Inner value encoded as bytes.
    value: Bytes,
}

#[cfg(feature = "alloc")]
impl Any {
    /// Create a new [`Any`] from the provided [`Tag`] and DER bytes.
    pub fn new(tag: Tag, bytes: &[u8]) -> Result<Self> {
        let value = Bytes::new(bytes)?;

        // Ensure the tag and value are a valid `AnyRef`.
        AnyRef::new(tag, value.as_slice())?;
        Ok(Self { tag, value })
    }

    /// Attempt to decode this [`Any`] type into the inner value.
    pub fn decode_into<'a, T>(&'a self) -> Result<T>
    where
        T: DecodeValue<'a> + FixedTag,
    {
        self.tag.assert_eq(T::TAG)?;
        let header = Header {
            tag: self.tag,
            length: self.value.len(),
        };

        let mut decoder = SliceReader::new(self.value.as_slice())?;
        let result = T::decode_value(&mut decoder, header)?;
        decoder.finish(result)
    }
}

#[cfg(feature = "alloc")]
impl Choice<'_> for Any {
    fn can_decode(_: Tag) -> bool {
        true
    }
}

#[cfg(feature = "alloc")]
impl<'a> Decode<'a> for Any {
    fn decode<R: Reader<'a>>(reader: &mut R) -> Result<Self> {
        let header = Header::decode(reader)?;
        let value = reader.read_vec(header.length)?;
        Self::new(header.tag, &value)
    }
}

#[cfg(feature = "alloc")]
impl EncodeValue for Any {
    fn value_len(&self) -> Result<Length> {
        Ok(self.value.len())
    }

    fn encode_value(&self, writer: &mut dyn Writer) -> Result<()> {
        writer.write(self.value.as_slice())
    }
}

#[cfg(feature = "alloc")]
impl<'a> From<&'a Any> for AnyRef<'a> {
    fn from(any: &'a Any) -> AnyRef<'a> {
        // Ensured to parse successfully in constructor
        AnyRef::new(any.tag, any.value.as_slice()).expect("invalid ANY")
    }
}

#[cfg(feature = "alloc")]
impl Tagged for Any {
    fn tag(&self) -> Tag {
        self.tag
    }
}

#[cfg(feature = "alloc")]
impl<'a, T> From<T> for Any
where
    T: Into<AnyRef<'a>>,
{
    fn from(input: T) -> Any {
        let anyref: AnyRef<'a> = input.into();
        Self {
            tag: anyref.tag(),
            value: Bytes::new(anyref.value()).expect("invalid ANY"),
        }
    }
}
