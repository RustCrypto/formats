//! ASN.1 `ANY` type.

use crate::{
    asn1::*, ByteSlice, Choice, Decodable, Decoder, Encodable, Encoder, Error, ErrorKind, Header,
    Length, Result, Tag,
};
use core::convert::{TryFrom, TryInto};

#[cfg(feature = "oid")]
use crate::asn1::ObjectIdentifier;

/// ASN.1 `ANY`: represents any explicitly tagged ASN.1 value.
///
/// Technically `ANY` hasn't been a recommended part of ASN.1 since the X.209
/// revision from 1988. It was deprecated and replaced by Information Object
/// Classes in X.680 in 1994, and X.690 no longer refers to it whatsoever.
///
/// Nevertheless, this crate defines an [`Any`] type as it remains a familiar
/// and useful concept which is still extensively used in things like
/// PKI-related RFCs.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Any<'a> {
    /// Tag representing the type of the encoded value.
    tag: Tag,

    /// Encoded length of this [`Any`] value.
    length: Length,

    /// An optional "leading octet" of the inner value, stored separately
    /// from the rest.
    ///
    /// This allows adding a 1-byte prefix to any value, when the rest may come
    /// from an existing slice.
    ///
    /// It's used for the encoding of `BIT STRING` (which has a leading `0`
    /// byte) as well as any `IMPLICIT` value which decodes to a `BIT STRING`.
    leading_octet: Option<u8>,

    /// Inner value encoded as bytes.
    value: ByteSlice<'a>,
}

impl<'a> Any<'a> {
    /// Create a new [`Any`] from the provided [`Tag`] and byte slice.
    pub fn new(tag: Tag, bytes: &'a [u8]) -> Result<Self> {
        let value = ByteSlice::new(bytes).map_err(|_| ErrorKind::Length { tag })?;
        Ok(Self::from_tag_and_value(tag, value))
    }

    /// Infallible creation of an [`Any`] from a [`ByteSlice`].
    pub(crate) fn from_tag_and_value(tag: Tag, value: ByteSlice<'a>) -> Self {
        Self {
            tag,
            length: value.len(),
            leading_octet: None,
            value,
        }
    }

    /// Infallible creation of an [`Any`] with a leading octet from a [`ByteSlice`].
    pub(crate) fn from_tag_and_octet_prefixed_value(
        tag: Tag,
        octet: u8,
        value: ByteSlice<'a>,
    ) -> Result<Self> {
        let length = (value.len() + Length::ONE)?;

        Ok(Self {
            tag,
            length,
            leading_octet: Some(octet),
            value,
        })
    }

    /// Get the tag for this [`Any`] type.
    pub fn tag(self) -> Tag {
        self.tag
    }

    /// Get the [`Length`] of this [`Any`] type's value.
    pub fn len(self) -> Length {
        self.length
    }

    /// Is the body of this [`Any`] type empty?
    pub fn is_empty(self) -> bool {
        self.value.is_empty()
    }

    /// Is this value an ASN.1 NULL value?
    pub fn is_null(self) -> bool {
        Null::try_from(self).is_ok()
    }

    /// Get the raw value for this [`Any`] type as a byte slice.
    pub fn as_bytes(self) -> &'a [u8] {
        self.value.as_bytes()
    }

    /// Attempt to decode an ASN.1 `BIT STRING`.
    pub fn bit_string(self) -> Result<BitString<'a>> {
        self.try_into()
    }

    /// Attempt to decode an ASN.1 `CONTEXT-SPECIFIC` field.
    pub fn context_specific(self) -> Result<ContextSpecific<'a>> {
        self.try_into()
    }

    /// Attempt to decode an ASN.1 `GeneralizedTime`.
    pub fn generalized_time(self) -> Result<GeneralizedTime> {
        self.try_into()
    }

    /// Attempt to decode an ASN.1 `IA5String`.
    pub fn ia5_string(self) -> Result<Ia5String<'a>> {
        self.try_into()
    }

    /// Attempt to decode an ASN.1 `OCTET STRING`.
    pub fn octet_string(self) -> Result<OctetString<'a>> {
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

    /// Attempt to decode an ASN.1 `PrintableString`.
    pub fn printable_string(self) -> Result<PrintableString<'a>> {
        self.try_into()
    }

    /// Attempt to decode this value an ASN.1 `SEQUENCE`, creating a new
    /// nested [`Decoder`] and calling the provided argument with it.
    pub fn sequence<F, T>(self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Decoder<'a>) -> Result<T>,
    {
        Sequence::try_from(self)?.decode_nested(f)
    }

    /// Attempt to decode an ASN.1 `UTCTime`.
    pub fn utc_time(self) -> Result<UtcTime> {
        self.try_into()
    }

    /// Attempt to decode an ASN.1 `UTF8String`.
    pub fn utf8_string(self) -> Result<Utf8String<'a>> {
        self.try_into()
    }

    /// Get the leading octet of this `Any` if one is present.
    pub(crate) fn leading_octet(self) -> Option<u8> {
        self.leading_octet
    }
}

impl<'a> Choice<'a> for Any<'a> {
    fn can_decode(_: Tag) -> bool {
        true
    }
}

impl<'a> Decodable<'a> for Any<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> Result<Any<'a>> {
        let header = Header::decode(decoder)?;
        let tag = header.tag;
        let value = decoder
            .bytes(header.length)
            .map_err(|_| decoder.error(ErrorKind::Length { tag }))?;

        Self::new(tag, value).map_err(|e| decoder.error(e.kind()))
    }
}

impl<'a> Encodable for Any<'a> {
    fn encoded_len(&self) -> Result<Length> {
        self.len().for_tlv()
    }

    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<()> {
        Header::new(self.tag, self.len())?.encode(encoder)?;

        if let Some(octet) = self.leading_octet {
            encoder.byte(octet)?;
        }

        encoder.bytes(self.as_bytes())
    }
}

impl<'a> TryFrom<&'a [u8]> for Any<'a> {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Any<'a>> {
        Any::from_der(bytes)
    }
}

/// Obtain the inner [`ByteSlice`] value contained in an [`Any`]
impl<'a> From<Any<'a>> for ByteSlice<'a> {
    fn from(any: Any<'a>) -> ByteSlice<'a> {
        any.value
    }
}
