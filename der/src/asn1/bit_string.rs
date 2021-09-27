//! ASN.1 `BIT STRING` support.

use crate::{
    asn1::Any, ByteSlice, Encodable, Encoder, Error, ErrorKind, Length, Result, Tag, Tagged,
};
use core::convert::TryFrom;

/// ASN.1 `BIT STRING` type.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct BitString<'a> {
    /// Inner value
    inner: ByteSlice<'a>,
}

impl<'a> BitString<'a> {
    /// Create a new ASN.1 `BIT STRING` from a byte slice.
    pub fn new(bytes: &'a [u8]) -> Result<Self> {
        ByteSlice::new(bytes)
            .map(|inner| Self { inner })
            .map_err(|_| ErrorKind::Length { tag: Self::TAG }.into())
    }

    /// Borrow the inner byte slice.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.inner.as_bytes()
    }

    /// Get the length of the inner byte slice (sans leading `0` byte).
    pub fn len(&self) -> Length {
        self.inner.len()
    }

    /// Is the inner byte slice empty?
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl AsRef<[u8]> for BitString<'_> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<'a> From<&BitString<'a>> for BitString<'a> {
    fn from(value: &BitString<'a>) -> BitString<'a> {
        *value
    }
}

impl<'a> From<BitString<'a>> for &'a [u8] {
    fn from(bit_string: BitString<'a>) -> &'a [u8] {
        bit_string.as_bytes()
    }
}

impl<'a> TryFrom<Any<'a>> for BitString<'a> {
    type Error = Error;

    fn try_from(any: Any<'a>) -> Result<BitString<'a>> {
        any.tag().assert_eq(Self::TAG)?;

        let (prefix, inner) = if let Some(octet) = any.leading_octet() {
            (octet, any.into())
        } else if let Some((octet, rest)) = any.as_bytes().split_first() {
            (*octet, ByteSlice::new(rest)?)
        } else {
            return Err(Self::TAG.non_canonical_error());
        };

        // The prefix octet indicates the the number of bits which are
        // contained in the final byte of the BIT STRING.
        //
        // In DER this value is always `0`.
        if prefix != 0 {
            return Err(Self::TAG.non_canonical_error());
        }

        Ok(Self { inner })
    }
}

impl<'a> TryFrom<BitString<'a>> for Any<'a> {
    type Error = Error;

    fn try_from(bit_string: BitString<'a>) -> Result<Any<'a>> {
        Any::from_tag_and_octet_prefixed_value(Tag::BitString, 0, bit_string.inner)
    }
}

impl<'a> Encodable for BitString<'a> {
    fn encoded_len(&self) -> Result<Length> {
        Any::try_from(*self)?.encoded_len()
    }

    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<()> {
        Any::try_from(*self)?.encode(encoder)
    }
}

impl<'a> Tagged for BitString<'a> {
    const TAG: Tag = Tag::BitString;
}

#[cfg(test)]
mod tests {
    use super::{BitString, Result, Tag};
    use crate::asn1::Any;
    use core::convert::TryInto;

    /// Parse a `BitString` from an ASN.1 `Any` value to test decoding behaviors.
    fn parse_bitstring_from_any(bytes: &[u8]) -> Result<BitString<'_>> {
        Any::new(Tag::BitString, bytes)?.try_into()
    }

    #[test]
    fn decode_empty_bitstring() {
        let bs = parse_bitstring_from_any(&[0]).unwrap();
        assert_eq!(bs.as_ref(), &[]);
    }

    #[test]
    fn decode_non_empty_bitstring() {
        let bs = parse_bitstring_from_any(&[0, 1, 2, 3]).unwrap();
        assert_eq!(bs.as_ref(), &[1, 2, 3]);
    }
}
