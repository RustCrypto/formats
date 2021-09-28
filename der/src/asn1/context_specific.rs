//! Context-specific field.

use crate::{
    asn1::Any, Choice, Decodable, Encodable, Encoder, Error, Header, Length, Result, Tag, TagNumber,
};
use core::convert::TryFrom;

/// Context-specific field.
///
/// This type encodes a field which is specific to a particular context,
/// and is identified by a [`TagNumber`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct ContextSpecific<T> {
    /// Context-specific tag number sans the leading `0b10000000` class
    /// identifier bit and `0b100000` constructed flag.
    pub tag_number: TagNumber,

    /// Value of the field.
    pub value: T,
}

impl<'a, T> Choice<'a> for ContextSpecific<T>
where
    T: Decodable<'a> + Encodable,
{
    fn can_decode(tag: Tag) -> bool {
        tag.is_context_specific()
    }
}

impl<'a, T> TryFrom<Any<'a>> for ContextSpecific<T>
where
    T: Decodable<'a>,
{
    type Error = Error;

    fn try_from(any: Any<'a>) -> Result<ContextSpecific<T>> {
        match any.tag() {
            Tag::ContextSpecific {
                number,
                constructed: true,
            } => Ok(Self {
                tag_number: number,
                value: T::from_der(any.value())?,
            }),
            tag => Err(tag.unexpected_error(None)),
        }
    }
}

impl<T> Encodable for ContextSpecific<T>
where
    T: Encodable,
{
    fn encoded_len(&self) -> Result<Length> {
        self.value.encoded_len()?.for_tlv()
    }

    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<()> {
        let tag = Tag::ContextSpecific {
            number: self.tag_number,
            constructed: true,
        };
        Header::new(tag, self.value.encoded_len()?)?.encode(encoder)?;
        self.value.encode(encoder)
    }
}

#[cfg(test)]
mod tests {
    use super::ContextSpecific;
    use crate::{asn1::BitString, Decodable, Encodable};
    use hex_literal::hex;

    // Public key data from `pkcs8` crate's `ed25519-pkcs8-v2.der`
    const EXAMPLE_BYTES: &[u8] =
        &hex!("A123032100A3A7EAE3A8373830BC47E1167BC50E1DB551999651E0E2DC587623438EAC3F31");

    #[test]
    fn round_trip() {
        let field = ContextSpecific::<BitString<'_>>::from_der(EXAMPLE_BYTES).unwrap();
        assert_eq!(field.tag_number.value(), 1);
        assert_eq!(field.value, BitString::new(&EXAMPLE_BYTES[5..]).unwrap());

        let mut buf = [0u8; 128];
        let encoded = field.encode_to_slice(&mut buf).unwrap();
        assert_eq!(encoded, EXAMPLE_BYTES);
    }
}
