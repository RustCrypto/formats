//! ASN.1 DER headers.

use crate::{
    Decode, DerOrd, Encode, EncodingRules, Error, ErrorKind, Length, Reader, Result, Tag, Writer,
};
use core::cmp::Ordering;

/// ASN.1 DER headers: tag + length component of TLV-encoded values
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Header {
    /// Tag representing the type of the encoded value
    pub tag: Tag,

    /// Length of the encoded value
    pub length: Length,
}

impl Header {
    /// Create a new [`Header`] from a [`Tag`] and a specified length.
    ///
    /// Returns an error if the length exceeds the limits of [`Length`].
    pub fn new(tag: Tag, length: impl TryInto<Length>) -> Result<Self> {
        let length = length.try_into().map_err(|_| ErrorKind::Overflow)?;
        Ok(Self { tag, length })
    }

    /// Peek forward in the reader, attempting to decode a [`Header`] at the current position.
    ///
    /// Does not modify the reader's state.
    pub fn peek<'a>(reader: &impl Reader<'a>) -> Result<Self> {
        Header::decode(&mut reader.clone())
    }
}

impl<'a> Decode<'a> for Header {
    type Error = Error;

    fn decode<R: Reader<'a>>(reader: &mut R) -> Result<Header> {
        let is_constructed = Tag::peek_is_constructed(reader)?;
        let tag = Tag::decode(reader)?;

        let length = Length::decode(reader).map_err(|e| {
            if e.kind() == ErrorKind::Overlength {
                reader.error(tag.length_error())
            } else {
                e
            }
        })?;

        if length.is_indefinite() && !is_constructed {
            debug_assert_eq!(reader.encoding_rules(), EncodingRules::Ber);
            return Err(reader.error(ErrorKind::IndefiniteLength));
        }

        Ok(Self { tag, length })
    }
}

impl Encode for Header {
    fn encoded_len(&self) -> Result<Length> {
        self.tag.encoded_len()? + self.length.encoded_len()?
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        self.tag.encode(writer)?;
        self.length.encode(writer)
    }
}

impl DerOrd for Header {
    fn der_cmp(&self, other: &Self) -> Result<Ordering> {
        match self.tag.der_cmp(&other.tag)? {
            Ordering::Equal => self.length.der_cmp(&other.length),
            ordering => Ok(ordering),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Header;
    use crate::{Encode, Length, Reader, SliceReader, Tag, TagNumber};
    use hex_literal::hex;

    #[test]
    fn peek() {
        // INTEGER: 42
        const EXAMPLE_MSG: &[u8] = &hex!("02012A00");

        let reader = SliceReader::new(EXAMPLE_MSG).expect("slice to be valid length");
        assert_eq!(reader.position(), Length::ZERO);

        let header = Header::peek(&reader).expect("peeked tag");
        assert_eq!(header.tag, Tag::Integer);
        assert_eq!(header.length, Length::ONE);
        assert_eq!(reader.position(), Length::ZERO); // Position unchanged
    }

    #[test]
    fn peek_max_header() {
        const MAX_HEADER: [u8; 11] = hex!("BF8FFFFFFF7F 84FFFFFFFF");
        let reader = SliceReader::new(&MAX_HEADER).expect("slice to be valid length");

        let header = Header::peek(&reader).expect("peeked tag");
        assert_eq!(
            header.tag,
            Tag::ContextSpecific {
                constructed: true,
                number: TagNumber(0xFFFFFFFF)
            }
        );
        assert_eq!(
            header.length,
            Length::new_usize(0xFFFFFFFF).expect("u32 to fit")
        );
        assert_eq!(header.encoded_len(), Ok(Length::new(11)));
        assert_eq!(reader.position(), Length::ZERO); // Position unchanged
    }
    #[test]
    fn negative_peek_overlength_header() {
        const MAX_HEADER: [u8; 12] = hex!("BF8FFFFFFFFF7F 84FFFFFFFF");
        let reader = SliceReader::new(&MAX_HEADER).expect("slice to be valid length");
        // Should not decode
        Header::peek(&reader).expect_err("overlength error");
    }
}
