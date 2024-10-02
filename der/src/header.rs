//! ASN.1 DER headers.

use crate::{Decode, DerOrd, Encode, Error, ErrorKind, Length, Reader, Result, Tag, Writer};
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
    /// Maximum number of DER octets a header can be in this crate.
    pub(crate) const MAX_SIZE: usize = Tag::MAX_SIZE + Length::MAX_SIZE;

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
        let mut buf = [0u8; Self::MAX_SIZE];

        for i in 2..Self::MAX_SIZE {
            let slice = &mut buf[0..i];
            if reader.peek_into(slice).is_ok() {
                if let Ok(header) = Self::from_der(slice) {
                    return Ok(header);
                }
            }
        }

        Self::from_der(&buf)
    }
}

impl<'a> Decode<'a> for Header {
    type Error = Error;

    fn decode<R: Reader<'a>>(reader: &mut R) -> Result<Header> {
        let tag = Tag::decode(reader)?;

        let length = Length::decode(reader).map_err(|e| {
            if e.kind() == ErrorKind::Overlength {
                ErrorKind::Length { tag }.into()
            } else {
                e
            }
        })?;

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
    use crate::{Length, Reader, SliceReader, Tag};
    use hex_literal::hex;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn peek() {
        // INTEGER: 42
        const EXAMPLE_MSG: &[u8] = &hex!("02012A00");

        let reader = SliceReader::new(EXAMPLE_MSG).unwrap();
        assert_eq!(reader.position(), Length::ZERO);

        let header = Header::peek(&reader).unwrap();
        assert_eq!(header.tag, Tag::Integer);
        assert_eq!(header.length, Length::ONE);
        assert_eq!(reader.position(), Length::ZERO); // Position unchanged
    }
}
