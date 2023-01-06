//! X.509 serial number

use core::fmt::Display;

use der::{
    asn1::Int, DecodeValue, EncodeValue, ErrorKind, FixedTag, Header, Length, Reader, Result, Tag,
    ValueOrd, Writer,
};

/// [RFC 5280 Section 4.1.2.2.]  Serial Number
///
///   The serial number MUST be a positive integer assigned by the CA to
///   each certificate.  It MUST be unique for each certificate issued by a
///   given CA (i.e., the issuer name and serial number identify a unique
///   certificate).  CAs MUST force the serialNumber to be a non-negative
///   integer.
///
///   Given the uniqueness requirements above, serial numbers can be
///   expected to contain long integers.  Certificate users MUST be able to
///   handle serialNumber values up to 20 octets.  Conforming CAs MUST NOT
///   use serialNumber values longer than 20 octets.
///
///   Note: Non-conforming CAs may issue certificates with serial numbers
///   that are negative or zero.  Certificate users SHOULD be prepared to
///   gracefully handle such certificates.
#[derive(Clone, Debug, Eq, PartialEq, ValueOrd, PartialOrd, Ord)]
pub struct SerialNumber {
    inner: Int,
}

impl SerialNumber {
    /// Maximum length in bytes for a [`SerialNumber`]
    pub const MAX_LEN: Length = Length::new(20);

    /// Create a new [`SerialNumber`] from a byte slice.
    pub fn new(bytes: &[u8]) -> Result<Self> {
        let inner = Int::new(bytes)?;

        if inner.len() > SerialNumber::MAX_LEN {
            return Err(ErrorKind::Overlength.into());
        }

        Ok(Self { inner })
    }

    /// Borrow the inner byte slice which contains the least significant bytes
    /// of a big endian integer value with all leading zeros stripped.
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

impl EncodeValue for SerialNumber {
    fn value_len(&self) -> Result<Length> {
        self.inner.value_len()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        self.inner.encode_value(writer)
    }
}

impl<'a> DecodeValue<'a> for SerialNumber {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        let inner = Int::decode_value(reader, header)?;

        if inner.len() > SerialNumber::MAX_LEN {
            return Err(ErrorKind::Overlength.into());
        }

        Ok(Self { inner })
    }
}

impl FixedTag for SerialNumber {
    const TAG: Tag = <Int as FixedTag>::TAG;
}

impl Display for SerialNumber {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut iter = self.as_bytes().iter().peekable();

        while let Some(byte) = iter.next() {
            match iter.peek() {
                Some(_) => write!(f, "{:02X}:", byte)?,
                None => write!(f, "{:02X}", byte)?,
            }
        }

        Ok(())
    }
}

// Implement by hand because the derive would create invalid values.
// Use the constructor to create a valid value.
#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for SerialNumber {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = u.int_in_range(0u32..=Self::MAX_LEN.into())?;

        Self::new(u.bytes(len as usize)?).map_err(|_| arbitrary::Error::IncorrectFormat)
    }

    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        arbitrary::size_hint::and(u32::size_hint(depth), (0, None))
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn serial_number_display() {
        let sn = SerialNumber::new(&[0xAA, 0xBB, 0xCC, 0x01, 0x10, 0x00, 0x11])
            .expect("unexpected error");

        assert_eq!(sn.to_string(), "AA:BB:CC:01:10:00:11")
    }
}
