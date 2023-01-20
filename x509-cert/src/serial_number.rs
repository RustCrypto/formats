//! X.509 serial number

use core::fmt::Display;

use der::{
    asn1::Int, asn1::Uint, DecodeValue, EncodeValue, ErrorKind, FixedTag, Header, Length, Reader,
    Result, Tag, ValueOrd, Writer,
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

    /// See notes in `SerialNumber::new` and `SerialNumber::decode_value`.
    const MAX_DECODE_LEN: Length = Length::new(21);

    /// Create a new [`SerialNumber`] from a byte slice.
    ///
    /// The byte slice **must** represent a positive integer.
    pub fn new(bytes: &[u8]) -> Result<Self> {
        let inner = Uint::new(bytes)?;

        // The user might give us a 20 byte unsigned integer with a high MSB,
        // which we'd then encode with 21 octets to preserve the sign bit.
        // RFC 5280 is ambiguous about whether this is valid, so we limit
        // `SerialNumber` *encodings* to 20 bytes or fewer while permitting
        // `SerialNumber` *decodings* to have up to 21 bytes below.
        if inner.value_len()? > SerialNumber::MAX_LEN {
            return Err(ErrorKind::Overlength.into());
        }

        Ok(Self {
            inner: inner.into(),
        })
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

        // See the note in `SerialNumber::new`: we permit lengths of 21 bytes here,
        // since some X.509 implementations interpret the limit of 20 bytes to refer
        // to the pre-encoded value.
        if inner.len() > SerialNumber::MAX_DECODE_LEN {
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
    fn serial_number_invariants() {
        // Creating a new serial with an oversized encoding (due to high MSB) fails.
        {
            let too_big = [0x80; 20];
            assert!(SerialNumber::new(&too_big).is_err());
        }
    }

    fn serial_number_display() {
        let sn = SerialNumber::new(&[0xAA, 0xBB, 0xCC, 0x01, 0x10, 0x00, 0x11])
            .expect("unexpected error");

        // Creating a new serial with the maximum encoding succeeds.
        {
            let just_enough = [
                0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            ];
            assert!(SerialNumber::new(&just_enough).is_ok());
        }
    }

    #[test]
    fn serial_number_display() {
        {
            let sn = SerialNumber::new(&[0x11, 0x22, 0x33]).unwrap();

            assert_eq!(sn.to_string(), "11:22:33")
        }

        {
            let sn = SerialNumber::new(&[0xAA, 0xBB, 0xCC, 0x01, 0x10, 0x00, 0x11]).unwrap();

            // We force the user's serial to be positive if they give us a negative one.
            assert_eq!(sn.to_string(), "00:AA:BB:CC:01:10:00:11")
        }

        {
            let sn = SerialNumber::new(&[0x00, 0x00, 0x01]).unwrap();

            // Leading zeroes are ignored, due to canonicalization.
            assert_eq!(sn.to_string(), "01")
        }
    }
}
