//! Multiple precision integer

use crate::{
    base64::{self, Decode},
    Error, Result,
};
use alloc::vec::Vec;
use core::fmt;

/// Multiple precision integer, a.k.a. "mpint".
///
/// This type is used for representing the big integer components of
/// DSA and RSA keys.
///
/// Described in [RFC4251 § 5](https://datatracker.ietf.org/doc/html/rfc4251#section-5):
///
/// > Represents multiple precision integers in two's complement format,
/// > stored as a string, 8 bits per byte, MSB first.  Negative numbers
/// > have the value 1 as the most significant bit of the first byte of
/// > the data partition.  If the most significant bit would be set for
/// > a positive number, the number MUST be preceded by a zero byte.
/// > Unnecessary leading bytes with the value 0 or 255 MUST NOT be
/// > included.  The value zero MUST be stored as a string with zero
/// > bytes of data.
/// >
/// > By convention, a number that is used in modular computations in
/// > Z_n SHOULD be represented in the range 0 <= x < n.
///
/// ## Examples
///
/// | value (hex)     | representation (hex) |
/// |-----------------|----------------------|
/// | 0               | `00 00 00 00`
/// | 9a378f9b2e332a7 | `00 00 00 08 09 a3 78 f9 b2 e3 32 a7`
/// | 80              | `00 00 00 02 00 80`
/// |-1234            | `00 00 00 02 ed cc`
/// | -deadbeef       | `00 00 00 05 ff 21 52 41 11`
// TODO(tarcieri): support for heapless platforms, constant time comparisons
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct MPInt {
    /// Inner big endian-serialized integer value
    inner: Vec<u8>,
}

impl MPInt {
    /// Create a new multiple precision integer from the given
    /// big endian-encoded byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Vec::from(bytes).try_into()
    }

    /// Get the big integer data encoded as big endian bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl AsRef<[u8]> for MPInt {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Decode for MPInt {
    fn decode(decoder: &mut base64::Decoder<'_>) -> Result<Self> {
        decoder.decode_byte_vec()?.try_into()
    }
}

impl TryFrom<Vec<u8>> for MPInt {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        // TODO(tarcieri): check for unnecessary leading zero bytes
        Ok(Self { inner: bytes })
    }
}

impl fmt::Display for MPInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:X}", self)
    }
}

impl fmt::LowerHex for MPInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_bytes() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for MPInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_bytes() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MPInt;
    use hex_literal::hex;

    #[test]
    fn decode_0() {
        assert!(MPInt::from_bytes(&hex!("00 00 00 00")).is_ok());
    }

    #[test]
    fn decode_9a378f9b2e332a7() {
        assert!(MPInt::from_bytes(&hex!("00 00 00 08 09 a3 78 f9 b2 e3 32 a7")).is_ok());
    }

    #[test]
    fn decode_80() {
        assert!(MPInt::from_bytes(&hex!("00 00 00 02 00 80")).is_ok());
    }

    // TODO(tarcieri): drop support for negative numbers?
    #[test]
    fn decode_neg_1234() {
        assert!(MPInt::from_bytes(&hex!("00 00 00 02 ed cc")).is_ok());
    }

    // TODO(tarcieri): drop support for negative numbers?
    #[test]
    fn decode_neg_deadbeef() {
        assert!(MPInt::from_bytes(&hex!("00 00 00 05 ff 21 52 41 11")).is_ok());
    }
}
