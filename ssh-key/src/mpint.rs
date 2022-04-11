//! Multiple precision integer

use crate::{
    checked::CheckedSum, decode::Decode, encode::Encode, reader::Reader, writer::Writer, Error,
    Result,
};
use alloc::vec::Vec;
use core::fmt;
use zeroize::Zeroize;

#[cfg(feature = "rsa")]
use zeroize::Zeroizing;

#[cfg(feature = "subtle")]
use subtle::{Choice, ConstantTimeEq};

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
// TODO(tarcieri): support for heapless platforms
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct MPInt {
    /// Inner big endian-serialized integer value
    inner: Vec<u8>,
}

impl MPInt {
    /// Create a new multiple precision integer from the given
    /// big endian-encoded byte slice.
    ///
    /// Note that this method expects a leading zero on positive integers whose
    /// MSB is set, but does *NOT* expect a 4-byte length prefix.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bytes.try_into()
    }

    /// Create a new multiple precision integer from the given big endian
    /// encoded byte slice representing a positive integer.
    ///
    /// The integer should not start with any leading zeroes.
    pub fn from_positive_bytes(bytes: &[u8]) -> Result<Self> {
        let mut inner = Vec::with_capacity(bytes.len());

        match bytes.get(0).cloned() {
            Some(0) => return Err(Error::FormatEncoding),
            Some(n) if n >= 0x80 => inner.push(0),
            _ => (),
        }

        inner.extend_from_slice(bytes);
        inner.try_into()
    }

    /// Get the big integer data encoded as big endian bytes.
    ///
    /// This slice will contain a leading zero if the value is positive but the
    /// MSB is also set. Use [`MPInt::as_positive_bytes`] to ensure the number
    /// is positive and strip the leading zero byte if it exists.
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Get the bytes of a positive integer.
    ///
    /// # Returns
    /// - `Some(bytes)` if the number is positive. The leading zero byte will be stripped.
    /// - `None` if the value is negative
    pub fn as_positive_bytes(&self) -> Option<&[u8]> {
        match self.as_bytes() {
            [0x00, rest @ ..] => Some(rest),
            [byte, ..] if *byte < 0x80 => Some(self.as_bytes()),
            _ => None,
        }
    }
}

impl AsRef<[u8]> for MPInt {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Decode for MPInt {
    fn decode(reader: &mut impl Reader) -> Result<Self> {
        Vec::decode(reader)?.try_into()
    }
}

impl Encode for MPInt {
    fn encoded_len(&self) -> Result<usize> {
        [4, self.as_bytes().len()].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        self.as_bytes().encode(writer)
    }
}

impl TryFrom<&[u8]> for MPInt {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Vec::from(bytes).try_into()
    }
}

impl TryFrom<Vec<u8>> for MPInt {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        match bytes.as_slice() {
            // Unnecessary leading 0
            [0x00] => Err(Error::FormatEncoding),
            // Unnecessary leading 0
            [0x00, n, ..] if *n < 0x80 => Err(Error::FormatEncoding),
            _ => Ok(Self { inner: bytes }),
        }
    }
}

impl Zeroize for MPInt {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl fmt::Debug for MPInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MPInt({:X})", self)
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

#[cfg(feature = "rsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl TryFrom<rsa::BigUint> for MPInt {
    type Error = Error;

    fn try_from(uint: rsa::BigUint) -> Result<MPInt> {
        MPInt::try_from(&uint)
    }
}

#[cfg(feature = "rsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl TryFrom<&rsa::BigUint> for MPInt {
    type Error = Error;

    fn try_from(uint: &rsa::BigUint) -> Result<MPInt> {
        let bytes = Zeroizing::new(uint.to_bytes_be());
        MPInt::from_positive_bytes(bytes.as_slice())
    }
}

#[cfg(feature = "rsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl TryFrom<MPInt> for rsa::BigUint {
    type Error = Error;

    fn try_from(mpint: MPInt) -> Result<rsa::BigUint> {
        rsa::BigUint::try_from(&mpint)
    }
}

#[cfg(feature = "rsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl TryFrom<&MPInt> for rsa::BigUint {
    type Error = Error;

    fn try_from(mpint: &MPInt) -> Result<rsa::BigUint> {
        mpint
            .as_positive_bytes()
            .map(rsa::BigUint::from_bytes_be)
            .ok_or(Error::Crypto)
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl ConstantTimeEq for MPInt {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_ref().ct_eq(other.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::MPInt;
    use hex_literal::hex;

    #[test]
    fn decode_0() {
        let n = MPInt::from_bytes(b"").unwrap();
        assert_eq!(b"", n.as_bytes())
    }

    #[test]
    fn reject_extra_leading_zeroes() {
        assert!(MPInt::from_bytes(&hex!("00")).is_err());
        assert!(MPInt::from_bytes(&hex!("00 00")).is_err());
        assert!(MPInt::from_bytes(&hex!("00 01")).is_err());
    }

    #[test]
    fn decode_9a378f9b2e332a7() {
        assert!(MPInt::from_bytes(&hex!("09 a3 78 f9 b2 e3 32 a7")).is_ok());
    }

    #[test]
    fn decode_80() {
        let n = MPInt::from_bytes(&hex!("00 80")).unwrap();

        // Leading zero stripped
        assert_eq!(&hex!("80"), n.as_positive_bytes().unwrap())
    }

    // TODO(tarcieri): drop support for negative numbers?
    #[test]
    fn decode_neg_1234() {
        let n = MPInt::from_bytes(&hex!("ed cc")).unwrap();
        assert!(n.as_positive_bytes().is_none());
    }

    // TODO(tarcieri): drop support for negative numbers?
    #[test]
    fn decode_neg_deadbeef() {
        let n = MPInt::from_bytes(&hex!("ff 21 52 41 11")).unwrap();
        assert!(n.as_positive_bytes().is_none());
    }
}
