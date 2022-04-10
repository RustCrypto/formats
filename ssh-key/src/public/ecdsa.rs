//! Elliptic Curve Digital Signature Algorithm (ECDSA) public keys.

use crate::{
    checked::CheckedSum, decode::Decode, encode::Encode, reader::Reader, writer::Writer, Algorithm,
    EcdsaCurve, Error, Result,
};
use core::fmt;
use sec1::consts::{U32, U48, U66};

/// ECDSA/NIST P-256 public key.
pub type EcdsaNistP256PublicKey = sec1::EncodedPoint<U32>;

/// ECDSA/NIST P-384 public key.
pub type EcdsaNistP384PublicKey = sec1::EncodedPoint<U48>;

/// ECDSA/NIST P-521 public key.
pub type EcdsaNistP521PublicKey = sec1::EncodedPoint<U66>;

/// Elliptic Curve Digital Signature Algorithm (ECDSA) public key.
///
/// Public keys are represented as [`sec1::EncodedPoint`] and require the
/// `sec1` feature of this crate is enabled (which it is by default).
///
/// Described in [FIPS 186-4](https://csrc.nist.gov/publications/detail/fips/186/4/final).
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum EcdsaPublicKey {
    /// NIST P-256 ECDSA public key.
    NistP256(EcdsaNistP256PublicKey),

    /// NIST P-384 ECDSA public key.
    NistP384(EcdsaNistP384PublicKey),

    /// NIST P-521 ECDSA public key.
    NistP521(EcdsaNistP521PublicKey),
}

impl EcdsaPublicKey {
    /// Maximum size of a SEC1-encoded ECDSA public key (i.e. curve point).
    ///
    /// This is the size of 2 * P-521 field elements (2 * 66 = 132) which
    /// represent the affine coordinates of a curve point plus one additional
    /// byte for the SEC1 "tag" identifying the curve point encoding.
    const MAX_SIZE: usize = 133;

    /// Parse an ECDSA public key from a SEC1-encoded point.
    ///
    /// Determines the key type from the SEC1 tag byte and length.
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self> {
        match bytes {
            [tag, rest @ ..] => {
                let point_size = match sec1::point::Tag::from_u8(*tag)? {
                    sec1::point::Tag::CompressedEvenY | sec1::point::Tag::CompressedOddY => {
                        rest.len()
                    }
                    sec1::point::Tag::Uncompressed => rest.len() / 2,
                    _ => return Err(Error::Algorithm),
                };

                match point_size {
                    32 => Ok(Self::NistP256(EcdsaNistP256PublicKey::from_bytes(bytes)?)),
                    48 => Ok(Self::NistP384(EcdsaNistP384PublicKey::from_bytes(bytes)?)),
                    66 => Ok(Self::NistP521(EcdsaNistP521PublicKey::from_bytes(bytes)?)),
                    _ => Err(Error::Length),
                }
            }
            _ => Err(Error::Length),
        }
    }

    /// Borrow the SEC1-encoded key data as bytes.
    pub fn as_sec1_bytes(&self) -> &[u8] {
        match self {
            EcdsaPublicKey::NistP256(point) => point.as_bytes(),
            EcdsaPublicKey::NistP384(point) => point.as_bytes(),
            EcdsaPublicKey::NistP521(point) => point.as_bytes(),
        }
    }

    /// Get the [`Algorithm`] for this public key type.
    pub fn algorithm(&self) -> Algorithm {
        Algorithm::Ecdsa {
            curve: self.curve(),
        }
    }

    /// Get the [`EcdsaCurve`] for this key.
    pub fn curve(&self) -> EcdsaCurve {
        match self {
            EcdsaPublicKey::NistP256(_) => EcdsaCurve::NistP256,
            EcdsaPublicKey::NistP384(_) => EcdsaCurve::NistP384,
            EcdsaPublicKey::NistP521(_) => EcdsaCurve::NistP521,
        }
    }
}

impl AsRef<[u8]> for EcdsaPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.as_sec1_bytes()
    }
}

impl Decode for EcdsaPublicKey {
    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let curve = EcdsaCurve::decode(reader)?;

        let mut buf = [0u8; Self::MAX_SIZE];
        let key = Self::from_sec1_bytes(reader.read_byten(&mut buf)?)?;

        if key.curve() == curve {
            Ok(key)
        } else {
            Err(Error::Algorithm)
        }
    }
}

impl Encode for EcdsaPublicKey {
    fn encoded_len(&self) -> Result<usize> {
        [
            self.curve().encoded_len()?,
            4, // uint32 length prefix
            self.as_ref().len(),
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        self.curve().encode(writer)?;
        self.as_ref().encode(writer)
    }
}

impl fmt::Display for EcdsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:X}", self)
    }
}

impl fmt::LowerHex for EcdsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_sec1_bytes() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for EcdsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_sec1_bytes() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

#[cfg(feature = "p256")]
#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
impl TryFrom<EcdsaPublicKey> for p256::ecdsa::VerifyingKey {
    type Error = Error;

    fn try_from(key: EcdsaPublicKey) -> Result<p256::ecdsa::VerifyingKey> {
        p256::ecdsa::VerifyingKey::try_from(&key)
    }
}

#[cfg(feature = "p256")]
#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
impl TryFrom<&EcdsaPublicKey> for p256::ecdsa::VerifyingKey {
    type Error = Error;

    fn try_from(public_key: &EcdsaPublicKey) -> Result<p256::ecdsa::VerifyingKey> {
        match public_key {
            EcdsaPublicKey::NistP256(key) => {
                p256::ecdsa::VerifyingKey::from_encoded_point(key).map_err(|_| Error::Crypto)
            }
            _ => Err(Error::Algorithm),
        }
    }
}

#[cfg(feature = "p256")]
#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
impl From<p256::ecdsa::VerifyingKey> for EcdsaPublicKey {
    fn from(key: p256::ecdsa::VerifyingKey) -> EcdsaPublicKey {
        EcdsaPublicKey::from(&key)
    }
}

#[cfg(feature = "p256")]
#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
impl From<&p256::ecdsa::VerifyingKey> for EcdsaPublicKey {
    fn from(key: &p256::ecdsa::VerifyingKey) -> EcdsaPublicKey {
        EcdsaPublicKey::NistP256(key.to_encoded_point(false))
    }
}
