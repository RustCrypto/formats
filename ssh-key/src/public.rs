//! SSH public key support.
//!
//! Support for decoding SSH public keys from the OpenSSH file format.

mod openssh;

use crate::{base64, Algorithm, Error, Result};
use core::fmt;

#[cfg(feature = "alloc")]
use {
    crate::MPInt,
    alloc::{borrow::ToOwned, string::String},
};

#[cfg(feature = "sec1")]
use {
    crate::EcdsaCurve,
    sec1::consts::{U32, U48, U66},
};

/// SSH public key.
#[derive(Clone, Debug)]
pub struct PublicKey {
    /// Key data.
    pub data: KeyData,

    /// Comment on the key (e.g. email address)
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub comment: String,
}

impl PublicKey {
    /// Parse an OpenSSH-formatted public key.
    ///
    /// OpenSSH-formatted public keys look like the following:
    ///
    /// ```text
    /// ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti foo@bar.com
    /// ```
    pub fn from_openssh(input: impl AsRef<[u8]>) -> Result<Self> {
        let encapsulation = openssh::Encapsulation::parse(input.as_ref())?;
        let data = KeyData::decode(base64::Decoder::new(encapsulation.base64_data)?)?;

        // Verify that the algorithm in the Base64-encoded data matches the text
        if encapsulation.algorithm_id != data.algorithm().as_str() {
            return Err(Error::Algorithm);
        }

        Ok(Self {
            data,
            #[cfg(feature = "alloc")]
            comment: encapsulation.comment.to_owned(),
        })
    }

    /// Get the digital signature [`Algorithm`] used by this key.
    pub fn algorithm(&self) -> Algorithm {
        self.data.algorithm()
    }
}

/// Public key data.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum KeyData {
    /// Digital Signature Algorithm (DSA) public key data.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    Dsa(DsaPublicKey),

    /// Elliptic Curve Digital Signature Algorithm (ECDSA) public key data.
    #[cfg(feature = "sec1")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sec1")))]
    Ecdsa(EcdsaPublicKey),

    /// Ed25519 public key data.
    Ed25519(Ed25519PublicKey),

    /// RSA public key data.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    Rsa(RsaPublicKey),
}

impl KeyData {
    /// Get the [`Algorithm`] for this public key type.
    pub fn algorithm(&self) -> Algorithm {
        match self {
            #[cfg(feature = "alloc")]
            Self::Dsa(_) => Algorithm::Dsa,
            #[cfg(feature = "sec1")]
            Self::Ecdsa(key) => key.algorithm(),
            Self::Ed25519(_) => Algorithm::Ed25519,
            #[cfg(feature = "alloc")]
            Self::Rsa(_) => Algorithm::Rsa,
        }
    }

    /// Get ECDSA public key if this key is the correct type.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn dsa(&self) -> Option<&DsaPublicKey> {
        match self {
            Self::Dsa(key) => Some(key),
            _ => None,
        }
    }

    /// Get ECDSA public key if this key is the correct type.
    #[cfg(feature = "sec1")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sec1")))]
    pub fn ecdsa(&self) -> Option<&EcdsaPublicKey> {
        match self {
            Self::Ecdsa(key) => Some(key),
            _ => None,
        }
    }

    /// Get Ed25519 public key if this key is the correct type.
    pub fn ed25519(&self) -> Option<&Ed25519PublicKey> {
        match self {
            Self::Ed25519(key) => Some(key),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// Get RSA public key if this key is the correct type.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn rsa(&self) -> Option<&RsaPublicKey> {
        match self {
            Self::Rsa(key) => Some(key),
            _ => None,
        }
    }

    /// Is this key a DSA key?
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn is_dsa(&self) -> bool {
        matches!(self, Self::Dsa(_))
    }

    /// Is this key an ECDSA key?
    #[cfg(feature = "sec1")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sec1")))]
    pub fn is_ecdsa(&self) -> bool {
        matches!(self, Self::Ecdsa(_))
    }

    /// Is this key an Ed25519 key?
    pub fn is_ed25519(&self) -> bool {
        matches!(self, Self::Ed25519(_))
    }

    /// Is this key an RSA key?
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn is_rsa(&self) -> bool {
        matches!(self, Self::Rsa(_))
    }

    /// Decode data using the provided Base64 decoder.
    fn decode(mut decoder: base64::Decoder<'_>) -> Result<Self> {
        let result = match Algorithm::decode(&mut decoder)? {
            #[cfg(feature = "alloc")]
            Algorithm::Dsa => DsaPublicKey::decode(&mut decoder).map(Self::Dsa),
            #[cfg(feature = "sec1")]
            Algorithm::Ecdsa(curve) => {
                let key = EcdsaPublicKey::decode(&mut decoder)?;

                if key.curve() == curve {
                    Ok(Self::Ecdsa(key))
                } else {
                    Err(Error::Algorithm)
                }
            }
            Algorithm::Ed25519 => Ed25519PublicKey::decode(&mut decoder).map(Self::Ed25519),
            #[cfg(feature = "alloc")]
            Algorithm::Rsa => RsaPublicKey::decode(&mut decoder).map(Self::Rsa),
            #[allow(unreachable_patterns)]
            _ => return Err(Error::Algorithm),
        };

        if decoder.is_finished() {
            result
        } else {
            Err(Error::Length)
        }
    }
}

/// Digital Signature Algorithm (DSA) public key.
///
/// Described in [FIPS 186-4](https://csrc.nist.gov/publications/detail/fips/186/4/final).
// TODO(tarcieri): use `dsa::PublicKey`? (doesn't exist yet)
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct DsaPublicKey {
    /// Prime modulus
    pub p: MPInt,

    /// Prime divisor of `p - 1`
    pub q: MPInt,

    /// Generator of a subgroup of order `q` in the multiplicative group
    /// `GF(p)`, such that `1 < g < p`.
    pub g: MPInt,

    /// The public key, where `y = gˣ mod p`
    pub y: MPInt,
}

#[cfg(feature = "alloc")]
impl DsaPublicKey {
    /// Decode DSA public key using the provided Base64 decoder.
    fn decode(decoder: &mut base64::Decoder<'_>) -> Result<Self> {
        let p = MPInt::decode(decoder)?;
        let q = MPInt::decode(decoder)?;
        let g = MPInt::decode(decoder)?;
        let y = MPInt::decode(decoder)?;
        Ok(Self { p, q, g, y })
    }
}

/// Elliptic Curve Digital Signature Algorithm (ECDSA) public key.
///
/// Public keys are represented as [`sec1::EncodedPoint`] and require the
/// `sec1` feature of this crate is enabled (which it is by default).
///
/// Described in [FIPS 186-4](https://csrc.nist.gov/publications/detail/fips/186/4/final).
#[cfg(feature = "sec1")]
#[cfg_attr(docsrs, doc(cfg(feature = "sec1")))]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum EcdsaPublicKey {
    /// NIST P-256 ECDSA public key.
    NistP256(sec1::EncodedPoint<U32>),

    /// NIST P-384 ECDSA public key.
    NistP384(sec1::EncodedPoint<U48>),

    /// NIST P-521 ECDSA public key.
    NistP521(sec1::EncodedPoint<U66>),
}

#[cfg(feature = "sec1")]
impl EcdsaPublicKey {
    /// Maximum size of a SEC1-encoded ECDSA public key (i.e. curve point).
    ///
    /// This is the size of 2 * P-521 curve points (2 * 66 = 132) plus one
    /// additional byte for the "tag".
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
                    32 => Ok(Self::NistP256(sec1::EncodedPoint::from_bytes(bytes)?)),
                    48 => Ok(Self::NistP384(sec1::EncodedPoint::from_bytes(bytes)?)),
                    66 => Ok(Self::NistP521(sec1::EncodedPoint::from_bytes(bytes)?)),
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
        Algorithm::Ecdsa(self.curve())
    }

    /// Get the [`EcdsaCurve`] for this key.
    pub fn curve(&self) -> EcdsaCurve {
        match self {
            EcdsaPublicKey::NistP256(_) => EcdsaCurve::NistP256,
            EcdsaPublicKey::NistP384(_) => EcdsaCurve::NistP384,
            EcdsaPublicKey::NistP521(_) => EcdsaCurve::NistP521,
        }
    }

    /// Decode ECDSA public key using the provided Base64 decoder.
    fn decode(decoder: &mut base64::Decoder<'_>) -> Result<Self> {
        let curve = EcdsaCurve::decode(decoder)?;

        let mut buf = [0u8; Self::MAX_SIZE];
        let key = Self::from_sec1_bytes(decoder.decode_byte_slice(&mut buf)?)?;

        if key.curve() == curve {
            Ok(key)
        } else {
            Err(Error::Algorithm)
        }
    }
}

#[cfg(feature = "sec1")]
impl AsRef<[u8]> for EcdsaPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.as_sec1_bytes()
    }
}

#[cfg(feature = "sec1")]
impl fmt::Display for EcdsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:X}", self)
    }
}

#[cfg(feature = "sec1")]
impl fmt::LowerHex for EcdsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_sec1_bytes() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

#[cfg(feature = "sec1")]
impl fmt::UpperHex for EcdsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_sec1_bytes() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

/// Ed25519 public key.
// TODO(tarcieri): use `ed25519::PublicKey`? (doesn't exist yet)
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Ed25519PublicKey(pub [u8; Self::BYTE_SIZE]);

impl Ed25519PublicKey {
    /// Size of an Ed25519 public key in bytes.
    pub const BYTE_SIZE: usize = 32;

    /// Decode Ed25519 public key using the provided Base64 decoder.
    fn decode(decoder: &mut base64::Decoder<'_>) -> Result<Self> {
        // Validate length prefix
        if decoder.decode_usize()? != Self::BYTE_SIZE {
            return Err(Error::Length);
        }

        let mut bytes = [0u8; Self::BYTE_SIZE];
        decoder.decode_into(&mut bytes)?;
        Ok(Self(bytes))
    }
}

impl AsRef<[u8; Self::BYTE_SIZE]> for Ed25519PublicKey {
    fn as_ref(&self) -> &[u8; Self::BYTE_SIZE] {
        &self.0
    }
}

impl fmt::Display for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:X}", self)
    }
}

impl fmt::LowerHex for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

/// RSA public key.
///
/// Described in [RFC4253 § 6.6](https://datatracker.ietf.org/doc/html/rfc4253#section-6.6):
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct RsaPublicKey {
    /// Public exponent
    pub e: MPInt,

    /// Modulus
    pub n: MPInt,
}

#[cfg(feature = "alloc")]
impl RsaPublicKey {
    /// Decode RSA public key using the provided Base64 decoder.
    fn decode(decoder: &mut base64::Decoder<'_>) -> Result<Self> {
        let e = MPInt::decode(decoder)?;
        let n = MPInt::decode(decoder)?;
        Ok(Self { e, n })
    }
}
