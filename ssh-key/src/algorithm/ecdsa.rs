//! Elliptic Curve Digital Signature Algorithm (ECDSA).

use crate::{
    base64::{self, Decode},
    Algorithm, EcdsaCurve, Error, Result,
};
use core::fmt;
use sec1::consts::{U32, U48, U66};
use zeroize::Zeroize;

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
    NistP256(sec1::EncodedPoint<U32>),

    /// NIST P-384 ECDSA public key.
    NistP384(sec1::EncodedPoint<U48>),

    /// NIST P-521 ECDSA public key.
    NistP521(sec1::EncodedPoint<U66>),
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
}

impl AsRef<[u8]> for EcdsaPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.as_sec1_bytes()
    }
}

impl Decode for EcdsaPublicKey {
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

/// ECDSA private key.
#[derive(Clone)]
pub struct EcdsaPrivateKey<const SIZE: usize> {
    /// Byte array containing serialized big endian private scalar.
    bytes: [u8; SIZE],
}

impl<const SIZE: usize> EcdsaPrivateKey<SIZE> {
    /// Convert to the inner byte array.
    pub fn into_bytes(self) -> [u8; SIZE] {
        self.bytes
    }

    /// Decode Ecdsa private key using the provided Base64 decoder.
    fn decode(decoder: &mut base64::Decoder<'_>) -> Result<Self> {
        let len = decoder.decode_usize()?;

        if len == SIZE + 1 {
            // Strip leading zero
            // TODO(tarcieri): make sure leading zero was necessary
            if decoder.decode_u8()? != 0 {
                return Err(Error::FormatEncoding);
            }
        }

        let mut bytes = [0u8; SIZE];
        decoder.decode_into(&mut bytes)?;
        Ok(Self { bytes })
    }
}

impl<const SIZE: usize> AsRef<[u8; SIZE]> for EcdsaPrivateKey<SIZE> {
    fn as_ref(&self) -> &[u8; SIZE] {
        &self.bytes
    }
}

impl<const SIZE: usize> fmt::Debug for EcdsaPrivateKey<SIZE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519PrivateKey").finish_non_exhaustive()
    }
}

impl<const SIZE: usize> fmt::LowerHex for EcdsaPrivateKey<SIZE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl<const SIZE: usize> fmt::UpperHex for EcdsaPrivateKey<SIZE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl<const SIZE: usize> Drop for EcdsaPrivateKey<SIZE> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// ECDSA keypairs.
#[derive(Clone, Debug)]
pub enum EcdsaKeypair {
    /// NIST P-256 ECDSA keypair.
    NistP256 {
        /// Public key.
        public: sec1::EncodedPoint<U32>,

        /// Private key.
        private: EcdsaPrivateKey<32>,
    },

    /// NIST P-384 ECDSA keypair.
    NistP384 {
        /// Public key.
        public: sec1::EncodedPoint<U48>,

        /// Private key.
        private: EcdsaPrivateKey<48>,
    },

    /// NIST P-521 ECDSA keypair.
    NistP521 {
        /// Public key.
        public: sec1::EncodedPoint<U66>,

        /// Private key.
        private: EcdsaPrivateKey<66>,
    },
}

impl EcdsaKeypair {
    /// Get the [`Algorithm`] for this public key type.
    pub fn algorithm(&self) -> Algorithm {
        Algorithm::Ecdsa(self.curve())
    }

    /// Get the [`EcdsaCurve`] for this key.
    pub fn curve(&self) -> EcdsaCurve {
        match self {
            Self::NistP256 { .. } => EcdsaCurve::NistP256,
            Self::NistP384 { .. } => EcdsaCurve::NistP384,
            Self::NistP521 { .. } => EcdsaCurve::NistP521,
        }
    }

    /// Get the bytes representing the public key.
    pub fn public_key_bytes(&self) -> &[u8] {
        match self {
            Self::NistP256 { public, .. } => public.as_ref(),
            Self::NistP384 { public, .. } => public.as_ref(),
            Self::NistP521 { public, .. } => public.as_ref(),
        }
    }

    /// Get the bytes representing the private key.
    pub fn private_key_bytes(&self) -> &[u8] {
        match self {
            Self::NistP256 { private, .. } => private.as_ref(),
            Self::NistP384 { private, .. } => private.as_ref(),
            Self::NistP521 { private, .. } => private.as_ref(),
        }
    }
}

impl Decode for EcdsaKeypair {
    fn decode(decoder: &mut base64::Decoder<'_>) -> Result<Self> {
        match EcdsaPublicKey::decode(decoder)? {
            EcdsaPublicKey::NistP256(public) => {
                let private = EcdsaPrivateKey::<32>::decode(decoder)?;
                Ok(Self::NistP256 { public, private })
            }
            EcdsaPublicKey::NistP384(public) => {
                let private = EcdsaPrivateKey::<48>::decode(decoder)?;
                Ok(Self::NistP384 { public, private })
            }
            EcdsaPublicKey::NistP521(public) => {
                let private = EcdsaPrivateKey::<66>::decode(decoder)?;
                Ok(Self::NistP521 { public, private })
            }
        }
    }
}

impl From<EcdsaKeypair> for EcdsaPublicKey {
    fn from(keypair: EcdsaKeypair) -> EcdsaPublicKey {
        EcdsaPublicKey::from(&keypair)
    }
}

impl From<&EcdsaKeypair> for EcdsaPublicKey {
    fn from(keypair: &EcdsaKeypair) -> EcdsaPublicKey {
        match keypair {
            EcdsaKeypair::NistP256 { public, .. } => EcdsaPublicKey::NistP256(*public),
            EcdsaKeypair::NistP384 { public, .. } => EcdsaPublicKey::NistP384(*public),
            EcdsaKeypair::NistP521 { public, .. } => EcdsaPublicKey::NistP521(*public),
        }
    }
}
