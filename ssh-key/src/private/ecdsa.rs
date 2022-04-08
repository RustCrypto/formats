//! Elliptic Curve Digital Signature Algorithm (ECDSA) private keys.

use crate::{
    checked::CheckedSum, decode::Decode, encode::Encode, public::EcdsaPublicKey, reader::Reader,
    writer::Writer, Algorithm, EcdsaCurve, Error, Result,
};
use core::fmt;
use sec1::consts::{U32, U48, U66};
use zeroize::Zeroize;

#[cfg(feature = "subtle")]
use subtle::{Choice, ConstantTimeEq};

/// Elliptic Curve Digital Signature Algorithm (ECDSA) private key.
#[derive(Clone)]
pub struct EcdsaPrivateKey<const SIZE: usize> {
    /// Byte array containing serialized big endian private scalar.
    bytes: [u8; SIZE],
}

impl<const SIZE: usize> EcdsaPrivateKey<SIZE> {
    /// Borrow the inner byte array as a slice.
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// Convert to the inner byte array.
    pub fn into_bytes(self) -> [u8; SIZE] {
        self.bytes
    }

    /// Decode ECDSA private key using the provided Base64 reader.
    fn decode(reader: &mut impl Reader) -> Result<Self> {
        reader.read_nested(|reader| {
            if reader.remaining_len() == SIZE.checked_add(1).ok_or(Error::Length)? {
                // Strip leading zero
                // TODO(tarcieri): make sure leading zero was necessary
                if u8::decode(reader)? != 0 {
                    return Err(Error::FormatEncoding);
                }
            }

            let mut bytes = [0u8; SIZE];
            reader.read(&mut bytes)?;
            Ok(Self { bytes })
        })
    }

    /// Does this private key need to be prefixed with a leading zero?
    fn needs_leading_zero(&self) -> bool {
        self.bytes[0] >= 0x80
    }
}

impl<const SIZE: usize> Encode for EcdsaPrivateKey<SIZE> {
    fn encoded_len(&self) -> Result<usize> {
        [4, self.needs_leading_zero().into(), SIZE].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        [self.needs_leading_zero().into(), SIZE]
            .checked_sum()?
            .encode(writer)?;

        if self.needs_leading_zero() {
            writer.write(&[0])?;
        }

        writer.write(&self.bytes)
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

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl<const SIZE: usize> ConstantTimeEq for EcdsaPrivateKey<SIZE> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_ref().ct_eq(other.as_ref())
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl<const SIZE: usize> PartialEq for EcdsaPrivateKey<SIZE> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl<const SIZE: usize> Eq for EcdsaPrivateKey<SIZE> {}

/// Elliptic Curve Digital Signature Algorithm (ECDSA) private/public keypair.
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
        Algorithm::Ecdsa {
            curve: self.curve(),
        }
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
    fn decode(reader: &mut impl Reader) -> Result<Self> {
        match EcdsaPublicKey::decode(reader)? {
            EcdsaPublicKey::NistP256(public) => {
                let private = EcdsaPrivateKey::<32>::decode(reader)?;
                Ok(Self::NistP256 { public, private })
            }
            EcdsaPublicKey::NistP384(public) => {
                let private = EcdsaPrivateKey::<48>::decode(reader)?;
                Ok(Self::NistP384 { public, private })
            }
            EcdsaPublicKey::NistP521(public) => {
                let private = EcdsaPrivateKey::<66>::decode(reader)?;
                Ok(Self::NistP521 { public, private })
            }
        }
    }
}

impl Encode for EcdsaKeypair {
    fn encoded_len(&self) -> Result<usize> {
        let public_len = EcdsaPublicKey::from(self).encoded_len()?;

        let private_len = match self {
            Self::NistP256 { private, .. } => private.encoded_len()?,
            Self::NistP384 { private, .. } => private.encoded_len()?,
            Self::NistP521 { private, .. } => private.encoded_len()?,
        };

        [public_len, private_len].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        EcdsaPublicKey::from(self).encode(writer)?;

        match self {
            Self::NistP256 { private, .. } => private.encode(writer)?,
            Self::NistP384 { private, .. } => private.encode(writer)?,
            Self::NistP521 { private, .. } => private.encode(writer)?,
        }

        Ok(())
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

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl ConstantTimeEq for EcdsaKeypair {
    fn ct_eq(&self, other: &Self) -> Choice {
        let public_eq =
            Choice::from((EcdsaPublicKey::from(self) == EcdsaPublicKey::from(other)) as u8);

        let private_key_a = match self {
            Self::NistP256 { private, .. } => private.as_slice(),
            Self::NistP384 { private, .. } => private.as_slice(),
            Self::NistP521 { private, .. } => private.as_slice(),
        };

        let private_key_b = match other {
            Self::NistP256 { private, .. } => private.as_slice(),
            Self::NistP384 { private, .. } => private.as_slice(),
            Self::NistP521 { private, .. } => private.as_slice(),
        };

        public_eq & private_key_a.ct_eq(private_key_b)
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl PartialEq for EcdsaKeypair {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl Eq for EcdsaKeypair {}
