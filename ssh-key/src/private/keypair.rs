//! Private key pairs.

use super::ed25519::Ed25519Keypair;
use crate::{
    checked::CheckedSum,
    decoder::{Decode, Decoder},
    encoder::{Encode, Encoder},
    public, Algorithm, Error, Result,
};

#[cfg(feature = "alloc")]
use {
    super::{DsaKeypair, RsaKeypair},
    alloc::vec::Vec,
};

#[cfg(feature = "ecdsa")]
use super::EcdsaKeypair;

#[cfg(feature = "subtle")]
use subtle::{Choice, ConstantTimeEq};

/// Private key data: digital signature key pairs.
///
/// SSH private keys contain pairs of public and private keys for various
/// supported digital signature algorithms.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum KeypairData {
    /// Digital Signature Algorithm (DSA) keypair.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    Dsa(DsaKeypair),

    /// ECDSA keypair.
    #[cfg(feature = "ecdsa")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
    Ecdsa(EcdsaKeypair),

    /// Ed25519 keypair.
    Ed25519(Ed25519Keypair),

    /// Encrypted private key (ciphertext).
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    Encrypted(Vec<u8>),

    /// RSA keypair.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    Rsa(RsaKeypair),
}

impl KeypairData {
    /// Get the [`Algorithm`] for this private key.
    pub fn algorithm(&self) -> Result<Algorithm> {
        Ok(match self {
            #[cfg(feature = "alloc")]
            Self::Dsa(_) => Algorithm::Dsa,
            #[cfg(feature = "ecdsa")]
            Self::Ecdsa(key) => key.algorithm(),
            Self::Ed25519(_) => Algorithm::Ed25519,
            #[cfg(feature = "alloc")]
            Self::Encrypted(_) => return Err(Error::Encrypted),
            #[cfg(feature = "alloc")]
            Self::Rsa(_) => Algorithm::Rsa,
        })
    }

    /// Get DSA keypair if this key is the correct type.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn dsa(&self) -> Option<&DsaKeypair> {
        match self {
            Self::Dsa(key) => Some(key),
            _ => None,
        }
    }

    /// Get ECDSA private key if this key is the correct type.
    #[cfg(feature = "ecdsa")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
    pub fn ecdsa(&self) -> Option<&EcdsaKeypair> {
        match self {
            Self::Ecdsa(keypair) => Some(keypair),
            _ => None,
        }
    }

    /// Get Ed25519 private key if this key is the correct type.
    pub fn ed25519(&self) -> Option<&Ed25519Keypair> {
        match self {
            Self::Ed25519(key) => Some(key),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// Get the encrypted ciphertext if this key is encrypted.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn encrypted(&self) -> Option<&[u8]> {
        match self {
            Self::Encrypted(ciphertext) => Some(ciphertext),
            _ => None,
        }
    }

    /// Get RSA keypair if this key is the correct type.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn rsa(&self) -> Option<&RsaKeypair> {
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
    #[cfg(feature = "ecdsa")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
    pub fn is_ecdsa(&self) -> bool {
        matches!(self, Self::Ecdsa(_))
    }

    /// Is this key an Ed25519 key?
    pub fn is_ed25519(&self) -> bool {
        matches!(self, Self::Ed25519(_))
    }

    /// Is this key encrypted?
    #[cfg(not(feature = "alloc"))]
    pub fn is_encrypted(&self) -> bool {
        false
    }

    /// Is this key encrypted?
    #[cfg(feature = "alloc")]
    pub fn is_encrypted(&self) -> bool {
        matches!(self, Self::Encrypted(_))
    }

    /// Is this key an RSA key?
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn is_rsa(&self) -> bool {
        matches!(self, Self::Rsa(_))
    }

    /// Compute a deterministic "checkint" for this private key.
    ///
    /// This is a sort of primitive pseudo-MAC used by the OpenSSH key format.
    // TODO(tarcieri): true randomness or a better algorithm?
    pub(super) fn checkint(&self) -> u32 {
        let bytes = match self {
            #[cfg(feature = "alloc")]
            Self::Dsa(dsa) => dsa.private.as_bytes(),
            #[cfg(feature = "ecdsa")]
            Self::Ecdsa(ecdsa) => ecdsa.private_key_bytes(),
            Self::Ed25519(ed25519) => ed25519.private.as_ref(),
            #[cfg(feature = "alloc")]
            Self::Encrypted(ciphertext) => ciphertext.as_ref(),
            #[cfg(feature = "alloc")]
            Self::Rsa(rsa) => rsa.private.d.as_bytes(),
        };

        let mut n = 0u32;

        for chunk in bytes.chunks_exact(4) {
            n ^= u32::from_be_bytes(chunk.try_into().expect("not 4 bytes"));
        }

        n
    }
}

impl Decode for KeypairData {
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        match Algorithm::decode(decoder)? {
            #[cfg(feature = "alloc")]
            Algorithm::Dsa => DsaKeypair::decode(decoder).map(Self::Dsa),
            #[cfg(feature = "ecdsa")]
            Algorithm::Ecdsa(curve) => match EcdsaKeypair::decode(decoder)? {
                keypair if keypair.curve() == curve => Ok(Self::Ecdsa(keypair)),
                _ => Err(Error::Algorithm),
            },
            Algorithm::Ed25519 => Ed25519Keypair::decode(decoder).map(Self::Ed25519),
            #[cfg(feature = "alloc")]
            Algorithm::Rsa => RsaKeypair::decode(decoder).map(Self::Rsa),
            #[allow(unreachable_patterns)]
            _ => Err(Error::Algorithm),
        }
    }
}

impl Encode for KeypairData {
    fn encoded_len(&self) -> Result<usize> {
        let key_len = match self {
            #[cfg(feature = "alloc")]
            Self::Dsa(key) => key.encoded_len()?,
            #[cfg(feature = "ecdsa")]
            Self::Ecdsa(key) => key.encoded_len()?,
            Self::Ed25519(key) => key.encoded_len()?,
            #[cfg(feature = "alloc")]
            Self::Encrypted(ciphertext) => return Ok(ciphertext.len()),
            #[cfg(feature = "alloc")]
            Self::Rsa(key) => key.encoded_len()?,
        };

        [self.algorithm()?.encoded_len()?, key_len].checked_sum()
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        if !self.is_encrypted() {
            self.algorithm()?.encode(encoder)?;
        }

        match self {
            #[cfg(feature = "alloc")]
            Self::Dsa(key) => key.encode(encoder),
            #[cfg(feature = "ecdsa")]
            Self::Ecdsa(key) => key.encode(encoder),
            Self::Ed25519(key) => key.encode(encoder),
            #[cfg(feature = "alloc")]
            Self::Encrypted(ciphertext) => encoder.write(ciphertext),
            #[cfg(feature = "alloc")]
            Self::Rsa(key) => key.encode(encoder),
        }
    }
}

impl TryFrom<&KeypairData> for public::KeyData {
    type Error = Error;

    fn try_from(keypair_data: &KeypairData) -> Result<public::KeyData> {
        Ok(match keypair_data {
            #[cfg(feature = "alloc")]
            KeypairData::Dsa(dsa) => public::KeyData::Dsa(dsa.into()),
            #[cfg(feature = "ecdsa")]
            KeypairData::Ecdsa(ecdsa) => public::KeyData::Ecdsa(ecdsa.into()),
            KeypairData::Ed25519(ed25519) => public::KeyData::Ed25519(ed25519.into()),
            #[cfg(feature = "alloc")]
            KeypairData::Encrypted(_) => return Err(Error::Encrypted),
            #[cfg(feature = "alloc")]
            KeypairData::Rsa(rsa) => public::KeyData::Rsa(rsa.into()),
        })
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl From<DsaKeypair> for KeypairData {
    fn from(keypair: DsaKeypair) -> KeypairData {
        Self::Dsa(keypair)
    }
}

#[cfg(feature = "ecdsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
impl From<EcdsaKeypair> for KeypairData {
    fn from(keypair: EcdsaKeypair) -> KeypairData {
        Self::Ecdsa(keypair)
    }
}

impl From<Ed25519Keypair> for KeypairData {
    fn from(keypair: Ed25519Keypair) -> KeypairData {
        Self::Ed25519(keypair)
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl From<RsaKeypair> for KeypairData {
    fn from(keypair: RsaKeypair) -> KeypairData {
        Self::Rsa(keypair)
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl ConstantTimeEq for KeypairData {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Note: constant-time with respect to key *data* comparisons, not algorithms
        match (self, other) {
            #[cfg(feature = "alloc")]
            (Self::Dsa(a), Self::Dsa(b)) => a.ct_eq(b),
            #[cfg(feature = "ecdsa")]
            (Self::Ecdsa(a), Self::Ecdsa(b)) => a.ct_eq(b),
            (Self::Ed25519(a), Self::Ed25519(b)) => a.ct_eq(b),
            #[cfg(feature = "alloc")]
            (Self::Encrypted(a), Self::Encrypted(b)) => a.ct_eq(b),
            #[cfg(feature = "alloc")]
            (Self::Rsa(a), Self::Rsa(b)) => a.ct_eq(b),
            _ => Choice::from(0),
        }
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl PartialEq for KeypairData {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl Eq for KeypairData {}
