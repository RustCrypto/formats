//! Private key pairs.

use super::ed25519::Ed25519Keypair;
use crate::{
    checked::CheckedSum,
    decoder::{Decode, Decoder},
    encoder::{Encode, Encoder},
    public, Algorithm, Cipher, Error, PublicKey, Result,
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

/// Maximum supported block size.
///
/// This is the block size used by e.g. AES.
const MAX_BLOCK_SIZE: usize = 16;

/// Padding bytes to use.
const PADDING_BYTES: [u8; MAX_BLOCK_SIZE - 1] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

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

    /// Decode [`KeypairData`] along with its associated comment, storing
    /// the comment in the provided public key.
    ///
    /// This method also checks padding for validity and ensures that the
    /// decoded private key matches the provided public key.
    ///
    /// For private key format specification, see OpenSSH [PROTOCOL.key] § 3.
    ///
    /// [PROTOCOL.key]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.key?annotate=HEAD
    pub(super) fn decode_padded(
        decoder: &mut impl Decoder,
        public_key: &mut PublicKey,
        cipher: Cipher,
    ) -> Result<Self> {
        debug_assert!(cipher.block_size() <= MAX_BLOCK_SIZE);

        // Ensure input data is padding-aligned
        if decoder.remaining_len().checked_rem(cipher.block_size()) != Some(0) {
            return Err(Error::Length);
        }

        let key_data = KeypairData::decode(decoder)?;

        // Ensure public key matches private key
        if public_key.key_data() != &public::KeyData::try_from(&key_data)? {
            return Err(Error::PublicKey);
        }

        public_key.decode_comment(decoder)?;

        let padding_len = decoder.remaining_len();

        if padding_len >= cipher.block_size() {
            return Err(Error::Length);
        }

        if padding_len != 0 {
            let mut padding = [0u8; MAX_BLOCK_SIZE];
            decoder.decode_raw(&mut padding[..padding_len])?;

            if PADDING_BYTES[..padding_len] != padding[..padding_len] {
                return Err(Error::FormatEncoding);
            }
        }

        if !decoder.is_finished() {
            return Err(Error::Length);
        }

        Ok(key_data)
    }

    /// Encode [`KeypairData`] along with its associated comment and padding.
    pub(super) fn encode_padded(
        &self,
        encoder: &mut impl Encoder,
        comment: &str,
        cipher: Cipher,
    ) -> Result<()> {
        if self.is_encrypted() {
            // This method is intended for use with unencrypted keys only
            return Err(Error::Encrypted);
        }

        let unpadded_len = self.encoded_len_with_comment(comment)?;
        let padding_len = cipher.padding_len(unpadded_len);

        self.encode(encoder)?;
        encoder.encode_str(comment)?;
        encoder.encode_raw(&PADDING_BYTES[..padding_len])?;
        Ok(())
    }

    /// Get the length of this private key when encoded with the given comment
    /// and padded using the padding size for the given cipher.
    pub(super) fn encoded_len_padded(&self, comment: &str, cipher: Cipher) -> Result<usize> {
        let len = self.encoded_len_with_comment(comment)?;
        [len, cipher.padding_len(len)].checked_sum()
    }

    /// Get the length of this private key when encoded with the given comment.
    ///
    /// This length is sans padding.
    fn encoded_len_with_comment(&self, comment: &str) -> Result<usize> {
        // Comments are part of the encrypted plaintext
        if self.is_encrypted() {
            return Err(Error::Encrypted);
        }

        [4, self.encoded_len()?, comment.len()].checked_sum()
    }
}

impl Decode for KeypairData {
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        let checkint1 = decoder.decode_u32()?;
        let checkint2 = decoder.decode_u32()?;

        if checkint1 != checkint2 {
            return Err(Error::Crypto);
        }

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
        #[cfg(feature = "alloc")]
        if let Some(ciphertext) = self.encrypted() {
            return Ok(ciphertext.len());
        }

        let key_len = match self {
            #[cfg(feature = "alloc")]
            Self::Dsa(key) => key.encoded_len()?,
            #[cfg(feature = "ecdsa")]
            Self::Ecdsa(key) => key.encoded_len()?,
            Self::Ed25519(key) => key.encoded_len()?,
            #[cfg(feature = "alloc")]
            Self::Encrypted(_) => return Err(Error::Encrypted),
            #[cfg(feature = "alloc")]
            Self::Rsa(key) => key.encoded_len()?,
        };

        [
            8, // 2 x uint32 checkints
            self.algorithm()?.encoded_len()?,
            key_len,
        ]
        .checked_sum()
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        if !self.is_encrypted() {
            // Compute checkint (uses deterministic method)
            let checkint = public::KeyData::try_from(self)?.checkint();
            encoder.encode_u32(checkint)?;
            encoder.encode_u32(checkint)?;

            self.algorithm()?.encode(encoder)?;
        }

        match self {
            #[cfg(feature = "alloc")]
            Self::Dsa(key) => key.encode(encoder),
            #[cfg(feature = "ecdsa")]
            Self::Ecdsa(key) => key.encode(encoder),
            Self::Ed25519(key) => key.encode(encoder),
            #[cfg(feature = "alloc")]
            Self::Encrypted(ciphertext) => encoder.encode_raw(ciphertext),
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
