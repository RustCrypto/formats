//! Ed25519 private keys.
//!
//! Edwards Digital Signature Algorithm (EdDSA) over Curve25519.

use crate::{
    checked::CheckedSum,
    decoder::{Decode, Decoder},
    encoder::{Encode, Encoder},
    public::Ed25519PublicKey,
    Error, Result,
};
use core::fmt;
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "rand_core")]
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "subtle")]
use subtle::{Choice, ConstantTimeEq};

/// Ed25519 private key.
// TODO(tarcieri): use `ed25519::PrivateKey`? (doesn't exist yet)
#[derive(Clone)]
pub struct Ed25519PrivateKey([u8; Self::BYTE_SIZE]);

impl Ed25519PrivateKey {
    /// Size of an Ed25519 private key in bytes.
    pub const BYTE_SIZE: usize = 32;

    /// Convert to the inner byte array.
    pub fn into_bytes(self) -> [u8; Self::BYTE_SIZE] {
        self.0
    }

    /// Generate a random Ed25519 private key.
    #[cfg(feature = "rand_core")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand_core")))]
    pub fn random(mut rng: impl CryptoRng + RngCore) -> Self {
        let mut key_bytes = [0u8; Self::BYTE_SIZE];
        rng.fill_bytes(&mut key_bytes);
        Self(key_bytes)
    }
}

impl AsRef<[u8; Self::BYTE_SIZE]> for Ed25519PrivateKey {
    fn as_ref(&self) -> &[u8; Self::BYTE_SIZE] {
        &self.0
    }
}

impl Drop for Ed25519PrivateKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Ed25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519PrivateKey").finish_non_exhaustive()
    }
}

impl fmt::LowerHex for Ed25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for Ed25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
impl From<Ed25519PrivateKey> for ed25519_dalek::SecretKey {
    fn from(key: Ed25519PrivateKey) -> ed25519_dalek::SecretKey {
        ed25519_dalek::SecretKey::from(&key)
    }
}

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
impl From<&Ed25519PrivateKey> for ed25519_dalek::SecretKey {
    fn from(key: &Ed25519PrivateKey) -> ed25519_dalek::SecretKey {
        ed25519_dalek::SecretKey::from_bytes(key.as_ref()).expect("invalid Ed25519 key")
    }
}

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
impl From<ed25519_dalek::SecretKey> for Ed25519PrivateKey {
    fn from(key: ed25519_dalek::SecretKey) -> Ed25519PrivateKey {
        Ed25519PrivateKey::from(&key)
    }
}

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
impl From<&ed25519_dalek::SecretKey> for Ed25519PrivateKey {
    fn from(key: &ed25519_dalek::SecretKey) -> Ed25519PrivateKey {
        Ed25519PrivateKey(key.to_bytes())
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl ConstantTimeEq for Ed25519PrivateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_ref().ct_eq(other.as_ref())
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl PartialEq for Ed25519PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl Eq for Ed25519PrivateKey {}

/// Ed25519 private/public keypair.
#[derive(Clone)]
pub struct Ed25519Keypair {
    /// Public key.
    pub public: Ed25519PublicKey,

    /// Private key.
    pub private: Ed25519PrivateKey,
}

impl Ed25519Keypair {
    /// Size of an Ed25519 keypair in bytes.
    pub const BYTE_SIZE: usize = 64;

    /// Generate a random Ed25519 private keypair.
    #[cfg(feature = "ed25519")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
    pub fn random(rng: impl CryptoRng + RngCore) -> Self {
        Ed25519PrivateKey::random(rng).into()
    }

    /// Serialize an Ed25519 keypair as bytes.
    pub fn to_bytes(&self) -> [u8; Self::BYTE_SIZE] {
        let mut result = [0u8; Self::BYTE_SIZE];
        result[..(Self::BYTE_SIZE / 2)].copy_from_slice(self.private.as_ref());
        result[(Self::BYTE_SIZE / 2)..].copy_from_slice(self.public.as_ref());
        result
    }
}

impl Decode for Ed25519Keypair {
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        // Decode private key
        let public = Ed25519PublicKey::decode(decoder)?;

        // The OpenSSH serialization of Ed25519 keys is repetitive and includes
        // a serialization of `private_key[32] || public_key[32]` immediately
        // following the public key.
        let mut bytes = Zeroizing::new([0u8; Self::BYTE_SIZE]);
        decoder.decode_length_prefixed(|decoder, _len| decoder.decode_raw(&mut *bytes))?;

        let (priv_bytes, pub_bytes) = bytes.split_at(Ed25519PrivateKey::BYTE_SIZE);
        let private = Ed25519PrivateKey(priv_bytes.try_into()?);

        // Ensure public key matches the one one the keypair
        if pub_bytes != public.as_ref() {
            return Err(Error::Crypto);
        }

        Ok(Self { public, private })
    }
}

impl Encode for Ed25519Keypair {
    fn encoded_len(&self) -> Result<usize> {
        [4, self.public.encoded_len()?, Self::BYTE_SIZE].checked_sum()
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        self.public.encode(encoder)?;
        encoder.encode_byte_slice(&*Zeroizing::new(self.to_bytes()))
    }
}

impl From<Ed25519Keypair> for Ed25519PublicKey {
    fn from(keypair: Ed25519Keypair) -> Ed25519PublicKey {
        keypair.public
    }
}

impl From<&Ed25519Keypair> for Ed25519PublicKey {
    fn from(keypair: &Ed25519Keypair) -> Ed25519PublicKey {
        keypair.public
    }
}

impl fmt::Debug for Ed25519Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519Keypair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
impl From<Ed25519PrivateKey> for Ed25519Keypair {
    fn from(private: Ed25519PrivateKey) -> Ed25519Keypair {
        let secret = ed25519_dalek::SecretKey::from(&private);
        let public = ed25519_dalek::PublicKey::from(&secret);

        Ed25519Keypair {
            private,
            public: public.into(),
        }
    }
}

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
impl TryFrom<Ed25519Keypair> for ed25519_dalek::Keypair {
    type Error = Error;

    fn try_from(key: Ed25519Keypair) -> Result<ed25519_dalek::Keypair> {
        Ok(ed25519_dalek::Keypair {
            secret: key.private.into(),
            public: key.public.try_into()?,
        })
    }
}

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
impl TryFrom<&Ed25519Keypair> for ed25519_dalek::Keypair {
    type Error = Error;

    fn try_from(key: &Ed25519Keypair) -> Result<ed25519_dalek::Keypair> {
        Ok(ed25519_dalek::Keypair {
            secret: (&key.private).into(),
            public: key.public.try_into()?,
        })
    }
}

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
impl From<ed25519_dalek::Keypair> for Ed25519Keypair {
    fn from(key: ed25519_dalek::Keypair) -> Ed25519Keypair {
        Ed25519Keypair {
            private: key.secret.into(),
            public: key.public.into(),
        }
    }
}

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
impl From<&ed25519_dalek::Keypair> for Ed25519Keypair {
    fn from(key: &ed25519_dalek::Keypair) -> Ed25519Keypair {
        Ed25519Keypair {
            private: (&key.secret).into(),
            public: key.public.into(),
        }
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl ConstantTimeEq for Ed25519Keypair {
    fn ct_eq(&self, other: &Self) -> Choice {
        Choice::from((self.public == other.public) as u8) & self.private.ct_eq(&other.private)
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl PartialEq for Ed25519Keypair {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl Eq for Ed25519Keypair {}
