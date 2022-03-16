//! Ed25519 private keys.
//!
//! Edwards Digital Signature Algorithm (EdDSA) over Curve25519.

use crate::{
    decoder::{Decode, Decoder},
    encoder::{Encode, Encoder},
    public::Ed25519PublicKey,
    Error, Result,
};
use core::fmt;
use zeroize::{Zeroize, Zeroizing};

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
        if decoder.decode_usize()? != Self::BYTE_SIZE {
            return Err(Error::Length);
        }

        let mut bytes = Zeroizing::new([0u8; Self::BYTE_SIZE]);
        decoder.decode_raw(&mut *bytes)?;

        let (priv_bytes, pub_bytes) = bytes.split_at(Ed25519PrivateKey::BYTE_SIZE);

        if pub_bytes != public.as_ref() {
            return Err(Error::FormatEncoding);
        }

        let private = Ed25519PrivateKey(priv_bytes.try_into()?);

        Ok(Self { public, private })
    }
}

impl Encode for Ed25519Keypair {
    fn encoded_len(&self) -> Result<usize> {
        Ok(self.public.encoded_len()? + 4 + Self::BYTE_SIZE)
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
