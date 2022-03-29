//! Ed25519 public keys.
//!
//! Edwards Digital Signature Algorithm (EdDSA) over Curve25519.

use crate::{
    decoder::{Decode, Decoder},
    encoder::{Encode, Encoder},
    Error, Result,
};
use core::fmt;

/// Ed25519 public key.
// TODO(tarcieri): use `ed25519::PublicKey`? (doesn't exist yet)
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Ed25519PublicKey(pub [u8; Self::BYTE_SIZE]);

impl Ed25519PublicKey {
    /// Size of an Ed25519 public key in bytes.
    pub const BYTE_SIZE: usize = 32;
}

impl AsRef<[u8; Self::BYTE_SIZE]> for Ed25519PublicKey {
    fn as_ref(&self) -> &[u8; Self::BYTE_SIZE] {
        &self.0
    }
}

impl Decode for Ed25519PublicKey {
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        let mut bytes = [0u8; Self::BYTE_SIZE];
        decoder.decode_length_prefixed(|decoder, _len| decoder.decode_raw(&mut bytes))?;
        Ok(Self(bytes))
    }
}

impl Encode for Ed25519PublicKey {
    fn encoded_len(&self) -> Result<usize> {
        4usize.checked_add(Self::BYTE_SIZE).ok_or(Error::Length)
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        encoder.encode_byte_slice(self.as_ref())
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

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
impl TryFrom<Ed25519PublicKey> for ed25519_dalek::PublicKey {
    type Error = Error;

    fn try_from(key: Ed25519PublicKey) -> Result<ed25519_dalek::PublicKey> {
        ed25519_dalek::PublicKey::try_from(&key)
    }
}

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
impl TryFrom<&Ed25519PublicKey> for ed25519_dalek::PublicKey {
    type Error = Error;

    fn try_from(key: &Ed25519PublicKey) -> Result<ed25519_dalek::PublicKey> {
        ed25519_dalek::PublicKey::from_bytes(key.as_ref()).map_err(|_| Error::Crypto)
    }
}

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
impl From<ed25519_dalek::PublicKey> for Ed25519PublicKey {
    fn from(key: ed25519_dalek::PublicKey) -> Ed25519PublicKey {
        Ed25519PublicKey::from(&key)
    }
}

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
impl From<&ed25519_dalek::PublicKey> for Ed25519PublicKey {
    fn from(key: &ed25519_dalek::PublicKey) -> Ed25519PublicKey {
        Ed25519PublicKey(key.to_bytes())
    }
}
