//! Ed25519 public keys.
//!
//! Edwards Digital Signature Algorithm (EdDSA) over Curve25519.

use crate::{
    base64::{self, Decode, Encode},
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

impl Encode for Ed25519PublicKey {
    fn encoded_len(&self) -> Result<usize> {
        Ok(4 + Self::BYTE_SIZE)
    }

    fn encode(&self, encoder: &mut base64::Encoder<'_>) -> Result<()> {
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
