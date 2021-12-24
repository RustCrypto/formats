//! Ed25519: Edwards Digital Signature Algorithm (EdDSA) over Curve25519.

use crate::{base64, Error, Result};
use core::fmt;
use zeroize::{Zeroize, Zeroizing};

/// Ed25519 public key.
// TODO(tarcieri): use `ed25519::PublicKey`? (doesn't exist yet)
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Ed25519PublicKey(pub [u8; Self::BYTE_SIZE]);

impl Ed25519PublicKey {
    /// Size of an Ed25519 public key in bytes.
    pub const BYTE_SIZE: usize = 32;

    /// Decode Ed25519 public key using the provided Base64 decoder.
    pub(crate) fn decode(decoder: &mut base64::Decoder<'_>) -> Result<Self> {
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

impl Drop for Ed25519PrivateKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Ed25519 keypairs.
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

    /// Decode Ed25519 private key using the provided Base64 decoder.
    pub(crate) fn decode(decoder: &mut base64::Decoder<'_>) -> Result<Self> {
        // Decode private key
        let public = Ed25519PublicKey::decode(decoder)?;

        // The OpenSSH serialization of Ed25519 keys is repetitive and includes
        // a serialization of `private_key[32] || public_key[32]` immediately
        // following the public key.
        if decoder.decode_usize()? != Self::BYTE_SIZE {
            return Err(Error::Length);
        }

        let mut bytes = Zeroizing::new([0u8; Self::BYTE_SIZE]);
        decoder.decode_into(&mut *bytes)?;

        let (priv_bytes, pub_bytes) = bytes.split_at(Ed25519PrivateKey::BYTE_SIZE);
        if pub_bytes != public.as_ref() {
            return Err(Error::FormatEncoding);
        }

        let private = Ed25519PrivateKey(priv_bytes.try_into()?);
        Ok(Self { public, private })
    }
}

impl fmt::Debug for Ed25519Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519Keypair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}
