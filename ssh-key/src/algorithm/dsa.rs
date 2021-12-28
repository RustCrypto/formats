//! Digital Signature Algorithm (DSA).

use crate::{
    base64::{self, Decode},
    MPInt, Result,
};
use core::fmt;
use zeroize::Zeroize;

/// Digital Signature Algorithm (DSA) public key.
///
/// Described in [FIPS 186-4 § 4.1](https://csrc.nist.gov/publications/detail/fips/186/4/final).
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct DsaPublicKey {
    /// Prime modulus.
    pub p: MPInt,

    /// Prime divisor of `p - 1`.
    pub q: MPInt,

    /// Generator of a subgroup of order `q` in the multiplicative group
    /// `GF(p)`, such that `1 < g < p`.
    pub g: MPInt,

    /// The public key, where `y = gˣ mod p`.
    pub y: MPInt,
}

impl Decode for DsaPublicKey {
    fn decode(decoder: &mut base64::Decoder<'_>) -> Result<Self> {
        let p = MPInt::decode(decoder)?;
        let q = MPInt::decode(decoder)?;
        let g = MPInt::decode(decoder)?;
        let y = MPInt::decode(decoder)?;
        Ok(Self { p, q, g, y })
    }
}

/// Digital Signature Algorithm (DSA) private key.
///
/// Described in [FIPS 186-4 § 4.1](https://csrc.nist.gov/publications/detail/fips/186/4/final).
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Clone)]
pub struct DsaPrivateKey {
    /// Integer representing a DSA private key.
    inner: MPInt,
}

impl DsaPrivateKey {
    /// Get the serialized private key as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }

    /// Get the inner [`MPInt`].
    pub fn as_mpint(&self) -> &MPInt {
        &self.inner
    }
}

impl AsRef<[u8]> for DsaPrivateKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Decode for DsaPrivateKey {
    fn decode(decoder: &mut base64::Decoder<'_>) -> Result<Self> {
        Ok(Self {
            inner: MPInt::decode(decoder)?,
        })
    }
}

impl Drop for DsaPrivateKey {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

/// Dsa keypairs.
#[derive(Clone)]
pub struct DsaKeypair {
    /// Public key.
    pub public: DsaPublicKey,

    /// Private key.
    pub private: DsaPrivateKey,
}

impl Decode for DsaKeypair {
    fn decode(decoder: &mut base64::Decoder<'_>) -> Result<Self> {
        let public = DsaPublicKey::decode(decoder)?;
        let private = DsaPrivateKey::decode(decoder)?;
        Ok(DsaKeypair { public, private })
    }
}

impl fmt::Debug for DsaKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DsaKeypair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}
