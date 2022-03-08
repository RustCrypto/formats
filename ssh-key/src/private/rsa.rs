//! Rivest–Shamir–Adleman (RSA) private keys.

use crate::{
    base64::{Decode, DecoderExt},
    public::RsaPublicKey,
    MPInt, Result,
};
use core::fmt;
use zeroize::Zeroize;

/// RSA private key.
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Clone)]
pub struct RsaPrivateKey {
    /// RSA private exponent.
    pub d: MPInt,

    /// CRT coefficient: `(inverse of q) mod p`.
    pub iqmp: MPInt,

    /// First prime factor of `n`.
    pub p: MPInt,

    /// Second prime factor of `n`.
    pub q: MPInt,
}

impl Decode for RsaPrivateKey {
    fn decode(decoder: &mut impl DecoderExt) -> Result<Self> {
        let d = MPInt::decode(decoder)?;
        let iqmp = MPInt::decode(decoder)?;
        let p = MPInt::decode(decoder)?;
        let q = MPInt::decode(decoder)?;
        Ok(Self { d, iqmp, p, q })
    }
}

impl Drop for RsaPrivateKey {
    fn drop(&mut self) {
        self.d.zeroize();
        self.iqmp.zeroize();
        self.p.zeroize();
        self.q.zeroize();
    }
}

/// RSA private/public keypair.
#[derive(Clone)]
pub struct RsaKeypair {
    /// Public key.
    pub public: RsaPublicKey,

    /// Private key.
    pub private: RsaPrivateKey,
}

impl Decode for RsaKeypair {
    fn decode(decoder: &mut impl DecoderExt) -> Result<Self> {
        let n = MPInt::decode(decoder)?;
        let e = MPInt::decode(decoder)?;
        let public = RsaPublicKey { n, e };
        let private = RsaPrivateKey::decode(decoder)?;
        Ok(RsaKeypair { public, private })
    }
}

impl From<RsaKeypair> for RsaPublicKey {
    fn from(keypair: RsaKeypair) -> RsaPublicKey {
        keypair.public
    }
}

impl From<&RsaKeypair> for RsaPublicKey {
    fn from(keypair: &RsaKeypair) -> RsaPublicKey {
        keypair.public.clone()
    }
}

impl fmt::Debug for RsaKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaKeypair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}
