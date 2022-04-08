//! Rivest–Shamir–Adleman (RSA) private keys.

use crate::{
    checked::CheckedSum, decode::Decode, encode::Encode, public::RsaPublicKey, reader::Reader,
    writer::Writer, MPInt, Result,
};
use core::fmt;
use zeroize::Zeroize;

#[cfg(feature = "subtle")]
use subtle::{Choice, ConstantTimeEq};

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
    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let d = MPInt::decode(reader)?;
        let iqmp = MPInt::decode(reader)?;
        let p = MPInt::decode(reader)?;
        let q = MPInt::decode(reader)?;
        Ok(Self { d, iqmp, p, q })
    }
}

impl Encode for RsaPrivateKey {
    fn encoded_len(&self) -> Result<usize> {
        [
            self.d.encoded_len()?,
            self.iqmp.encoded_len()?,
            self.p.encoded_len()?,
            self.q.encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        self.d.encode(writer)?;
        self.iqmp.encode(writer)?;
        self.p.encode(writer)?;
        self.q.encode(writer)
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

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl ConstantTimeEq for RsaPrivateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.d.ct_eq(&other.d)
            & self.iqmp.ct_eq(&self.iqmp)
            & self.p.ct_eq(&other.p)
            & self.q.ct_eq(&other.q)
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl PartialEq for RsaPrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl Eq for RsaPrivateKey {}

/// RSA private/public keypair.
#[derive(Clone)]
pub struct RsaKeypair {
    /// Public key.
    pub public: RsaPublicKey,

    /// Private key.
    pub private: RsaPrivateKey,
}

impl Decode for RsaKeypair {
    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let n = MPInt::decode(reader)?;
        let e = MPInt::decode(reader)?;
        let public = RsaPublicKey { n, e };
        let private = RsaPrivateKey::decode(reader)?;
        Ok(RsaKeypair { public, private })
    }
}

impl Encode for RsaKeypair {
    fn encoded_len(&self) -> Result<usize> {
        [
            self.public.n.encoded_len()?,
            self.public.e.encoded_len()?,
            self.private.encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        self.public.n.encode(writer)?;
        self.public.e.encode(writer)?;
        self.private.encode(writer)
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

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl ConstantTimeEq for RsaKeypair {
    fn ct_eq(&self, other: &Self) -> Choice {
        Choice::from((self.public == other.public) as u8) & self.private.ct_eq(&other.private)
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl PartialEq for RsaKeypair {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl Eq for RsaKeypair {}
