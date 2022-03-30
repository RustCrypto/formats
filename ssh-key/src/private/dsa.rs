//! Digital Signature Algorithm (DSA) private keys.

use crate::{
    checked::CheckedSum,
    decoder::{Decode, Decoder},
    encoder::{Encode, Encoder},
    public::DsaPublicKey,
    MPInt, Result,
};
use core::fmt;
use zeroize::Zeroize;

#[cfg(feature = "subtle")]
use subtle::{Choice, ConstantTimeEq};

/// Digital Signature Algorithm (DSA) private key.
///
/// Uniformly random integer `x`, such that `0 < x < q`, i.e. `x` is in the
/// range `[1, q–1]`.
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
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
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

impl Encode for DsaPrivateKey {
    fn encoded_len(&self) -> Result<usize> {
        self.inner.encoded_len()
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        self.inner.encode(encoder)
    }
}

impl fmt::Debug for DsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DsaPrivateKey").finish_non_exhaustive()
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl ConstantTimeEq for DsaPrivateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.inner.ct_eq(&other.inner)
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl PartialEq for DsaPrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl Eq for DsaPrivateKey {}

/// Digital Signature Algorithm (DSA) private/public keypair.
#[derive(Clone)]
pub struct DsaKeypair {
    /// Public key.
    pub public: DsaPublicKey,

    /// Private key.
    pub private: DsaPrivateKey,
}

impl Decode for DsaKeypair {
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        let public = DsaPublicKey::decode(decoder)?;
        let private = DsaPrivateKey::decode(decoder)?;
        Ok(DsaKeypair { public, private })
    }
}

impl Encode for DsaKeypair {
    fn encoded_len(&self) -> Result<usize> {
        [self.public.encoded_len()?, self.private.encoded_len()?].checked_sum()
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        self.public.encode(encoder)?;
        self.private.encode(encoder)
    }
}

impl From<DsaKeypair> for DsaPublicKey {
    fn from(keypair: DsaKeypair) -> DsaPublicKey {
        keypair.public
    }
}

impl From<&DsaKeypair> for DsaPublicKey {
    fn from(keypair: &DsaKeypair) -> DsaPublicKey {
        keypair.public.clone()
    }
}

impl fmt::Debug for DsaKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DsaKeypair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl ConstantTimeEq for DsaKeypair {
    fn ct_eq(&self, other: &Self) -> Choice {
        Choice::from((self.public == other.public) as u8) & self.private.ct_eq(&other.private)
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl PartialEq for DsaKeypair {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl Eq for DsaKeypair {}
