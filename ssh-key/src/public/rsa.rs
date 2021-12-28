//! Rivest–Shamir–Adleman (RSA).

use crate::{
    base64::{self, Decode},
    MPInt, Result,
};

/// RSA public key.
///
/// Described in [RFC4253 § 6.6](https://datatracker.ietf.org/doc/html/rfc4253#section-6.6):
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct RsaPublicKey {
    /// Public exponent
    pub e: MPInt,

    /// Modulus
    pub n: MPInt,
}

impl Decode for RsaPublicKey {
    fn decode(decoder: &mut base64::Decoder<'_>) -> Result<Self> {
        let e = MPInt::decode(decoder)?;
        let n = MPInt::decode(decoder)?;
        Ok(Self { e, n })
    }
}
