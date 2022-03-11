//! Digital Signature Algorithm (DSA) public keys.

use crate::{
    base64::{Decode, DecoderExt, Encode, EncoderExt},
    MPInt, Result,
};

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

impl DsaPublicKey {
    /// Borrow the bytes used to compute a "checkint" for this key.
    ///
    /// This is a sort of primitive pseudo-MAC used by the OpenSSH key format.
    pub(super) fn checkint_bytes(&self) -> &[u8] {
        self.y.as_bytes()
    }
}

impl Decode for DsaPublicKey {
    fn decode(decoder: &mut impl DecoderExt) -> Result<Self> {
        let p = MPInt::decode(decoder)?;
        let q = MPInt::decode(decoder)?;
        let g = MPInt::decode(decoder)?;
        let y = MPInt::decode(decoder)?;
        Ok(Self { p, q, g, y })
    }
}

impl Encode for DsaPublicKey {
    fn encoded_len(&self) -> Result<usize> {
        Ok(self.p.encoded_len()?
            + self.q.encoded_len()?
            + self.g.encoded_len()?
            + self.y.encoded_len()?)
    }

    fn encode(&self, encoder: &mut impl EncoderExt) -> Result<()> {
        self.p.encode(encoder)?;
        self.q.encode(encoder)?;
        self.g.encode(encoder)?;
        self.y.encode(encoder)
    }
}
