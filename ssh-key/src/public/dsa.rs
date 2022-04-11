//! Digital Signature Algorithm (DSA) public keys.

use crate::{
    checked::CheckedSum, decode::Decode, encode::Encode, reader::Reader, writer::Writer, MPInt,
    Result,
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

impl Decode for DsaPublicKey {
    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let p = MPInt::decode(reader)?;
        let q = MPInt::decode(reader)?;
        let g = MPInt::decode(reader)?;
        let y = MPInt::decode(reader)?;
        Ok(Self { p, q, g, y })
    }
}

impl Encode for DsaPublicKey {
    fn encoded_len(&self) -> Result<usize> {
        [
            self.p.encoded_len()?,
            self.q.encoded_len()?,
            self.g.encoded_len()?,
            self.y.encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        self.p.encode(writer)?;
        self.q.encode(writer)?;
        self.g.encode(writer)?;
        self.y.encode(writer)
    }
}
