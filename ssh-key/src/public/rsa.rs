//! Rivest–Shamir–Adleman (RSA) public keys.

use crate::{
    checked::CheckedSum, decode::Decode, encode::Encode, reader::Reader, writer::Writer, MPInt,
    Result,
};

/// RSA public key.
///
/// Described in [RFC4253 § 6.6](https://datatracker.ietf.org/doc/html/rfc4253#section-6.6):
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct RsaPublicKey {
    /// RSA public exponent.
    pub e: MPInt,

    /// RSA modulus.
    pub n: MPInt,
}

impl Decode for RsaPublicKey {
    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let e = MPInt::decode(reader)?;
        let n = MPInt::decode(reader)?;
        Ok(Self { e, n })
    }
}

impl Encode for RsaPublicKey {
    fn encoded_len(&self) -> Result<usize> {
        [self.e.encoded_len()?, self.n.encoded_len()?].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        self.e.encode(writer)?;
        self.n.encode(writer)
    }
}
