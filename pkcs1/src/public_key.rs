//! PKCS#1 RSA Public Keys.

#[cfg(feature = "alloc")]
pub(crate) mod document;

use crate::{Error, Result};
use der::{asn1::UIntBytes, Decodable, Sequence};

#[cfg(feature = "alloc")]
use crate::RsaPublicKeyDocument;

#[cfg(feature = "pem")]
use {crate::LineEnding, alloc::string::String, der::Document};

/// PKCS#1 RSA Public Keys as defined in [RFC 8017 Appendix 1.1].
///
/// ASN.1 structure containing a serialized RSA public key:
///
/// ```text
/// RSAPublicKey ::= SEQUENCE {
///     modulus           INTEGER,  -- n
///     publicExponent    INTEGER   -- e
/// }
/// ```
///
/// [RFC 8017 Appendix 1.1]: https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.1
#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence)]
pub struct RsaPublicKey<'a> {
    /// `n`: RSA modulus
    pub modulus: UIntBytes<'a>,

    /// `e`: RSA public exponent
    pub public_exponent: UIntBytes<'a>,
}

impl<'a> RsaPublicKey<'a> {
    /// Encode this [`RsaPublicKey`] as ASN.1 DER.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn to_der(self) -> Result<RsaPublicKeyDocument> {
        self.try_into()
    }

    /// Encode this [`RsaPublicKey`] as PEM-encoded ASN.1 DER with the given
    /// [`LineEnding`].
    #[cfg(feature = "pem")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    pub fn to_pem(self, line_ending: LineEnding) -> Result<String> {
        Ok(self.to_der()?.to_pem(line_ending)?)
    }
}

impl<'a> TryFrom<&'a [u8]> for RsaPublicKey<'a> {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(Self::from_der(bytes)?)
    }
}
