//! PKCS#1 RSA Public Keys.

use crate::{Error, Result};
use der::{asn1::UIntRef, Decode, DecodeValue, Encode, Header, Reader, Sequence};

#[cfg(feature = "alloc")]
use der::Document;

#[cfg(feature = "pem")]
use der::pem::PemLabel;

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
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RsaPublicKey<'a> {
    /// `n`: RSA modulus
    pub modulus: UIntRef<'a>,

    /// `e`: RSA public exponent
    pub public_exponent: UIntRef<'a>,
}

impl<'a> DecodeValue<'a> for RsaPublicKey<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            Ok(Self {
                modulus: reader.decode()?,
                public_exponent: reader.decode()?,
            })
        })
    }
}

impl<'a> Sequence<'a> for RsaPublicKey<'a> {
    fn fields<F, T>(&self, f: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encode]) -> der::Result<T>,
    {
        f(&[&self.modulus, &self.public_exponent])
    }
}

impl<'a> TryFrom<&'a [u8]> for RsaPublicKey<'a> {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(Self::from_der(bytes)?)
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl TryFrom<RsaPublicKey<'_>> for Document {
    type Error = Error;

    fn try_from(spki: RsaPublicKey<'_>) -> Result<Document> {
        Self::try_from(&spki)
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl TryFrom<&RsaPublicKey<'_>> for Document {
    type Error = Error;

    fn try_from(spki: &RsaPublicKey<'_>) -> Result<Document> {
        Ok(Self::encode_msg(spki)?)
    }
}

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl PemLabel for RsaPublicKey<'_> {
    const PEM_LABEL: &'static str = "RSA PUBLIC KEY";
}
