//! PKCS#1 RSA Public Keys.

use crate::{Error, Result};
use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Sequence, Writer,
    asn1::UintRef,
};

#[cfg(feature = "alloc")]
use der::{Document, asn1::Uint};

#[cfg(feature = "pem")]
use der::pem::PemLabel;

/// [`RsaPublicKey`] with [`UintRef`] INTEGERs.
pub type RsaPublicKeyRef<'a> = RsaPublicKey<UintRef<'a>>;

/// [`RsaPublicKey`] with allocating [`Uint`] INTEGERs.
#[cfg(feature = "alloc")]
pub type RsaPublicKeyOwned = RsaPublicKey<Uint>;

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
pub struct RsaPublicKey<U> {
    /// `n`: RSA modulus
    pub modulus: U,

    /// `e`: RSA public exponent
    pub public_exponent: U,
}

impl<'a, U> DecodeValue<'a> for RsaPublicKey<U>
where
    U: DecodeValue<'a, Error = der::Error> + FixedTag + 'a,
{
    type Error = der::Error;
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        Ok(Self {
            modulus: reader.decode()?,
            public_exponent: reader.decode()?,
        })
    }
}

impl<U> EncodeValue for RsaPublicKey<U>
where
    U: EncodeValue + FixedTag,
{
    fn value_len(&self) -> der::Result<Length> {
        self.modulus.encoded_len()? + self.public_exponent.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.modulus.encode(writer)?;
        self.public_exponent.encode(writer)?;
        Ok(())
    }
}

impl<'a, U> Sequence<'a> for RsaPublicKey<U> {}

impl<'a, U> TryFrom<&'a [u8]> for RsaPublicKey<U>
where
    RsaPublicKey<U>: Decode<'a>,
    Error: From<<RsaPublicKey<U> as Decode<'a>>::Error>,
{
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(Self::from_der(bytes)?)
    }
}

#[cfg(feature = "alloc")]
impl<U> TryFrom<RsaPublicKey<U>> for Document
where
    RsaPublicKey<U>: EncodeValue,
{
    type Error = Error;

    fn try_from(spki: RsaPublicKey<U>) -> Result<Document> {
        Self::try_from(&spki)
    }
}

#[cfg(feature = "alloc")]
impl<U> TryFrom<&RsaPublicKey<U>> for Document
where
    RsaPublicKey<U>: EncodeValue,
{
    type Error = Error;

    fn try_from(spki: &RsaPublicKey<U>) -> Result<Document> {
        Ok(Self::encode_msg(spki)?)
    }
}

#[cfg(feature = "pem")]
impl<U> PemLabel for RsaPublicKey<U> {
    const PEM_LABEL: &'static str = "RSA PUBLIC KEY";
}
