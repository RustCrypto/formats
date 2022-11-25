//! X.509 `SubjectPublicKeyInfo`

use crate::{AlgorithmIdentifier, Error, Result};
use core::cmp::Ordering;
use der::{
    asn1::BitStringRef, Decode, DecodeValue, DerOrd, Encode, Header, Reader, Sequence, ValueOrd,
};

#[cfg(feature = "alloc")]
use der::Document;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "fingerprint")]
use crate::{fingerprint, FingerprintBytes};

#[cfg(all(feature = "alloc", feature = "fingerprint"))]
use {
    alloc::string::String,
    base64ct::{Base64, Encoding},
};

#[cfg(feature = "pem")]
use der::pem::PemLabel;

/// X.509 `SubjectPublicKeyInfo` (SPKI) as defined in [RFC 5280 § 4.1.2.7].
///
/// ASN.1 structure containing an [`AlgorithmIdentifier`] and public key
/// data in an algorithm specific format.
///
/// ```text
///    SubjectPublicKeyInfo  ::=  SEQUENCE  {
///         algorithm            AlgorithmIdentifier,
///         subjectPublicKey     BIT STRING  }
/// ```
///
/// [RFC 5280 § 4.1.2.7]: https://tools.ietf.org/html/rfc5280#section-4.1.2.7
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectPublicKeyInfo {
    /// X.509 [`AlgorithmIdentifier`] for the public key type
    pub algorithm: AlgorithmIdentifier,

    /// Public key data
    pub subject_public_key: Vec<u8>,
}

impl SubjectPublicKeyInfo {
    /// Calculate the SHA-256 fingerprint of this [`SubjectPublicKeyInfo`] and
    /// encode it as a Base64 string.
    ///
    /// See [RFC7469 § 2.1.1] for more information.
    ///
    /// [RFC7469 § 2.1.1]: https://datatracker.ietf.org/doc/html/rfc7469#section-2.1.1
    #[cfg(all(feature = "fingerprint", feature = "alloc"))]
    #[cfg_attr(docsrs, doc(cfg(all(feature = "fingerprint", feature = "alloc"))))]
    pub fn fingerprint_base64(&self) -> Result<String> {
        Ok(Base64::encode_string(&self.fingerprint_bytes()?))
    }

    /// Calculate the SHA-256 fingerprint of this [`SubjectPublicKeyInfo`] as
    /// a raw byte array.
    ///
    /// See [RFC7469 § 2.1.1] for more information.
    ///
    /// [RFC7469 § 2.1.1]: https://datatracker.ietf.org/doc/html/rfc7469#section-2.1.1
    #[cfg(feature = "fingerprint")]
    #[cfg_attr(docsrs, doc(cfg(feature = "fingerprint")))]
    pub fn fingerprint_bytes(&self) -> Result<FingerprintBytes> {
        let mut builder = fingerprint::Builder::new();
        self.encode(&mut builder)?;
        Ok(builder.finish())
    }

    /// Get a [`BitString`] representing the `subject_public_key`
    fn bitstring<'a>(&'a self) -> der::Result<BitStringRef<'a>> {
        BitStringRef::from_bytes(&self.subject_public_key)
    }
}

impl<'a> DecodeValue<'a> for SubjectPublicKeyInfo {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            Ok(Self {
                algorithm: reader.decode()?,
                subject_public_key: BitStringRef::decode(reader)?
                    .as_bytes()
                    .ok_or_else(|| der::Tag::BitString.value_error())?
                    .to_vec(),
            })
        })
    }
}

impl<'a> Sequence<'a> for SubjectPublicKeyInfo {
    fn fields<F, T>(&self, f: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encode]) -> der::Result<T>,
    {
        f(&[&self.algorithm, &self.bitstring()?])
    }
}

impl TryFrom<&[u8]> for SubjectPublicKeyInfo {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(Self::from_der(bytes)?)
    }
}

impl ValueOrd for SubjectPublicKeyInfo {
    fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
        match self.algorithm.der_cmp(&other.algorithm)? {
            Ordering::Equal => self.bitstring()?.der_cmp(&other.bitstring()?),
            other => Ok(other),
        }
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl TryFrom<SubjectPublicKeyInfo> for Document {
    type Error = Error;

    fn try_from(spki: SubjectPublicKeyInfo) -> Result<Document> {
        Self::try_from(&spki)
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl TryFrom<&SubjectPublicKeyInfo> for Document {
    type Error = Error;

    fn try_from(spki: &SubjectPublicKeyInfo) -> Result<Document> {
        Ok(Self::encode_msg(spki)?)
    }
}

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl PemLabel for SubjectPublicKeyInfo {
    const PEM_LABEL: &'static str = "PUBLIC KEY";
}
