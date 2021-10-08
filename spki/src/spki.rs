//! X.509 `SubjectPublicKeyInfo`

use crate::AlgorithmIdentifier;
use core::convert::TryFrom;
use der::{asn1::BitString, Decodable, Decoder, Encodable, Error, Message, Result};

#[cfg(feature = "alloc")]
use alloc::string::String;

#[cfg(feature = "fingerprint")]
use sha2::{digest, Digest, Sha256};

#[cfg(all(feature = "fingerprint", feature = "alloc"))]
use base64ct::{Base64, Encoding};

/// X.509 `SubjectPublicKeyInfo` (SPKI) as defined in [RFC 5280 Section 4.1.2.7].
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
/// [RFC 5280 Section 4.1.2.7]: https://tools.ietf.org/html/rfc5280#section-4.1.2.7
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SubjectPublicKeyInfo<'a> {
    /// X.509 [`AlgorithmIdentifier`] for the public key type
    pub algorithm: AlgorithmIdentifier<'a>,

    /// Public key data
    pub subject_public_key: &'a [u8],
}

impl<'a> SubjectPublicKeyInfo<'a> {
    #[cfg(feature = "fingerprint")]
    #[cfg_attr(docsrs, doc(cfg(feature = "fingerprint")))]
    /// Calculate the SHA-256 fingerprint of this SubjectPublicKeyInfo
    pub fn fingerprint(&self) -> Result<digest::Output<Sha256>> {
        let mut buf = [0u8; 4096];
        Ok(Sha256::digest(self.encode_to_slice(&mut buf)?))
    }

    #[cfg(all(feature = "fingerprint", feature = "alloc"))]
    #[cfg_attr(docsrs, doc(cfg(all(feature = "fingerprint", feature = "alloc"))))]
    /// Calculate the SHA-256 fingerprint of this SubjectPublicKeyInfo and encode it as a Base64 string
    pub fn fingerprint_base64(&self) -> Result<String> {
        Ok(Base64::encode_string(self.fingerprint()?.as_slice()))
    }
}

impl<'a> Decodable<'a> for SubjectPublicKeyInfo<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> Result<Self> {
        decoder.sequence(|decoder| {
            Ok(Self {
                algorithm: decoder.decode()?,
                subject_public_key: decoder.bit_string()?.as_bytes(),
            })
        })
    }
}

impl<'a> Message<'a> for SubjectPublicKeyInfo<'a> {
    fn fields<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> Result<T>,
    {
        f(&[&self.algorithm, &BitString::new(self.subject_public_key)?])
    }
}

impl<'a> TryFrom<&'a [u8]> for SubjectPublicKeyInfo<'a> {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Self::from_der(bytes)
    }
}
