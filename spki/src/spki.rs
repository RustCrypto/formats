//! X.509 `SubjectPublicKeyInfo`

#[cfg(feature = "fingerprint")]
extern crate sha2;

use crate::AlgorithmIdentifier;
use base64ct::{Base64, Encoding, InvalidLengthError};
use core::convert::TryFrom;
use der::{
    asn1::{Any, BitString},
    Decodable, Encodable, Encoder, Error, Message, Result,
};
#[cfg(feature = "fingerprint")]
use sha2::{Digest, Sha256};

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

impl<'a> TryFrom<&'a [u8]> for SubjectPublicKeyInfo<'a> {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Self::from_der(bytes)
    }
}

impl<'a> TryFrom<Any<'a>> for SubjectPublicKeyInfo<'a> {
    type Error = Error;

    fn try_from(any: Any<'a>) -> Result<SubjectPublicKeyInfo<'a>> {
        any.sequence(|decoder| {
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

#[cfg(feature = "fingerprint")]
#[derive(Debug)]
pub enum FingerprintError {
    DerEncodingError(Error),
    Base64EncodingError(InvalidLengthError),
}

#[cfg(feature = "fingerprint")]
impl<'a> SubjectPublicKeyInfo<'a> {
    /// Calculate the SHA-256 fingerprint of this SubjectPublicKeyInfo
    pub fn fingerprint(
        &self,
        fingerprint: &'a mut [u8],
    ) -> core::result::Result<&'a str, FingerprintError> {
        const BUFSIZE: usize = 4096;
        let mut buf = [0u8; BUFSIZE];

        let mut encoder = Encoder::new(&mut buf);
        self.encode(&mut encoder)
            .map_err(|e| FingerprintError::DerEncodingError(e))?;
        let spki_der = encoder
            .finish()
            .map_err(|e| FingerprintError::DerEncodingError(e))?;

        let hash = Sha256::digest(spki_der);
        Base64::encode(hash.as_slice(), fingerprint)
            .map_err(|e| FingerprintError::Base64EncodingError(e))
    }
}
