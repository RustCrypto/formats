#![doc = include_str!("../README.md")]

//! # Usage
//!
//! The main API for this crate is the [`EncryptionScheme`] enum, which impls
//! the [`Decodable`][`der::Decodable`] and [`Encodable`] traits from the
//! [`der`] crate, and can be used for decoding/encoding PKCS#5
//! [`AlgorithmIdentifier`] fields.
//!
//! [RFC 8018]: https://tools.ietf.org/html/rfc8018

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_root_url = "https://docs.rs/pkcs5/0.4.0"
)]
#![forbid(unsafe_code, clippy::unwrap_used)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

#[cfg(all(feature = "alloc", feature = "pbes2"))]
extern crate alloc;

mod error;

pub mod pbes1;
pub mod pbes2;

pub use crate::error::{Error, Result};
pub use der::{self, asn1::ObjectIdentifier};
pub use spki::AlgorithmIdentifier;

use der::{Decodable, Decoder, Encodable, Encoder, Length, Tag};

#[cfg(all(feature = "alloc", feature = "pbes2"))]
use alloc::vec::Vec;

/// Supported PKCS#5 password-based encryption schemes.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum EncryptionScheme<'a> {
    /// Password-Based Encryption Scheme 1 as defined in [RFC 8018 Section 6.1].
    ///
    /// [RFC 8018 Section 6.1]: https://tools.ietf.org/html/rfc8018#section-6.1
    Pbes1(pbes1::Parameters),

    /// Password-Based Encryption Scheme 2 as defined in [RFC 8018 Section 6.2].
    ///
    /// [RFC 8018 Section 6.2]: https://tools.ietf.org/html/rfc8018#section-6.2
    Pbes2(pbes2::Parameters<'a>),
}

impl<'a> EncryptionScheme<'a> {
    /// Attempt to decrypt the given ciphertext, allocating and returning a
    /// byte vector containing the plaintext.
    #[cfg(all(feature = "alloc", feature = "pbes2"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    #[cfg_attr(docsrs, doc(cfg(feature = "pbes2")))]
    pub fn decrypt(&self, password: impl AsRef<[u8]>, ciphertext: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Pbes2(params) => params.decrypt(password, ciphertext),
            Self::Pbes1(_) => Err(Error::NoPbes1CryptSupport),
        }
    }

    /// Attempt to decrypt the given ciphertext in-place using a key derived
    /// from the provided password and this scheme's parameters.
    ///
    /// Returns an error if the algorithm specified in this scheme's parameters
    /// is unsupported, or if the ciphertext is malformed (e.g. not a multiple
    /// of a block mode's padding)
    #[cfg(feature = "pbes2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pbes2")))]
    pub fn decrypt_in_place<'b>(
        &self,
        password: impl AsRef<[u8]>,
        buffer: &'b mut [u8],
    ) -> Result<&'b [u8]> {
        match self {
            Self::Pbes2(params) => params.decrypt_in_place(password, buffer),
            Self::Pbes1(_) => Err(Error::NoPbes1CryptSupport),
        }
    }

    /// Encrypt the given plaintext, allocating and returning a vector
    /// containing the ciphertext.
    #[cfg(all(feature = "alloc", feature = "pbes2"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    #[cfg_attr(docsrs, doc(cfg(feature = "pbes2")))]
    pub fn encrypt(&self, password: impl AsRef<[u8]>, plaintext: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Pbes2(params) => params.encrypt(password, plaintext),
            Self::Pbes1(_) => Err(Error::NoPbes1CryptSupport),
        }
    }

    /// Encrypt the given ciphertext in-place using a key derived from the
    /// provided password and this scheme's parameters.
    #[cfg(feature = "pbes2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pbes2")))]
    pub fn encrypt_in_place<'b>(
        &self,
        password: impl AsRef<[u8]>,
        buffer: &'b mut [u8],
        pos: usize,
    ) -> Result<&'b [u8]> {
        match self {
            Self::Pbes2(params) => params.encrypt_in_place(password, buffer, pos),
            Self::Pbes1(_) => Err(Error::NoPbes1CryptSupport),
        }
    }

    /// Get the [`ObjectIdentifier`] (a.k.a OID) for this algorithm.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            Self::Pbes1(params) => params.oid(),
            Self::Pbes2(_) => pbes2::PBES2_OID,
        }
    }

    /// Get [`pbes1::Parameters`] if it is the selected algorithm.
    pub fn pbes1(&self) -> Option<&pbes1::Parameters> {
        match self {
            Self::Pbes1(params) => Some(params),
            _ => None,
        }
    }

    /// Get [`pbes2::Parameters`] if it is the selected algorithm.
    pub fn pbes2(&self) -> Option<&pbes2::Parameters<'a>> {
        match self {
            Self::Pbes2(params) => Some(params),
            _ => None,
        }
    }
}

impl<'a> Decodable<'a> for EncryptionScheme<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        AlgorithmIdentifier::decode(decoder)?.try_into()
    }
}

impl<'a> Encodable for EncryptionScheme<'a> {
    fn encoded_len(&self) -> der::Result<Length> {
        match self {
            Self::Pbes1(pbes1) => pbes1.encoded_len(),
            Self::Pbes2(pbes2) => {
                (pbes2::PBES2_OID.encoded_len()? + pbes2.encoded_len()?)?.for_tlv()
            }
        }
    }

    fn encode(&self, encoder: &mut Encoder<'_>) -> der::Result<()> {
        match self {
            Self::Pbes1(pbes1) => pbes1.encode(encoder),
            Self::Pbes2(pbes2) => {
                let seq_len = (pbes2::PBES2_OID.encoded_len()? + pbes2.encoded_len()?)?;
                encoder.sequence(seq_len, |seq| {
                    seq.encode(&pbes2::PBES2_OID)?;
                    seq.encode(pbes2)
                })
            }
        }
    }
}

impl<'a> From<pbes1::Parameters> for EncryptionScheme<'a> {
    fn from(params: pbes1::Parameters) -> EncryptionScheme<'a> {
        Self::Pbes1(params)
    }
}

impl<'a> From<pbes2::Parameters<'a>> for EncryptionScheme<'a> {
    fn from(params: pbes2::Parameters<'a>) -> EncryptionScheme<'a> {
        Self::Pbes2(params)
    }
}

impl<'a> TryFrom<AlgorithmIdentifier<'a>> for EncryptionScheme<'a> {
    type Error = der::Error;

    fn try_from(alg: AlgorithmIdentifier<'a>) -> der::Result<EncryptionScheme<'_>> {
        if alg.oid == pbes2::PBES2_OID {
            if let Some(params) = alg.parameters {
                pbes2::Parameters::try_from(params).map(Into::into)
            } else {
                Err(Tag::OctetString.value_error())
            }
        } else {
            pbes1::Parameters::try_from(alg).map(Into::into)
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for EncryptionScheme<'a> {
    type Error = der::Error;

    fn try_from(bytes: &'a [u8]) -> der::Result<EncryptionScheme<'a>> {
        AlgorithmIdentifier::from_der(bytes)?.try_into()
    }
}
