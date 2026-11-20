//! Supported MAC and encryption algorithms

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use super::Error;
#[cfg(feature = "legacy")]
use const_oid::db::rfc5912::ID_SHA_1;
use const_oid::{
    ObjectIdentifier,
    db::rfc5912::{ID_SHA_256, ID_SHA_384, ID_SHA_512},
};
use hmac::{Hmac, KeyInit, Mac};
#[cfg(feature = "legacy")]
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

/// Supported MAC algorithms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MacAlgorithm {
    /// HMAC SHA1 (verification only, legacy/interoperability)
    #[cfg(feature = "legacy")]
    HmacSha1,
    /// HMAC SHA256
    HmacSha256,
    /// HMAC SHA384
    HmacSha384,
    /// HMAC SHA512
    HmacSha512,
}

impl TryFrom<ObjectIdentifier> for MacAlgorithm {
    type Error = Error;

    /// Attempt to map an OID to a [`MacAlgorithm`] variant. Returns an error if the OID is not
    /// one of the supported HMAC-SHA-2 algorithms.
    fn try_from(value: ObjectIdentifier) -> Result<Self, Self::Error> {
        match value {
            #[cfg(feature = "legacy")]
            ID_SHA_1 => Ok(Self::HmacSha1),
            ID_SHA_256 => Ok(Self::HmacSha256),
            ID_SHA_384 => Ok(Self::HmacSha384),
            ID_SHA_512 => Ok(Self::HmacSha512),
            _ => Err(Error::Pkcs12Builder(format!(
                "{} is not a recognized MAC algorithm",
                value
            ))),
        }
    }
}
impl MacAlgorithm {
    /// Return the OID of the algorithm.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            #[cfg(feature = "legacy")]
            MacAlgorithm::HmacSha1 => ID_SHA_1,
            MacAlgorithm::HmacSha256 => ID_SHA_256,
            MacAlgorithm::HmacSha384 => ID_SHA_384,
            MacAlgorithm::HmacSha512 => ID_SHA_512,
        }
    }

    /// Return the output size of the associated digest algorithm.
    pub fn output_size(&self) -> usize {
        match self {
            #[cfg(feature = "legacy")]
            MacAlgorithm::HmacSha1 => 20,
            MacAlgorithm::HmacSha256 => 32,
            MacAlgorithm::HmacSha384 => 48,
            MacAlgorithm::HmacSha512 => 64,
        }
    }

    /// Return DER-encoded parameters for inclusion in an `AlgorithmIdentifier`. For all supported
    /// HMAC-SHA-2 algorithms this is a DER-encoded NULL (`0x05 0x00`).
    pub fn parameters(&self) -> Vec<u8> {
        vec![0x05, 0x00]
    }

    /// Compute an HMAC over `content` using the given `key`.
    pub fn compute_hmac(
        &self,
        key: &[u8],
        content: &[u8],
    ) -> Result<Vec<u8>, digest::InvalidLength> {
        match self {
            #[cfg(feature = "legacy")]
            MacAlgorithm::HmacSha1 => {
                let mut mac = Hmac::<Sha1>::new_from_slice(key)?;
                mac.update(content);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            MacAlgorithm::HmacSha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key)?;
                mac.update(content);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            MacAlgorithm::HmacSha384 => {
                let mut mac = Hmac::<Sha384>::new_from_slice(key)?;
                mac.update(content);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            MacAlgorithm::HmacSha512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(key)?;
                mac.update(content);
                Ok(mac.finalize().into_bytes().to_vec())
            }
        }
    }
}

/// Supported encryption algorithms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EncryptionAlgorithm {
    /// AES128 CBC
    Aes128Cbc,
    /// AES-192 CBC
    Aes192Cbc,
    /// AES-256 CBC
    Aes256Cbc,
}

impl EncryptionAlgorithm {
    /// Return the OID of the algorithm.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            EncryptionAlgorithm::Aes128Cbc => const_oid::db::rfc5911::ID_AES_128_CBC,
            EncryptionAlgorithm::Aes192Cbc => const_oid::db::rfc5911::ID_AES_192_CBC,
            EncryptionAlgorithm::Aes256Cbc => const_oid::db::rfc5911::ID_AES_256_CBC,
        }
    }
}

/// Legacy PKCS#12 PBE algorithms (SHA-1 based KDF with 3DES-CBC or RC2-CBC).
///
/// These algorithms are required for interoperability with iOS `SecPKCS12Import`,
/// which does not support PBES2 (PBKDF2 + AES-CBC).
#[cfg(feature = "legacy")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyPbeAlgorithm {
    /// pbeWithSHAAnd3-KeyTripleDES-CBC (OID 1.2.840.113549.1.12.1.3)
    ShaAnd3KeyTripleDesCbc,
    /// pbeWithSHAAnd128BitRC2-CBC (OID 1.2.840.113549.1.12.1.5)
    ShaAnd128BitRc2Cbc,
}

#[cfg(feature = "legacy")]
impl LegacyPbeAlgorithm {
    /// Return the OID of the algorithm.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            LegacyPbeAlgorithm::ShaAnd3KeyTripleDesCbc => {
                crate::PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC
            }
            LegacyPbeAlgorithm::ShaAnd128BitRc2Cbc => crate::PKCS_12_PBE_WITH_SHAAND128_BIT_RC2_CBC,
        }
    }

    /// Return the encryption key length in bytes.
    pub fn key_len(&self) -> usize {
        match self {
            LegacyPbeAlgorithm::ShaAnd3KeyTripleDesCbc => 24,
            LegacyPbeAlgorithm::ShaAnd128BitRc2Cbc => 16,
        }
    }

    /// Return the IV length in bytes.
    pub fn iv_len(&self) -> usize {
        8
    }
}
