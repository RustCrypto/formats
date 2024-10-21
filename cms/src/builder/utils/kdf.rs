//! KDF module
//!
//! This module contains KDF logic.
//!

use crate::builder::{Error, Result};
use alloc::string::String;

#[derive(PartialEq, Eq, Debug)]
pub(in crate::builder) enum HashDigest {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

/// Wrapper for ANSI-X9.63 KDF
///
/// This function wraps ansi_x963_kdf, applying a Hash Disgest based on the key agreement algorithm identifier
pub(in crate::builder) fn try_ansi_x963_kdf(
    secret: &[u8],
    other_info: &[u8],
    key: &mut impl AsMut<[u8]>,
    digest: &HashDigest,
) -> Result<()> {
    match digest {
        HashDigest::Sha224 => ansi_x963_kdf_sha224(secret, other_info, key).map_err(|_| {
            Error::Builder(String::from(
                "Could not generate a shared secret via ansi-x9.63-kdf SHA-224",
            ))
        }),
        HashDigest::Sha256 => ansi_x963_kdf_sha256(secret, other_info, key).map_err(|_| {
            Error::Builder(String::from(
                "Could not generate a shared secret via ansi-x9.63-kdf SHA-256",
            ))
        }),
        HashDigest::Sha384 => ansi_x963_kdf_sha384(secret, other_info, key).map_err(|_| {
            Error::Builder(String::from(
                "Could not generate a shared secret via ansi-x9.63-kdf SHA-384",
            ))
        }),
        HashDigest::Sha512 => ansi_x963_kdf_sha512(secret, other_info, key).map_err(|_| {
            Error::Builder(String::from(
                "Could not generate a shared secret via ansi-x9.63-kdf SHA-512",
            ))
        }),
    }
}

/// ANSI-X9.63-KDF with SHA224
fn ansi_x963_kdf_sha224(
    secret: &[u8],
    other_info: &[u8],
    key: &mut impl AsMut<[u8]>,
) -> Result<()> {
    ansi_x963_kdf::derive_key_into::<sha2::Sha224>(secret, other_info, key.as_mut()).map_err(|_| {
        Error::Builder(String::from(
            "Could not generate a shared secret via ansi-x9.63-kdf",
        ))
    })
}

/// ANSI-X9.63-KDF with SHA256
fn ansi_x963_kdf_sha256(
    secret: &[u8],
    other_info: &[u8],
    key: &mut impl AsMut<[u8]>,
) -> Result<()> {
    ansi_x963_kdf::derive_key_into::<sha2::Sha256>(secret, other_info, key.as_mut()).map_err(|_| {
        Error::Builder(String::from(
            "Could not generate a shared secret via ansi-x9.63-kdf",
        ))
    })
}

/// ANSI-X9.63-KDF with SHA384
fn ansi_x963_kdf_sha384(
    secret: &[u8],
    other_info: &[u8],
    key: &mut impl AsMut<[u8]>,
) -> Result<()> {
    ansi_x963_kdf::derive_key_into::<sha2::Sha384>(secret, other_info, key.as_mut()).map_err(|_| {
        Error::Builder(String::from(
            "Could not generate a shared secret via ansi-x9.63-kdf",
        ))
    })
}

/// ANSI-X9.63-KDF with SHA512
fn ansi_x963_kdf_sha512(
    secret: &[u8],
    other_info: &[u8],
    key: &mut impl AsMut<[u8]>,
) -> Result<()> {
    ansi_x963_kdf::derive_key_into::<sha2::Sha512>(secret, other_info, key.as_mut()).map_err(|_| {
        Error::Builder(String::from(
            "Could not generate a shared secret via ansi-x9.63-kdf",
        ))
    })
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_try_ansi_x963_kdf() {
        let secret = [0u8; 16];
        let other_info = [];
        let mut key = [0u8; 16];
        assert!(try_ansi_x963_kdf(&secret, &other_info, &mut key, &HashDigest::Sha224).is_ok());
        assert_eq!(
            key,
            [33, 35, 2, 122, 169, 122, 164, 137, 12, 5, 195, 31, 101, 142, 44, 237]
        )
    }

    #[test]
    fn test_try_ansi_x963_kdf_error() {
        // Empty secret should trigger error of ansi_x963_kdf
        let secret = [];
        let other_info = [];
        let mut key = [0u8; 16];
        assert!(try_ansi_x963_kdf(&secret, &other_info, &mut key, &HashDigest::Sha224).is_err());
    }

    #[test]
    fn test_try_ansi_x963_kdf_sha224() {
        let secret = [0u8; 16];
        let other_info = [];
        let mut key = [0u8; 16];
        assert!(ansi_x963_kdf_sha224(&secret, &other_info, &mut key).is_ok());
        assert_eq!(
            key,
            [33, 35, 2, 122, 169, 122, 164, 137, 12, 5, 195, 31, 101, 142, 44, 237]
        )
    }

    #[test]
    fn test_try_ansi_x963_kdf_sha256() {
        let secret = [0u8; 16];
        let other_info = [];
        let mut key = [0u8; 16];
        assert!(ansi_x963_kdf_sha256(&secret, &other_info, &mut key).is_ok());
        assert_eq!(
            key,
            [233, 255, 14, 110, 109, 233, 93, 165, 111, 240, 159, 78, 62, 15, 72, 29]
        )
    }

    #[test]
    fn test_try_ansi_x963_kdf_sha384() {
        let secret = [0u8; 16];
        let other_info = [];
        let mut key = [0u8; 16];
        assert!(ansi_x963_kdf_sha384(&secret, &other_info, &mut key).is_ok());
        assert_eq!(
            key,
            [156, 231, 52, 7, 234, 137, 225, 91, 29, 49, 193, 212, 25, 40, 137, 8]
        )
    }

    #[test]
    fn test_try_ansi_x963_kdf_sha512() {
        let secret = [0u8; 16];
        let other_info = [];
        let mut key = [0u8; 16];
        assert!(ansi_x963_kdf_sha512(&secret, &other_info, &mut key).is_ok());
        assert_eq!(
            key,
            [160, 237, 224, 79, 173, 198, 48, 115, 203, 162, 233, 108, 204, 185, 88, 209]
        )
    }
}
