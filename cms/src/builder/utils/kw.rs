//! Key wrap module
//!
//! This module contains the key wrapping logic based on aes-kw algorithms
//!

use alloc::{string::String, vec::Vec};

use crate::builder::{ContentEncryptionAlgorithm, Error, Result};
use aes_kw::Kek;
use const_oid::ObjectIdentifier;
use der::Any;
use spki::AlgorithmIdentifierOwned;

/// Represents supported key wrap algorithm for ECC - as defined in [RFC 5753 Section 7.1.5].
///
/// As per [RFC 5753 Section 8]:
/// ```text
/// Implementations that support EnvelopedData with the ephemeral-static
/// ECDH standard primitive:
///
/// - MUST support the dhSinglePass-stdDH-sha256kdf-scheme key
///   agreement algorithm, the id-aes128-wrap key wrap algorithm, and
///   the id-aes128-cbc content encryption algorithm; and
/// - MAY support the dhSinglePass-stdDH-sha1kdf-scheme, dhSinglePass-
///    stdDH-sha224kdf-scheme, dhSinglePass-stdDH-sha384kdf-scheme, and
///    dhSinglePass-stdDH-sha512kdf-scheme key agreement algorithms;
///    the id-alg-CMS3DESwrap, id-aes192-wrap, and id-aes256-wrap key
///    wrap algorithms; and the des-ede3-cbc, id-aes192-cbc, and id-
///    aes256-cbc content encryption algorithms; other algorithms MAY
///    also be supported.
/// ```
///
/// As such the following algorithm are currently supported
/// - id-aes128-wrap
/// - id-aes192-wrap
/// - id-aes256-wrap
///
/// [RFC 5753 Section 8]: https://datatracker.ietf.org/doc/html/rfc5753#section-8
/// [RFC 5753 Section 7.1.5]: https://datatracker.ietf.org/doc/html/rfc5753#section-7.1.5
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeyWrapAlgorithm {
    /// id-aes128-wrap
    Aes128,
    /// id-aes192-wrap
    Aes192,
    /// id-aes256-wrap
    Aes256,
}
impl KeyWrapAlgorithm {
    /// Return the Object Identifier (OID) of the algorithm.
    ///
    /// OID are defined in [RFC 3565 Section 2.3.2]
    ///
    /// [RFC 3565 Section 2.3.2]:
    /// ```text
    /// NIST has assigned the following OIDs to define the AES key wrap
    /// algorithm.
    ///
    ///     id-aes128-wrap OBJECT IDENTIFIER ::= { aes 5 }
    ///     id-aes192-wrap OBJECT IDENTIFIER ::= { aes 25 }
    ///     id-aes256-wrap OBJECT IDENTIFIER ::= { aes 45 }
    ///
    /// In all cases the parameters field MUST be absent.
    /// ```
    ///
    /// [RFC 3565 Section 2.3.2]: https://datatracker.ietf.org/doc/html/rfc3565#section-2.3.2
    fn oid(&self) -> ObjectIdentifier {
        match self {
            Self::Aes128 => const_oid::db::rfc5911::ID_AES_128_WRAP,
            Self::Aes192 => const_oid::db::rfc5911::ID_AES_192_WRAP,
            Self::Aes256 => const_oid::db::rfc5911::ID_AES_256_WRAP,
        }
    }

    /// Return parameters of the algorithm to be used in the context of `AlgorithmIdentifierOwned`.
    ///
    /// It should be absent as defined in [RFC 3565 Section 2.3.2] and per usage in [RFC 5753 Section 7.2].
    ///
    /// [RFC 3565 Section 2.3.2]:
    /// ```text
    /// NIST has assigned the following OIDs to define the AES key wrap
    /// algorithm.
    ///
    ///     id-aes128-wrap OBJECT IDENTIFIER ::= { aes 5 }
    ///     id-aes192-wrap OBJECT IDENTIFIER ::= { aes 25 }
    ///     id-aes256-wrap OBJECT IDENTIFIER ::= { aes 45 }
    ///
    /// In all cases the parameters field MUST be absent.
    /// ```
    ///
    /// [RFC 3565 Section 2.3.2]: https://datatracker.ietf.org/doc/html/rfc3565#section-2.3.2
    /// [RFC 5753 Section 7.2]: https://datatracker.ietf.org/doc/html/rfc5753#section-7.2
    fn parameters(&self) -> Option<Any> {
        match self {
            Self::Aes128 => None,
            Self::Aes192 => None,
            Self::Aes256 => None,
        }
    }

    /// Return key size of the algorithm in number of bits
    pub fn key_size_in_bits(&self) -> u32 {
        match self {
            Self::Aes128 => 128,
            Self::Aes192 => 192,
            Self::Aes256 => 256,
        }
    }
}
impl From<KeyWrapAlgorithm> for AlgorithmIdentifierOwned {
    /// Convert a `KeyWrapAlgorithm` to the corresponding `AlgorithmIdentifierOwned`.
    ///
    /// Conversion is done according to [RFC 5753 Section 7.2]:
    ///
    ///
    /// [RFC 5753 Section 7.2]
    /// ```text
    /// keyInfo contains the object identifier of the key-encryption
    /// algorithm (used to wrap the CEK) and associated parameters.  In
    /// this specification, 3DES wrap has NULL parameters while the AES
    /// wraps have absent parameters.
    /// ```
    ///
    /// [RFC 5753 Section 7.2]: https://datatracker.ietf.org/doc/html/rfc5753#section-7.2
    fn from(kw_algo: KeyWrapAlgorithm) -> Self {
        Self {
            oid: kw_algo.oid(),
            parameters: kw_algo.parameters(),
        }
    }
}
impl From<ContentEncryptionAlgorithm> for KeyWrapAlgorithm {
    /// Convert a `ContentEncryptionAlgorithm` to a `KeyWrapAlgorithm`.
    ///
    /// Conversion is done matching encryption strength.
    fn from(ce_algo: ContentEncryptionAlgorithm) -> Self {
        match ce_algo {
            ContentEncryptionAlgorithm::Aes128Cbc => Self::Aes128,
            ContentEncryptionAlgorithm::Aes192Cbc => Self::Aes192,
            ContentEncryptionAlgorithm::Aes256Cbc => Self::Aes256,
        }
    }
}

/// This struct can be used to perform key wrapping operation.
///
/// It abstracts some of the key-wrapping logic over incoming wrapping-key and outgoing wrapped-key of different sizes.
/// It currently implements:
/// - try_new() - initialize a key wrapper with right sized depending on KeyWrapAlgorithm and key-to-wrap size
/// - try_wrap() - wrap a key with the corresponding aes-key-wrap algorithms
///
/// # Note
/// For convenience KeyWrapper can:
/// - yield the inner wrapping-key as a mutable reference (e.g. to use with a KDF)
/// - convert to Vec<u8> to obtain Owned data to the wrapped key
#[derive(Debug, Clone, Copy)]
pub(in crate::builder) struct KeyWrapper {
    /// Wrapping key
    wrapping_key: WrappingKey,
    /// Wrapped key
    wrapped_key: WrappedKey,
}
impl KeyWrapper {
    /// Initialize a new KeyWrapper based on `KeyWrapAlgorithm` and key-to-wrap size.
    pub(in crate::builder) fn try_new(kw_algo: &KeyWrapAlgorithm, key_size: usize) -> Result<Self> {
        let wrapped_key = WrappedKey::try_from(key_size)?;
        let wrapping_key = WrappingKey::from(kw_algo);

        Ok(Self {
            wrapping_key,
            wrapped_key,
        })
    }
    /// Wraps a given key.
    ///
    /// This function attempts to wrap the provided `target_key`.
    ///
    /// # Arguments
    /// * `target_key` - A slice of bytes representing the key to be wrapped.
    pub(in crate::builder) fn try_wrap(&mut self, target_key: &[u8]) -> Result<()> {
        match self.wrapping_key {
            WrappingKey::Aes128(wrap_key) => Kek::from(wrap_key)
                .wrap(target_key, self.wrapped_key.as_mut())
                .map_err(|_| {
                    Error::Builder(String::from(
                        "could not wrap key with Aes128 key wrap algorithm",
                    ))
                }),
            WrappingKey::Aes192(kek) => Kek::from(kek)
                .wrap(target_key, self.wrapped_key.as_mut())
                .map_err(|_| {
                    Error::Builder(String::from(
                        "could not wrap key with Aes192 key wrap algorithm",
                    ))
                }),
            WrappingKey::Aes256(kek) => Kek::from(kek)
                .wrap(target_key, self.wrapped_key.as_mut())
                .map_err(|_| {
                    Error::Builder(String::from(
                        "could not wrap key with Aes256 key wrap algorithm",
                    ))
                }),
        }
    }
}
impl AsMut<[u8]> for KeyWrapper {
    fn as_mut(&mut self) -> &mut [u8] {
        self.wrapping_key.as_mut()
    }
}
impl From<KeyWrapper> for Vec<u8> {
    fn from(wrapper: KeyWrapper) -> Self {
        Self::from(wrapper.wrapped_key)
    }
}

/// Represents a wrapping key to be used by [KeyWrapper]
///
/// This type can be used to abstract over wrapping-key material of different size.
/// The following wrapping key type are currently supported:
/// - Aes128
/// - Aes192
/// - Aes256
///
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WrappingKey {
    /// id-aes128-wrap
    Aes128([u8; 16]),
    /// id-aes192-wrap
    Aes192([u8; 24]),
    /// id-aes256-wrap
    Aes256([u8; 32]),
}
impl From<&KeyWrapAlgorithm> for WrappingKey {
    fn from(kw_algo: &KeyWrapAlgorithm) -> Self {
        match kw_algo {
            KeyWrapAlgorithm::Aes128 => Self::Aes128([0u8; 16]),
            KeyWrapAlgorithm::Aes192 => Self::Aes192([0u8; 24]),
            KeyWrapAlgorithm::Aes256 => Self::Aes256([0u8; 32]),
        }
    }
}
impl AsMut<[u8]> for WrappingKey {
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Aes128(key) => key,
            Self::Aes192(key) => key,
            Self::Aes256(key) => key,
        }
    }
}
/// Represents a wrapped key to be used by [KeyWrapper]
///
/// This type can be used to abstract over wrapped key of different size for aes-key-wrap algorithms.
/// It currently supports the following incoming key size:
/// - 16
/// - 24
/// - 32
#[derive(Debug, Clone, Copy)]
enum WrappedKey {
    Aes128([u8; 24]),
    Aes192([u8; 32]),
    Aes256([u8; 40]),
}
impl TryFrom<usize> for WrappedKey {
    type Error = Error;
    fn try_from(key_size: usize) -> Result<Self> {
        match key_size {
            16 => Ok(Self::Aes128([0u8; 24])),
            24 => Ok(Self::Aes192([0u8; 32])),
            32 => Ok(Self::Aes256([0u8; 40])),
            _ => Err(Error::Builder(String::from(
                "could not wrap key: key size is not supported",
            ))),
        }
    }
}
impl AsMut<[u8]> for WrappedKey {
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Aes128(key) => key,
            Self::Aes192(key) => key,
            Self::Aes256(key) => key,
        }
    }
}
impl From<WrappedKey> for Vec<u8> {
    fn from(key: WrappedKey) -> Self {
        match key {
            WrappedKey::Aes128(arr) => arr.to_vec(),
            WrappedKey::Aes192(arr) => arr.to_vec(),
            WrappedKey::Aes256(arr) => arr.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use alloc::string::ToString;

    #[test]
    fn test_keywrapalgorithm_oid() {
        assert_eq!(
            KeyWrapAlgorithm::Aes128.oid(),
            const_oid::db::rfc5911::ID_AES_128_WRAP
        );
        assert_eq!(
            KeyWrapAlgorithm::Aes192.oid(),
            const_oid::db::rfc5911::ID_AES_192_WRAP
        );
        assert_eq!(
            KeyWrapAlgorithm::Aes256.oid(),
            const_oid::db::rfc5911::ID_AES_256_WRAP
        );
    }

    #[test]
    fn test_keywrapalgorithm_parameters() {
        assert_eq!(KeyWrapAlgorithm::Aes128.parameters(), None);
        assert_eq!(KeyWrapAlgorithm::Aes192.parameters(), None);
        assert_eq!(KeyWrapAlgorithm::Aes256.parameters(), None);
    }

    #[test]
    fn test_keywrapalgorithm_key_size_in_bits() {
        assert_eq!(KeyWrapAlgorithm::Aes128.key_size_in_bits(), 128);
        assert_eq!(KeyWrapAlgorithm::Aes192.key_size_in_bits(), 192);
        assert_eq!(KeyWrapAlgorithm::Aes256.key_size_in_bits(), 256);
    }

    #[test]
    fn test_algorithmidentifierowned_from_keywrapalgorithm() {
        assert_eq!(
            AlgorithmIdentifierOwned::from(KeyWrapAlgorithm::Aes128),
            AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5911::ID_AES_128_WRAP,
                parameters: None,
            }
        );
        assert_eq!(
            AlgorithmIdentifierOwned::from(KeyWrapAlgorithm::Aes192),
            AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5911::ID_AES_192_WRAP,
                parameters: None,
            }
        );
        assert_eq!(
            AlgorithmIdentifierOwned::from(KeyWrapAlgorithm::Aes256),
            AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5911::ID_AES_256_WRAP,
                parameters: None,
            }
        )
    }
    #[test]
    fn test_keywrapalgorithm_from_contentencryptionalgorithm() {
        assert_eq!(
            KeyWrapAlgorithm::from(ContentEncryptionAlgorithm::Aes128Cbc),
            KeyWrapAlgorithm::Aes128
        );
        assert_eq!(
            KeyWrapAlgorithm::from(ContentEncryptionAlgorithm::Aes192Cbc),
            KeyWrapAlgorithm::Aes192
        );
        assert_eq!(
            KeyWrapAlgorithm::from(ContentEncryptionAlgorithm::Aes256Cbc),
            KeyWrapAlgorithm::Aes256
        );
    }

    #[test]
    fn test_keywrapper_try_new() {
        assert!(KeyWrapper::try_new(&KeyWrapAlgorithm::Aes128, 10).is_err());
        assert!(KeyWrapper::try_new(&KeyWrapAlgorithm::Aes128, 16).is_ok());
        assert!(KeyWrapper::try_new(&KeyWrapAlgorithm::Aes192, 24).is_ok());
        assert!(KeyWrapper::try_new(&KeyWrapAlgorithm::Aes256, 32).is_ok());
    }

    fn fake_kdf(_in: &[u8], _out: &mut impl AsMut<[u8]>) {}

    #[test]
    fn test_keywrapper_try_wrap() {
        // Key to wrap
        let key_to_wrap = [0u8; 16];

        // Shared secret
        let shared_secret = [1u8; 16];

        // Define a key wrapper from Aes128-key-wrap and key-to-wrap size
        let mut key_wrapper =
            KeyWrapper::try_new(&KeyWrapAlgorithm::Aes128, key_to_wrap.len()).unwrap();

        // Derive shared key - one can call .as_mut() on key_wrapper
        fake_kdf(&shared_secret, &mut key_wrapper);

        // Wrap the key
        let r: core::result::Result<(), Error> = key_wrapper.try_wrap(&key_to_wrap);

        assert!(r.is_ok());
        let wrapped_key = Vec::from(key_wrapper);
        assert_eq!(
            wrapped_key,
            alloc::vec![
                191, 59, 119, 181, 233, 12, 170, 159, 80, 9, 254, 150, 38, 228, 239, 226, 13, 237,
                117, 238, 59, 26, 192, 213
            ]
        )
    }

    #[test]
    fn test_keywrapper_try_wrap_error() {
        // Key to wrap
        let key_to_wrap = [0u8; 16];

        // Define a key wrapper with unsupported key size
        assert_eq!(
            KeyWrapper::try_new(&KeyWrapAlgorithm::Aes128, 15)
                .unwrap_err()
                .to_string(),
            "builder error: could not wrap key: key size is not supported"
        );

        // Define a key wrapper from Aes128-key-wrap but with a different size than key-to-wrap
        let mut key_wrapper = KeyWrapper::try_new(&KeyWrapAlgorithm::Aes128, 24).unwrap();

        // Wrap the key
        assert_eq!(
            key_wrapper.try_wrap(&key_to_wrap).unwrap_err().to_string(),
            "builder error: could not wrap key with Aes128 key wrap algorithm"
        );
    }

    #[test]
    fn test_keywrapper_as_mut() {
        let mut key_wrapper = KeyWrapper::try_new(&KeyWrapAlgorithm::Aes128, 16).unwrap();
        let slice_a128 = key_wrapper.as_mut();
        assert_eq!(slice_a128.len(), 16);
        assert_eq!(slice_a128[0], 0);
    }

    #[test]
    fn test_vecu8_from_keywrapper() {
        let key_wrapper = KeyWrapper::try_new(&KeyWrapAlgorithm::Aes128, 16).unwrap();
        let vec = Vec::from(key_wrapper);
        assert_eq!(vec.len(), 24);
        assert_eq!(vec[0], 0);

        let key_wrapper = KeyWrapper::try_new(&KeyWrapAlgorithm::Aes192, 16).unwrap();
        let vec = Vec::from(key_wrapper);
        assert_eq!(vec.len(), 24);
        assert_eq!(vec[0], 0);

        let key_wrapper = KeyWrapper::try_new(&KeyWrapAlgorithm::Aes256, 16).unwrap();
        let vec = Vec::from(key_wrapper);
        assert_eq!(vec.len(), 24);
        assert_eq!(vec[0], 0);

        let key_wrapper = KeyWrapper::try_new(&KeyWrapAlgorithm::Aes192, 24).unwrap();
        let vec = Vec::from(key_wrapper);
        assert_eq!(vec.len(), 32);
        assert_eq!(vec[0], 0);

        let key_wrapper = KeyWrapper::try_new(&KeyWrapAlgorithm::Aes192, 24).unwrap();
        let vec = Vec::from(key_wrapper);
        assert_eq!(vec.len(), 32);
        assert_eq!(vec[0], 0);

        let key_wrapper = KeyWrapper::try_new(&KeyWrapAlgorithm::Aes192, 24).unwrap();
        let vec = Vec::from(key_wrapper);
        assert_eq!(vec.len(), 32);
        assert_eq!(vec[0], 0);

        let key_wrapper = KeyWrapper::try_new(&KeyWrapAlgorithm::Aes128, 32).unwrap();
        let vec = Vec::from(key_wrapper);
        assert_eq!(vec.len(), 40);
        assert_eq!(vec[0], 0);

        let key_wrapper = KeyWrapper::try_new(&KeyWrapAlgorithm::Aes192, 32).unwrap();
        let vec = Vec::from(key_wrapper);
        assert_eq!(vec.len(), 40);
        assert_eq!(vec[0], 0);

        let key_wrapper = KeyWrapper::try_new(&KeyWrapAlgorithm::Aes256, 32).unwrap();
        let vec = Vec::from(key_wrapper);
        assert_eq!(vec.len(), 40);
        assert_eq!(vec[0], 0);
    }

    #[test]
    fn test_wrappingkey_from_keywrapalgorithm() {
        assert_eq!(
            WrappingKey::from(&KeyWrapAlgorithm::Aes128),
            WrappingKey::Aes128([0u8; 16])
        );
        assert_eq!(
            WrappingKey::from(&KeyWrapAlgorithm::Aes192),
            WrappingKey::Aes192([0u8; 24])
        );
        assert_eq!(
            WrappingKey::from(&KeyWrapAlgorithm::Aes256),
            WrappingKey::Aes256([0u8; 32])
        );
    }

    #[test]
    fn test_wrappingkey_as_mut() {
        let mut key_a128 = WrappingKey::Aes128([0; 16]);
        let slice_a128 = key_a128.as_mut();
        assert_eq!(slice_a128.len(), 16);
        assert_eq!(slice_a128[0], 0);

        let mut key_a192 = WrappingKey::Aes192([0; 24]);
        let slice_a192 = key_a192.as_mut();
        assert_eq!(slice_a192.len(), 24);
        assert_eq!(slice_a192[0], 0);

        let mut key_a256 = WrappingKey::Aes256([0; 32]);
        let slice_a256 = key_a256.as_mut();
        assert_eq!(slice_a256.len(), 32);
        assert_eq!(slice_a256[0], 0);
    }

    #[test]
    fn test_wrappedkey_from_usize() {
        let key_size: usize = 16;
        assert!(WrappedKey::try_from(key_size).is_ok());

        let key_size: usize = 24;
        assert!(WrappedKey::try_from(key_size).is_ok());

        let key_size: usize = 32;
        assert!(WrappedKey::try_from(key_size).is_ok());

        let key_size: usize = 0;
        assert!(WrappedKey::try_from(key_size).is_err());
    }
    #[test]
    fn test_wrappedkey_as_mut() {
        let mut key_a128 = WrappedKey::Aes128([0; 24]);
        let slice_a128 = key_a128.as_mut();
        assert_eq!(slice_a128.len(), 24);
        assert_eq!(slice_a128[0], 0);

        let mut key_a192 = WrappedKey::Aes192([0; 32]);
        let slice_a192 = key_a192.as_mut();
        assert_eq!(slice_a192.len(), 32);
        assert_eq!(slice_a192[0], 0);

        let mut key_a256 = WrappedKey::Aes256([0; 40]);
        let slice_a256 = key_a256.as_mut();
        assert_eq!(slice_a256.len(), 40);
        assert_eq!(slice_a256[0], 0);
    }

    #[test]
    fn test_vecu8_from_wrappedkey() {
        let key_a128 = WrappedKey::Aes128([0; 24]);
        let vec = Vec::from(key_a128);
        assert_eq!(vec.len(), 24);

        let key_a192 = WrappedKey::Aes192([0; 32]);
        let vec = Vec::from(key_a192);
        assert_eq!(vec.len(), 32);

        let key_a256 = WrappedKey::Aes256([0; 40]);
        let vec = Vec::from(key_a256);
        assert_eq!(vec.len(), 40);
    }
}
