//! Key wrap module
//!
//! This module contains the key wrapping logic based on aes-kw algorithms
//!

// Self imports
use crate::builder::{Error, Result};

// Internal imports
use const_oid::AssociatedOid;
use spki::AlgorithmIdentifierOwned;

// Alloc imports
use alloc::{string::String, vec::Vec};

// Core imports
use core::ops::Add;

// Rust crypto imports
use aes::cipher::{
    BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, Key, KeyInit, KeySizeUser,
    array::{Array, ArraySize},
    typenum::{Sum, U8, U16, Unsigned},
};
use aes_kw::AesKw;

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
///
/// Represents key wrap algorithms methods.
pub trait KeyWrapAlgorithm: AssociatedOid + KeySizeUser {
    /// Return key size of the key-wrap algorithm in bits
    fn key_size_in_bits() -> u32;

    /// Return algorithm identifier AlgorithmIdentifierOwned` associated with the key-wrap algorithm
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
    fn algorithm_identifier() -> AlgorithmIdentifierOwned;

    /// Return an empty wrapping key (KEK) with the adequate size to be used with aes-key-wrap
    fn init_kek() -> Key<Self>;

    /// Return an empty wrapped key with the adequate size to be used with aes-key-wrap
    fn init_wrapped<T>() -> WrappedKey<T>
    where
        T: KeySizeUser,
        Sum<T::KeySize, U8>: ArraySize,
        <T as KeySizeUser>::KeySize: Add<U8>;

    /// Try to wrap some data using given wrapping key
    fn try_wrap(key: &Key<Self>, data: &[u8], out: &mut [u8]) -> Result<()>;
}

/// Struct representing a wrapped key
///
/// Can be used to abstract wrapped key over different incoming key sizes.
pub struct WrappedKey<T>
where
    T: KeySizeUser,
    Sum<T::KeySize, U8>: ArraySize,
    <T as KeySizeUser>::KeySize: Add<U8>,
{
    inner: Array<u8, Sum<T::KeySize, U8>>,
}

impl<T> AsMut<[u8]> for WrappedKey<T>
where
    T: KeySizeUser,
    Sum<T::KeySize, U8>: ArraySize,
    <T as KeySizeUser>::KeySize: Add<U8>,
{
    fn as_mut(&mut self) -> &mut [u8] {
        self.inner.as_mut()
    }
}

impl<T> From<WrappedKey<T>> for Vec<u8>
where
    T: KeySizeUser,
    Sum<T::KeySize, U8>: ArraySize,
    <T as KeySizeUser>::KeySize: Add<U8>,
{
    fn from(wrapped_key: WrappedKey<T>) -> Self {
        wrapped_key.inner.to_vec()
    }
}

impl<AesWrap> KeyWrapAlgorithm for AesKw<AesWrap>
where
    AesWrap: KeyInit + BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + BlockCipherDecrypt,
    AesKw<AesWrap>: AssociatedOid + KeyInit,
{
    fn key_size_in_bits() -> u32 {
        AesWrap::KeySize::U32 * 8u32
    }

    fn algorithm_identifier() -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: Self::OID,
            parameters: None,
        }
    }

    fn init_kek() -> Key<Self> {
        Key::<Self>::default()
    }

    fn init_wrapped<AesEnc>() -> WrappedKey<AesEnc>
    where
        AesEnc: KeySizeUser,
        Sum<AesEnc::KeySize, aes_kw::IvLen>: ArraySize,
        <AesEnc as KeySizeUser>::KeySize: Add<aes_kw::IvLen>,
    {
        WrappedKey::<AesEnc> {
            inner: Array::<u8, Sum<AesEnc::KeySize, aes_kw::IvLen>>::default(),
        }
    }

    fn try_wrap(key: &Key<Self>, data: &[u8], out: &mut [u8]) -> Result<()> {
        let kek = AesKw::new(key);
        let res = kek
            .wrap_key(data, out)
            .map_err(|_| Error::Builder(String::from("could not wrap key")))?;
        if res.len() != out.len() {
            return Err(Error::Builder(String::from("output buffer invalid size")));
        }
        Ok(())
    }
}

/*
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
*/
