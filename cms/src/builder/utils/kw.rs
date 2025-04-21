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
