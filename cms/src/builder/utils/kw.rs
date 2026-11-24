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
use alloc::{string::String, vec, vec::Vec};

// Core imports
use core::{fmt, marker::PhantomData};

// Rust crypto imports
use aes::cipher::{
    BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, KeyInit,
    typenum::{U16, Unsigned},
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
/// [`AesKeyWrap`] implements it for id-aes128-wrap, id-aes192-wrap and id-aes256-wrap.
/// Implement it to wrap keys elsewhere than in process, e.g. in a FIPS 140-3 validated module.
///
/// [RFC 5753 Section 8]: https://www.rfc-editor.org/info/rfc5753#section-8
/// [RFC 5753 Section 7.1.5]: https://www.rfc-editor.org/info/rfc5753#section-7.1.5
pub trait KeyWrapAlgorithm {
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
    /// [RFC 3565 Section 2.3.2]: https://www.rfc-editor.org/info/rfc3565#section-2.3.2
    /// [RFC 5753 Section 7.2]: https://www.rfc-editor.org/info/rfc5753#section-7.2
    fn algorithm_identifier(&self) -> AlgorithmIdentifierOwned;

    /// Return the size of the key-encryption key (KEK), in bytes.
    fn kek_size(&self) -> usize;

    /// Wrap `key` with the key-encryption key `kek`, which is [`Self::kek_size`] bytes long.
    fn try_wrap(&self, kek: &[u8], key: &[u8]) -> Result<Vec<u8>>;
}

/// AES key wrap (RFC 3394) with RustCrypto `aes-kw`, for `A` one of `aes::Aes128`, `aes::Aes192`
/// and `aes::Aes256`.
pub struct AesKeyWrap<A> {
    _cipher: PhantomData<A>,
}

impl<A> AesKeyWrap<A> {
    /// Creates an AES key wrap algorithm.
    pub fn new() -> Self {
        Self {
            _cipher: PhantomData,
        }
    }
}

impl<A> Default for AesKeyWrap<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A> Clone for AesKeyWrap<A> {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<A> fmt::Debug for AesKeyWrap<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesKeyWrap").finish()
    }
}

impl<A> KeyWrapAlgorithm for AesKeyWrap<A>
where
    A: KeyInit + BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + BlockCipherDecrypt,
    AesKw<A>: AssociatedOid,
{
    fn algorithm_identifier(&self) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: AesKw::<A>::OID,
            parameters: None,
        }
    }

    fn kek_size(&self) -> usize {
        A::KeySize::USIZE
    }

    fn try_wrap(&self, kek: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        let kek = AesKw::<A>::new_from_slice(kek)
            .map_err(|_| Error::Builder(String::from("invalid key-encryption key size")))?;
        let mut wrapped = vec![0u8; key.len() + aes_kw::IV_LEN];
        kek.wrap_key(key, &mut wrapped)
            .map_err(|_| Error::Builder(String::from("could not wrap key")))?;
        Ok(wrapped)
    }
}
