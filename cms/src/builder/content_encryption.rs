//! Encryption and decryption of CMS content (an `EncryptedContentInfo`, as in `EnvelopedData`,
//! `AuthEnvelopedData` and `EncryptedData`), behind traits an application can implement, e.g. to
//! perform them in a cryptographic module, and with RustCrypto AES-CBC as the default.

use super::{Error, Result};
use aes::{Aes128, Aes192, Aes256};
use alloc::vec::Vec;
use cipher::{
    BlockModeDecrypt, BlockModeEncrypt, Iv, Key, KeyIvInit, block_padding::Pkcs7, common::Generate,
    rand_core::CryptoRng,
};
use const_oid::{DynAssociatedOid, ObjectIdentifier};
use der::{Any, Tag, asn1::OctetString};
use spki::AlgorithmIdentifierOwned;
use zeroize::Zeroizing;

/// The result of encrypting content.
pub struct ContentEncryptionOutput {
    /// The ciphertext, without the authentication tag.
    pub ciphertext: Vec<u8>,
    /// The content-encryption key, for the recipients to wrap.
    pub key: Zeroizing<Vec<u8>>,
    /// The content-encryption algorithm identifier, including its parameters (e.g. the IV).
    pub algorithm: AlgorithmIdentifierOwned,
    /// The authentication tag, present for an authenticated algorithm.
    pub tag: Option<Vec<u8>>,
}

impl core::fmt::Debug for ContentEncryptionOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ContentEncryptionOutput")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// Encrypts CMS content.
///
/// An implementation encrypts the content with a content-encryption key, generating the key when
/// none is given (as for `EnvelopedData`, whose recipients receive it) or using the given one (as
/// for `EncryptedData`, whose key the parties already share), and returns the key with the
/// algorithm identifier, including any IV or nonce, to record in the `EncryptedContentInfo`.
/// [`DynAssociatedOid::oid`] identifies the algorithm before encryption; the output's `algorithm`
/// carries the same OID with its parameters.
/// Implement it to perform content encryption elsewhere than in process, e.g. in a FIPS 140-3
/// validated module; an implementation whose key never leaves the module may refuse a given key.
/// [`ContentEncryptionAlgorithm`] implements it with RustCrypto AES-CBC.
pub trait ContentEncryptor<R: ?Sized>: DynAssociatedOid {
    /// Encrypts `plaintext` with `key`, or with a newly generated key when `key` is `None`.
    /// `aad` is additional authenticated data, for an authenticated algorithm only.
    fn encrypt_content(
        &self,
        key: Option<&[u8]>,
        plaintext: &[u8],
        aad: Option<&[u8]>,
        rng: &mut R,
    ) -> Result<ContentEncryptionOutput>;
}

/// Decrypts CMS content with the content-encryption key.
///
/// The counterpart of [`ContentEncryptor`]. [`AesCbcContentDecryptor`] implements it with
/// RustCrypto AES-CBC.
pub trait ContentDecryptor {
    /// Decrypts `ciphertext` with `key` under `algorithm`, the `EncryptedContentInfo`'s
    /// `contentEncryptionAlgorithm` including its parameters. `aad` and `tag` are for an
    /// authenticated algorithm only.
    fn decrypt_content(
        &self,
        algorithm: &AlgorithmIdentifierOwned,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        tag: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>>;
}

/// Supported content encryption algorithms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContentEncryptionAlgorithm {
    /// AES-128 CBC
    Aes128Cbc,
    /// AES-192 CBC
    Aes192Cbc,
    /// AES-256 CBC
    Aes256Cbc,
}

impl ContentEncryptionAlgorithm {
    /// Return the OID of the algorithm.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            ContentEncryptionAlgorithm::Aes128Cbc => const_oid::db::rfc5911::ID_AES_128_CBC,
            ContentEncryptionAlgorithm::Aes192Cbc => const_oid::db::rfc5911::ID_AES_192_CBC,
            ContentEncryptionAlgorithm::Aes256Cbc => const_oid::db::rfc5911::ID_AES_256_CBC,
        }
    }
}

impl DynAssociatedOid for ContentEncryptionAlgorithm {
    fn oid(&self) -> ObjectIdentifier {
        ContentEncryptionAlgorithm::oid(self)
    }
}

/// Helps encrypting.
macro_rules! encrypt_block_mode {
    ($data:expr, $block_mode:ident::$typ:ident<$alg:ident>, $key:expr, $rng:expr, $oid:expr) => {{
        let (key, iv) = match $key {
            None => {
                let key = Key::<$block_mode::$typ<$alg>>::generate_from_rng($rng);
                let iv = Iv::<$block_mode::$typ<$alg>>::generate_from_rng($rng);
                (key, iv)
            }
            Some(key) => {
                let key = Key::<$block_mode::$typ<$alg>>::try_from(key)
                    .map_err(|_| Error::Builder("invalid key size for chosen algorithm".into()))?;
                let iv = Iv::<$block_mode::$typ<$alg>>::generate_from_rng($rng);
                (key, iv)
            }
        };
        let encryptor = $block_mode::$typ::<$alg>::new(&key.into(), &iv.into());
        Ok((
            encryptor.encrypt_padded_vec::<Pkcs7>($data),
            key.to_vec(),
            AlgorithmIdentifierOwned {
                oid: $oid,
                parameters: Some(Any::new(Tag::OctetString, iv.to_vec())?),
            },
        ))
    }};
}

/// Symmetrically encrypt data.
/// Returns encrypted content, content-encryption key and the used algorithm identifier (including
/// the used algorithm parameters).
///
/// TODO Which encryption algorithms shall also be supported?
pub(super) fn encrypt_data<R>(
    data: &[u8],
    encryption_algorithm_identifier: &ContentEncryptionAlgorithm,
    key: Option<&[u8]>,
    rng: &mut R,
) -> Result<(Vec<u8>, Vec<u8>, AlgorithmIdentifierOwned)>
where
    R: CryptoRng + ?Sized,
{
    match encryption_algorithm_identifier {
        ContentEncryptionAlgorithm::Aes128Cbc => encrypt_block_mode!(
            data,
            cbc::Encryptor<Aes128>,
            key,
            rng,
            encryption_algorithm_identifier.oid()
        ),
        ContentEncryptionAlgorithm::Aes192Cbc => encrypt_block_mode!(
            data,
            cbc::Encryptor<Aes192>,
            key,
            rng,
            encryption_algorithm_identifier.oid()
        ),
        ContentEncryptionAlgorithm::Aes256Cbc => encrypt_block_mode!(
            data,
            cbc::Encryptor<Aes256>,
            key,
            rng,
            encryption_algorithm_identifier.oid()
        ),
    }
}

impl<R: CryptoRng + ?Sized> ContentEncryptor<R> for ContentEncryptionAlgorithm {
    fn encrypt_content(
        &self,
        key: Option<&[u8]>,
        plaintext: &[u8],
        aad: Option<&[u8]>,
        rng: &mut R,
    ) -> Result<ContentEncryptionOutput> {
        if aad.is_some() {
            return Err(Error::Builder(
                "AES-CBC does not take additional authenticated data".into(),
            ));
        }
        let (ciphertext, key, algorithm) = encrypt_data(plaintext, self, key, rng)?;
        Ok(ContentEncryptionOutput {
            ciphertext,
            key: Zeroizing::new(key),
            algorithm,
            tag: None,
        })
    }
}

/// Decrypts AES-128, AES-192 and AES-256 CBC content with RustCrypto.
#[derive(Clone, Copy, Debug, Default)]
pub struct AesCbcContentDecryptor;

macro_rules! decrypt_block_mode {
    ($ciphertext:expr, $block_mode:ident::$typ:ident<$alg:ident>, $key:expr, $iv:expr) => {{
        let key = Key::<$block_mode::$typ<$alg>>::try_from($key).map_err(|_| {
            Error::Builder("invalid key size for the content-encryption algorithm".into())
        })?;
        let iv = Iv::<$block_mode::$typ<$alg>>::try_from($iv).map_err(|_| {
            Error::Builder("invalid IV size for the content-encryption algorithm".into())
        })?;
        $block_mode::$typ::<$alg>::new(&key, &iv)
            .decrypt_padded_vec::<Pkcs7>($ciphertext)
            .map(Zeroizing::new)
            .map_err(|_| Error::Builder("content decryption failed".into()))
    }};
}

impl ContentDecryptor for AesCbcContentDecryptor {
    fn decrypt_content(
        &self,
        algorithm: &AlgorithmIdentifierOwned,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        tag: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        if aad.is_some() || tag.is_some() {
            return Err(Error::Builder(
                "AES-CBC does not take additional authenticated data or a tag".into(),
            ));
        }
        let iv = algorithm
            .parameters
            .as_ref()
            .ok_or_else(|| Error::Builder("the AES-CBC parameters (IV) are absent".into()))?
            .decode_as::<OctetString>()?;
        let iv = iv.as_bytes();
        match algorithm.oid {
            const_oid::db::rfc5911::ID_AES_128_CBC => {
                decrypt_block_mode!(ciphertext, cbc::Decryptor<Aes128>, key, iv)
            }
            const_oid::db::rfc5911::ID_AES_192_CBC => {
                decrypt_block_mode!(ciphertext, cbc::Decryptor<Aes192>, key, iv)
            }
            const_oid::db::rfc5911::ID_AES_256_CBC => {
                decrypt_block_mode!(ciphertext, cbc::Decryptor<Aes256>, key, iv)
            }
            _ => Err(Error::Builder(alloc::format!(
                "unsupported content-encryption algorithm {}",
                algorithm.oid
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AesCbcContentDecryptor, ContentDecryptor, ContentEncryptionAlgorithm, ContentEncryptor,
    };
    use const_oid::DynAssociatedOid;

    const PLAINTEXT: &[u8] = b"content that is not a multiple of the block size";

    #[test]
    fn aes_cbc_round_trips_through_the_traits() {
        for alg in [
            ContentEncryptionAlgorithm::Aes128Cbc,
            ContentEncryptionAlgorithm::Aes192Cbc,
            ContentEncryptionAlgorithm::Aes256Cbc,
        ] {
            let output = alg
                .encrypt_content(None, PLAINTEXT, None, &mut rand::rng())
                .unwrap();
            assert_eq!(output.algorithm.oid, DynAssociatedOid::oid(&alg));
            assert!(output.tag.is_none());
            assert_ne!(output.ciphertext.as_slice(), PLAINTEXT);

            let plaintext = AesCbcContentDecryptor
                .decrypt_content(
                    &output.algorithm,
                    &output.key,
                    &output.ciphertext,
                    None,
                    None,
                )
                .unwrap();
            assert_eq!(plaintext.as_slice(), PLAINTEXT);
        }
    }

    #[test]
    fn aes_cbc_refuses_additional_authenticated_data() {
        let alg = ContentEncryptionAlgorithm::Aes128Cbc;
        assert!(
            alg.encrypt_content(None, PLAINTEXT, Some(b"aad"), &mut rand::rng())
                .is_err()
        );

        let output = alg
            .encrypt_content(None, PLAINTEXT, None, &mut rand::rng())
            .unwrap();
        assert!(
            AesCbcContentDecryptor
                .decrypt_content(
                    &output.algorithm,
                    &output.key,
                    &output.ciphertext,
                    Some(b"aad"),
                    None
                )
                .is_err()
        );
    }

    #[test]
    fn aes_cbc_decryption_rejects_a_wrong_key_size() {
        let output = ContentEncryptionAlgorithm::Aes256Cbc
            .encrypt_content(None, PLAINTEXT, None, &mut rand::rng())
            .unwrap();
        assert!(
            AesCbcContentDecryptor
                .decrypt_content(
                    &output.algorithm,
                    &output.key[..16],
                    &output.ciphertext,
                    None,
                    None
                )
                .is_err()
        );
    }

    #[test]
    fn aes_cbc_encrypts_with_a_supplied_key() {
        let key = [0x42_u8; 32];
        let output = ContentEncryptionAlgorithm::Aes256Cbc
            .encrypt_content(Some(&key), PLAINTEXT, None, &mut rand::rng())
            .unwrap();
        assert_eq!(output.key.as_slice(), key.as_slice());

        let plaintext = AesCbcContentDecryptor
            .decrypt_content(&output.algorithm, &key, &output.ciphertext, None, None)
            .unwrap();
        assert_eq!(plaintext.as_slice(), PLAINTEXT);

        assert!(
            ContentEncryptionAlgorithm::Aes256Cbc
                .encrypt_content(Some(&key[..16]), PLAINTEXT, None, &mut rand::rng())
                .is_err()
        );
    }
}
