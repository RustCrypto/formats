//! PBES2 encryption.

use super::{
    EncryptionSchemeInner, KdfInner, ParametersInner, Pbkdf2ParamsInner, Pbkdf2Prf,
    ScryptParamsInner,
};
use crate::{Error, Result};
use cbc::cipher::{
    block_padding::Pkcs7, BlockCipher, BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit,
};
use pbkdf2::{
    hmac::digest::{
        block_buffer::Eager,
        core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
        generic_array::typenum::{IsLess, Le, NonZero, U256},
        HashMarker,
    },
    pbkdf2_hmac,
};
use scrypt::scrypt;

/// Maximum size of a derived encryption key
const MAX_KEY_LEN: usize = 32;

fn cbc_encrypt<'a, C: BlockEncryptMut + BlockCipher + KeyInit, AesBlock, DesBlock>(
    es: &EncryptionSchemeInner<AesBlock, DesBlock>,
    key: EncryptionKey,
    iv: &[u8],
    buffer: &'a mut [u8],
    pos: usize,
) -> Result<&'a [u8]> {
    cbc::Encryptor::<C>::new_from_slices(key.as_slice(), iv)
        .map_err(|_| es.to_alg_params_invalid())?
        .encrypt_padded_mut::<Pkcs7>(buffer, pos)
        .map_err(|_| Error::EncryptFailed)
}

fn cbc_decrypt<'a, C: BlockDecryptMut + BlockCipher + KeyInit, AesBlock, DesBlock>(
    es: &EncryptionSchemeInner<AesBlock, DesBlock>,
    key: EncryptionKey,
    iv: &[u8],
    buffer: &'a mut [u8],
) -> Result<&'a [u8]> {
    cbc::Decryptor::<C>::new_from_slices(key.as_slice(), iv)
        .map_err(|_| es.to_alg_params_invalid())?
        .decrypt_padded_mut::<Pkcs7>(buffer)
        .map_err(|_| Error::EncryptFailed)
}

pub fn encrypt_in_place<'b, AesBlock, DesBlock, Salt>(
    params: &ParametersInner<AesBlock, DesBlock, Salt>,
    password: impl AsRef<[u8]>,
    buf: &'b mut [u8],
    pos: usize,
) -> Result<&'b [u8]>
where
    Salt: AsRef<[u8]>,
    AesBlock: AsRef<[u8]>,
    DesBlock: AsRef<[u8]>,
{
    let es = &params.encryption;
    let key_size = es.key_size();
    if key_size > MAX_KEY_LEN {
        return Err(es.to_alg_params_invalid());
    }
    let key = EncryptionKey::derive_from_password(password.as_ref(), &params.kdf, key_size)?;

    match es {
        EncryptionSchemeInner::<AesBlock, DesBlock>::Aes128Cbc { iv } => {
            cbc_encrypt::<aes::Aes128Enc, AesBlock, DesBlock>(es, key, iv.as_ref(), buf, pos)
        }
        EncryptionSchemeInner::<AesBlock, DesBlock>::Aes192Cbc { iv } => {
            cbc_encrypt::<aes::Aes192Enc, AesBlock, DesBlock>(es, key, iv.as_ref(), buf, pos)
        }
        EncryptionSchemeInner::<AesBlock, DesBlock>::Aes256Cbc { iv } => {
            cbc_encrypt::<aes::Aes256Enc, AesBlock, DesBlock>(es, key, iv.as_ref(), buf, pos)
        }
        #[cfg(feature = "3des")]
        EncryptionSchemeInner::<AesBlock, DesBlock>::DesEde3Cbc { iv } => {
            cbc_encrypt::<des::TdesEde3, AesBlock, DesBlock>(es, key, iv.as_ref(), buf, pos)
        }
        #[cfg(feature = "des-insecure")]
        EncryptionSchemeInner::<AesBlock, DesBlock>::DesCbc { .. } => {
            Err(Error::UnsupportedAlgorithm {
                oid: super::DES_CBC_OID,
            })
        }
    }
}

/// Decrypt a message encrypted with PBES2-based key derivation
pub fn decrypt_in_place<'a, AesBlock, DesBlock, Salt>(
    params: &ParametersInner<AesBlock, DesBlock, Salt>,
    password: impl AsRef<[u8]>,
    buf: &'a mut [u8],
) -> Result<&'a [u8]>
where
    Salt: AsRef<[u8]>,
    AesBlock: AsRef<[u8]>,
    DesBlock: AsRef<[u8]>,
{
    let es = &params.encryption;
    let key = EncryptionKey::derive_from_password(password.as_ref(), &params.kdf, es.key_size())?;

    match es {
        EncryptionSchemeInner::<AesBlock, DesBlock>::Aes128Cbc { iv } => {
            cbc_decrypt::<aes::Aes128Dec, AesBlock, DesBlock>(es, key, iv.as_ref(), buf)
        }
        EncryptionSchemeInner::<AesBlock, DesBlock>::Aes192Cbc { iv } => {
            cbc_decrypt::<aes::Aes192Dec, AesBlock, DesBlock>(es, key, iv.as_ref(), buf)
        }
        EncryptionSchemeInner::<AesBlock, DesBlock>::Aes256Cbc { iv } => {
            cbc_decrypt::<aes::Aes256Dec, AesBlock, DesBlock>(es, key, iv.as_ref(), buf)
        }
        #[cfg(feature = "3des")]
        EncryptionSchemeInner::<AesBlock, DesBlock>::DesEde3Cbc { iv } => {
            cbc_decrypt::<des::TdesEde3, AesBlock, DesBlock>(es, key, iv.as_ref(), buf)
        }
        #[cfg(feature = "des-insecure")]
        EncryptionSchemeInner::<AesBlock, DesBlock>::DesCbc { iv } => {
            cbc_decrypt::<des::Des, AesBlock, DesBlock>(es, key, iv.as_ref(), buf)
        }
    }
}

/// Encryption key as derived by PBKDF2
// TODO(tarcieri): zeroize?
struct EncryptionKey {
    buffer: [u8; MAX_KEY_LEN],
    length: usize,
}

impl EncryptionKey {
    /// Derive an encryption key using the supplied PBKDF parameters.
    pub fn derive_from_password<Salt>(
        password: &[u8],
        kdf: &KdfInner<Salt>,
        key_size: usize,
    ) -> Result<Self>
    where
        Salt: AsRef<[u8]>,
    {
        // if the kdf params defined a key length, ensure it matches the required key size
        if let Some(len) = kdf.key_length() {
            if key_size != len.into() {
                return Err(kdf.to_alg_params_invalid());
            }
        }

        match kdf {
            KdfInner::Pbkdf2(pbkdf2_params) => {
                let key = match pbkdf2_params.prf {
                    #[cfg(feature = "sha1-insecure")]
                    Pbkdf2Prf::HmacWithSha1 => {
                        EncryptionKey::derive_with_pbkdf2::<sha1::Sha1, Salt>(
                            password,
                            pbkdf2_params,
                            key_size,
                        )
                    }
                    #[cfg(not(feature = "sha1-insecure"))]
                    Pbkdf2Prf::HmacWithSha1 => {
                        return Err(Error::UnsupportedAlgorithm {
                            oid: super::HMAC_WITH_SHA1_OID,
                        })
                    }
                    Pbkdf2Prf::HmacWithSha224 => EncryptionKey::derive_with_pbkdf2::<
                        sha2::Sha224,
                        Salt,
                    >(
                        password, pbkdf2_params, key_size
                    ),
                    Pbkdf2Prf::HmacWithSha256 => EncryptionKey::derive_with_pbkdf2::<
                        sha2::Sha256,
                        Salt,
                    >(
                        password, pbkdf2_params, key_size
                    ),
                    Pbkdf2Prf::HmacWithSha384 => EncryptionKey::derive_with_pbkdf2::<
                        sha2::Sha384,
                        Salt,
                    >(
                        password, pbkdf2_params, key_size
                    ),
                    Pbkdf2Prf::HmacWithSha512 => EncryptionKey::derive_with_pbkdf2::<
                        sha2::Sha512,
                        Salt,
                    >(
                        password, pbkdf2_params, key_size
                    ),
                };

                Ok(key)
            }
            KdfInner::Scrypt(scrypt_params) => {
                EncryptionKey::derive_with_scrypt(password, scrypt_params, key_size)
            }
        }
    }

    /// Derive key using PBKDF2.
    fn derive_with_pbkdf2<D, Salt>(
        password: &[u8],
        params: &Pbkdf2ParamsInner<Salt>,
        length: usize,
    ) -> Self
    where
        D: CoreProxy,
        D::Core: Sync
            + HashMarker
            + UpdateCore
            + FixedOutputCore
            + BufferKindUser<BufferKind = Eager>
            + Default
            + Clone,
        <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
        Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
        Salt: AsRef<[u8]>,
    {
        let mut buffer = [0u8; MAX_KEY_LEN];

        pbkdf2_hmac::<D>(
            password,
            params.salt.as_ref(),
            params.iteration_count,
            &mut buffer[..length],
        );

        Self { buffer, length }
    }

    /// Derive key using scrypt.
    fn derive_with_scrypt<Salt>(
        password: &[u8],
        params: &ScryptParamsInner<Salt>,
        length: usize,
    ) -> Result<Self>
    where
        Salt: AsRef<[u8]>,
    {
        let mut buffer = [0u8; MAX_KEY_LEN];
        scrypt(
            password,
            params.salt.as_ref(),
            &params.try_into()?,
            &mut buffer[..length],
        )
        .map_err(|_| Error::AlgorithmParametersInvalid {
            oid: super::SCRYPT_OID,
        })?;

        Ok(Self { buffer, length })
    }

    /// Get the key material as a slice
    fn as_slice(&self) -> &[u8] {
        &self.buffer[..self.length]
    }
}
