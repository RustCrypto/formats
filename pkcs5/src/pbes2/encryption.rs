//! PBES2 encryption implementation

use super::{EncryptionScheme, Kdf, Parameters, Pbkdf2Params, Pbkdf2Prf, ScryptParams};
use crate::{Error, Result};
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use core::convert::TryInto;
use hmac::{
    digest::{generic_array::ArrayLength, BlockInput, FixedOutput, Reset, Update},
    Hmac,
};
use pbkdf2::pbkdf2;
use scrypt::scrypt;

type Aes128Cbc = Cbc<aes::Aes128, Pkcs7>;
type Aes192Cbc = Cbc<aes::Aes192, Pkcs7>;
type Aes256Cbc = Cbc<aes::Aes256, Pkcs7>;
#[cfg(feature = "des-insecure")]
type DesCbc = Cbc<des::Des, Pkcs7>;
#[cfg(feature = "3des")]
type DesEde3Cbc = Cbc<des::TdesEde3, Pkcs7>;

/// Maximum size of a derived encryption key
const MAX_KEY_LEN: usize = 32;

pub fn encrypt_in_place<'b>(
    params: &Parameters<'_>,
    password: impl AsRef<[u8]>,
    buffer: &'b mut [u8],
    pos: usize,
) -> Result<&'b [u8]> {
    let es = params.encryption;
    let key_size = es.key_size();
    if key_size > MAX_KEY_LEN {
        return Err(es.to_alg_params_invalid());
    }
    let encryption_key =
        EncryptionKey::derive_from_password(password.as_ref(), &params.kdf, key_size)?;

    match es {
        EncryptionScheme::Aes128Cbc { iv } => {
            let cipher = Aes128Cbc::new_from_slices(encryption_key.as_slice(), iv)
                .map_err(|_| es.to_alg_params_invalid())?;
            cipher
                .encrypt(buffer, pos)
                .map_err(|_| Error::EncryptFailed)
        }
        EncryptionScheme::Aes192Cbc { iv } => {
            let cipher = Aes192Cbc::new_from_slices(encryption_key.as_slice(), iv)
                .map_err(|_| es.to_alg_params_invalid())?;
            cipher
                .encrypt(buffer, pos)
                .map_err(|_| Error::EncryptFailed)
        }
        EncryptionScheme::Aes256Cbc { iv } => {
            let cipher = Aes256Cbc::new_from_slices(encryption_key.as_slice(), iv)
                .map_err(|_| es.to_alg_params_invalid())?;
            cipher
                .encrypt(buffer, pos)
                .map_err(|_| Error::EncryptFailed)
        }
        #[cfg(feature = "3des")]
        EncryptionScheme::DesEde3Cbc { iv } => {
            let cipher = DesEde3Cbc::new_from_slices(encryption_key.as_slice(), iv)
                .map_err(|_| es.to_alg_params_invalid())?;
            cipher
                .encrypt(buffer, pos)
                .map_err(|_| Error::EncryptFailed)
        }
        #[cfg(feature = "des-insecure")]
        EncryptionScheme::DesCbc { .. } => Err(Error::UnsupportedAlgorithm {
            oid: super::DES_CBC_OID,
        }),
    }
}

/// Decrypt a message encrypted with PBES2-based key derivation
pub fn decrypt_in_place<'a>(
    params: &Parameters<'_>,
    password: impl AsRef<[u8]>,
    buffer: &'a mut [u8],
) -> Result<&'a [u8]> {
    let es = params.encryption;
    let encryption_key =
        EncryptionKey::derive_from_password(password.as_ref(), &params.kdf, es.key_size())?;

    match es {
        EncryptionScheme::Aes128Cbc { iv } => {
            let cipher = Aes128Cbc::new_from_slices(encryption_key.as_slice(), iv)
                .map_err(|_| es.to_alg_params_invalid())?;
            cipher.decrypt(buffer).map_err(|_| Error::DecryptFailed)
        }
        EncryptionScheme::Aes192Cbc { iv } => {
            let cipher = Aes192Cbc::new_from_slices(encryption_key.as_slice(), iv)
                .map_err(|_| es.to_alg_params_invalid())?;
            cipher.decrypt(buffer).map_err(|_| Error::DecryptFailed)
        }
        EncryptionScheme::Aes256Cbc { iv } => {
            let cipher = Aes256Cbc::new_from_slices(encryption_key.as_slice(), iv)
                .map_err(|_| es.to_alg_params_invalid())?;
            cipher.decrypt(buffer).map_err(|_| Error::DecryptFailed)
        }
        #[cfg(feature = "3des")]
        EncryptionScheme::DesEde3Cbc { iv } => {
            let cipher = DesEde3Cbc::new_from_slices(encryption_key.as_slice(), iv)
                .map_err(|_| es.to_alg_params_invalid())?;
            cipher.decrypt(buffer).map_err(|_| Error::DecryptFailed)
        }
        #[cfg(feature = "des-insecure")]
        EncryptionScheme::DesCbc { iv } => {
            let cipher = DesCbc::new_from_slices(encryption_key.as_slice(), iv)
                .map_err(|_| es.to_alg_params_invalid())?;
            cipher.decrypt(buffer).map_err(|_| Error::DecryptFailed)
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
    pub fn derive_from_password(password: &[u8], kdf: &Kdf<'_>, key_size: usize) -> Result<Self> {
        // if the kdf params defined a key length, ensure it matches the required key size
        if let Some(len) = kdf.key_length() {
            if key_size != len.into() {
                return Err(kdf.to_alg_params_invalid());
            }
        }

        match kdf {
            Kdf::Pbkdf2(pbkdf2_params) => {
                let key = match pbkdf2_params.prf {
                    #[cfg(feature = "sha1")]
                    Pbkdf2Prf::HmacWithSha1 => EncryptionKey::derive_with_pbkdf2::<sha1::Sha1>(
                        password,
                        pbkdf2_params,
                        key_size,
                    ),
                    #[cfg(not(feature = "sha1"))]
                    Pbkdf2Prf::HmacWithSha1 => {
                        return Err(Error::UnsupportedAlgorithm {
                            oid: super::HMAC_WITH_SHA1_OID,
                        })
                    }
                    Pbkdf2Prf::HmacWithSha224 => EncryptionKey::derive_with_pbkdf2::<sha2::Sha224>(
                        password,
                        pbkdf2_params,
                        key_size,
                    ),
                    Pbkdf2Prf::HmacWithSha256 => EncryptionKey::derive_with_pbkdf2::<sha2::Sha256>(
                        password,
                        pbkdf2_params,
                        key_size,
                    ),
                    Pbkdf2Prf::HmacWithSha384 => EncryptionKey::derive_with_pbkdf2::<sha2::Sha384>(
                        password,
                        pbkdf2_params,
                        key_size,
                    ),
                    Pbkdf2Prf::HmacWithSha512 => EncryptionKey::derive_with_pbkdf2::<sha2::Sha512>(
                        password,
                        pbkdf2_params,
                        key_size,
                    ),
                };

                Ok(key)
            }
            Kdf::Scrypt(scrypt_params) => {
                EncryptionKey::derive_with_scrypt(password, scrypt_params, key_size)
            }
        }
    }

    /// Derive key using PBKDF2.
    fn derive_with_pbkdf2<D>(password: &[u8], params: &Pbkdf2Params<'_>, length: usize) -> Self
    where
        D: Update + BlockInput + FixedOutput + Reset + Default + Clone + Sync,
        D::BlockSize: ArrayLength<u8>,
    {
        let mut buffer = [0u8; MAX_KEY_LEN];
        pbkdf2::<Hmac<D>>(
            password,
            params.salt,
            params.iteration_count as u32,
            &mut buffer[..length],
        );

        Self { buffer, length }
    }

    /// Derive key using scrypt.
    fn derive_with_scrypt(
        password: &[u8],
        params: &ScryptParams<'_>,
        length: usize,
    ) -> Result<Self> {
        let mut buffer = [0u8; MAX_KEY_LEN];
        scrypt(
            password,
            params.salt,
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
