//! Key Derivation Functions.
//!
//! These are used for deriving an encryption key from a password.

use crate::{
    checked::CheckedSum,
    decoder::{Decode, Decoder},
    encoder::{Encode, Encoder},
    Error, KdfAlg, Result,
};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "encryption")]
use {
    crate::Cipher,
    bcrypt_pbkdf::bcrypt_pbkdf,
    rand_core::{CryptoRng, RngCore},
    zeroize::Zeroizing,
};

/// Default number of rounds to use for bcrypt-pbkdf.
#[cfg(feature = "encryption")]
const DEFAULT_BCRYPT_ROUNDS: u32 = 16;

/// Default salt size. Matches OpenSSH.
#[cfg(feature = "encryption")]
const DEFAULT_SALT_SIZE: usize = 16;

/// Key Derivation Functions (KDF).
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Kdf {
    /// No KDF.
    None,

    /// bcrypt-pbkdf options.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    Bcrypt {
        /// Salt
        salt: Vec<u8>,

        /// Rounds
        rounds: u32,
    },
}

impl Kdf {
    /// Initialize KDF configuration for the given algorithm.
    #[cfg(feature = "encryption")]
    #[cfg_attr(docsrs, doc(cfg(feature = "encryption")))]
    pub fn new(algorithm: KdfAlg, mut rng: impl CryptoRng + RngCore) -> Result<Self> {
        let mut salt = vec![0u8; DEFAULT_SALT_SIZE];
        rng.fill_bytes(&mut salt);

        match algorithm {
            KdfAlg::None => {
                // Disallow explicit initialization with a `none` algorithm
                Err(Error::Algorithm)
            }
            KdfAlg::Bcrypt => Ok(Kdf::Bcrypt {
                salt,
                rounds: DEFAULT_BCRYPT_ROUNDS,
            }),
        }
    }

    /// Get the KDF algorithm.
    pub fn algorithm(&self) -> KdfAlg {
        match self {
            Self::None => KdfAlg::None,
            #[cfg(feature = "alloc")]
            Self::Bcrypt { .. } => KdfAlg::Bcrypt,
        }
    }

    /// Derive an encryption key from the given password.
    #[cfg(feature = "encryption")]
    #[cfg_attr(docsrs, doc(cfg(feature = "encryption")))]
    pub fn derive(&self, password: impl AsRef<[u8]>, output: &mut [u8]) -> Result<()> {
        match self {
            Kdf::None => Err(Error::Decrypted),
            Kdf::Bcrypt { salt, rounds } => {
                bcrypt_pbkdf(password, salt, *rounds, output).map_err(|_| Error::Crypto)?;
                Ok(())
            }
        }
    }

    /// Derive key and IV for the given [`Cipher`].
    ///
    /// Returns two byte vectors containing the key and IV respectively.
    #[cfg(feature = "encryption")]
    #[cfg_attr(docsrs, doc(cfg(feature = "encryption")))]
    pub fn derive_key_and_iv(
        &self,
        cipher: Cipher,
        password: impl AsRef<[u8]>,
    ) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
        let (key_size, iv_size) = cipher.key_and_iv_size().ok_or(Error::Decrypted)?;
        let okm_size = key_size.checked_add(iv_size).ok_or(Error::Length)?;

        let mut okm = Zeroizing::new(vec![0u8; okm_size]);
        self.derive(password, &mut okm)?;
        let iv = okm.split_off(key_size);
        Ok((okm, iv))
    }

    /// Is the KDF configured as `none`?
    pub fn is_none(&self) -> bool {
        self == &Self::None
    }

    /// Is the KDF configured as `bcrypt` (i.e. bcrypt-pbkdf)?
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn is_bcrypt(&self) -> bool {
        matches!(self, Self::Bcrypt { .. })
    }
}

impl Default for Kdf {
    fn default() -> Self {
        Self::None
    }
}

impl Decode for Kdf {
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        match KdfAlg::decode(decoder)? {
            KdfAlg::None => {
                if decoder.decode_usize()? == 0 {
                    Ok(Self::None)
                } else {
                    Err(Error::Algorithm)
                }
            }
            KdfAlg::Bcrypt => {
                #[cfg(not(feature = "alloc"))]
                return Err(Error::Algorithm);

                #[cfg(feature = "alloc")]
                decoder.decode_length_prefixed(|decoder, _len| {
                    let salt = decoder.decode_byte_vec()?;
                    let rounds = decoder.decode_u32()?;
                    Ok(Self::Bcrypt { salt, rounds })
                })
            }
        }
    }
}

impl Encode for Kdf {
    fn encoded_len(&self) -> Result<usize> {
        let kdfopts_len = match self {
            Self::None => 0,
            #[cfg(feature = "alloc")]
            Self::Bcrypt { salt, .. } => [8, salt.len()].checked_sum()?,
        };

        [
            self.algorithm().encoded_len()?,
            4, // kdfopts length prefix (uint32)
            kdfopts_len,
        ]
        .checked_sum()
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        self.algorithm().encode(encoder)?;

        match self {
            Self::None => encoder.encode_usize(0),
            #[cfg(feature = "alloc")]
            Self::Bcrypt { salt, rounds } => {
                encoder.encode_usize([8, salt.len()].checked_sum()?)?;
                encoder.encode_byte_slice(salt)?;
                encoder.encode_u32(*rounds)
            }
        }
    }
}
