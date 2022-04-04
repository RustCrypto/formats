//! Symmetric encryption ciphers.
//!
//! These are used for encrypting private keys.

use crate::{algorithm::AlgString, Error, Result};
use core::{fmt, str};

#[cfg(feature = "encryption")]
use aes::{
    cipher::{InnerIvInit, KeyInit, StreamCipherCore},
    Aes256,
};

/// AES-256 in counter (CTR) mode
const AES256_CTR: &str = "aes256-ctr";

/// Counter mode with a 32-bit big endian counter.
#[cfg(feature = "encryption")]
type Ctr128BE<Cipher> = ctr::CtrCore<Cipher, ctr::flavors::Ctr128BE>;

/// Cipher algorithms.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Cipher {
    /// No cipher (unencrypted key).
    None,

    /// AES-256 in counter (CTR) mode.
    Aes256Ctr,
}

impl Cipher {
    /// Decode cipher algorithm from the given `ciphername`.
    ///
    /// # Supported cipher names
    /// - `aes256-ctr`
    pub fn new(ciphername: &str) -> Result<Self> {
        match ciphername {
            "none" => Ok(Self::None),
            AES256_CTR => Ok(Self::Aes256Ctr),
            _ => Err(Error::Algorithm),
        }
    }

    /// Get the string identifier which corresponds to this algorithm.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Aes256Ctr => AES256_CTR,
        }
    }

    /// Get the key and IV size for this cipher in bytes.
    pub fn key_and_iv_size(self) -> Option<(usize, usize)> {
        match self {
            Self::None => None,
            Self::Aes256Ctr => Some((32, 16)),
        }
    }

    /// Get the block size for this cipher in bytes.
    pub fn block_size(self) -> usize {
        match self {
            Self::None => 8,
            Self::Aes256Ctr => 16,
        }
    }

    /// Compute the length of padding necessary to pad the given input to
    /// the block size.
    #[allow(clippy::integer_arithmetic)]
    pub fn padding_len(self, input_size: usize) -> usize {
        match input_size % self.block_size() {
            0 => 0,
            input_rem => self.block_size() - input_rem,
        }
    }

    /// Is this cipher `none`?
    pub fn is_none(self) -> bool {
        self == Self::None
    }

    /// Is the cipher anything other than `none`?
    pub fn is_some(self) -> bool {
        !self.is_none()
    }

    /// Decrypt the ciphertext in the `buffer` in-place using this cipher.
    #[cfg(feature = "encryption")]
    #[cfg_attr(docsrs, doc(cfg(feature = "encryption")))]
    pub fn decrypt(self, key: &[u8], iv: &[u8], buffer: &mut [u8]) -> Result<()> {
        match self {
            Self::None => return Err(Error::Crypto),
            // Counter mode encryption and decryption are the same operation
            Self::Aes256Ctr => self.encrypt(key, iv, buffer)?,
        }

        Ok(())
    }

    /// Encrypt the ciphertext in the `buffer` in-place using this cipher.
    #[cfg(feature = "encryption")]
    #[cfg_attr(docsrs, doc(cfg(feature = "encryption")))]
    pub fn encrypt(self, key: &[u8], iv: &[u8], buffer: &mut [u8]) -> Result<()> {
        match self {
            Self::None => return Err(Error::Crypto),
            Self::Aes256Ctr => {
                let cipher = Aes256::new_from_slice(key)
                    .and_then(|aes| Ctr128BE::inner_iv_slice_init(aes, iv))
                    .map_err(|_| Error::Crypto)?;

                cipher
                    .try_apply_keystream_partial(buffer.into())
                    .map_err(|_| Error::Crypto)?;
            }
        }

        Ok(())
    }
}

impl AsRef<str> for Cipher {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AlgString for Cipher {}

impl Default for Cipher {
    fn default() -> Cipher {
        Cipher::Aes256Ctr
    }
}

impl fmt::Display for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl str::FromStr for Cipher {
    type Err = Error;

    fn from_str(id: &str) -> Result<Self> {
        Self::new(id)
    }
}
