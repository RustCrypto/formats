//! Key Derivation Functions.
//!
//! These are used for deriving an encryption key from a password.

use crate::{
    decoder::{Decode, Decoder},
    encoder::{Encode, Encoder},
    Error, KdfAlg, Result,
};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "encryption")]
use bcrypt_pbkdf::bcrypt_pbkdf;

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
                {
                    // TODO(tarcieri): validate length
                    let _len = decoder.decode_usize()?;
                    let salt = decoder.decode_byte_vec()?;
                    let rounds = decoder.decode_u32()?;
                    Ok(Self::Bcrypt { salt, rounds })
                }
            }
        }
    }
}

impl Encode for Kdf {
    fn encoded_len(&self) -> Result<usize> {
        Ok(self.algorithm().encoded_len()?
            + match self {
                Self::None => 4,
                #[cfg(feature = "alloc")]
                Self::Bcrypt { salt, .. } => 4 + 4 + salt.len() + 4,
            })
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        self.algorithm().encode(encoder)?;

        match self {
            Self::None => encoder.encode_usize(0),
            #[cfg(feature = "alloc")]
            Self::Bcrypt { salt, rounds } => {
                encoder.encode_usize(4 + salt.len() + 4)?;
                encoder.encode_byte_slice(salt)?;
                encoder.encode_u32(*rounds)
            }
        }
    }
}
