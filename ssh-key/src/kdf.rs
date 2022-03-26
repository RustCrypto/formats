//! Key Derivation Functions.
//!
//! These are used for deriving an encryption key from a password.

use crate::{
    decoder::Decoder,
    encoder::{Encode, Encoder},
    Error, KdfAlg, Result,
};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Key Derivation Function (KDF) options.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KdfOpts {
    /// No KDF options.
    Empty,

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

impl KdfOpts {
    /// Decode KDF options for the given algorithm.
    pub(crate) fn decode(alg: KdfAlg, decoder: &mut impl Decoder) -> Result<Self> {
        match alg {
            KdfAlg::None => {
                if decoder.decode_usize()? == 0 {
                    Ok(Self::Empty)
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

    /// Get the KDF algorithm.
    pub fn algorithm(&self) -> KdfAlg {
        match self {
            Self::Empty => KdfAlg::None,
            #[cfg(feature = "alloc")]
            Self::Bcrypt { .. } => KdfAlg::Bcrypt,
        }
    }

    /// Are the KDF options empty?
    pub fn is_empty(&self) -> bool {
        self == &Self::Empty
    }
}

impl Default for KdfOpts {
    fn default() -> Self {
        Self::Empty
    }
}

impl Encode for KdfOpts {
    fn encoded_len(&self) -> Result<usize> {
        match self {
            Self::Empty => Ok(4),
            #[cfg(feature = "alloc")]
            Self::Bcrypt { salt, .. } => Ok(4 + 4 + salt.len() + 4),
        }
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        match self {
            Self::Empty => encoder.encode_usize(0),
            #[cfg(feature = "alloc")]
            Self::Bcrypt { salt, rounds } => {
                encoder.encode_usize(4 + salt.len() + 4)?;
                encoder.encode_byte_slice(salt)?;
                encoder.encode_u32(*rounds)
            }
        }
    }
}
