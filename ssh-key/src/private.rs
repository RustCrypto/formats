//! SSH private key support.
//!
//! Support for decoding SSH private keys from the OpenSSH file format:
//!
//! <https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key>

mod openssh;

#[cfg(feature = "ecdsa")]
pub use crate::algorithm::ecdsa::{EcdsaKeypair, EcdsaPrivateKey};
pub use crate::algorithm::ed25519::{Ed25519Keypair, Ed25519PrivateKey};

use crate::{
    base64::{self, Decode},
    public, Algorithm, CipherAlg, Error, KdfAlg, KdfOptions, Result,
};

#[cfg(feature = "alloc")]
use alloc::string::String;

/// SSH private key.
#[derive(Clone, Debug)]
pub struct PrivateKey {
    /// Cipher algorithm (a.k.a. `ciphername`).
    pub cipher_alg: CipherAlg,

    /// KDF algorithm.
    pub kdf_alg: KdfAlg,

    /// KDF options.
    pub kdf_options: KdfOptions,

    /// Key data.
    pub key_data: KeypairData,

    /// Comment on the key (e.g. email address).
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub comment: String,
}

impl PrivateKey {
    /// Magic string used to identify keys in this format.
    pub const AUTH_MAGIC: &'static [u8] = b"openssh-key-v1\0";

    /// Parse an OpenSSH-formatted private key.
    ///
    /// OpenSSH-formatted private keys begin with the following:
    ///
    /// ```text
    /// -----BEGIN OPENSSH PRIVATE KEY-----
    /// ```
    pub fn from_openssh(input: impl AsRef<[u8]>) -> Result<Self> {
        let encapsulation = openssh::Encapsulation::decode(input.as_ref())?;
        let mut decoder = base64::Decoder::new_wrapped(
            encapsulation.base64_data,
            openssh::Encapsulation::LINE_WIDTH,
        )?;

        let mut auth_magic = [0u8; Self::AUTH_MAGIC.len()];
        decoder.decode_into(&mut auth_magic)?;

        if auth_magic != Self::AUTH_MAGIC {
            return Err(Error::FormatEncoding);
        }

        let cipher_alg = CipherAlg::decode(&mut decoder)?;
        let kdf_alg = KdfAlg::decode(&mut decoder)?;
        let kdf_options = KdfOptions::decode(&mut decoder)?;
        let nkeys = decoder.decode_u32()? as usize;

        // TODO(tarcieri): support more than one key?
        if nkeys != 1 {
            return Err(Error::Length);
        }

        for _ in 0..nkeys {
            // TODO(tarcieri): validate decoded length
            let _len = decoder.decode_u32()? as usize;
            let _pubkey = public::KeyData::decode(&mut decoder)?;
        }

        // Begin decoding unencrypted list of N private keys
        // See OpenSSH PROTOCOL.key § 3
        // TODO(tarcieri): validate decoded length
        let _len = decoder.decode_u32()? as usize;
        let checkint1 = decoder.decode_u32()?;
        let checkint2 = decoder.decode_u32()?;

        if checkint1 != checkint2 {
            // TODO(tarcieri): treat this as a cryptographic error?
            return Err(Error::FormatEncoding);
        }

        let key_data = KeypairData::decode(&mut decoder)?;

        #[cfg(feature = "alloc")]
        let comment = decoder.decode_string()?;

        // TODO(tarcieri): parse/validate padding bytes?
        Ok(Self {
            cipher_alg,
            kdf_alg,
            kdf_options,
            key_data,
            #[cfg(feature = "alloc")]
            comment,
        })
    }

    /// Get the digital signature [`Algorithm`] used by this key.
    pub fn algorithm(&self) -> Algorithm {
        self.key_data.algorithm()
    }
}

/// Private key data.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum KeypairData {
    /// ECDSA keypair.
    #[cfg(feature = "ecdsa")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
    Ecdsa(EcdsaKeypair),

    /// Ed25519 keypair.
    Ed25519(Ed25519Keypair),
}

impl KeypairData {
    /// Get the [`Algorithm`] for this private key.
    pub fn algorithm(&self) -> Algorithm {
        match self {
            #[cfg(feature = "ecdsa")]
            Self::Ecdsa(key) => key.algorithm(),
            Self::Ed25519(_) => Algorithm::Ed25519,
        }
    }

    /// Get ECDSA private key if this key is the correct type.
    #[cfg(feature = "ecdsa")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
    pub fn ecdsa(&self) -> Option<&EcdsaKeypair> {
        match self {
            Self::Ecdsa(keypair) => Some(keypair),
            _ => None,
        }
    }

    /// Get Ed25519 private key if this key is the correct type.
    pub fn ed25519(&self) -> Option<&Ed25519Keypair> {
        match self {
            Self::Ed25519(key) => Some(key),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// Is this key an Ed25519 key?
    pub fn is_ed25519(&self) -> bool {
        matches!(self, Self::Ed25519(_))
    }
}

impl Decode for KeypairData {
    fn decode(decoder: &mut base64::Decoder<'_>) -> Result<Self> {
        match Algorithm::decode(decoder)? {
            #[cfg(feature = "ecdsa")]
            Algorithm::Ecdsa(curve) => match EcdsaKeypair::decode(decoder)? {
                keypair if keypair.curve() == curve => Ok(Self::Ecdsa(keypair)),
                _ => Err(Error::Algorithm),
            },
            Algorithm::Ed25519 => Ed25519Keypair::decode(decoder).map(Self::Ed25519),
            #[allow(unreachable_patterns)]
            _ => Err(Error::Algorithm),
        }
    }
}
