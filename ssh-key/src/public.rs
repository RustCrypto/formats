//! SSH public key support.
//!
//! Support for decoding SSH public keys from the OpenSSH file format.

#[cfg(feature = "alloc")]
mod dsa;
#[cfg(feature = "ecdsa")]
mod ecdsa;
mod ed25519;
mod openssh;
#[cfg(feature = "alloc")]
mod rsa;

#[cfg(feature = "ecdsa")]
pub use self::ecdsa::EcdsaPublicKey;
pub use self::ed25519::Ed25519PublicKey;
#[cfg(feature = "alloc")]
pub use self::{dsa::DsaPublicKey, rsa::RsaPublicKey};

use crate::{
    base64::{self, Decode},
    Algorithm, Error, Result,
};
use core::str::FromStr;

#[cfg(feature = "alloc")]
use alloc::{borrow::ToOwned, string::String};

/// SSH public key.
#[derive(Clone, Debug)]
pub struct PublicKey {
    /// Key data.
    pub key_data: KeyData,

    /// Comment on the key (e.g. email address)
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub comment: String,
}

impl PublicKey {
    /// Parse an OpenSSH-formatted public key.
    ///
    /// OpenSSH-formatted public keys look like the following:
    ///
    /// ```text
    /// ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti foo@bar.com
    /// ```
    pub fn from_openssh(input: impl AsRef<[u8]>) -> Result<Self> {
        let encapsulation = openssh::Encapsulation::decode(input.as_ref())?;
        let mut decoder = base64::Decoder::new(encapsulation.base64_data)?;
        let key_data = KeyData::decode(&mut decoder)?;

        if !decoder.is_finished() {
            return Err(Error::Length);
        }

        // Verify that the algorithm in the Base64-encoded data matches the text
        if encapsulation.algorithm_id != key_data.algorithm().as_str() {
            return Err(Error::Algorithm);
        }

        Ok(Self {
            key_data,
            #[cfg(feature = "alloc")]
            comment: encapsulation.comment.to_owned(),
        })
    }

    /// Get the digital signature [`Algorithm`] used by this key.
    pub fn algorithm(&self) -> Algorithm {
        self.key_data.algorithm()
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_openssh(s)
    }
}

/// Public key data.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum KeyData {
    /// Digital Signature Algorithm (DSA) public key data.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    Dsa(DsaPublicKey),

    /// Elliptic Curve Digital Signature Algorithm (ECDSA) public key data.
    #[cfg(feature = "ecdsa")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
    Ecdsa(EcdsaPublicKey),

    /// Ed25519 public key data.
    Ed25519(Ed25519PublicKey),

    /// RSA public key data.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    Rsa(RsaPublicKey),
}

impl KeyData {
    /// Get the [`Algorithm`] for this public key.
    pub fn algorithm(&self) -> Algorithm {
        match self {
            #[cfg(feature = "alloc")]
            Self::Dsa(_) => Algorithm::Dsa,
            #[cfg(feature = "ecdsa")]
            Self::Ecdsa(key) => key.algorithm(),
            Self::Ed25519(_) => Algorithm::Ed25519,
            #[cfg(feature = "alloc")]
            Self::Rsa(_) => Algorithm::Rsa,
        }
    }

    /// Get DSA public key if this key is the correct type.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn dsa(&self) -> Option<&DsaPublicKey> {
        match self {
            Self::Dsa(key) => Some(key),
            _ => None,
        }
    }

    /// Get ECDSA public key if this key is the correct type.
    #[cfg(feature = "ecdsa")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
    pub fn ecdsa(&self) -> Option<&EcdsaPublicKey> {
        match self {
            Self::Ecdsa(key) => Some(key),
            _ => None,
        }
    }

    /// Get Ed25519 public key if this key is the correct type.
    pub fn ed25519(&self) -> Option<&Ed25519PublicKey> {
        match self {
            Self::Ed25519(key) => Some(key),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// Get RSA public key if this key is the correct type.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn rsa(&self) -> Option<&RsaPublicKey> {
        match self {
            Self::Rsa(key) => Some(key),
            _ => None,
        }
    }

    /// Is this key a DSA key?
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn is_dsa(&self) -> bool {
        matches!(self, Self::Dsa(_))
    }

    /// Is this key an ECDSA key?
    #[cfg(feature = "ecdsa")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
    pub fn is_ecdsa(&self) -> bool {
        matches!(self, Self::Ecdsa(_))
    }

    /// Is this key an Ed25519 key?
    pub fn is_ed25519(&self) -> bool {
        matches!(self, Self::Ed25519(_))
    }

    /// Is this key an RSA key?
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn is_rsa(&self) -> bool {
        matches!(self, Self::Rsa(_))
    }
}

impl Decode for KeyData {
    fn decode(decoder: &mut base64::Decoder<'_>) -> Result<Self> {
        match Algorithm::decode(decoder)? {
            #[cfg(feature = "alloc")]
            Algorithm::Dsa => DsaPublicKey::decode(decoder).map(Self::Dsa),
            #[cfg(feature = "ecdsa")]
            Algorithm::Ecdsa(curve) => match EcdsaPublicKey::decode(decoder)? {
                key if key.curve() == curve => Ok(Self::Ecdsa(key)),
                _ => Err(Error::Algorithm),
            },
            Algorithm::Ed25519 => Ed25519PublicKey::decode(decoder).map(Self::Ed25519),
            #[cfg(feature = "alloc")]
            Algorithm::Rsa => RsaPublicKey::decode(decoder).map(Self::Rsa),
            #[allow(unreachable_patterns)]
            _ => Err(Error::Algorithm),
        }
    }
}
