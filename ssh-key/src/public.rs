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

pub(crate) use self::openssh::Encapsulation;

use crate::{
    checked::CheckedSum,
    decoder::{Base64Decoder, Decode, Decoder},
    encoder::{Encode, Encoder},
    Algorithm, Error, Result,
};
use core::str::FromStr;

#[cfg(feature = "alloc")]
use {
    crate::encoder::base64_encoded_len,
    alloc::{
        borrow::ToOwned,
        string::{String, ToString},
    },
};

#[cfg(feature = "fingerprint")]
use crate::{Fingerprint, HashAlg, Sha256Fingerprint};

#[cfg(feature = "std")]
use std::{fs, path::Path};

/// SSH public key.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct PublicKey {
    /// Key data.
    pub(crate) key_data: KeyData,

    /// Comment on the key (e.g. email address)
    #[cfg(feature = "alloc")]
    pub(crate) comment: String,
}

impl PublicKey {
    /// Create a new public key with the given comment.
    ///
    /// On `no_std` platforms, use `PublicKey::from(key_data)` instead.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn new(key_data: KeyData, comment: impl Into<String>) -> Self {
        Self {
            key_data,
            comment: comment.into(),
        }
    }

    /// Parse an OpenSSH-formatted public key.
    ///
    /// OpenSSH-formatted public keys look like the following:
    ///
    /// ```text
    /// ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti foo@bar.com
    /// ```
    pub fn from_openssh(input: impl AsRef<[u8]>) -> Result<Self> {
        let encapsulation = Encapsulation::decode(input.as_ref())?;
        let mut decoder = Base64Decoder::new(encapsulation.base64_data)?;
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

    /// Encode OpenSSH-formatted public key.
    pub fn encode_openssh<'o>(&self, out: &'o mut [u8]) -> Result<&'o str> {
        Encapsulation::encode(out, self.algorithm().as_str(), self.comment(), |encoder| {
            self.key_data.encode(encoder)
        })
    }

    /// Encode an OpenSSH-formatted public key, allocating a [`String`] for
    /// the result.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn to_openssh(&self) -> Result<String> {
        let encoded_len = [
            2, // interstitial spaces
            self.algorithm().as_str().len(),
            base64_encoded_len(self.key_data.encoded_len()?),
            self.comment.len(),
        ]
        .checked_sum()?;

        let mut buf = vec![0u8; encoded_len];
        let actual_len = self.encode_openssh(&mut buf)?.len();
        buf.truncate(actual_len);
        Ok(String::from_utf8(buf)?)
    }

    /// Read public key from an OpenSSH-formatted file.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn read_openssh_file(path: &Path) -> Result<Self> {
        let input = fs::read_to_string(path)?;
        Self::from_openssh(&*input)
    }

    /// Write public key as an OpenSSH-formatted file.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn write_openssh_file(&self, path: &Path) -> Result<()> {
        let encoded = self.to_openssh()?;
        fs::write(path, encoded.as_bytes())?;
        Ok(())
    }

    /// Get the digital signature [`Algorithm`] used by this key.
    pub fn algorithm(&self) -> Algorithm {
        self.key_data.algorithm()
    }

    /// Comment on the key (e.g. email address).
    #[cfg(not(feature = "alloc"))]
    pub fn comment(&self) -> &str {
        ""
    }

    /// Comment on the key (e.g. email address).
    #[cfg(feature = "alloc")]
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Private key data.
    pub fn key_data(&self) -> &KeyData {
        &self.key_data
    }

    /// Compute key fingerprint.
    ///
    /// Use [`Default::default()`] to use the default hash function (SHA-256).
    #[cfg(feature = "fingerprint")]
    #[cfg_attr(docsrs, doc(cfg(feature = "fingerprint")))]
    pub fn fingerprint(&self, hash_alg: HashAlg) -> Result<Fingerprint> {
        self.key_data.fingerprint(hash_alg)
    }

    /// Set the comment on the key.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn set_comment(&mut self, comment: impl Into<String>) {
        self.comment = comment.into();
    }

    /// Decode comment (e.g. email address).
    ///
    /// This is a stub implementation that ignores the comment.
    #[cfg(not(feature = "alloc"))]
    pub(crate) fn decode_comment(&mut self, decoder: &mut impl Decoder) -> Result<()> {
        decoder.drain_prefixed()?;
        Ok(())
    }

    /// Decode comment (e.g. email address)
    #[cfg(feature = "alloc")]
    pub(crate) fn decode_comment(&mut self, decoder: &mut impl Decoder) -> Result<()> {
        self.comment = String::decode(decoder)?;
        Ok(())
    }
}

impl From<KeyData> for PublicKey {
    fn from(key_data: KeyData) -> PublicKey {
        PublicKey {
            key_data,
            #[cfg(feature = "alloc")]
            comment: String::new(),
        }
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_openssh(s)
    }
}

#[cfg(feature = "alloc")]
impl ToString for PublicKey {
    fn to_string(&self) -> String {
        self.to_openssh().expect("SSH public key encoding error")
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
            Self::Rsa(_) => Algorithm::Rsa { hash: None },
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

    /// Compute key fingerprint.
    ///
    /// Use [`Default::default()`] to use the default hash function (SHA-256).
    #[cfg(feature = "fingerprint")]
    #[cfg_attr(docsrs, doc(cfg(feature = "fingerprint")))]
    pub fn fingerprint(&self, hash_alg: HashAlg) -> Result<Fingerprint> {
        match hash_alg {
            HashAlg::Sha256 => Sha256Fingerprint::try_from(self).map(Into::into),
            _ => Err(Error::Algorithm),
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

    /// Decode [`KeyData`] for the specified algorithm.
    pub(crate) fn decode_algorithm(
        decoder: &mut impl Decoder,
        algorithm: Algorithm,
    ) -> Result<Self> {
        match algorithm {
            #[cfg(feature = "alloc")]
            Algorithm::Dsa => DsaPublicKey::decode(decoder).map(Self::Dsa),
            #[cfg(feature = "ecdsa")]
            Algorithm::Ecdsa { curve } => match EcdsaPublicKey::decode(decoder)? {
                key if key.curve() == curve => Ok(Self::Ecdsa(key)),
                _ => Err(Error::Algorithm),
            },
            Algorithm::Ed25519 => Ed25519PublicKey::decode(decoder).map(Self::Ed25519),
            #[cfg(feature = "alloc")]
            Algorithm::Rsa { .. } => RsaPublicKey::decode(decoder).map(Self::Rsa),
            #[allow(unreachable_patterns)]
            _ => Err(Error::Algorithm),
        }
    }

    /// Get the encoded length of this key data without a leading algorithm
    /// identifier.
    pub(crate) fn encoded_key_data_len(&self) -> Result<usize> {
        match self {
            #[cfg(feature = "alloc")]
            Self::Dsa(key) => key.encoded_len(),
            #[cfg(feature = "ecdsa")]
            Self::Ecdsa(key) => key.encoded_len(),
            Self::Ed25519(key) => key.encoded_len(),
            #[cfg(feature = "alloc")]
            Self::Rsa(key) => key.encoded_len(),
        }
    }

    /// Encode the key data without a leading algorithm identifier.
    pub(crate) fn encode_key_data(&self, encoder: &mut impl Encoder) -> Result<()> {
        match self {
            #[cfg(feature = "alloc")]
            Self::Dsa(key) => key.encode(encoder),
            #[cfg(feature = "ecdsa")]
            Self::Ecdsa(key) => key.encode(encoder),
            Self::Ed25519(key) => key.encode(encoder),
            #[cfg(feature = "alloc")]
            Self::Rsa(key) => key.encode(encoder),
        }
    }
}

impl Decode for KeyData {
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        let algorithm = Algorithm::decode(decoder)?;
        Self::decode_algorithm(decoder, algorithm)
    }
}

impl Encode for KeyData {
    fn encoded_len(&self) -> Result<usize> {
        [
            self.algorithm().encoded_len()?,
            self.encoded_key_data_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        self.algorithm().encode(encoder)?;
        self.encode_key_data(encoder)
    }
}
