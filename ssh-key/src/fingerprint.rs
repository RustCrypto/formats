//! SSH public key fingerprints.

use crate::{encoder::Encode, public, Error, HashAlg, Result};
use base64ct::{Base64Unpadded, Encoding};
use core::{fmt, str};
use sha2::{Digest, Sha256};

/// Error message for malformed encoded strings which are expected to be
/// well-formed according to type-level invariants.
const ENCODING_ERR_MSG: &str = "Base64 encoding error";

/// Size of a SHA-256 hash encoded as Base64.
const SHA256_BASE64_LEN: usize = 43;

/// Size of a SHA-256 hash serialized as binary.
const SHA256_BIN_LEN: usize = 32;

/// Prefix of SHA-256 fingerprints.
const SHA256_PREFIX: &str = "SHA256:";

/// SSH public key fingerprints.
///
/// Fingerprints have an associated key fingerprint algorithm, i.e. a hash
/// function which is used to compute the fingerprint.
#[cfg_attr(docsrs, doc(cfg(feature = "fingerprint")))]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Fingerprint {
    /// Fingerprints computed using SHA-256.
    Sha256(Sha256Fingerprint),
}

impl Fingerprint {
    /// Get the hash algorithm used for this fingerprint.
    pub fn algorithm(self) -> HashAlg {
        match self {
            Self::Sha256(_) => HashAlg::Sha256,
        }
    }

    /// Get the SHA-256 fingerprint, if this is one.
    pub fn sha256(self) -> Option<Sha256Fingerprint> {
        match self {
            Self::Sha256(fingerprint) => Some(fingerprint),
        }
    }

    /// Is this fingerprint SHA-256?
    pub fn is_sha256(self) -> bool {
        self.sha256().is_some()
    }
}

impl From<Sha256Fingerprint> for Fingerprint {
    fn from(fingerprint: Sha256Fingerprint) -> Fingerprint {
        Fingerprint::Sha256(fingerprint)
    }
}

impl str::FromStr for Fingerprint {
    type Err = Error;

    fn from_str(id: &str) -> Result<Self> {
        if id.starts_with(SHA256_PREFIX) {
            Sha256Fingerprint::from_str(id).map(Into::into)
        } else {
            Err(Error::Algorithm)
        }
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha256(fingerprint) => write!(f, "{}", fingerprint),
        }
    }
}

/// SSH key fingerprints calculated using the SHA-256 hash function.
#[cfg_attr(docsrs, doc(cfg(feature = "fingerprint")))]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Sha256Fingerprint([u8; SHA256_BASE64_LEN]);

impl Sha256Fingerprint {
    /// Create a new SHA-256 fingerprint from the given binary digest.
    ///
    /// Use [`FromStr`][`str::FromStr`] to parse an existing Base64-encoded
    /// fingerprint.
    pub fn new(digest_bytes: &[u8; SHA256_BIN_LEN]) -> Self {
        let mut base64 = [0u8; SHA256_BASE64_LEN];
        Base64Unpadded::encode(digest_bytes, &mut base64).expect(ENCODING_ERR_MSG);
        Self(base64)
    }

    /// Borrow the Base64 encoding of the digest as a string.
    ///
    /// Does not include the `SHA256:` algorithm prefix.
    pub fn as_base64(&self) -> &str {
        str::from_utf8(&self.0).expect("invalid Base64 encoding")
    }

    /// Decode a Base64-encoded fingerprint to binary.
    pub fn to_bytes(&self) -> [u8; SHA256_BIN_LEN] {
        let mut decoded_bytes = [0u8; SHA256_BIN_LEN];
        let decoded_len = Base64Unpadded::decode(&self.0, &mut decoded_bytes)
            .expect(ENCODING_ERR_MSG)
            .len();

        assert_eq!(SHA256_BIN_LEN, decoded_len);
        decoded_bytes
    }
}

impl TryFrom<public::KeyData> for Sha256Fingerprint {
    type Error = Error;

    fn try_from(public_key: public::KeyData) -> Result<Sha256Fingerprint> {
        Sha256Fingerprint::try_from(&public_key)
    }
}

impl TryFrom<&public::KeyData> for Sha256Fingerprint {
    type Error = Error;

    fn try_from(public_key: &public::KeyData) -> Result<Sha256Fingerprint> {
        let mut digest = Sha256::new();
        public_key.encode(&mut digest)?;
        Ok(Self::new(&digest.finalize().into()))
    }
}

impl fmt::Display for Sha256Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", SHA256_PREFIX, self.as_base64())
    }
}

impl str::FromStr for Sha256Fingerprint {
    type Err = Error;

    fn from_str(id: &str) -> Result<Self> {
        let id = id.strip_prefix(SHA256_PREFIX).ok_or(Error::Algorithm)?;

        let mut decoded_bytes = [0u8; SHA256_BIN_LEN];
        match Base64Unpadded::decode(id, &mut decoded_bytes)?.len() {
            SHA256_BIN_LEN => id
                .as_bytes()
                .try_into()
                .map(Self)
                .map_err(|_| Error::Length),
            _ => Err(Error::Length),
        }
    }
}
