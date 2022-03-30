//! Algorithm support.

use crate::{
    checked::CheckedSum,
    decoder::{Decode, Decoder},
    encoder::{Encode, Encoder},
    Error, Result,
};
use core::{fmt, str};

/// bcrypt-pbkdf
const BCRYPT: &str = "bcrypt";

/// ECDSA with SHA-256 + NIST P-256
const ECDSA_SHA2_P256: &str = "ecdsa-sha2-nistp256";

/// ECDSA with SHA-256 + NIST P-256
const ECDSA_SHA2_P384: &str = "ecdsa-sha2-nistp384";

/// ECDSA with SHA-256 + NIST P-256
const ECDSA_SHA2_P521: &str = "ecdsa-sha2-nistp521";

/// None
const NONE: &str = "none";

/// SHA-256 hash function.
const SHA256: &str = "SHA256";

/// Digital Signature Algorithm
const SSH_DSA: &str = "ssh-dss";

/// Ed25519
const SSH_ED25519: &str = "ssh-ed25519";

/// RSA
const SSH_RSA: &str = "ssh-rsa";

/// String identifiers for cryptographic algorithms.
///
/// Receives a blanket impl of [`Decode`] and [`Encode`].
pub(crate) trait AlgString: AsRef<str> + str::FromStr<Err = Error> {
    /// Decoding buffer type.
    ///
    /// This needs to be a byte array large enough to fit the largest
    /// possible value of this type.
    type DecodeBuf: AsMut<[u8]> + Default;
}

impl<T: AlgString> Decode for T {
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        let mut buf = T::DecodeBuf::default();
        decoder
            .decode_str(buf.as_mut())
            .map_err(|_| Error::Algorithm)?
            .parse()
    }
}

impl<T: AlgString> Encode for T {
    fn encoded_len(&self) -> Result<usize> {
        [4, self.as_ref().len()].checked_sum()
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        encoder.encode_str(self.as_ref())
    }
}

/// SSH key algorithms.
///
/// This type provides a registry of supported digital signature algorithms
/// used for SSH keys.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Algorithm {
    /// Digital Signature Algorithm
    Dsa,

    /// Elliptic Curve Digital Signature Algorithm
    Ecdsa(EcdsaCurve),

    /// Ed25519
    Ed25519,

    /// RSA
    Rsa,
}

impl Algorithm {
    /// Decode algorithm from the given string identifier.
    ///
    /// # Supported algorithms
    /// - `ecdsa-sha2-nistp256`
    /// - `ecdsa-sha2-nistp384`
    /// - `ecdsa-sha2-nistp521`
    /// - `ssh-dss`
    /// - `ssh-ed25519`
    /// - `ssh-rsa`
    pub fn new(id: &str) -> Result<Self> {
        match id {
            ECDSA_SHA2_P256 => Ok(Algorithm::Ecdsa(EcdsaCurve::NistP256)),
            ECDSA_SHA2_P384 => Ok(Algorithm::Ecdsa(EcdsaCurve::NistP384)),
            ECDSA_SHA2_P521 => Ok(Algorithm::Ecdsa(EcdsaCurve::NistP521)),
            SSH_DSA => Ok(Algorithm::Dsa),
            SSH_ED25519 => Ok(Algorithm::Ed25519),
            SSH_RSA => Ok(Algorithm::Rsa),
            _ => Err(Error::Algorithm),
        }
    }

    /// Get the string identifier which corresponds to this algorithm.
    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::Dsa => SSH_DSA,
            Algorithm::Ecdsa(EcdsaCurve::NistP256) => ECDSA_SHA2_P256,
            Algorithm::Ecdsa(EcdsaCurve::NistP384) => ECDSA_SHA2_P384,
            Algorithm::Ecdsa(EcdsaCurve::NistP521) => ECDSA_SHA2_P521,
            Algorithm::Ed25519 => SSH_ED25519,
            Algorithm::Rsa => SSH_RSA,
        }
    }

    /// Is the algorithm DSA?
    pub fn is_dsa(self) -> bool {
        self == Algorithm::Dsa
    }

    /// Is the algorithm ECDSA?
    pub fn is_ecdsa(self) -> bool {
        matches!(self, Algorithm::Ecdsa(_))
    }

    /// Is the algorithm Ed25519?
    pub fn is_ed25519(self) -> bool {
        self == Algorithm::Ed25519
    }

    /// Is the algorithm RSA?
    pub fn is_rsa(self) -> bool {
        self == Algorithm::Rsa
    }
}

impl AsRef<str> for Algorithm {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AlgString for Algorithm {
    type DecodeBuf = [u8; 20]; // max length: "ecdsa-sha2-nistpXXX"
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl str::FromStr for Algorithm {
    type Err = Error;

    fn from_str(id: &str) -> Result<Self> {
        Self::new(id)
    }
}

/// Elliptic curves supported for use with ECDSA.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum EcdsaCurve {
    /// NIST P-256 (a.k.a. prime256v1, secp256r1)
    NistP256,

    /// NIST P-384 (a.k.a. secp384r1)
    NistP384,

    /// NIST P-521 (a.k.a. secp521r1)
    NistP521,
}

impl EcdsaCurve {
    /// Maximum length of an algorithm string: `nistpXXX` (8 chars)
    const MAX_SIZE: usize = 8;

    /// Decode elliptic curve from the given string identifier.
    ///
    /// # Supported curves
    ///
    /// - `nistp256`
    /// - `nistp384`
    /// - `nistp521`
    pub fn new(id: &str) -> Result<Self> {
        match id {
            "nistp256" => Ok(EcdsaCurve::NistP256),
            "nistp384" => Ok(EcdsaCurve::NistP384),
            "nistp521" => Ok(EcdsaCurve::NistP521),
            _ => Err(Error::Algorithm),
        }
    }

    /// Get the string identifier which corresponds to this ECDSA elliptic curve.
    pub fn as_str(self) -> &'static str {
        match self {
            EcdsaCurve::NistP256 => "nistp256",
            EcdsaCurve::NistP384 => "nistp384",
            EcdsaCurve::NistP521 => "nistp521",
        }
    }
}

impl AsRef<str> for EcdsaCurve {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AlgString for EcdsaCurve {
    type DecodeBuf = [u8; Self::MAX_SIZE];
}

impl fmt::Display for EcdsaCurve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl str::FromStr for EcdsaCurve {
    type Err = Error;

    fn from_str(id: &str) -> Result<Self> {
        EcdsaCurve::new(id)
    }
}

/// Hashing algorithms a.k.a. digest functions.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum HashAlg {
    /// SHA-256
    Sha256,
}

impl HashAlg {
    /// Decode elliptic curve from the given string identifier.
    ///
    /// # Supported hash algorithms
    ///
    /// - `SHA256`
    pub fn new(id: &str) -> Result<Self> {
        match id {
            SHA256 => Ok(HashAlg::Sha256),
            _ => Err(Error::Algorithm),
        }
    }

    /// Get the string identifier for this hash algorithm.
    pub fn as_str(self) -> &'static str {
        match self {
            HashAlg::Sha256 => SHA256,
        }
    }
}

impl AsRef<str> for HashAlg {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Default for HashAlg {
    fn default() -> Self {
        HashAlg::Sha256
    }
}

impl fmt::Display for HashAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl str::FromStr for HashAlg {
    type Err = Error;

    fn from_str(id: &str) -> Result<Self> {
        HashAlg::new(id)
    }
}

/// Key Derivation Function (KDF) algorithms.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum KdfAlg {
    /// None.
    None,

    /// bcrypt-pbkdf.
    Bcrypt,
}

impl KdfAlg {
    /// Maximum length of an algorithm string: `bcrypt` (6 chars)
    const MAX_SIZE: usize = 6;

    /// Decode KDF algorithm from the given `kdfname`.
    ///
    /// # Supported KDF names
    /// - `none`
    pub fn new(kdfname: &str) -> Result<Self> {
        match kdfname {
            NONE => Ok(Self::None),
            BCRYPT => Ok(Self::Bcrypt),
            _ => Err(Error::Algorithm),
        }
    }

    /// Get the string identifier which corresponds to this algorithm.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => NONE,
            Self::Bcrypt => BCRYPT,
        }
    }

    /// Is the KDF algorithm "none"?
    pub fn is_none(self) -> bool {
        self == Self::None
    }
}

impl AsRef<str> for KdfAlg {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AlgString for KdfAlg {
    type DecodeBuf = [u8; Self::MAX_SIZE];
}

impl Default for KdfAlg {
    fn default() -> KdfAlg {
        KdfAlg::Bcrypt
    }
}

impl fmt::Display for KdfAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl str::FromStr for KdfAlg {
    type Err = Error;

    fn from_str(id: &str) -> Result<Self> {
        Self::new(id)
    }
}
