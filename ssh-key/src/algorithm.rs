//! Algorithm support.

#[cfg(feature = "alloc")]
pub(crate) mod dsa;
#[cfg(feature = "sec1")]
pub(crate) mod ecdsa;
pub(crate) mod ed25519;
#[cfg(feature = "alloc")]
pub(crate) mod rsa;

use crate::{base64, Error, Result};
use core::{fmt, str};

/// ECDSA with SHA-256 + NIST P-256
const ECDSA_SHA2_P256: &str = "ecdsa-sha2-nistp256";

/// ECDSA with SHA-256 + NIST P-256
const ECDSA_SHA2_P384: &str = "ecdsa-sha2-nistp384";

/// ECDSA with SHA-256 + NIST P-256
const ECDSA_SHA2_P521: &str = "ecdsa-sha2-nistp521";

/// Digital Signature Algorithm
const SSH_DSA: &str = "ssh-dss";

/// Ed25519
const SSH_ED25519: &str = "ssh-ed25519";

/// RSA
const SSH_RSA: &str = "ssh-rsa";

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
    /// Maximum size of algorithms known to this crate in bytes.
    const MAX_SIZE: usize = 20;

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

    /// Decode algorithm using the supplied Base64 decoder.
    pub(crate) fn decode(decoder: &mut base64::Decoder<'_>) -> Result<Self> {
        let mut buf = [0u8; Self::MAX_SIZE];
        Self::new(decoder.decode_str(&mut buf)?)
    }
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

/// Cipher algorithms.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum CipherAlg {
    /// None.
    None,
}

impl CipherAlg {
    /// Maximum size of cipher algorithms known to this crate in bytes.
    const MAX_SIZE: usize = 4;

    /// Decode cipher algorithm from the given `ciphername`.
    ///
    /// # Supported ciphernames
    /// - `none`
    pub fn new(ciphername: &str) -> Result<Self> {
        match ciphername {
            "none" => Ok(CipherAlg::None),
            _ => Err(Error::Algorithm),
        }
    }

    /// Get the string identifier which corresponds to this algorithm.
    pub fn as_str(self) -> &'static str {
        match self {
            CipherAlg::None => "none",
        }
    }

    /// Decode cipher algorithm using the supplied Base64 decoder.
    pub(crate) fn decode(decoder: &mut base64::Decoder<'_>) -> Result<Self> {
        let mut buf = [0u8; Self::MAX_SIZE];
        Self::new(decoder.decode_str(&mut buf)?)
    }
}

impl fmt::Display for CipherAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl str::FromStr for CipherAlg {
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
    /// Maximum size of a curve identifier known to this crate in bytes.
    #[cfg(feature = "sec1")]
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

    /// Decode ECDSA curve type using the supplied Base64 decoder.
    #[cfg(feature = "sec1")]
    pub(crate) fn decode(decoder: &mut base64::Decoder<'_>) -> Result<Self> {
        let mut buf = [0u8; Self::MAX_SIZE];
        Self::new(decoder.decode_str(&mut buf)?)
    }
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

/// Key Derivation Function (KDF) algorithms.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum KdfAlg {
    /// None.
    None,
}

impl KdfAlg {
    /// Maximum size of KDF algorithms known to this crate in bytes.
    const MAX_SIZE: usize = 4;

    /// Decode KDF algorithm from the given `kdfname`.
    ///
    /// # Supported kdfnames
    /// - `none`
    pub fn new(kdfname: &str) -> Result<Self> {
        match kdfname {
            "none" => Ok(KdfAlg::None),
            _ => Err(Error::Algorithm),
        }
    }

    /// Get the string identifier which corresponds to this algorithm.
    pub fn as_str(self) -> &'static str {
        match self {
            KdfAlg::None => "none",
        }
    }

    /// Decode KDF algorithm using the supplied Base64 decoder.
    pub(crate) fn decode(decoder: &mut base64::Decoder<'_>) -> Result<Self> {
        let mut buf = [0u8; Self::MAX_SIZE];
        Self::new(decoder.decode_str(&mut buf)?)
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

/// Key Derivation Function (KDF) options.
// TODO(tarcieri): stub!
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct KdfOptions {}

impl KdfOptions {
    /// Create new KDF options.
    pub(crate) fn new(kdfoptions: &str) -> Result<Self> {
        // TODO(tarcieri): support for KDF options
        if kdfoptions.is_empty() {
            Ok(Self {})
        } else {
            Err(Error::Algorithm)
        }
    }

    /// Decode KDF options using the supplied Base64 decoder.
    pub(crate) fn decode(decoder: &mut base64::Decoder<'_>) -> Result<Self> {
        let mut buf = [0u8; 0];
        Self::new(decoder.decode_str(&mut buf)?)
    }
}
