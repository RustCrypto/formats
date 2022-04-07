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

/// OpenSSH certificate for DSA public key
const CERT_DSA: &str = "ssh-dss-cert-v01@openssh.com";

/// OpenSSH certificate for ECDSA (NIST P-256) public key
const CERT_ECDSA_SHA2_P256: &str = "ecdsa-sha2-nistp256-cert-v01@openssh.com";

/// OpenSSH certificate for ECDSA (NIST P-384) public key
const CERT_ECDSA_SHA2_P384: &str = "ecdsa-sha2-nistp384-cert-v01@openssh.com";

/// OpenSSH certificate for ECDSA (NIST P-521) public key
const CERT_ECDSA_SHA2_P521: &str = "ecdsa-sha2-nistp521-cert-v01@openssh.com";

/// OpenSSH certificate for Ed25519 public key
const CERT_ED25519: &str = "ssh-ed25519-cert-v01@openssh.com";

/// OpenSSH certificate for ECDSA (NIST P-256) U2F/FIDO security key
const CERT_SK_ECDSA_SHA2_P256: &str = "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com";

/// OpenSSH certificate for Ed25519 U2F/FIDO security key
const CERT_SK_SSH_ED25519: &str = "sk-ssh-ed25519-cert-v01@openssh.com";

/// OpenSSH certificate with RSA public key
const CERT_RSA: &str = "ssh-rsa-cert-v01@openssh.com";

/// ECDSA with SHA-256 + NIST P-256
const ECDSA_SHA2_P256: &str = "ecdsa-sha2-nistp256";

/// ECDSA with SHA-256 + NIST P-256
const ECDSA_SHA2_P384: &str = "ecdsa-sha2-nistp384";

/// ECDSA with SHA-256 + NIST P-256
const ECDSA_SHA2_P521: &str = "ecdsa-sha2-nistp521";

/// None
const NONE: &str = "none";

/// SHA-256 hash function
const SHA256: &str = "SHA256";

/// Digital Signature Algorithm
const SSH_DSA: &str = "ssh-dss";

/// Ed25519
const SSH_ED25519: &str = "ssh-ed25519";

/// RSA
const SSH_RSA: &str = "ssh-rsa";

/// U2F/FIDO security key with ECDSA/NIST P-256
const SK_ECDSA_SHA2_P256: &str = "sk-ecdsa-sha2-nistp256@openssh.com";

/// U2F/FIDO security key with Ed25519
const SK_SSH_ED25519: &str = "sk-ssh-ed25519@openssh.com";

/// Maximum size of any algorithm name/identifier.
const MAX_ALG_NAME_SIZE: usize = 48;

/// String identifiers for cryptographic algorithms.
///
/// Receives a blanket impl of [`Decode`] and [`Encode`].
pub(crate) trait AlgString: AsRef<str> + str::FromStr<Err = Error> {}

impl<T: AlgString> Decode for T {
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        let mut buf = [0u8; MAX_ALG_NAME_SIZE];
        decoder
            .read_string(buf.as_mut())
            .map_err(|_| Error::Algorithm)?
            .parse()
    }
}

impl<T: AlgString> Encode for T {
    fn encoded_len(&self) -> Result<usize> {
        [4, self.as_ref().len()].checked_sum()
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        self.as_ref().encode(encoder)
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

    /// FIDO/U2F key with ECDSA/NIST-P256 + SHA-256
    SkEcdsaSha2NistP256,

    /// FIDO/U2F key with Ed25519
    SkEd25519,
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
    /// - `sk-ecdsa-sha2-nistp256@openssh.com` (FIDO/U2F key)
    /// - `sk-ssh-ed25519@openssh.com` (FIDO/U2F key)
    pub fn new(id: &str) -> Result<Self> {
        match id {
            SSH_DSA => Ok(Algorithm::Dsa),
            ECDSA_SHA2_P256 => Ok(Algorithm::Ecdsa(EcdsaCurve::NistP256)),
            ECDSA_SHA2_P384 => Ok(Algorithm::Ecdsa(EcdsaCurve::NistP384)),
            ECDSA_SHA2_P521 => Ok(Algorithm::Ecdsa(EcdsaCurve::NistP521)),
            SSH_ED25519 => Ok(Algorithm::Ed25519),
            SSH_RSA => Ok(Algorithm::Rsa),
            SK_ECDSA_SHA2_P256 => Ok(Algorithm::SkEcdsaSha2NistP256),
            SK_SSH_ED25519 => Ok(Algorithm::SkEd25519),
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
            Algorithm::SkEcdsaSha2NistP256 => SK_ECDSA_SHA2_P256,
            Algorithm::SkEd25519 => SK_SSH_ED25519,
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

impl AlgString for Algorithm {}

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
/// OpenSSH certificate algorithms.
///
/// Digital signature algorithms used by OpenSSH certificates.
///
/// These map 1:1 to [`Algorithm`], but have different algorithm identifiers
/// for use in certificates. See [PROTOCOL.certkeys] for more information.
///
/// [PROTOCOL.certkeys]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum CertificateAlg {
    /// Digital Signature Algorithm
    Dsa,

    /// Elliptic Curve Digital Signature Algorithm
    Ecdsa(EcdsaCurve),

    /// Ed25519
    Ed25519,

    /// RSA
    Rsa,

    /// FIDO/U2F key with ECDSA/NIST-P256 + SHA-256
    SkEcdsaSha2NistP256,

    /// FIDO/U2F key with Ed25519
    SkEd25519,
}

impl CertificateAlg {
    /// Decode algorithm from the given string identifier.
    ///
    /// # Supported algorithms
    /// - `ssh-rsa-cert-v01@openssh.com`
    /// - `ssh-dss-cert-v01@openssh.com`
    /// - `ecdsa-sha2-nistp256-cert-v01@openssh.com`
    /// - `ecdsa-sha2-nistp384-cert-v01@openssh.com`
    /// - `ecdsa-sha2-nistp521-cert-v01@openssh.com`
    /// - `ssh-ed25519-cert-v01@openssh.com`
    /// - `sk-ecdsa-sha2-nistp256-cert-v01@openssh.com` (FIDO/U2F key)
    /// - `sk-ssh-ed25519-cert-v01@openssh.com` (FIDO/U2F key)
    pub fn new(id: &str) -> Result<Self> {
        match id {
            CERT_DSA => Ok(CertificateAlg::Dsa),
            CERT_ECDSA_SHA2_P256 => Ok(CertificateAlg::Ecdsa(EcdsaCurve::NistP256)),
            CERT_ECDSA_SHA2_P384 => Ok(CertificateAlg::Ecdsa(EcdsaCurve::NistP384)),
            CERT_ECDSA_SHA2_P521 => Ok(CertificateAlg::Ecdsa(EcdsaCurve::NistP521)),
            CERT_ED25519 => Ok(CertificateAlg::Ed25519),
            CERT_RSA => Ok(CertificateAlg::Rsa),
            CERT_SK_ECDSA_SHA2_P256 => Ok(CertificateAlg::SkEcdsaSha2NistP256),
            CERT_SK_SSH_ED25519 => Ok(CertificateAlg::SkEd25519),
            _ => Err(Error::Algorithm),
        }
    }

    /// Get the string identifier which corresponds to this algorithm.
    pub fn as_str(self) -> &'static str {
        match self {
            CertificateAlg::Dsa => CERT_DSA,
            CertificateAlg::Ecdsa(EcdsaCurve::NistP256) => CERT_ECDSA_SHA2_P256,
            CertificateAlg::Ecdsa(EcdsaCurve::NistP384) => CERT_ECDSA_SHA2_P384,
            CertificateAlg::Ecdsa(EcdsaCurve::NistP521) => CERT_ECDSA_SHA2_P521,
            CertificateAlg::Ed25519 => CERT_ED25519,
            CertificateAlg::Rsa => CERT_RSA,
            CertificateAlg::SkEcdsaSha2NistP256 => CERT_SK_ECDSA_SHA2_P256,
            CertificateAlg::SkEd25519 => CERT_SK_SSH_ED25519,
        }
    }

    /// Is the algorithm DSA?
    pub fn is_dsa(self) -> bool {
        self == CertificateAlg::Dsa
    }

    /// Is the algorithm ECDSA?
    pub fn is_ecdsa(self) -> bool {
        matches!(self, CertificateAlg::Ecdsa(_))
    }

    /// Is the algorithm Ed25519?
    pub fn is_ed25519(self) -> bool {
        self == CertificateAlg::Ed25519
    }

    /// Is the algorithm RSA?
    pub fn is_rsa(self) -> bool {
        self == CertificateAlg::Rsa
    }
}

impl AsRef<str> for CertificateAlg {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AlgString for CertificateAlg {}

impl fmt::Display for CertificateAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl str::FromStr for CertificateAlg {
    type Err = Error;

    fn from_str(id: &str) -> Result<Self> {
        Self::new(id)
    }
}

impl From<CertificateAlg> for Algorithm {
    fn from(algorithm: CertificateAlg) -> Algorithm {
        match algorithm {
            CertificateAlg::Dsa => Algorithm::Dsa,
            CertificateAlg::Ecdsa(EcdsaCurve::NistP256) => Algorithm::Ecdsa(EcdsaCurve::NistP256),
            CertificateAlg::Ecdsa(EcdsaCurve::NistP384) => Algorithm::Ecdsa(EcdsaCurve::NistP384),
            CertificateAlg::Ecdsa(EcdsaCurve::NistP521) => Algorithm::Ecdsa(EcdsaCurve::NistP521),
            CertificateAlg::Ed25519 => Algorithm::Ed25519,
            CertificateAlg::Rsa => Algorithm::Rsa,
            CertificateAlg::SkEcdsaSha2NistP256 => Algorithm::SkEcdsaSha2NistP256,
            CertificateAlg::SkEd25519 => Algorithm::SkEd25519,
        }
    }
}

impl From<Algorithm> for CertificateAlg {
    fn from(algorithm: Algorithm) -> CertificateAlg {
        match algorithm {
            Algorithm::Dsa => CertificateAlg::Dsa,
            Algorithm::Ecdsa(EcdsaCurve::NistP256) => CertificateAlg::Ecdsa(EcdsaCurve::NistP256),
            Algorithm::Ecdsa(EcdsaCurve::NistP384) => CertificateAlg::Ecdsa(EcdsaCurve::NistP384),
            Algorithm::Ecdsa(EcdsaCurve::NistP521) => CertificateAlg::Ecdsa(EcdsaCurve::NistP521),
            Algorithm::Ed25519 => CertificateAlg::Ed25519,
            Algorithm::Rsa => CertificateAlg::Rsa,
            Algorithm::SkEcdsaSha2NistP256 => CertificateAlg::SkEcdsaSha2NistP256,
            Algorithm::SkEd25519 => CertificateAlg::SkEd25519,
        }
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

impl AlgString for EcdsaCurve {}

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

impl AlgString for KdfAlg {}

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
