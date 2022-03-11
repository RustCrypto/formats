//! SSH private key support.
//!
//! Support for decoding SSH private keys from the OpenSSH file format:
//!
//! <https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key>

#[cfg(feature = "alloc")]
mod dsa;
#[cfg(feature = "ecdsa")]
mod ecdsa;
mod ed25519;
#[cfg(feature = "alloc")]
mod rsa;

#[cfg(feature = "ecdsa")]
pub use self::ecdsa::{EcdsaKeypair, EcdsaPrivateKey};
pub use self::ed25519::{Ed25519Keypair, Ed25519PrivateKey};
#[cfg(feature = "alloc")]
pub use self::{
    dsa::{DsaKeypair, DsaPrivateKey},
    rsa::RsaKeypair,
};

use crate::{
    base64::{Decode, DecoderExt, Encode, EncoderExt},
    public, Algorithm, CipherAlg, Error, KdfAlg, KdfOptions, PublicKey, Result,
};
use core::str;
use pem_rfc7468::{self as pem, LineEnding, PemLabel};

#[cfg(feature = "alloc")]
use {crate::base64, alloc::string::String, zeroize::Zeroizing};

#[cfg(feature = "std")]
use std::{fs, io::Write, path::Path};

#[cfg(all(unix, feature = "std"))]
use std::os::unix::fs::OpenOptionsExt;

#[cfg(feature = "subtle")]
use subtle::{Choice, ConstantTimeEq};

/// Padding bytes to use.
const PADDING_BYTES: [u8; 7] = [1, 2, 3, 4, 5, 6, 7];

/// Line width used by the PEM encoding of OpenSSH private keys.
const PEM_LINE_WIDTH: usize = 70;

/// Block size to use for unencrypted keys.
const UNENCRYPTED_BLOCK_SIZE: usize = 8;

/// Unix file permissions for SSH private keys.
#[cfg(all(unix, feature = "std"))]
const UNIX_FILE_PERMISSIONS: u32 = 0o600;

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

    /// Parse an OpenSSH-formatted PEM private key.
    ///
    /// OpenSSH-formatted private keys begin with the following:
    ///
    /// ```text
    /// -----BEGIN OPENSSH PRIVATE KEY-----
    /// ```
    pub fn from_openssh(input: impl AsRef<[u8]>) -> Result<Self> {
        let mut pem_decoder = pem::Decoder::new_wrapped(input.as_ref(), PEM_LINE_WIDTH)?;
        Self::validate_pem_label(pem_decoder.type_label())?;

        let mut auth_magic = [0u8; Self::AUTH_MAGIC.len()];
        pem_decoder.decode(&mut auth_magic)?;

        if auth_magic != Self::AUTH_MAGIC {
            return Err(Error::FormatEncoding);
        }

        let cipher_alg = CipherAlg::decode(&mut pem_decoder)?;
        let kdf_alg = KdfAlg::decode(&mut pem_decoder)?;
        let kdf_options = KdfOptions::decode(&mut pem_decoder)?;
        let nkeys = pem_decoder.decode_usize()?;

        // TODO(tarcieri): support more than one key?
        if nkeys != 1 {
            return Err(Error::Length);
        }

        for _ in 0..nkeys {
            // TODO(tarcieri): validate decoded length
            let _len = pem_decoder.decode_usize()?;
            let _pubkey = public::KeyData::decode(&mut pem_decoder)?;
        }

        // Begin decoding unencrypted list of N private keys
        // See OpenSSH PROTOCOL.key § 3
        // TODO(tarcieri): validate decoded length
        let _len = pem_decoder.decode_usize()?;
        let checkint1 = pem_decoder.decode_u32()?;
        let checkint2 = pem_decoder.decode_u32()?;

        // TODO(tarcieri): constant-time comparison?
        if checkint1 != checkint2 {
            // TODO(tarcieri): treat this as a cryptographic error?
            return Err(Error::FormatEncoding);
        }

        let key_data = KeypairData::decode(&mut pem_decoder)?;

        #[cfg(not(feature = "alloc"))]
        {
            let len = pem_decoder.decode_usize()?;
            for _ in 0..len {
                let mut byte = [0];
                pem_decoder.decode(&mut byte)?;
            }
        }
        #[cfg(feature = "alloc")]
        let comment = pem_decoder.decode_string()?;

        let private_key = Self {
            cipher_alg,
            kdf_alg,
            kdf_options,
            key_data,
            #[cfg(feature = "alloc")]
            comment,
        };

        let padding_len = private_key.padding_len()?;

        if padding_len != 0 {
            // TODO(tarcieri): support for encrypted private keys
            let mut padding = [0u8; UNENCRYPTED_BLOCK_SIZE];
            pem_decoder.decode(&mut padding[..padding_len])?;

            if PADDING_BYTES[..padding_len] != padding[..padding_len] {
                return Err(Error::FormatEncoding);
            }
        }

        if !pem_decoder.is_finished() {
            return Err(Error::Length);
        }

        Ok(private_key)
    }

    /// Encode OpenSSH-formatted (PEM) public key.
    pub fn encode_openssh<'o>(
        &self,
        line_ending: LineEnding,
        out: &'o mut [u8],
    ) -> Result<&'o str> {
        let mut pem_encoder =
            pem::Encoder::new_wrapped(Self::TYPE_LABEL, PEM_LINE_WIDTH, line_ending, out)?;

        pem_encoder.encode(Self::AUTH_MAGIC)?;

        // TODO(tarcieri): support for encrypted private keys
        self.cipher_alg.encode(&mut pem_encoder)?;
        self.kdf_alg.encode(&mut pem_encoder)?;
        self.kdf_options.encode(&mut pem_encoder)?;

        // TODO(tarcieri): support for encoding more than one private key
        let nkeys = 1;
        pem_encoder.encode_usize(nkeys)?;

        // Encode public key
        let public_key_data = public::KeyData::from(&self.key_data);
        pem_encoder.encode_usize(public_key_data.encoded_len()?)?;
        public_key_data.encode(&mut pem_encoder)?;

        // Get private key comment
        // TODO(tarcieri): comment accessor method with consistent behavior
        #[cfg(not(feature = "alloc"))]
        let comment = "";
        #[cfg(feature = "alloc")]
        let comment = &self.comment;

        // Encode private key
        let padding_len = self.padding_len()?;
        debug_assert!(padding_len <= 7, "padding too long: {}", padding_len);

        pem_encoder.encode_usize(self.private_key_len()? + padding_len)?;
        let checkint = public_key_data.checkint();
        pem_encoder.encode_u32(checkint)?;
        pem_encoder.encode_u32(checkint)?;
        self.key_data.encode(&mut pem_encoder)?;
        pem_encoder.encode_str(comment)?;
        pem_encoder.encode_base64(&PADDING_BYTES[..padding_len])?;

        let encoded_len = pem_encoder.finish()?;
        Ok(str::from_utf8(&out[..encoded_len])?)
    }

    /// Encode an OpenSSH-formatted PEM private key, allocating a
    /// self-zeroizing [`String`] for the result.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn to_openssh(&self, line_ending: LineEnding) -> Result<Zeroizing<String>> {
        let encoded_len = self.openssh_encoded_len(line_ending)?;
        let mut buf = vec![0u8; encoded_len];
        let actual_len = self.encode_openssh(line_ending, &mut buf)?.len();
        buf.truncate(actual_len);
        Ok(Zeroizing::new(String::from_utf8(buf)?))
    }

    /// Read private key from an OpenSSH-formatted PEM file.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn read_openssh_file(path: &Path) -> Result<Self> {
        // TODO(tarcieri): verify file permissions match `UNIX_FILE_PERMISSIONS`
        let pem = Zeroizing::new(fs::read_to_string(path)?);
        Self::from_openssh(&*pem)
    }

    /// Write private key as an OpenSSH-formatted PEM file.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn write_openssh_file(&self, path: &Path, line_ending: LineEnding) -> Result<()> {
        let pem = self.to_openssh(line_ending)?;

        #[cfg(not(unix))]
        fs::write(path, pem.as_bytes())?;
        #[cfg(unix)]
        fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(UNIX_FILE_PERMISSIONS)
            .open(path)
            .and_then(|mut file| file.write_all(pem.as_bytes()))?;

        Ok(())
    }

    /// Get the digital signature [`Algorithm`] used by this key.
    pub fn algorithm(&self) -> Algorithm {
        self.key_data.algorithm()
    }

    /// Get the [`PublicKey`] which corresponds to this private key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            key_data: public::KeyData::from(&self.key_data),
            #[cfg(feature = "alloc")]
            comment: self.comment.clone(),
        }
    }

    /// Estimated length of a PEM-encoded key in OpenSSH format.
    ///
    /// May be slightly longer than the actual result.
    #[cfg(feature = "alloc")]
    fn openssh_encoded_len(&self, line_ending: LineEnding) -> Result<usize> {
        let bytes_len = Self::AUTH_MAGIC.len()
            + self.cipher_alg.encoded_len()?
            + self.kdf_alg.encoded_len()?
            + self.kdf_options.encoded_len()?
            + 4 // number of keys
            + 4 + public::KeyData::from(&self.key_data).encoded_len()?
            + 4 + self.private_key_len()?
            + self.padding_len()?;

        let mut base64_len = base64::encoded_len(bytes_len);
        base64_len += (base64_len.saturating_sub(1) / PEM_LINE_WIDTH) * line_ending.len();

        Ok(pem::encapsulated_len(
            Self::TYPE_LABEL,
            line_ending,
            base64_len,
        ))
    }

    /// Get the length of the private key data in bytes (not including padding).
    fn private_key_len(&self) -> Result<usize> {
        // TODO(tarcieri): comment accessor method with consistent behavior
        #[cfg(not(feature = "alloc"))]
        let comment_len = 0;
        #[cfg(feature = "alloc")]
        let comment_len = self.comment.len();

        Ok(8 // 2 * checkints
            + self.key_data.encoded_len()?
            + 4 // comment length prefix
            + comment_len)
    }

    /// Get the number of padding bytes to add to this key (without padding).
    fn padding_len(&self) -> Result<usize> {
        // TODO(tarcieri): encrypted key support
        let block_size = UNENCRYPTED_BLOCK_SIZE;

        match block_size.checked_sub(self.private_key_len()? % block_size) {
            Some(len) => {
                if len == block_size {
                    Ok(0)
                } else {
                    Ok(len)
                }
            }
            None => Err(Error::Length),
        }
    }
}

impl From<PrivateKey> for PublicKey {
    fn from(private_key: PrivateKey) -> PublicKey {
        private_key.public_key()
    }
}

impl From<&PrivateKey> for PublicKey {
    fn from(private_key: &PrivateKey) -> PublicKey {
        private_key.public_key()
    }
}

impl PemLabel for PrivateKey {
    const TYPE_LABEL: &'static str = "OPENSSH PRIVATE KEY";
}

impl str::FromStr for PrivateKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_openssh(s)
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl ConstantTimeEq for PrivateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        // TODO(tarcieri): comment accessor method with consistent behavior
        #[cfg(not(feature = "alloc"))]
        let comment_eq = Choice::from(1);
        #[cfg(feature = "alloc")]
        let comment_eq = self.comment.as_bytes().ct_eq(other.comment.as_bytes());

        comment_eq & self.key_data.ct_eq(&other.key_data)
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl Eq for PrivateKey {}

/// Private key data.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum KeypairData {
    /// Digital Signature Algorithm (DSA) keypair.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    Dsa(DsaKeypair),

    /// ECDSA keypair.
    #[cfg(feature = "ecdsa")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
    Ecdsa(EcdsaKeypair),

    /// Ed25519 keypair.
    Ed25519(Ed25519Keypair),

    /// RSA keypair.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    Rsa(RsaKeypair),
}

impl KeypairData {
    /// Get the [`Algorithm`] for this private key.
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

    /// Get DSA keypair if this key is the correct type.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn dsa(&self) -> Option<&DsaKeypair> {
        match self {
            Self::Dsa(key) => Some(key),
            _ => None,
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

    /// Get RSA keypair if this key is the correct type.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn rsa(&self) -> Option<&RsaKeypair> {
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

impl Decode for KeypairData {
    fn decode(decoder: &mut impl DecoderExt) -> Result<Self> {
        match Algorithm::decode(decoder)? {
            #[cfg(feature = "alloc")]
            Algorithm::Dsa => DsaKeypair::decode(decoder).map(Self::Dsa),
            #[cfg(feature = "ecdsa")]
            Algorithm::Ecdsa(curve) => match EcdsaKeypair::decode(decoder)? {
                keypair if keypair.curve() == curve => Ok(Self::Ecdsa(keypair)),
                _ => Err(Error::Algorithm),
            },
            Algorithm::Ed25519 => Ed25519Keypair::decode(decoder).map(Self::Ed25519),
            #[cfg(feature = "alloc")]
            Algorithm::Rsa => RsaKeypair::decode(decoder).map(Self::Rsa),
            #[allow(unreachable_patterns)]
            _ => Err(Error::Algorithm),
        }
    }
}

impl Encode for KeypairData {
    fn encoded_len(&self) -> Result<usize> {
        let alg_len = self.algorithm().encoded_len()?;

        let key_len = match self {
            #[cfg(feature = "alloc")]
            Self::Dsa(key) => key.encoded_len()?,
            #[cfg(feature = "ecdsa")]
            Self::Ecdsa(key) => key.encoded_len()?,
            Self::Ed25519(key) => key.encoded_len()?,
            #[cfg(feature = "alloc")]
            Self::Rsa(key) => key.encoded_len()?,
        };

        Ok(alg_len + key_len)
    }

    fn encode(&self, encoder: &mut impl EncoderExt) -> Result<()> {
        self.algorithm().encode(encoder)?;

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

impl From<&KeypairData> for public::KeyData {
    fn from(keypair_data: &KeypairData) -> public::KeyData {
        match keypair_data {
            #[cfg(feature = "alloc")]
            KeypairData::Dsa(dsa) => public::KeyData::Dsa(dsa.into()),
            #[cfg(feature = "ecdsa")]
            KeypairData::Ecdsa(ecdsa) => public::KeyData::Ecdsa(ecdsa.into()),
            KeypairData::Ed25519(ed25519) => public::KeyData::Ed25519(ed25519.into()),
            #[cfg(feature = "alloc")]
            KeypairData::Rsa(rsa) => public::KeyData::Rsa(rsa.into()),
        }
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl ConstantTimeEq for KeypairData {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Note: constant-time with respect to key *data* comparisons, not algorithms
        match (self, other) {
            #[cfg(feature = "alloc")]
            (Self::Dsa(a), Self::Dsa(b)) => a.ct_eq(b),
            #[cfg(feature = "ecdsa")]
            (Self::Ecdsa(a), Self::Ecdsa(b)) => a.ct_eq(b),
            (Self::Ed25519(a), Self::Ed25519(b)) => a.ct_eq(b),
            #[cfg(feature = "alloc")]
            (Self::Rsa(a), Self::Rsa(b)) => a.ct_eq(b),
            _ => Choice::from(0),
        }
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl PartialEq for KeypairData {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

#[cfg(feature = "subtle")]
#[cfg_attr(docsrs, doc(cfg(feature = "subtle")))]
impl Eq for KeypairData {}
