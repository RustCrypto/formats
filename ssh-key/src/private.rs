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
mod keypair;
#[cfg(feature = "alloc")]
mod rsa;

#[cfg(feature = "ecdsa")]
pub use self::ecdsa::{EcdsaKeypair, EcdsaPrivateKey};
pub use self::ed25519::{Ed25519Keypair, Ed25519PrivateKey};
pub use self::keypair::KeypairData;
#[cfg(feature = "alloc")]
pub use self::{
    dsa::{DsaKeypair, DsaPrivateKey},
    rsa::RsaKeypair,
};

use crate::{
    decoder::{Decode, Decoder},
    encoder::{Encode, Encoder},
    public, Algorithm, Cipher, Error, Kdf, PublicKey, Result,
};
use core::str;
use pem_rfc7468::{self as pem, LineEnding, PemLabel};

#[cfg(feature = "alloc")]
use {crate::encoder::base64_encoded_len, alloc::string::String, zeroize::Zeroizing};

#[cfg(feature = "fingerprint")]
use crate::{Fingerprint, HashAlg};

#[cfg(any(feature = "ed25519", feature = "encryption"))]
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "encryption")]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::{fs, io::Write, path::Path};

#[cfg(all(unix, feature = "std"))]
use std::os::unix::fs::OpenOptionsExt;

#[cfg(feature = "subtle")]
use subtle::{Choice, ConstantTimeEq};

/// Line width used by the PEM encoding of OpenSSH private keys.
const PEM_LINE_WIDTH: usize = 70;

/// Unix file permissions for SSH private keys.
#[cfg(all(unix, feature = "std"))]
const UNIX_FILE_PERMISSIONS: u32 = 0o600;

/// SSH private key.
#[derive(Clone, Debug)]
pub struct PrivateKey {
    /// Cipher algorithm.
    cipher: Cipher,

    /// KDF options.
    kdf: Kdf,

    /// Public key.
    public_key: PublicKey,

    /// Private keypair data.
    key_data: KeypairData,
}

impl PrivateKey {
    /// Magic string used to identify keys in this format.
    const AUTH_MAGIC: &'static [u8] = b"openssh-key-v1\0";

    /// Create a new unencrypted private key with the given keypair data and comment.
    ///
    /// On `no_std` platforms, use `PrivateKey::from(key_data)` instead.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn new(key_data: KeypairData, comment: impl Into<String>) -> Result<Self> {
        if key_data.is_encrypted() {
            return Err(Error::Encrypted);
        }

        let mut private_key = Self::try_from(key_data)?;
        private_key.public_key.comment = comment.into();
        Ok(private_key)
    }

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

        let cipher = Cipher::decode(&mut pem_decoder)?;
        let kdf = Kdf::decode(&mut pem_decoder)?;
        let nkeys = pem_decoder.decode_usize()?;

        // TODO(tarcieri): support more than one key?
        if nkeys != 1 {
            return Err(Error::Length);
        }

        #[cfg_attr(not(feature = "alloc"), allow(unused_mut))]
        let mut public_key = PublicKey::from(
            pem_decoder.decode_length_prefixed(|decoder, _len| public::KeyData::decode(decoder))?,
        );

        // Handle encrypted private key
        #[cfg(not(feature = "alloc"))]
        if cipher.is_some() {
            return Err(Error::Encrypted);
        }
        #[cfg(feature = "alloc")]
        if cipher.is_some() {
            let ciphertext = pem_decoder.decode_byte_vec()?;

            // Ensure ciphertext is padded to the expected length
            if ciphertext.len().checked_rem(cipher.block_size()) != Some(0) {
                return Err(Error::Crypto);
            }

            if !pem_decoder.is_finished() {
                return Err(Error::Length);
            }

            return Ok(Self {
                cipher,
                kdf,
                public_key,
                key_data: KeypairData::Encrypted(ciphertext),
            });
        }

        let key_data = pem_decoder.decode_length_prefixed(|decoder, _len| {
            KeypairData::decode_padded(decoder, &mut public_key, cipher)
        })?;

        Ok(Self {
            cipher,
            kdf,
            public_key,
            key_data,
        })
    }

    /// Encode OpenSSH-formatted (PEM) private key.
    pub fn encode_openssh<'o>(
        &self,
        line_ending: LineEnding,
        out: &'o mut [u8],
    ) -> Result<&'o str> {
        let mut pem_encoder =
            pem::Encoder::new_wrapped(Self::TYPE_LABEL, PEM_LINE_WIDTH, line_ending, out)?;

        pem_encoder.encode(Self::AUTH_MAGIC)?;
        self.cipher.encode(&mut pem_encoder)?;
        self.kdf.encode(&mut pem_encoder)?;

        // TODO(tarcieri): support for encoding more than one private key
        let nkeys = 1;
        pem_encoder.encode_usize(nkeys)?;

        // Encode public key
        pem_encoder.encode_length_prefixed(self.public_key.key_data())?;

        // Encode private key
        if self.is_encrypted() {
            pem_encoder.encode_usize(self.key_data.encoded_len()?)?;
            self.key_data.encode(&mut pem_encoder)?;
        } else {
            pem_encoder.encode_usize(
                self.key_data
                    .encoded_len_padded(self.comment(), self.cipher)?,
            )?;

            self.key_data
                .encode_padded(&mut pem_encoder, self.comment(), self.cipher)?;
        }

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

    /// Attempt to decrypt an encrypted private key using the provided
    /// password to derive an encryption key.
    ///
    /// Returns [`Error::Decrypted`] if the private key is already decrypted.
    #[cfg(feature = "encryption")]
    #[cfg_attr(docsrs, doc(cfg(feature = "encryption")))]
    pub fn decrypt(&self, password: impl AsRef<[u8]>) -> Result<Self> {
        let (key_bytes, iv_bytes) = self.kdf.derive_key_and_iv(self.cipher, password)?;

        let ciphertext = self.key_data.encrypted().ok_or(Error::Decrypted)?;
        let mut buffer = Zeroizing::new(ciphertext.to_vec());
        self.cipher.decrypt(&key_bytes, &iv_bytes, &mut buffer)?;

        let mut public_key = self.public_key.clone();
        let key_data = KeypairData::decode_padded(&mut &**buffer, &mut public_key, self.cipher)?;

        Ok(Self {
            cipher: Cipher::None,
            kdf: Kdf::None,
            public_key,
            key_data,
        })
    }

    /// Attempt to encrypt an unencrypted private key using the provided
    /// password to derive an encryption key.
    ///
    /// Uses the following algorithms:
    /// - Cipher: [`Cipher::Aes256Ctr`]
    /// - KDF: [`Kdf::Bcrypt`] (i.e. `bcrypt-pbkdf`)
    ///
    /// Returns [`Error::Encrypted`] if the private key is already encrypted.
    #[cfg(feature = "encryption")]
    #[cfg_attr(docsrs, doc(cfg(feature = "encryption")))]
    pub fn encrypt(
        &self,
        rng: impl CryptoRng + RngCore,
        password: impl AsRef<[u8]>,
    ) -> Result<Self> {
        if self.is_encrypted() {
            return Err(Error::Encrypted);
        }

        let cipher = Cipher::default();
        let kdf = Kdf::new(Default::default(), rng)?;
        let (key_bytes, iv_bytes) = kdf.derive_key_and_iv(cipher, password)?;
        let mut buffer =
            Vec::with_capacity(self.key_data.encoded_len_padded(self.comment(), cipher)?);

        // Encode and encrypt private key
        self.key_data
            .encode_padded(&mut buffer, self.comment(), cipher)?;
        cipher.encrypt(&key_bytes, &iv_bytes, buffer.as_mut_slice())?;

        Ok(Self {
            cipher,
            kdf,
            public_key: self.public_key.key_data.clone().into(),
            key_data: KeypairData::Encrypted(buffer),
        })
    }

    /// Get the digital signature [`Algorithm`] used by this key.
    pub fn algorithm(&self) -> Algorithm {
        self.public_key.algorithm()
    }

    /// Comment on the key (e.g. email address).
    pub fn comment(&self) -> &str {
        self.public_key.comment()
    }

    /// Cipher algorithm (a.k.a. `ciphername`).
    pub fn cipher(&self) -> Cipher {
        self.cipher
    }

    /// Compute key fingerprint.
    ///
    /// Use [`Default::default()`] to use the default hash function (SHA-256).
    #[cfg(feature = "fingerprint")]
    #[cfg_attr(docsrs, doc(cfg(feature = "fingerprint")))]
    pub fn fingerprint(&self, hash_alg: HashAlg) -> Fingerprint {
        self.public_key.fingerprint(hash_alg)
    }

    /// Is this key encrypted?
    pub fn is_encrypted(&self) -> bool {
        let ret = self.key_data.is_encrypted();
        debug_assert_eq!(ret, self.cipher.is_some());
        ret
    }

    /// Key Derivation Function (KDF) used to encrypt this key.
    ///
    /// Returns [`Kdf::None`] if this key is not encrypted.
    pub fn kdf(&self) -> &Kdf {
        &self.kdf
    }

    /// Keypair data.
    pub fn key_data(&self) -> &KeypairData {
        &self.key_data
    }

    /// Get the [`PublicKey`] which corresponds to this private key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Generate a random Ed25519 private key.
    #[cfg(feature = "ed25519")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
    pub fn random_ed25519(rng: impl CryptoRng + RngCore) -> Self {
        let key_data = KeypairData::from(Ed25519Keypair::random(rng));
        let public_key = public::KeyData::try_from(&key_data).expect("invalid key");

        Self {
            cipher: Cipher::None,
            kdf: Kdf::None,
            public_key: public_key.into(),
            key_data,
        }
    }

    /// Set the comment on the key.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn set_comment(&mut self, comment: impl Into<String>) {
        self.public_key.set_comment(comment);
    }

    /// Estimated length of a PEM-encoded key in OpenSSH format.
    ///
    /// May be slightly longer than the actual result.
    #[cfg(feature = "alloc")]
    fn openssh_encoded_len(&self, line_ending: LineEnding) -> Result<usize> {
        let private_key_len = if self.is_encrypted() {
            self.key_data.encoded_len()?
        } else {
            self.key_data
                .encoded_len_padded(self.comment(), self.cipher)?
        };

        let bytes_len = [
            Self::AUTH_MAGIC.len(),
            self.cipher.encoded_len()?,
            self.kdf.encoded_len()?,
            4, // number of keys (uint32)
            4, // public key length prefix (uint32)
            self.public_key.key_data().encoded_len()?,
            4, // private key length prefix (uint32)
            private_key_len,
        ]
        .iter()
        .try_fold(0usize, |acc, &len| acc.checked_add(len))
        .ok_or(Error::Length)?;

        let base64_len = base64_encoded_len(bytes_len);

        // Add the length of the line endings which will be inserted when
        // encoded Base64 is line wrapped
        let newline_len = base64_len
            .saturating_sub(1)
            .checked_div(PEM_LINE_WIDTH)
            .and_then(|len| len.checked_add(line_ending.len()))
            .ok_or(Error::Length)?;

        Ok(pem::encapsulated_len(
            Self::TYPE_LABEL,
            line_ending,
            base64_len.checked_add(newline_len).ok_or(Error::Length)?,
        ))
    }
}

impl TryFrom<KeypairData> for PrivateKey {
    type Error = Error;

    fn try_from(key_data: KeypairData) -> Result<PrivateKey> {
        let public_key = public::KeyData::try_from(&key_data)?;

        Ok(Self {
            cipher: Cipher::None,
            kdf: Kdf::None,
            public_key: public_key.into(),
            key_data,
        })
    }
}

impl From<PrivateKey> for PublicKey {
    fn from(private_key: PrivateKey) -> PublicKey {
        private_key.public_key
    }
}

impl From<&PrivateKey> for PublicKey {
    fn from(private_key: &PrivateKey) -> PublicKey {
        private_key.public_key.clone()
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
        // Constant-time with respect to private key data
        self.key_data.ct_eq(&other.key_data)
            & Choice::from(
                (self.cipher == other.cipher
                    && self.kdf == other.kdf
                    && self.public_key == other.public_key) as u8,
            )
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
