//! SSH private key support.
//!
//! Support for decoding SSH private keys (i.e. digital signature keys)
//! from the OpenSSH file format:
//!
//! <https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.key?annotate=HEAD>
//!
//! ## Decrypting encrypted private keys
//!
//! When the `encryption` feature of this crate is enabled, it's possible to
//! decrypt keys which have been encrypted under a password:
//!
#![cfg_attr(all(feature = "encryption", feature = "std"), doc = " ```")]
#![cfg_attr(not(all(feature = "encryption", feature = "std")), doc = " ```ignore")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use ssh_key::PrivateKey;
//!
//! // WARNING: don't actually hardcode private keys in source code!!!
//! let encoded_key = r#"
//! -----BEGIN OPENSSH PRIVATE KEY-----
//! b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBKH96ujW
//! umB6/WnTNPjTeaAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN
//! 796jTiQfZfG1KaT0PtFDJ/XFSqtiAAAAoFzvbvyFMhAiwBOXF0mhUUacPUCMZXivG2up2c
//! hEnAw1b6BLRPyWbY5cC2n9ggD4ivJ1zSts6sBgjyiXQAReyrP35myYvT/OIB/NpwZM/xIJ
//! N7MHSUzlkX4adBrga3f7GS4uv4ChOoxC4XsE5HsxtGsq1X8jzqLlZTmOcxkcEneYQexrUc
//! bQP0o+gL5aKK8cQgiIlXeDbRjqhc4+h4EF6lY=
//! -----END OPENSSH PRIVATE KEY-----
//! "#;
//!
//! let encrypted_key = PrivateKey::from_openssh(encoded_key)?;
//! assert!(encrypted_key.is_encrypted());
//!
//! // WARNING: don't hardcode passwords, and this one's bad anyway
//! let password = "hunter42";
//!
//! let decrypted_key = encrypted_key.decrypt(password)?;
//! assert!(!decrypted_key.is_encrypted());
//! # Ok(())
//! # }
//! ```
//!
//! ## Encrypting plaintext private keys
//!
//! When the `encryption` feature of this crate is enabled, it's possible to
//! encrypt plaintext private keys under a provided password.
//!
//! The example below also requires enabling this crate's `getrandom` feature.
//!
#![cfg_attr(
    all(
        feature = "ed25519",
        feature = "encryption",
        feature = "getrandom",
        feature = "std"
    ),
    doc = " ```"
)]
#![cfg_attr(
    not(all(
        feature = "ed25519",
        feature = "encryption",
        feature = "getrandom",
        feature = "std"
    )),
    doc = " ```ignore"
)]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use ssh_key::{PrivateKey, rand_core::OsRng};
//!
//! // Generate a random key
//! let unencrypted_key = PrivateKey::random_ed25519(&mut OsRng);
//!
//! // WARNING: don't hardcode passwords, and this one's bad anyway
//! let password = "hunter42";
//!
//! let encrypted_key = unencrypted_key.encrypt(&mut OsRng, password)?;
//! assert!(encrypted_key.is_encrypted());
//! # Ok(())
//! # }
//! ```
//!
//! ## Generating random keys
//!
//! This crate supports generation of random keys using algorithm-specific
//! backends gated on cargo features.
//!
//! The examples below require enabling this crate's `getrandom` feature as
//! well as the crate feature identified in backticks in the title of each
//! example.
//!
//! ### `ed25519`: support for generating Ed25519 keys using `ed25519_dalek`
//!
#![cfg_attr(all(feature = "ed25519", feature = "getrandom"), doc = " ```")]
#![cfg_attr(
    not(all(feature = "ed25519", feature = "getrandom")),
    doc = " ```ignore"
)]
//! use ssh_key::{PrivateKey, rand_core::OsRng};
//!
//! let private_key = PrivateKey::random_ed25519(&mut OsRng);
//! ```

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
    checked::CheckedSum,
    decoder::{Decode, Decoder},
    encoder::{Encode, Encoder},
    pem::{self, LineEnding, PemLabel},
    public, Algorithm, Cipher, Error, Kdf, PublicKey, Result,
};
use core::str;

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

/// Maximum supported block size.
///
/// This is the block size used by e.g. AES.
const MAX_BLOCK_SIZE: usize = 16;

/// Padding bytes to use.
const PADDING_BYTES: [u8; MAX_BLOCK_SIZE - 1] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

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

    /// "Checkint" value used to verify successful decryption.
    checkint: Option<u32>,

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

        let public_key =
            pem_decoder.decode_length_prefixed(|decoder, _len| public::KeyData::decode(decoder))?;

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
                checkint: None,
                public_key: public_key.into(),
                key_data: KeypairData::Encrypted(ciphertext),
            });
        }

        // Processing unencrypted key. No KDF should be set.
        if kdf.is_some() {}

        pem_decoder.decode_length_prefixed(|decoder, _len| {
            Self::decode_privatekey_comment_pair(decoder, public_key, cipher.block_size())
        })
    }

    /// Encode OpenSSH-formatted (PEM) private key.
    pub fn encode_openssh<'o>(
        &self,
        line_ending: LineEnding,
        out: &'o mut [u8],
    ) -> Result<&'o str> {
        let mut pem_encoder =
            pem::Encoder::new_wrapped(Self::PEM_LABEL, PEM_LINE_WIDTH, line_ending, out)?;

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
            let len = self.encoded_privatekey_comment_pair_len(Cipher::None)?;
            let checkint = self.checkint.unwrap_or_else(|| self.key_data.checkint());
            pem_encoder.encode_usize(len)?;
            self.encode_privatekey_comment_pair(&mut pem_encoder, Cipher::None, checkint)?;
        }

        let encoded_len = pem_encoder.finish()?;
        Ok(str::from_utf8(&out[..encoded_len])?)
    }

    /// Encode an OpenSSH-formatted PEM private key, allocating a
    /// self-zeroizing [`String`] for the result.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn to_openssh(&self, line_ending: LineEnding) -> Result<Zeroizing<String>> {
        let encoded_len = self.pem_encoded_len(line_ending)?;
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

        Self::decode_privatekey_comment_pair(
            &mut &**buffer,
            self.public_key.key_data.clone(),
            self.cipher.block_size(),
        )
    }

    /// Encrypt an unencrypted private key using the provided password to
    /// derive an encryption key.
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
        mut rng: impl CryptoRng + RngCore,
        password: impl AsRef<[u8]>,
    ) -> Result<Self> {
        let checkint = rng.next_u32();

        self.encrypt_with(
            Cipher::default(),
            Kdf::new(Default::default(), rng)?,
            checkint,
            password,
        )
    }

    /// Encrypt an unencrypted private key using the provided cipher and KDF
    /// configuration.
    ///
    /// Returns [`Error::Encrypted`] if the private key is already encrypted.
    #[cfg(feature = "encryption")]
    #[cfg_attr(docsrs, doc(cfg(feature = "encryption")))]
    pub fn encrypt_with(
        &self,
        cipher: Cipher,
        kdf: Kdf,
        checkint: u32,
        password: impl AsRef<[u8]>,
    ) -> Result<Self> {
        if self.is_encrypted() {
            return Err(Error::Encrypted);
        }

        let (key_bytes, iv_bytes) = kdf.derive_key_and_iv(cipher, password)?;
        let msg_len = self.encoded_privatekey_comment_pair_len(cipher)?;
        let mut out = Vec::with_capacity(msg_len);

        // Encode and encrypt private key
        self.encode_privatekey_comment_pair(&mut out, cipher, checkint)?;
        cipher.encrypt(&key_bytes, &iv_bytes, out.as_mut_slice())?;

        Ok(Self {
            cipher,
            kdf,
            checkint: None,
            public_key: self.public_key.key_data.clone().into(),
            key_data: KeypairData::Encrypted(out),
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
    pub fn random_ed25519(mut rng: impl CryptoRng + RngCore) -> Self {
        let checkint = rng.next_u32();
        let key_data = KeypairData::from(Ed25519Keypair::random(rng));
        let public_key = public::KeyData::try_from(&key_data).expect("invalid key");

        Self {
            cipher: Cipher::None,
            kdf: Kdf::None,
            checkint: Some(checkint),
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

    /// Decode [`KeypairData`] along with its associated checkints and comment,
    /// storing the comment in the provided public key on success.
    ///
    /// This method also checks padding for validity and ensures that the
    /// decoded private key matches the provided public key.
    ///
    /// For private key format specification, see OpenSSH [PROTOCOL.key] § 3:
    ///
    /// ```text
    /// uint32  checkint
    /// uint32  checkint
    /// byte[]  privatekey1
    /// string  comment1
    /// byte[]  privatekey2
    /// string  comment2
    /// ...
    /// string  privatekeyN
    /// string  commentN
    /// char    1
    /// char    2
    /// char    3
    /// ...
    /// char    padlen % 255
    /// ```
    ///
    /// [PROTOCOL.key]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.key?annotate=HEAD
    fn decode_privatekey_comment_pair(
        decoder: &mut impl Decoder,
        public_key: public::KeyData,
        block_size: usize,
    ) -> Result<Self> {
        debug_assert!(block_size <= MAX_BLOCK_SIZE);

        // Ensure input data is padding-aligned
        if decoder.remaining_len().checked_rem(block_size) != Some(0) {
            return Err(Error::Length);
        }

        let checkint1 = decoder.decode_u32()?;
        let checkint2 = decoder.decode_u32()?;

        if checkint1 != checkint2 {
            return Err(Error::Crypto);
        }

        let key_data = KeypairData::decode(decoder)?;

        // Ensure public key matches private key
        if public_key != public::KeyData::try_from(&key_data)? {
            return Err(Error::PublicKey);
        }

        let mut public_key = PublicKey::from(public_key);
        public_key.decode_comment(decoder)?;

        let padding_len = decoder.remaining_len();

        if padding_len >= block_size {
            return Err(Error::Length);
        }

        if padding_len != 0 {
            let mut padding = [0u8; MAX_BLOCK_SIZE];
            decoder.decode_raw(&mut padding[..padding_len])?;

            if PADDING_BYTES[..padding_len] != padding[..padding_len] {
                return Err(Error::FormatEncoding);
            }
        }

        if !decoder.is_finished() {
            return Err(Error::Length);
        }

        Ok(Self {
            cipher: Cipher::None,
            kdf: Kdf::None,
            checkint: Some(checkint1),
            public_key,
            key_data,
        })
    }

    /// Encode [`KeypairData`] along with its associated checkints, comment,
    /// and padding.
    fn encode_privatekey_comment_pair(
        &self,
        encoder: &mut impl Encoder,
        cipher: Cipher,
        checkint: u32,
    ) -> Result<()> {
        let unpadded_len = self.unpadded_privatekey_comment_pair_len()?;
        let padding_len = cipher.padding_len(unpadded_len);

        encoder.encode_u32(checkint)?;
        encoder.encode_u32(checkint)?;
        self.key_data.encode(encoder)?;
        encoder.encode_str(self.comment())?;
        encoder.encode_raw(&PADDING_BYTES[..padding_len])?;
        Ok(())
    }

    /// Get the length of this private key when encoded with the given comment
    /// and padded using the padding size for the given cipher.
    fn encoded_privatekey_comment_pair_len(&self, cipher: Cipher) -> Result<usize> {
        let len = self.unpadded_privatekey_comment_pair_len()?;
        [len, cipher.padding_len(len)].checked_sum()
    }

    /// Get the length of this private key when encoded with the given comment.
    ///
    /// This length is just the checkints, private key data, and comment sans
    /// any padding.
    fn unpadded_privatekey_comment_pair_len(&self) -> Result<usize> {
        // This method is intended for use with unencrypted keys only
        if self.is_encrypted() {
            return Err(Error::Encrypted);
        }

        [
            8, // 2 x uint32 checkints,
            4, // u32 length prefix for key data
            self.key_data.encoded_len()?,
            self.comment().len(),
        ]
        .checked_sum()
    }

    /// Estimated length of a PEM-encoded key in OpenSSH format.
    ///
    /// May be slightly longer than the actual result.
    #[cfg(feature = "alloc")]
    fn pem_encoded_len(&self, line_ending: LineEnding) -> Result<usize> {
        let private_key_len = if self.is_encrypted() {
            self.key_data.encoded_len()?
        } else {
            self.encoded_privatekey_comment_pair_len(Cipher::None)?
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
        .checked_sum()?;

        let base64_len = base64_encoded_len(bytes_len);

        // Add the length of the line endings which will be inserted when
        // encoded Base64 is line wrapped
        let newline_len = base64_len
            .saturating_sub(1)
            .checked_div(PEM_LINE_WIDTH)
            .and_then(|len| len.checked_add(line_ending.len()))
            .ok_or(Error::Length)?;

        Ok(pem::encapsulated_len(
            Self::PEM_LABEL,
            line_ending,
            [base64_len, newline_len].checked_sum()?,
        )?)
    }
}

impl TryFrom<KeypairData> for PrivateKey {
    type Error = Error;

    fn try_from(key_data: KeypairData) -> Result<PrivateKey> {
        let public_key = public::KeyData::try_from(&key_data)?;

        Ok(Self {
            cipher: Cipher::None,
            kdf: Kdf::None,
            checkint: None,
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
    const PEM_LABEL: &'static str = "OPENSSH PRIVATE KEY";
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
