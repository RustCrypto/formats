//! PKCS#8 `EncryptedPrivateKeyInfo`

use crate::{Error, Result};
use core::fmt;
use der::{
    asn1::OctetStringRef, Decode, DecodeValue, Encode, EncodeValue, Header, Length, Reader,
    Sequence, Writer,
};
use pkcs5::EncryptionScheme;

#[cfg(feature = "alloc")]
use {alloc::boxed::Box, der::SecretDocument};

#[cfg(feature = "encryption")]
use {
    pkcs5::pbes2,
    rand_core::{CryptoRng, RngCore},
};

#[cfg(feature = "pem")]
use der::pem::PemLabel;

/// PKCS#8 `EncryptedPrivateKeyInfo`.
///
/// ASN.1 structure containing a PKCS#5 [`EncryptionScheme`] identifier for a
/// password-based symmetric encryption scheme and encrypted private key data.
///
/// ## Schema
/// Structure described in [RFC 5208 Section 6]:
///
/// ```text
/// EncryptedPrivateKeyInfo ::= SEQUENCE {
///   encryptionAlgorithm  EncryptionAlgorithmIdentifier,
///   encryptedData        EncryptedData }
///
/// EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
///
/// EncryptedData ::= OCTET STRING
/// ```
///
/// [RFC 5208 Section 6]: https://tools.ietf.org/html/rfc5208#section-6
#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedPrivateKeyInfo<Data> {
    /// Algorithm identifier describing a password-based symmetric encryption
    /// scheme used to encrypt the `encrypted_data` field.
    pub encryption_algorithm: EncryptionScheme,

    /// Private key data
    pub encrypted_data: Data,
}

impl<'a, Data> EncryptedPrivateKeyInfo<Data>
where
    Data: AsRef<[u8]> + From<&'a [u8]>,
{
    /// Attempt to decrypt this encrypted private key using the provided
    /// password to derive an encryption key.
    #[cfg(feature = "encryption")]
    pub fn decrypt(&self, password: impl AsRef<[u8]>) -> Result<SecretDocument> {
        Ok(self
            .encryption_algorithm
            .decrypt(password, self.encrypted_data.as_ref())?
            .try_into()?)
    }

    /// Encrypt the given ASN.1 DER document using a symmetric encryption key
    /// derived from the provided password.
    #[cfg(feature = "encryption")]
    pub(crate) fn encrypt(
        mut rng: impl CryptoRng + RngCore,
        password: impl AsRef<[u8]>,
        doc: &[u8],
    ) -> Result<SecretDocument> {
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);

        let mut iv = [0u8; 16];
        rng.fill_bytes(&mut iv);

        let pbes2_params = pbes2::Parameters::scrypt_aes256cbc(Default::default(), &salt, iv)?;
        Self::encrypt_with(pbes2_params, password, doc)
    }

    /// Encrypt this private key using a symmetric encryption key derived
    /// from the provided password and [`pbes2::Parameters`].
    #[cfg(feature = "encryption")]
    pub(crate) fn encrypt_with(
        pbes2_params: pbes2::Parameters,
        password: impl AsRef<[u8]>,
        doc: &[u8],
    ) -> Result<SecretDocument> {
        let encrypted_data = pbes2_params.encrypt(password, doc)?;

        EncryptedPrivateKeyInfo {
            encryption_algorithm: pbes2_params.into(),
            encrypted_data,
        }
        .try_into()
    }
}

impl<'a, Data> DecodeValue<'a> for EncryptedPrivateKeyInfo<Data>
where
    Data: From<&'a [u8]>,
{
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            Ok(Self {
                encryption_algorithm: reader.decode()?,
                encrypted_data: OctetStringRef::decode(reader)?.as_bytes().into(),
            })
        })
    }
}

impl<Data> EncodeValue for EncryptedPrivateKeyInfo<Data>
where
    Data: AsRef<[u8]>,
{
    fn value_len(&self) -> der::Result<Length> {
        self.encryption_algorithm.encoded_len()?
            + OctetStringRef::new(self.encrypted_data.as_ref())?.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.encryption_algorithm.encode(writer)?;
        OctetStringRef::new(self.encrypted_data.as_ref())?.encode(writer)?;
        Ok(())
    }
}

impl<'a, Data> Sequence<'a> for EncryptedPrivateKeyInfo<Data> where
    Data: AsRef<[u8]> + From<&'a [u8]>
{
}

impl<'a, Data> TryFrom<&'a [u8]> for EncryptedPrivateKeyInfo<Data>
where
    Data: AsRef<[u8]> + From<&'a [u8]>,
{
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(Self::from_der(bytes)?)
    }
}

impl<Data> fmt::Debug for EncryptedPrivateKeyInfo<Data> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedPrivateKeyInfo")
            .field("encryption_algorithm", &self.encryption_algorithm)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "alloc")]
impl<'a, Data> TryFrom<EncryptedPrivateKeyInfo<Data>> for SecretDocument
where
    Data: AsRef<[u8]> + From<&'a [u8]>,
{
    type Error = Error;

    fn try_from(encrypted_private_key: EncryptedPrivateKeyInfo<Data>) -> Result<SecretDocument> {
        SecretDocument::try_from(&encrypted_private_key)
    }
}

#[cfg(feature = "alloc")]
impl<'a, Data> TryFrom<&EncryptedPrivateKeyInfo<Data>> for SecretDocument
where
    Data: AsRef<[u8]> + From<&'a [u8]>,
{
    type Error = Error;

    fn try_from(encrypted_private_key: &EncryptedPrivateKeyInfo<Data>) -> Result<SecretDocument> {
        Ok(Self::encode_msg(encrypted_private_key)?)
    }
}

#[cfg(feature = "pem")]
impl<Data> PemLabel for EncryptedPrivateKeyInfo<Data> {
    const PEM_LABEL: &'static str = "ENCRYPTED PRIVATE KEY";
}

/// [`EncryptedPrivateKeyInfo`] with `&[u8]` encrypted data.
pub type EncryptedPrivateKeyInfoRef<'a> = EncryptedPrivateKeyInfo<&'a [u8]>;

#[cfg(feature = "alloc")]
/// [`EncryptedPrivateKeyInfo`] with `Box<[u8]>` encrypted data.
pub type EncryptedPrivateKeyInfoOwned = EncryptedPrivateKeyInfo<Box<[u8]>>;
