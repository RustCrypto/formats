//! OpenSSH certificate support.

mod builder;
mod cert_type;
mod options_map;
mod signing_key;

pub use self::{
    builder::Builder, cert_type::CertType, options_map::OptionsMap, signing_key::SigningKey,
};

use crate::{
    checked::CheckedSum,
    decode::Decode,
    encode::Encode,
    public::{Encapsulation, KeyData},
    reader::{Base64Reader, Reader},
    writer::{base64_len, Writer},
    Algorithm, Error, Result, Signature,
};
use alloc::{
    borrow::ToOwned,
    string::{String, ToString},
    vec::Vec,
};
use core::str::FromStr;

#[cfg(feature = "fingerprint")]
use {
    crate::{Fingerprint, HashAlg},
    signature::Verifier,
};

#[cfg(feature = "serde")]
use serde::{de, ser, Deserialize, Serialize};

#[cfg(feature = "std")]
use std::{
    fs,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// OpenSSH certificate as specified in [PROTOCOL.certkeys].
///
/// OpenSSH supports X.509-like certificate authorities, but using a custom
/// encoding format.
///
/// # ⚠️ Security Warning
///
/// Certificates must be validated before they can be trusted!
///
/// See documentation for [`Certificate::validate`] and
/// [`Certificate::validate_at`] methods for more information.
///
/// # `serde` support
///
/// When the `serde` feature of this crate is enabled, this type receives impls
/// of [`Deserialize`][`serde::Deserialize`] and [`Serialize`][`serde::Serialize`].
///
/// The serialization uses a binary encoding with binary formats like bincode
/// and CBOR, and the OpenSSH string serialization when used with
/// human-readable formats like JSON and TOML.
///
/// [PROTOCOL.certkeys]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Certificate {
    /// CA-provided random bitstring of arbitrary length
    /// (but typically 16 or 32 bytes).
    nonce: Vec<u8>,

    /// Public key data.
    public_key: KeyData,

    /// Serial number.
    serial: u64,

    /// Certificate type.
    cert_type: CertType,

    /// Key ID.
    key_id: String,

    /// Valid principals.
    valid_principals: Vec<String>,

    /// Valid after (Unix time).
    valid_after: u64,

    /// Valid before (Unix time).
    valid_before: u64,

    /// Critical options.
    critical_options: OptionsMap,

    /// Extensions.
    extensions: OptionsMap,

    /// Reserved field.
    reserved: Vec<u8>,

    /// Signature key of signing CA.
    signature_key: KeyData,

    /// Signature over the certificate.
    signature: Signature,

    /// Comment on the certificate.
    comment: String,
}

impl Certificate {
    /// Parse an OpenSSH-formatted certificate.
    ///
    /// OpenSSH-formatted certificates look like the following
    /// (i.e. similar to OpenSSH public keys with `-cert-v01@openssh.com`):
    ///
    /// ```text
    /// ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlc...8REbCaAw== user@example.com
    /// ```
    pub fn from_openssh(certificate_str: &str) -> Result<Self> {
        let encapsulation = Encapsulation::decode(certificate_str.trim_end().as_bytes())?;
        let mut reader = Base64Reader::new(encapsulation.base64_data)?;
        let mut cert = Certificate::decode(&mut reader)?;

        // Verify that the algorithm in the Base64-encoded data matches the text
        if encapsulation.algorithm_id != cert.algorithm().as_certificate_str() {
            return Err(Error::Algorithm);
        }

        cert.comment = encapsulation.comment.to_owned();
        reader.finish(cert)
    }

    /// Parse a raw binary OpenSSH certificate.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self> {
        let reader = &mut bytes;
        let cert = Certificate::decode(reader)?;
        reader.finish(cert)
    }

    /// Encode OpenSSH certificate to a [`String`].
    pub fn to_openssh(&self) -> Result<String> {
        let encoded_len = [
            2, // interstitial spaces
            self.algorithm().as_certificate_str().len(),
            base64_len(self.encoded_len()?),
            self.comment.len(),
        ]
        .checked_sum()?;

        let mut out = vec![0u8; encoded_len];
        let actual_len = Encapsulation::encode(
            &mut out,
            self.algorithm().as_certificate_str(),
            self.comment(),
            |writer| self.encode(writer),
        )?
        .len();
        out.truncate(actual_len);
        Ok(String::from_utf8(out)?)
    }

    /// Serialize OpenSSH certificate as raw bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut cert_bytes = Vec::new();
        self.encode(&mut cert_bytes)?;
        Ok(cert_bytes)
    }

    /// Read OpenSSH certificate from a file.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn read_file(path: &Path) -> Result<Self> {
        let input = fs::read_to_string(path)?;
        Self::from_openssh(&*input)
    }

    /// Write OpenSSH certificate to a file.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn write_file(&self, path: &Path) -> Result<()> {
        let encoded = self.to_openssh()?;
        fs::write(path, encoded.as_bytes())?;
        Ok(())
    }

    /// Get the public key algorithm for this certificate.
    pub fn algorithm(&self) -> Algorithm {
        self.public_key.algorithm()
    }

    /// Get the comment on this certificate.
    pub fn comment(&self) -> &str {
        self.comment.as_str()
    }

    /// Nonces are a CA-provided random bitstring of arbitrary length
    /// (but typically 16 or 32 bytes).
    ///
    /// It's included to make attacks that depend on inducing collisions in the
    /// signature hash infeasible.
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// Get this certificate's public key data.
    pub fn public_key(&self) -> &KeyData {
        &self.public_key
    }

    /// Optional certificate serial number set by the CA to provide an
    /// abbreviated way to refer to certificates from that CA.
    ///
    /// If a CA does not wish to number its certificates, it must set this
    /// field to zero.
    pub fn serial(&self) -> u64 {
        self.serial
    }

    /// Specifies whether this certificate is for identification of a user or
    /// a host.
    pub fn cert_type(&self) -> CertType {
        self.cert_type
    }

    /// Key IDs are a free-form text field that is filled in by the CA at the
    /// time of signing.
    ///
    /// The intention is that the contents of this field are used to identify
    /// the identity principal in log messages.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// List of zero or more principals which this certificate is valid for.
    ///
    /// Principals are hostnames for host certificates and usernames for user
    /// certificates.
    ///
    /// As a special case, a zero-length "valid principals" field means the
    /// certificate is valid for any principal of the specified type.
    pub fn valid_principals(&self) -> &[String] {
        &self.valid_principals
    }

    /// Valid after (Unix time).
    pub fn valid_after(&self) -> u64 {
        self.valid_after
    }

    /// Valid before (Unix time).
    pub fn valid_before(&self) -> u64 {
        self.valid_before
    }

    /// Valid after (system time).
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn valid_after_time(&self) -> SystemTime {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(self.valid_after))
            .expect("time overflow")
    }

    /// Valid before (system time).
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn valid_before_time(&self) -> SystemTime {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(self.valid_before))
            .expect("time overflow")
    }

    /// The critical options section of the certificate specifies zero or more
    /// options on the certificate's validity.
    ///
    /// Each named option may only appear once in a certificate.
    ///
    /// All options are "critical"; if an implementation does not recognize an
    /// option, then the validating party should refuse to accept the
    /// certificate.
    pub fn critical_options(&self) -> &OptionsMap {
        &self.critical_options
    }

    /// The extensions section of the certificate specifies zero or more
    /// non-critical certificate extensions.
    ///
    /// If an implementation does not recognise an extension, then it should
    /// ignore it.
    pub fn extensions(&self) -> &OptionsMap {
        &self.extensions
    }

    /// Signature key of signing CA.
    pub fn signature_key(&self) -> &KeyData {
        &self.signature_key
    }

    /// Signature computed over all preceding fields from the initial string up
    /// to, and including the signature key.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Perform certificate validation using the system clock to check that
    /// the current time is within the certificate's validity window.
    ///
    /// # ⚠️ Security Warning: Some Assembly Required
    ///
    /// See [`Certificate::validate_at`] documentation for important notes on
    /// how to properly validate certificates!
    #[cfg(all(feature = "fingerprint", feature = "std"))]
    #[cfg_attr(docsrs, doc(cfg(all(feature = "fingerprint", feature = "std"))))]
    pub fn validate<'a, I>(&self, ca_fingerprints: I) -> Result<()>
    where
        I: IntoIterator<Item = &'a Fingerprint>,
    {
        let unix_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::CertificateValidation)?
            .as_secs();

        self.validate_at(unix_time, ca_fingerprints)
    }

    /// Perform certificate validation.
    ///
    /// Checks for the following:
    ///
    /// - Specified Unix timestamp is within the certificate's valid range
    /// - Certificate's signature validates against the public key included in
    ///   the certificate
    /// - Fingerprint of the public key included in the certificate matches one
    ///   of the trusted certificate authority (CA) fingerprints provided in
    ///   the `ca_fingerprints` parameter.
    ///
    /// NOTE: only SHA-256 fingerprints are supported at this time.
    ///
    /// # ⚠️ Security Warning: Some Assembly Required
    ///
    /// This method does not perform the full set of validation checks needed
    /// to determine if a certificate is to be trusted.
    ///
    /// If this method succeeds, the following properties still need to be
    /// checked to ensure the certificate is valid:
    ///
    /// - `valid_principals` is empty or contains the expected principal
    /// - `critical_options` is empty or contains *only* options which are
    ///   recognized, and that the recognized options are all valid
    ///
    /// ## Returns
    /// - `Ok` if the certificate validated successfully
    /// - `Error::CertificateValidation` if the certificate failed to validate
    #[cfg(feature = "fingerprint")]
    #[cfg_attr(docsrs, doc(cfg(feature = "fingerprint")))]
    pub fn validate_at<'a, I>(&self, unix_timestamp: u64, ca_fingerprints: I) -> Result<()>
    where
        I: IntoIterator<Item = &'a Fingerprint>,
    {
        self.verify_signature()?;

        // TODO(tarcieri): support non SHA-256 public key fingerprints?
        let cert_fingerprint = self.signature_key.fingerprint(HashAlg::Sha256);

        if !ca_fingerprints.into_iter().any(|f| f == &cert_fingerprint) {
            return Err(Error::CertificateValidation);
        }

        // From PROTOCOL.certkeys:
        //
        //  "valid after" and "valid before" specify a validity period for the
        //  certificate. Each represents a time in seconds since 1970-01-01
        //  A certificate is considered valid if:
        //
        //     valid after <= current time < valid before
        if self.valid_after <= unix_timestamp && unix_timestamp < self.valid_before {
            Ok(())
        } else {
            Err(Error::CertificateValidation)
        }
    }

    /// Verify the signature on the certificate against the public key in the
    /// certificate.
    ///
    /// # ⚠️ Security Warning
    ///
    /// DON'T USE THIS!
    ///
    /// This function alone does not provide any security guarantees whatsoever.
    ///
    /// It verifies the signature in the certificate matches the CA public key
    /// in the certificate, but does not ensure the CA is trusted.
    ///
    /// It is public only for testing purposes, and deliberately hidden from
    /// the documentation for that reason.
    #[cfg(feature = "fingerprint")]
    #[doc(hidden)]
    pub fn verify_signature(&self) -> Result<()> {
        let mut tbs_certificate = Vec::new();
        self.encode_tbs(&mut tbs_certificate)?;
        self.signature_key
            .verify(&tbs_certificate, &self.signature)
            .map_err(|_| Error::CertificateValidation)
    }

    /// Encode the portion of the certificate "to be signed" by the CA
    /// (or to be verified against an existing CA signature)
    fn encode_tbs(&self, writer: &mut impl Writer) -> Result<()> {
        self.algorithm().as_certificate_str().encode(writer)?;
        self.nonce.encode(writer)?;
        self.public_key.encode_key_data(writer)?;
        self.serial.encode(writer)?;
        self.cert_type.encode(writer)?;
        self.key_id.encode(writer)?;
        self.valid_principals.encode(writer)?;
        self.valid_after.encode(writer)?;
        self.valid_before.encode(writer)?;
        self.critical_options.encode(writer)?;
        self.extensions.encode(writer)?;
        self.reserved.encode(writer)?;
        self.signature_key.encode_nested(writer)
    }
}

impl Decode for Certificate {
    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let algorithm = Algorithm::new_certificate(&String::decode(reader)?)?;

        Ok(Self {
            nonce: Vec::decode(reader)?,
            public_key: KeyData::decode_as(reader, algorithm)?,
            serial: u64::decode(reader)?,
            cert_type: CertType::decode(reader)?,
            key_id: String::decode(reader)?,
            valid_principals: Vec::decode(reader)?,
            valid_after: u64::decode(reader)?,
            valid_before: u64::decode(reader)?,
            critical_options: OptionsMap::decode(reader)?,
            extensions: OptionsMap::decode(reader)?,
            reserved: Vec::decode(reader)?,
            signature_key: reader.read_nested(KeyData::decode)?,
            signature: reader.read_nested(Signature::decode)?,
            comment: String::new(),
        })
    }
}

impl Encode for Certificate {
    fn encoded_len(&self) -> Result<usize> {
        [
            self.algorithm().as_certificate_str().encoded_len()?,
            self.nonce.encoded_len()?,
            self.public_key.encoded_key_data_len()?,
            self.serial.encoded_len()?,
            self.cert_type.encoded_len()?,
            self.key_id.encoded_len()?,
            self.valid_principals.encoded_len()?,
            self.valid_after.encoded_len()?,
            self.valid_before.encoded_len()?,
            self.critical_options.encoded_len()?,
            self.extensions.encoded_len()?,
            self.reserved.encoded_len()?,
            4, // signature key length prefix (uint32)
            self.signature_key.encoded_len()?,
            4, // signature length prefix (uint32)
            self.signature.encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        self.encode_tbs(writer)?;
        self.signature.encode_nested(writer)
    }
}

impl FromStr for Certificate {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_openssh(s)
    }
}

impl ToString for Certificate {
    fn to_string(&self) -> String {
        self.to_openssh().expect("SSH certificate encoding error")
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> Deserialize<'de> for Certificate {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let string = String::deserialize(deserializer)?;
            Self::from_openssh(&string).map_err(de::Error::custom)
        } else {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            Self::from_bytes(&bytes).map_err(de::Error::custom)
        }
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl Serialize for Certificate {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            self.to_openssh()
                .map_err(ser::Error::custom)?
                .serialize(serializer)
        } else {
            self.to_bytes()
                .map_err(ser::Error::custom)?
                .serialize(serializer)
        }
    }
}
