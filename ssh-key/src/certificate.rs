//! OpenSSH certificate support.

use crate::{
    checked::CheckedSum,
    decoder::{Base64Decoder, Decode, Decoder},
    encoder::{base64_encoded_len, Encode, Encoder},
    public::{Encapsulation, KeyData},
    CertificateAlg, Error, Result, Signature,
};
use alloc::{borrow::ToOwned, string::String, vec::Vec};
use core::{cmp::Ordering, str::FromStr};

#[cfg(feature = "std")]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Key/value map type used for certificate's critical options and extensions.
pub type OptionsMap = alloc::collections::BTreeMap<String, String>;

/// OpenSSH certificate as specified in [PROTOCOL.certkeys].
///
/// OpenSSH supports X.509-like certificate authorities, but using a custom
/// encoding format.
///
/// [PROTOCOL.certkeys]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Certificate {
    /// Certificate algorithm.
    algorithm: CertificateAlg,

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
    /// Get the public key algorithm for this certificate.
    pub fn algorithm(&self) -> CertificateAlg {
        self.algorithm
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

    /// The reserved field is currently unused and is ignored in this version
    /// of the protocol.
    pub fn reserved(&self) -> &[u8] {
        &self.reserved
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

    /// Encode OpenSSH certificate to a [`String`].
    pub fn to_string(&self) -> Result<String> {
        let encoded_len = [
            2, // interstitial spaces
            self.algorithm().as_str().len(),
            base64_encoded_len(self.encoded_len()?),
            self.comment.len(),
        ]
        .checked_sum()?;

        let mut out = vec![0u8; encoded_len];
        let actual_len = Encapsulation::encode(
            &mut out,
            self.algorithm().as_str(),
            self.comment(),
            |encoder| self.encode(encoder),
        )?
        .len();
        out.truncate(actual_len);
        Ok(String::from_utf8(out)?)
    }
}

impl Decode for Certificate {
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        let algorithm = CertificateAlg::decode(decoder)?;
        let nonce = decoder.decode_byte_vec()?;
        let public_key = KeyData::decode_algorithm(decoder, algorithm.into())?;
        let serial = decoder.decode_u64()?;
        let cert_type = decoder.decode_u32()?;
        let key_id = decoder.decode_string()?;
        let valid_principals = Vec::decode(decoder)?;
        let valid_after = decoder.decode_u64()?;
        let valid_before = decoder.decode_u64()?;
        let critical_options = OptionsMap::decode(decoder)?;
        let extensions = OptionsMap::decode(decoder)?;
        let reserved = decoder.decode_byte_vec()?;
        let signature_key = decoder.decode_length_prefixed(|dec, _len| KeyData::decode(dec))?;
        let signature = decoder.decode_length_prefixed(|dec, _len| Signature::decode(dec))?;

        Ok(Self {
            algorithm,
            nonce,
            public_key,
            serial,
            cert_type: cert_type.try_into()?,
            key_id,
            valid_principals,
            valid_after,
            valid_before,
            critical_options,
            extensions,
            reserved,
            signature_key,
            signature,
            comment: String::new(),
        })
    }
}

impl Encode for Certificate {
    fn encoded_len(&self) -> Result<usize> {
        [
            self.algorithm.encoded_len()?,
            4, // nonce length prefix (uint32)
            self.nonce.len(),
            self.public_key.encoded_key_data_len()?,
            8, // serial (uint64)
            4, // cert type (uint32)
            4, // key id length prefix (uint32)
            self.key_id.len(),
            self.valid_principals.encoded_len()?,
            8, // valid after (uint64)
            8, // valid before (uint64)
            4, // critical options length prefix (uint32)
            self.critical_options.encoded_len()?,
            4, // extensions length prefix (uint32)
            self.extensions.encoded_len()?,
            4, // reserved length prefix (uint32)
            self.reserved.len(),
            4, // signature key length prefix (uint32)
            self.signature_key.encoded_len()?,
            4, // signature length prefix (uint32)
            self.signature.encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        self.algorithm.encode(encoder)?;
        encoder.encode_byte_slice(&self.nonce)?;
        self.public_key.encode_key_data(encoder)?;
        encoder.encode_u64(self.serial)?;
        encoder.encode_u32(self.cert_type.into())?;
        encoder.encode_str(&self.key_id)?;
        self.valid_principals.encode(encoder)?;
        encoder.encode_u64(self.valid_after)?;
        encoder.encode_u64(self.valid_before)?;
        self.critical_options.encode(encoder)?;
        self.extensions.encode(encoder)?;
        encoder.encode_byte_slice(&self.reserved)?;
        encoder.encode_usize(self.signature_key.encoded_len()?)?;
        self.signature_key.encode(encoder)?;
        encoder.encode_usize(self.signature.encoded_len()?)?;
        self.signature.encode(encoder)
    }
}

impl FromStr for Certificate {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let encapsulation = Encapsulation::decode(s.trim_end().as_bytes())?;
        let mut decoder = Base64Decoder::new(encapsulation.base64_data)?;
        let mut certificate = Certificate::decode(&mut decoder)?;

        if !decoder.is_finished() {
            return Err(Error::Length);
        }

        // Verify that the algorithm in the Base64-encoded data matches the text
        if encapsulation.algorithm_id != certificate.algorithm().as_str() {
            return Err(Error::Algorithm);
        }

        certificate.comment = encapsulation.comment.to_owned();
        Ok(certificate)
    }
}

/// Certificate types.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum CertType {
    /// User certificate
    User = 1,

    /// Host certificate
    Host = 2,
}

impl TryFrom<u32> for CertType {
    type Error = Error;

    fn try_from(n: u32) -> Result<CertType> {
        match n {
            1 => Ok(CertType::User),
            2 => Ok(CertType::Host),
            _ => Err(Error::FormatEncoding),
        }
    }
}

impl From<CertType> for u32 {
    fn from(cert_type: CertType) -> u32 {
        cert_type as u32
    }
}

impl Decode for Vec<String> {
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        decoder.decode_length_prefixed(|decoder, len| {
            let mut entries = Self::new();
            let offset = decoder.remaining_len();

            while offset.saturating_sub(decoder.remaining_len()) < len {
                entries.push(decoder.decode_string()?);
            }

            Ok(entries)
        })
    }
}

impl Encode for Vec<String> {
    fn encoded_len(&self) -> Result<usize> {
        self.iter()
            .try_fold(4, |acc, entry| [acc, 4, entry.len()].checked_sum())
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        let len = self.encoded_len()?.checked_sub(4).ok_or(Error::Length)?;
        encoder.encode_usize(len)?;

        for entry in self {
            encoder.encode_str(entry)?;
        }

        Ok(())
    }
}

impl Decode for OptionsMap {
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        decoder.decode_length_prefixed(|decoder, len| {
            let mut entries = Vec::<(String, String)>::new();
            let offset = decoder.remaining_len();

            while offset.saturating_sub(decoder.remaining_len()) < len {
                let name = decoder.decode_string()?;
                let data = decoder.decode_string()?;

                // Options must be lexically ordered by "name" if they appear in
                // the sequence. Each named option may only appear once in a
                // certificate.
                if let Some((prev_name, _)) = entries.last() {
                    if prev_name.cmp(&name) != Ordering::Less {
                        return Err(Error::FormatEncoding);
                    }
                }

                entries.push((name, data));
            }

            Ok(OptionsMap::from_iter(entries))
        })
    }
}

impl Encode for OptionsMap {
    fn encoded_len(&self) -> Result<usize> {
        self.iter().try_fold(4, |acc, (name, data)| {
            [acc, 4, name.len(), 4, data.len()].checked_sum()
        })
    }

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        let len = self.encoded_len()?.checked_sub(4).ok_or(Error::Length)?;
        encoder.encode_usize(len)?;

        for (name, data) in self {
            encoder.encode_str(name)?;
            encoder.encode_str(data)?;
        }

        Ok(())
    }
}
