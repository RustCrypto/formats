//! OpenSSH certificate support.

use crate::{
    decoder::{Base64Decoder, Decode, Decoder},
    public::{Encapsulation, KeyData},
    CertificateAlg, Error, Result,
};
use alloc::{borrow::ToOwned, string::String, vec::Vec};
use core::str::FromStr;

/// OpenSSH certificate as specified in [PROTOCOL.certkeys].
///
/// OpenSSH supports X.509-like certificate authorities, but using a custom
/// encoding format.
///
/// [PROTOCOL.certkeys]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
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
    cert_type: u32,

    /// Key ID.
    key_id: String,

    /// Valid principals.
    valid_principals: String,

    /// Valid after (Unix time).
    valid_after: u64,

    /// Valid before (Unix time).
    valid_before: u64,

    /// Critical options.
    critical_options: String,

    /// Extensions.
    extensions: String,

    /// Reserved field.
    reserved: String,

    /// Signature key of signing CA.
    signature_key: Vec<u8>,

    /// Signature over the certificate.
    signature: Vec<u8>,

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

    /// Get this certificate's public key data.
    pub fn public_key(&self) -> &KeyData {
        &self.public_key
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
        let valid_principals = decoder.decode_string()?;
        let valid_after = decoder.decode_u64()?;
        let valid_before = decoder.decode_u64()?;
        let critical_options = decoder.decode_string()?;
        let extensions = decoder.decode_string()?;
        let reserved = decoder.decode_string()?;
        let signature_key = decoder.decode_byte_vec()?;
        let signature = decoder.decode_byte_vec()?;

        Ok(Self {
            algorithm,
            nonce,
            public_key,
            serial,
            cert_type,
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
