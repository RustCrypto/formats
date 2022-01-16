//! Certificate [`Certificate`] and TBSCertificate [`TBSCertificate`] as defined in RFC 5280

use crate::{Name, Validity};
use der::asn1::{BitString, ContextSpecific, ObjectIdentifier, UIntBytes};
use der::{DecodeValue, Decoder, Length, Sequence, TagMode, TagNumber};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

/// returns false in support of integer DEFAULT fields set to 0
pub fn default_zero_u8() -> u8 {
    0
}

/// returns false in support of boolean DEFAULT fields
pub fn default_false() -> bool {
    false
}

/// returns false in support of integer DEFAULT fields set to 0
pub fn default_zero() -> u32 {
    0
}

/// only support v3 certificates
/// Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
pub const X509_CERT_VERSION: u8 = 2;

use der::OrdIsValueOrd;

/// X.509 `TBSCertificate` as defined in [RFC 5280 Section 4.1.2.5]
///
/// ASN.1 structure containing the names of the subject and issuer, a public key associated
/// with the subject, a validity period, and other associated information.
///
/// ```text
///   TBSCertificate  ::=  SEQUENCE  {
///       version         \[0\]  Version DEFAULT v1,
///       serialNumber         CertificateSerialNumber,
///       signature            AlgorithmIdentifier{SIGNATURE-ALGORITHM, {SignatureAlgorithms}},
///       issuer               Name,
///       validity             Validity,
///       subject              Name,
///       subjectPublicKeyInfo SubjectPublicKeyInfo,
///       ... ,
///       [[2:               -- If present, version MUST be v2
///       issuerUniqueID  \[1\]  IMPLICIT UniqueIdentifier OPTIONAL,
///       subjectUniqueID \[2\]  IMPLICIT UniqueIdentifier OPTIONAL
///       ]],
///       [[3:               -- If present, version MUST be v3 --
///       extensions      \[3\]  Extensions{{CertExtensions}} OPTIONAL
///       ]], ... }
/// ```
///
/// [RFC 5280 Section 4.1.2.5]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct TBSCertificate<'a> {
    /// version         \[0\]  Version DEFAULT v1,
    //#[asn1(context_specific = "0", default = "default_zero_u8")]
    pub version: u8,
    /// serialNumber         CertificateSerialNumber,
    pub serial_number: UIntBytes<'a>,
    /// signature            AlgorithmIdentifier{SIGNATURE-ALGORITHM, {SignatureAlgorithms}},
    pub signature: AlgorithmIdentifier<'a>,
    /// issuer               Name,
    pub issuer: Name<'a>,
    /// validity             Validity,
    pub validity: Validity,
    /// subject              Name,
    pub subject: Name<'a>,
    /// subjectPublicKeyInfo SubjectPublicKeyInfo,
    pub subject_public_key_info: SubjectPublicKeyInfo<'a>,
    /// issuerUniqueID  \[1\]  IMPLICIT UniqueIdentifier OPTIONAL,
    //#[asn1(context_specific = "1", optional = "true", tag_mode = "IMPLICIT")]
    pub issuer_unique_id: Option<BitString<'a>>,
    /// subjectUniqueID \[2\]  IMPLICIT UniqueIdentifier OPTIONAL
    //#[asn1(context_specific = "2", optional = "true", tag_mode = "IMPLICIT")]
    pub subject_unique_id: Option<BitString<'a>>,
    /// extensions      \[3\]  Extensions{{CertExtensions}} OPTIONAL
    //#[asn1(context_specific = "3", optional = "true", tag_mode = "EXPLICIT")]
    pub extensions: Option<Extensions<'a>>,
}
impl<'a> ::der::Decodable<'a> for TBSCertificate<'a> {
    fn decode(decoder: &mut ::der::Decoder<'a>) -> ::der::Result<Self> {
        decoder.sequence(|decoder| {
            let version =
                ::der::asn1::ContextSpecific::decode_explicit(decoder, ::der::TagNumber::N0)?
                    .map(|cs| cs.value)
                    .unwrap_or_else(default_zero_u8);
            let serial_number = decoder.decode()?;
            let signature = decoder.decode()?;
            let issuer = decoder.decode()?;
            let validity = decoder.decode()?;
            let subject = decoder.decode()?;
            let subject_public_key_info = decoder.decode()?;
            let issuer_unique_id =
                ::der::asn1::ContextSpecific::decode_implicit(decoder, ::der::TagNumber::N1)?
                    .map(|cs| cs.value);
            let subject_unique_id =
                ::der::asn1::ContextSpecific::decode_implicit(decoder, ::der::TagNumber::N2)?
                    .map(|cs| cs.value);
            let extensions =
                ::der::asn1::ContextSpecific::decode_explicit(decoder, ::der::TagNumber::N3)?
                    .map(|cs| cs.value);
            Ok(Self {
                version,
                serial_number,
                signature,
                issuer,
                validity,
                subject,
                subject_public_key_info,
                issuer_unique_id,
                subject_unique_id,
                extensions,
            })
        })
    }
}
const VERSION_TAG: TagNumber = TagNumber::new(0);
const EXTENSIONS_TAG: TagNumber = TagNumber::new(3);
impl<'a> ::der::Sequence<'a> for TBSCertificate<'a> {
    fn fields<F, T>(&self, f: F) -> ::der::Result<T>
    where
        F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
    {
        #[allow(unused_imports)]
        use core::convert::TryFrom;
        f(&[
            &ContextSpecific {
                tag_number: VERSION_TAG,
                tag_mode: TagMode::Explicit,
                value: self.version,
            },
            &self.serial_number,
            &self.signature,
            &self.issuer,
            &self.validity,
            &self.subject,
            &self.subject_public_key_info,
            &self.issuer_unique_id,
            &self.subject_unique_id,
            &self.extensions.as_ref().map(|exts| ContextSpecific {
                tag_number: EXTENSIONS_TAG,
                tag_mode: TagMode::Explicit,
                value: exts.clone(),
            }),
        ])
    }
}

impl<'a> ::core::fmt::Debug for TBSCertificate<'a> {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        f.write_fmt(format_args!("\n\tVersion: {:02X?}\n", self.version))?;
        f.write_fmt(format_args!("\tSerial Number: 0x"))?;
        for b in self.serial_number.as_bytes() {
            f.write_fmt(format_args!("{:02X?}", b))?;
        }
        f.write_fmt(format_args!("\n"))?;
        f.write_fmt(format_args!("\tSignature: {:?}\n", self.signature))?;
        f.write_fmt(format_args!("\tIssuer: {:?}\n", self.issuer))?;
        f.write_fmt(format_args!("\tValidity: {:?}\n", self.validity))?;
        f.write_fmt(format_args!("\tSubject: {:?}\n", self.subject))?;
        f.write_fmt(format_args!(
            "\tSubject Public Key Info: {:?}\n",
            self.subject_public_key_info
        ))?;
        f.write_fmt(format_args!(
            "\tIssuer Unique ID: {:?}\n",
            self.issuer_unique_id
        ))?;
        f.write_fmt(format_args!(
            "\tSubject Unique ID: {:?}\n",
            self.subject_unique_id
        ))?;
        if let Some(exts) = self.extensions.as_ref() {
            for (i, e) in exts.iter().enumerate() {
                f.write_fmt(format_args!("\tExtension #{}: {:?}\n", i, e))?;
            }
        } else {
            f.write_fmt(format_args!("\tExtensions: None\n"))?;
        }
        Ok(())
    }
}

/// X.509 certificates are defined in [RFC 5280 Section 4.1].
///
/// ASN.1 structure for an X.509 certificate:
///
/// ```text
/// Certificate  ::=  SEQUENCE  {
///      tbsCertificate       TBSCertificate,
///      signatureAlgorithm   AlgorithmIdentifier,
///      signature            BIT STRING  }
/// ```
///
/// [RFC 5280 Section 4.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Certificate<'a> {
    /// tbsCertificate       TBSCertificate,
    pub tbs_certificate: TBSCertificate<'a>,
    /// signatureAlgorithm   AlgorithmIdentifier,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    /// signature            BIT STRING
    pub signature: BitString<'a>,
}
impl OrdIsValueOrd for Certificate<'_> {}

// impl<'a> ::der::Decodable<'a> for Certificate<'a> {
//     fn decode(decoder: &mut ::der::Decoder<'a>) -> ::der::Result<Self> {
//         decoder.sequence(|decoder| {
impl<'a> DecodeValue<'a> for Certificate<'a> {
    fn decode_value(decoder: &mut Decoder<'a>, _length: Length) -> der::Result<Self> {
        let tbs_certificate = decoder.decode()?;
        let signature_algorithm = decoder.decode()?;
        let signature = decoder.decode()?;
        Ok(Self {
            tbs_certificate,
            signature_algorithm,
            signature,
        })
        // })
    }
}

impl<'a> ::der::Sequence<'a> for Certificate<'a> {
    fn fields<F, T>(&self, f: F) -> ::der::Result<T>
    where
        F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
    {
        f(&[
            &self.tbs_certificate,
            &self.signature_algorithm,
            &self.signature,
        ])
    }
}

/// Extension as defined in [RFC 5280 Section 4.1.2.9].
///
/// The ASN.1 definition for Extension objects is below. The extnValue type may be further parsed using a decoder corresponding to the extnID value.
///
/// ```text
///    Extension  ::=  SEQUENCE  {
///         extnID      OBJECT IDENTIFIER,
///         critical    BOOLEAN DEFAULT FALSE,
///         extnValue   OCTET STRING
///                     -- contains the DER encoding of an ASN.1 value
///                     -- corresponding to the extension type identified
///                     -- by extnID
///         }
/// ```
///
/// [RFC 5280 Section 4.1.2.9]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.9
#[derive(Clone, Debug, Eq, PartialEq, Sequence, PartialOrd, Ord)]
pub struct Extension<'a> {
    /// extnID      OBJECT IDENTIFIER,
    pub extn_id: ObjectIdentifier,

    /// critical    BOOLEAN DEFAULT FALSE,
    #[asn1(default = "default_false")]
    pub critical: bool,

    /// extnValue   OCTET STRING
    #[asn1(type = "OCTET STRING")]
    pub extn_value: &'a [u8],
}

/// Extensions as defined in [RFC 5280 Section 4.1.2.9].
///
/// ```text
///    Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
/// ```
///
/// [RFC 5280 Section 4.1.2.9]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.9
//pub type Extensions<'a> = SequenceOf<Extension<'a>, 10>;
pub type Extensions<'a> = alloc::vec::Vec<Extension<'a>>;
