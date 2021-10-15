//! Certificate [`Certificate`] as defined in RFC 5280

use crate::{Extensions, RDNSequence, Validity};
use der::asn1::{BitString, UIntBytes};
use der::{Decodable, Decoder, Sequence, TagMode, TagNumber};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

// only support v3 certificates
// Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
const VERSION: u8 = 2;

// Context specific tags for TBSCertificate
const VERSION_TAG: TagNumber = TagNumber::new(0);
const ISSUER_UID_TAG: TagNumber = TagNumber::new(1);
const SUBJECT_UID_TAG: TagNumber = TagNumber::new(2);
const EXTENSIONS_TAG: TagNumber = TagNumber::new(3);

/// X.509 `TBSCertificate` as defined in [RFC 5280 Section 4.1.2.5]
///
/// ```text
///   TBSCertificate  ::=  SEQUENCE  {
///       version         [0]  Version DEFAULT v1,
///       serialNumber         CertificateSerialNumber,
///       signature            AlgorithmIdentifier{SIGNATURE-ALGORITHM, {SignatureAlgorithms}},
///       issuer               Name,
///       validity             Validity,
///       subject              Name,
///       subjectPublicKeyInfo SubjectPublicKeyInfo,
///       ... ,
///       [[2:               -- If present, version MUST be v2
///       issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
///       subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL
///       ]],
///       [[3:               -- If present, version MUST be v3 --
///       extensions      [3]  Extensions{{CertExtensions}} OPTIONAL
///       ]], ... }
/// ```
/// [RFC 5280 Section 4.1.2.5]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TBSCertificate<'a> {
    /// version         [0]  Version DEFAULT v1,
    pub version: u8,
    /// serialNumber         CertificateSerialNumber,
    pub serial_number: UIntBytes<'a>,
    /// signature            AlgorithmIdentifier{SIGNATURE-ALGORITHM, {SignatureAlgorithms}},
    pub signature: AlgorithmIdentifier<'a>,
    /// issuer               Name,
    pub issuer: RDNSequence<'a>,
    /// validity             Validity,
    pub validity: Validity,
    /// subject              Name,
    pub subject: RDNSequence<'a>,
    /// subjectPublicKeyInfo SubjectPublicKeyInfo,
    pub subject_public_key_info: SubjectPublicKeyInfo<'a>,
    /// issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
    pub issuer_unique_id: Option<BitString<'a>>,
    /// subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL
    pub subject_unique_id: Option<BitString<'a>>,
    /// extensions      [3]  Extensions{{CertExtensions}} OPTIONAL
    pub extensions: Option<Extensions<'a>>,
}

impl<'a> Decodable<'a> for TBSCertificate<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            let version = decoder
                .context_specific::<u8>(VERSION_TAG, TagMode::Explicit)?
                .unwrap();
            if version != VERSION {
                return Err(der::Tag::Integer.value_error());
            }

            // TODO refactor unwrap if this implementation remains
            let serial_number = UIntBytes::decode(decoder).unwrap();
            let signature = AlgorithmIdentifier::decode(decoder).unwrap();
            let issuer = RDNSequence::decode(decoder).unwrap();
            let validity = Validity::decode(decoder).unwrap();
            let subject = RDNSequence::decode(decoder).unwrap();
            let subject_public_key_info = SubjectPublicKeyInfo::decode(decoder).unwrap();
            let mut issuer_unique_id = Option::None;
            if (0b10000000 | ISSUER_UID_TAG.value()) == decoder.peek().unwrap() {
                issuer_unique_id =
                    decoder.context_specific::<BitString<'_>>(ISSUER_UID_TAG, TagMode::Explicit)?;
            }
            let mut subject_unique_id = Option::None;
            if (0b10000000 | SUBJECT_UID_TAG.value()) == decoder.peek().unwrap() {
                subject_unique_id = decoder
                    .context_specific::<BitString<'_>>(SUBJECT_UID_TAG, TagMode::Explicit)?;
            }
            let mut extensions = Option::None;
            if (0b10100000 | EXTENSIONS_TAG.value()) == decoder.peek().unwrap() {
                extensions = decoder
                    .context_specific::<Extensions<'_>>(EXTENSIONS_TAG, TagMode::Explicit)?;
            }
            Ok(TBSCertificate {
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

impl<'a> ::der::Sequence<'a> for TBSCertificate<'a> {
    fn fields<F, T>(&self, f: F) -> ::der::Result<T>
    where
        F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
    {
        #[allow(unused_imports)]
        use core::convert::TryFrom;
        f(&[
            &self.version,
            &self.serial_number,
            &self.signature,
            &self.issuer,
            &self.validity,
            &self.subject,
            &self.subject_public_key_info,
            &self.issuer_unique_id,
            &self.subject_unique_id,
            &self.extensions,
        ])
    }
}

/// Certificate  ::=  SEQUENCE  {
///      tbsCertificate       TBSCertificate,
///      signatureAlgorithm   AlgorithmIdentifier,
///      signature            BIT STRING  }
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Certificate<'a> {
    /// tbsCertificate       TBSCertificate,
    pub tbs_certificate: TBSCertificate<'a>,
    /// signatureAlgorithm   AlgorithmIdentifier,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    /// signature            BIT STRING
    pub signature: BitString<'a>,
}
