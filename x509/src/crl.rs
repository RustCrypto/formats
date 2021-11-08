//! CertificateList [`CertificateList`], TBSCertList [`TBSCertList`] and supporting structures as defined in RFC 5280

use crate::{Extensions, Name, Time};
use der::asn1::{BitString, UIntBytes};
use der::{Decodable, Decoder, Defer, Sequence, Tag, TagMode, TagNumber};
use spki::AlgorithmIdentifier;

const CRL_EXTENSIONS_TAG: TagNumber = TagNumber::new(0);
pub const X509_CRL_VERSION: u8 = 1;

/// CrlEntry represents the inner most part of the inline definition from the
/// revokedCertificates field in TBSCertList as defined in [RFC 5280 Section 5.1.2.6].
///
/// ```text
/// SEQUENCE  {
///           userCertificate         CertificateSerialNumber,
///           revocationDate          Time,
///           crlEntryExtensions      Extensions OPTIONAL
///                                    -- if present, version MUST be v2
/// ```
///
/// [RFC 5280 Section 5.1.2.6]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.1.2.6
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CrlEntry<'a> {
    /// serialNumber         CertificateSerialNumber,
    pub serial_number: UIntBytes<'a>,
    /// revocationDate             Time,
    pub this_update: Time,
    /// crlEntryExtensions      [0]  Extensions OPTIONAL
    pub crl_entry_extensions: Option<Extensions<'a>>,
}

/// CrlEntries represents the outer most part of the inline definition from the
/// revokedCertificates field in TBSCertList as defined in [RFC 5280 Section 5.1.2.6].
///
/// ```text
/// SEQUENCE OF SEQUENCE  {
///           userCertificate         CertificateSerialNumber,
///           revocationDate          Time,
///           crlEntryExtensions      Extensions OPTIONAL
///                                    -- if present, version MUST be v2
///                                }
/// ```
///
/// [RFC 5280 Section 5.1.2.6]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.1.2.6
//pub type CrlEntries<'a> = SequenceOf<CrlEntry<'a>, 10>;
pub type CrlEntries<'a> = alloc::vec::Vec<CrlEntry<'a>>;

/// X.509 `TBSCertList` as defined in [RFC 5280 Section 5.1.2]
///
/// ASN.1 structure containing the name of the issuer, issue date, issue date of the next
/// list, the optional list of revoked certificates, and optional CRL extensions.
///
/// ```text
///   TBSCertList  ::=  SEQUENCE  {
///      version                 Version OPTIONAL,
///                                    -- if present, MUST be v2
///      signature               AlgorithmIdentifier,
///      issuer                  Name,
///      thisUpdate              Time,
///      nextUpdate              Time OPTIONAL,
///      revokedCertificates     SEQUENCE OF SEQUENCE  {
///           userCertificate         CertificateSerialNumber,
///           revocationDate          Time,
///           crlEntryExtensions      Extensions OPTIONAL
///                                    -- if present, version MUST be v2
///                                }  OPTIONAL,
///      crlExtensions           [0] Extensions OPTIONAL }
///                                    -- if present, version MUST be v2
/// ```
///
/// [RFC 5280 Section 5.1.2]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.1.2
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TBSCertList<'a> {
    /// version         [0]  Version DEFAULT v1,
    pub version: Option<u8>,
    /// signature            AlgorithmIdentifier{SIGNATURE-ALGORITHM, {SignatureAlgorithms}},
    pub signature: AlgorithmIdentifier<'a>,
    /// issuer               Name,
    pub issuer: Name<'a>,
    /// thisUpdate             Time,
    pub this_update: Time,
    /// thisUpdate             Time,
    pub next_update: Time,
    /// revokedCertificates,
    pub revoked_certificates: CrlEntries<'a>,
    /// crlExtensions      [0]  Extensions OPTIONAL
    pub crl_extensions: Option<Extensions<'a>>,
}

// Custom Decodable to handle implicit context specific fields (this may move to derived later).
impl<'a> Decodable<'a> for TBSCertList<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            let mut version = Some(0);
            if decoder.peek_tag()? == Tag::Integer {
                version = decoder.decode()?;
                if version != Some(X509_CRL_VERSION) {
                    return Err(der::Tag::Integer.value_error());
                }
            }

            let signature = AlgorithmIdentifier::decode(decoder)?;
            let issuer = Name::decode(decoder)?;
            let this_update = Time::decode(decoder)?;
            let next_update = Time::decode(decoder)?;
            let revoked_certificates = CrlEntries::decode(decoder)?;
            let crl_extensions = decoder
                .context_specific::<Extensions<'_>>(CRL_EXTENSIONS_TAG, TagMode::Explicit)?;
            Ok(TBSCertList {
                version,
                signature,
                issuer,
                this_update,
                next_update,
                revoked_certificates,
                crl_extensions,
            })
        })
    }
}

impl<'a> ::der::Sequence<'a> for TBSCertList<'a> {
    fn fields<F, T>(&self, f: F) -> ::der::Result<T>
    where
        F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
    {
        #[allow(unused_imports)]
        use core::convert::TryFrom;
        f(&[
            &self.version,
            &self.signature,
            &self.issuer,
            &self.this_update,
            &self.next_update,
            &self.revoked_certificates,
            &self.crl_extensions,
        ])
    }
}

/// X.509 CRL as defined in [RFC 5280 Section 5.1.1].
///
/// ASN.1 structure containing a certificate revocation list (CRL).
///
/// ```text
/// CertificateList  ::=  SEQUENCE  {
///      tbsCertList          TBSCertList,
///      signatureAlgorithm   AlgorithmIdentifier,
///      signature            BIT STRING  }
/// ```
///
/// [RFC 5280 Section 5.1.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence, Defer)]
pub struct CertificateList<'a> {
    /// tbsCertificate       TBSCertList,
    #[asn1(defer = "true")]
    pub tbs_cert_list: TBSCertList<'a>,
    /// signatureAlgorithm   AlgorithmIdentifier,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    /// signature            BIT STRING
    pub signature: BitString<'a>,
}
