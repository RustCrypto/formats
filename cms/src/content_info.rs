//! ContentInfo types

use crate::cert::CertificateChoices;
use crate::revocation::RevocationInfoChoices;
use crate::signed_data::EncapsulatedContentInfo;
use crate::signed_data::{CertificateSet, SignedData, SignerInfos};
use core::cmp::Ordering;
use der::Encode;
use der::asn1::SetOfVec;
use der::{Any, AnyRef, Enumerated, Sequence, ValueOrd, asn1::ObjectIdentifier};
use x509_cert::{Certificate, PkiPath};

/// The `OtherCertificateFormat` type is defined in [RFC 5652 Section 10.2.5].
///
/// ```text
///  CMSVersion ::= INTEGER  { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
/// ```
///
/// [RFC 5652 Section 10.2.5]: https://www.rfc-editor.org/rfc/rfc5652#section-10.2.5
#[derive(Clone, Debug, Copy, PartialEq, Eq, PartialOrd, Ord, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
#[allow(missing_docs)]
pub enum CmsVersion {
    V0 = 0,
    V1 = 1,
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
}

impl ValueOrd for CmsVersion {
    fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
        (*self as u8).value_cmp(&(*other as u8))
    }
}

/// The `ContentInfo` type is defined in [RFC 5652 Section 3].
///
/// ```text
///   ContentInfo ::= SEQUENCE {
///       contentType        CONTENT-TYPE.
///                       &id({ContentSet}),
///       content            [0] EXPLICIT CONTENT-TYPE.
///                       &Type({ContentSet}{@contentType})}
/// ```
///
/// [RFC 5652 Section 3]: https://www.rfc-editor.org/rfc/rfc5652#section-3
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct ContentInfo {
    pub content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub content: Any,
}

/// Convert a Certificate to a certs-only SignedData message
impl TryFrom<Certificate> for ContentInfo {
    type Error = der::Error;

    fn try_from(cert: Certificate) -> der::Result<Self> {
        let mut certs = CertificateSet(Default::default());
        certs.0.insert(CertificateChoices::Certificate(cert))?;

        // include empty CRLs field instead of omitting it to match OpenSSL's behavior
        let sd = SignedData {
            version: CmsVersion::V1,
            digest_algorithms: SetOfVec::default(),
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: const_oid::db::rfc5911::ID_DATA,
                econtent: None,
            },
            certificates: Some(certs),
            crls: Some(RevocationInfoChoices(Default::default())),
            signer_infos: SignerInfos(Default::default()),
        };

        let signed_data = sd.to_der()?;
        let content = AnyRef::try_from(signed_data.as_slice())?;

        Ok(ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: Any::from(content),
        })
    }
}

/// Convert a vector of Certificates to a certs-only SignedData message
impl TryFrom<PkiPath> for ContentInfo {
    type Error = der::Error;

    fn try_from(pki_path: PkiPath) -> der::Result<Self> {
        let mut certs = CertificateSet(Default::default());
        for cert in pki_path {
            certs.0.insert(CertificateChoices::Certificate(cert))?;
        }

        // include empty CRLs field instead of omitting it to match OpenSSL's behavior
        let sd = SignedData {
            version: CmsVersion::V1,
            digest_algorithms: SetOfVec::default(),
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: const_oid::db::rfc5911::ID_DATA,
                econtent: None,
            },
            certificates: Some(certs),
            crls: Some(RevocationInfoChoices(Default::default())),
            signer_infos: SignerInfos(Default::default()),
        };

        let signed_data = sd.to_der()?;
        let content = AnyRef::try_from(signed_data.as_slice())?;

        Ok(ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: Any::from(content),
        })
    }
}

#[cfg(feature = "pem")]
impl der::pem::PemLabel for ContentInfo {
    /// Per [RFC7468], ContentInfo can be encoded into PEM with a label of "CMS".
    ///
    /// [RFC7468]: https://www.rfc-editor.org/info/rfc7468/#section-9
    const PEM_LABEL: &'static str = "CMS";
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "pem")]
    use super::ContentInfo;

    #[cfg(feature = "pem")]
    #[test]
    fn test_pem_encode_decode() {
        let content_info = ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: der::Any::null(),
        };

        // Encode to PEM and check that it's come out looking plausible
        use der::EncodePem;
        let pem_encoding = content_info
            .to_pem(der::pem::LineEnding::LF)
            .expect("Failed to encode ContentInfo as PEM");
        assert!(pem_encoding.starts_with("-----BEGIN CMS-----\n"));
        assert!(pem_encoding.ends_with("\n-----END CMS-----\n"));

        // Parse back into ContentInfo, and check we end up with what we started with.
        use der::DecodePem;
        let parsed = ContentInfo::from_pem(pem_encoding).expect("Failed to decode ContentInfo PEM");
        assert_eq!(parsed, content_info);
    }
}
