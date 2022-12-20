//! `signed-data` content type [RFC 5652 § 5](https://datatracker.ietf.org/doc/html/rfc5652#section-5)

use crate::{signer_info::{SignerInfos}, encapsulated_content_info::EncapsulatedContentInfo, certificate_choices::CertificateChoices, revocation_info_choices::RevocationInfoChoices, cms_version::{CmsVersion}};
use der::{Sequence, asn1::{SetOfVec}};
use spki::{AlgorithmIdentifierRef};

/// ```text
/// DigestAlgorithmIdentifier ::= AlgorithmIdentifier
/// ```
type DigestAlgorithmIdentifier<'a> = AlgorithmIdentifierRef<'a>;

/// ```text
/// DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
/// ```
type DigestAlgorithmIdentifiers<'a> = SetOfVec<DigestAlgorithmIdentifier<'a>>;

/// ```text
/// CertificateSet ::= SET OF CertificateChoices
/// ```
type CertificateSet<'a> = SetOfVec<CertificateChoices<'a>>;

/// Signed-data content type [RFC 5652 § 5](https://datatracker.ietf.org/doc/html/rfc5652#section-5)
///
/// ```text
/// SignedData ::= SEQUENCE {
///     version CMSVersion,
///     digestAlgorithms DigestAlgorithmIdentifiers,
///     encapContentInfo EncapsulatedContentInfo,
///     certificates [0] IMPLICIT CertificateSet OPTIONAL,
///     crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
///     signerInfos SignerInfos }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SignedDataContent<'a> {
    /// the syntax version number.
    pub version: CmsVersion,

    /// digest algorithm
    pub digest_algorithms: DigestAlgorithmIdentifiers<'a>,

    /// content
    pub encap_content_info: EncapsulatedContentInfo<'a>,

    /// certs
    #[asn1(context_specific = "0", optional = "true", tag_mode = "IMPLICIT")]
    pub certificates: Option<CertificateSet<'a>>,

    /// crls
    #[asn1(context_specific = "1", optional = "true", tag_mode = "IMPLICIT")]
    pub crls: Option<RevocationInfoChoices<'a>>,

    /// signer info
    pub signer_infos: SignerInfos<'a>
}
