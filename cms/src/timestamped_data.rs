//! TimeStampedData-related types

use crate::content_info::ContentInfo;

use alloc::{string::String, vec::Vec};
use const_oid::ObjectIdentifier;
use der::{
    Any, Choice, Enumerated, Sequence,
    asn1::{Ia5String, OctetString, OctetStringRef},
};
use spki::AlgorithmIdentifierOwned;
use x509_cert::{
    attr::{Attribute, Attributes},
    crl::CertificateList,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
#[allow(missing_docs)]
pub enum TsdVersion {
    V1 = 1,
}

/// The `TimeStampedData` type is defined in [RFC 5544 Section 2].
///
/// ```text
/// TimeStampedData ::= SEQUENCE {
///     version              INTEGER { v1(1) },
///     dataUri              IA5String OPTIONAL,
///     metaData             MetaData OPTIONAL,
///     content              OCTET STRING OPTIONAL,
///     temporalEvidence     Evidence
/// }
/// ```
///
/// [RFC 5544 Section 2]: https://www.rfc-editor.org/rfc/rfc5544#section-2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct TimeStampedData<'a> {
    pub version: TsdVersion,
    #[asn1(optional = "true")]
    pub data_uri: Option<Ia5String>,
    #[asn1(optional = "true")]
    pub meta_data: Option<MetaData>,
    #[asn1(optional = "true")]
    pub content: Option<&'a OctetStringRef>,
    pub temporal_evidence: Evidence,
}

/// ```text
///  MetaData ::= SEQUENCE {
///     hashProtected        BOOLEAN,
///     fileName             UTF8String OPTIONAL,
///     mediaType            IA5String OPTIONAL,
///     otherMetaData        Attributes OPTIONAL
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct MetaData {
    pub hash_protected: bool,
    #[asn1(optional = "true")]
    pub file_name: Option<String>,
    #[asn1(optional = "true")]
    pub media_type: Option<Ia5String>,
    #[asn1(optional = "true")]
    pub other_meta_data: Option<Attributes>,
}

/// ```text
/// Evidence ::= CHOICE {
///     tstEvidence    [0] TimeStampTokenEvidence,   -- see RFC 3161
///     ersEvidence    [1] EvidenceRecord,           -- see RFC 4998
///     otherEvidence  [2] OtherEvidence
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(missing_docs)]
pub enum Evidence {
    #[asn1(context_specific = "0")]
    TstEvidence(TimeStampTokenEvidence),
    #[asn1(context_specific = "1")]
    ErsEvidence(EvidenceRecord),
    #[asn1(context_specific = "2")]
    OtherEvidence(OtherEvidence),
}

/// ```text
/// TimeStampTokenEvidence ::= SEQUENCE SIZE(1..MAX) OF TimeStampAndCrl
/// ```
pub type TimeStampTokenEvidence = Vec<TimeStampAndCrl>;

/// ```text
/// TimeStampAndCrl ::= SEQUENCE {
///     timeStamp   TimeStampToken,          -- according to RFC 3161
///     crl         CertificateList OPTIONAL -- according to RFC 5280
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct TimeStampAndCrl {
    pub time_stamp: TimeStampToken,
    #[asn1(optional = "true")]
    pub crl: Option<CertificateList>,
}

/// ```text
/// TimeStampToken ::= ContentInfo
/// ```
pub type TimeStampToken = ContentInfo;

/// ```text
/// EvidenceRecord ::= SEQUENCE {
///     version                   INTEGER { v1(1) } ,
///     digestAlgorithms          SEQUENCE OF AlgorithmIdentifier,
///     cryptoInfos               [0] CryptoInfos OPTIONAL,
///     encryptionInfo            [1] EncryptionInfo OPTIONAL,
///     archiveTimeStampSequence  ArchiveTimeStampSequence
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct EvidenceRecord {
    pub version: TsdVersion,
    pub digest_algorithm: Vec<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "0", optional = "true")]
    pub crypto_infos: Option<CryptoInfos>,
    #[asn1(context_specific = "1", optional = "true")]
    pub encryption_info: Option<EncryptionInfo>,
    pub archive_timestamp_sequence: ArchiveTimeStampSequence,
}

/// ```text
/// CryptoInfos ::= SEQUENCE SIZE (1..MAX) OF Attribute
/// ```
pub type CryptoInfos = Vec<Attribute>;

/// ```text
/// EncryptionInfo ::= SEQUENCE {
///     encryptionInfoType     OBJECT IDENTIFIER,
///     encryptionInfoValue    ANY DEFINED BY encryptionInfoType
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct EncryptionInfo {
    pub encryption_info_type: ObjectIdentifier,
    pub encryption_info_value: Any,
}

/// ```text
/// ArchiveTimeStampSequence ::= SEQUENCE OF ArchiveTimeStampChain
/// ```
#[allow(missing_docs)]
pub type ArchiveTimeStampSequence = Vec<ArchiveTimeStampChain>;

/// ```text
/// ArchiveTimeStampChain ::= SEQUENCE OF ArchiveTimeStamp
/// ```
#[allow(missing_docs)]
pub type ArchiveTimeStampChain = Vec<ArchiveTimeStamp>;

/// ```text
/// ArchiveTimeStamp ::= SEQUENCE {
///     digestAlgorithm [0] AlgorithmIdentifier OPTIONAL,
///     attributes      [1] Attributes OPTIONAL,
///     reducedHashtree [2] SEQUENCE OF PartialHashtree OPTIONAL,
///     timeStamp       ContentInfo }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct ArchiveTimeStamp {
    #[asn1(context_specific = "0", optional = "true")]
    digest_algorithm: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "1", optional = "true")]
    attributes: Option<Attributes>,
    #[asn1(context_specific = "2", optional = "true")]
    reduced_hashtree: Option<Vec<PartialHashtree>>,
    time_stamp: ContentInfo,
}

/// ```text
/// PartialHashtree ::= SEQUENCE OF OCTET STRING
/// ```
#[allow(missing_docs)]
pub type PartialHashtree = Vec<OctetString>;

/// ```text
/// OtherEvidence ::= SEQUENCE {
///     oeType               OBJECT IDENTIFIER,
///     oeValue              ANY DEFINED BY oeType }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct OtherEvidence {
    pub oe_type: ObjectIdentifier,
    pub oe_value: Any,
}
