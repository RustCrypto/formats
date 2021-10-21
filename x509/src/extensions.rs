//! Extensions [`Extensions`] as defined in RFC 5280

use der::asn1::{Any, BitString, ObjectIdentifier, OctetString, SequenceOf};
use der::Sequence;

///    Extension  ::=  SEQUENCE  {
///         extnID      OBJECT IDENTIFIER,
///         critical    BOOLEAN DEFAULT FALSE,
///         extnValue   OCTET STRING
///                     -- contains the DER encoding of an ASN.1 value
///                     -- corresponding to the extension type identified
///                     -- by extnID
///         }
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Extension<'a> {
    /// extnID      OBJECT IDENTIFIER,
    pub extn_id: ObjectIdentifier,

    /// critical    BOOLEAN DEFAULT FALSE,
    pub critical: Option<bool>,

    /// extnValue   OCTET STRING
    pub extn_value: OctetString<'a>,
}

///    Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
pub type Extensions<'a> = SequenceOf<Extension<'a>, 10>;

///    BasicConstraints ::= SEQUENCE {
///         cA                      BOOLEAN DEFAULT FALSE,
///         pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct BasicConstraints {
    /// Value read from cA field of BasicConstraints extension
    pub ca: Option<bool>,
    /// Value read from pathLenConstraint field of BasicConstraints extension
    pub path_len_constraint: Option<u8>,
}

/// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
///
///    GeneralName ::= CHOICE {
///         otherName                       [0]     OtherName,
///         rfc822Name                      [1]     IA5String,
///         dNSName                         [2]     IA5String,
///         x400Address                     [3]     ORAddress,
///         directoryName                   [4]     Name,
///         ediPartyName                    [5]     EDIPartyName,
///         uniformResourceIdentifier       [6]     IA5String,
///         iPAddress                       [7]     OCTET STRING,
///         registeredID                    [8]     OBJECT IDENTIFIER }
//TODO - implement GeneralNames

///   AuthorityKeyIdentifier ::= SEQUENCE {
///       keyIdentifier             [0] KeyIdentifier           OPTIONAL,
///       authorityCertIssuer       [1] GeneralNames            OPTIONAL,
///       authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
///
///    KeyIdentifier ::= OCTET STRING
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct AuthorityKeyIdentifier<'a> {
    /// Value read from keyIdentifier field of AKID extension
    pub key_identifier: Option<OctetString<'a>>,
    //TODO - implement remainder of AuthorityKeyIdentifier
    //pub authorityCertIssuer: Option<GeneralNames<'a>>,
    //pub authorityCertSerialNumber: Option<UIntBytes<'a>>
}

/// Typedef for SubjectKeyIdentifier values
pub type SubjectKeyIdentifier<'a> = OctetString<'a>;

/// KeyUsage ::= BIT STRING {
///      digitalSignature        (0),
///      nonRepudiation          (1),  -- recent editions of X.509 have
///                                 -- renamed this bit to contentCommitment
///      keyEncipherment         (2),
///      dataEncipherment        (3),
///      keyAgreement            (4),
///      keyCertSign             (5),
///      cRLSign                 (6),
///      encipherOnly            (7),
///      decipherOnly            (8) }

pub type KeyUsage<'a> = BitString<'a>;

///CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
pub type CertificatePolicies<'a> = SequenceOf<PolicyInformation<'a>, 10>;

/// PolicyInformation ::= SEQUENCE {
///      policyIdentifier   CertPolicyId,
///      policyQualifiers   SEQUENCE SIZE (1..MAX) OF
///              PolicyQualifierInfo OPTIONAL }
///
/// CertPolicyId ::= OBJECT IDENTIFIER
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct PolicyInformation<'a> {
    pub policy_identifier: ObjectIdentifier,
    pub policy_qualifiers: Option<SequenceOf<PolicyQualifierInfo<'a>, 10>>,
}

/// PolicyQualifierInfo ::= SEQUENCE {
///      policyQualifierId  PolicyQualifierId,
///      qualifier          ANY DEFINED BY policyQualifierId }
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct PolicyQualifierInfo<'a> {
    pub policy_qualifier_id: ObjectIdentifier,
    pub path_len_constraint: Option<Any<'a>>,
}
