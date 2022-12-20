//! `SignerInfo` data type [RFC 5652 § 5.3](https://datatracker.ietf.org/doc/html/rfc5652#section-5.3)

use core::cmp::Ordering;

use crate::{cms_version::{CmsVersion}};
use der::{Sequence, Choice, asn1::{OctetStringRef, SetOfVec, UintRef}, ValueOrd,
};
use spki::{AlgorithmIdentifierRef};
use x509_cert::{ext::pkix::{SubjectKeyIdentifier}, attr::{Attribute}, name::Name};

/// ```text
/// DigestAlgorithmIdentifier ::= AlgorithmIdentifier
/// ```
type DigestAlgorithmIdentifier<'a> = AlgorithmIdentifierRef<'a>;

/// ```text
/// SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
/// ```
type SignatureAlgorithmIdentifier<'a> = AlgorithmIdentifierRef<'a>;

/// ```text
/// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
/// ```
type SignedAttributes<'a>  = SetOfVec<Attribute>;

/// ```text
/// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
/// ```
type UnsignedAttributes<'a>  = SetOfVec<Attribute>;

/// ```text
/// SignerIdentifier ::= CHOICE {
//    issuerAndSerialNumber IssuerAndSerialNumber,
//    subjectKeyIdentifier [0] SubjectKeyIdentifier }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Choice)]
pub enum SignerIdentifier<'a> {
    IssuerAndSerialNumber(IssuerAndSerialNumber<'a>),

    #[asn1(context_specific = "0")]
    SubjectKeyIdentifier(SubjectKeyIdentifier<'a>),
}


#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct IssuerAndSerialNumber<'a> {
    pub name: Name,
    pub serial_number: UintRef<'a>,
}




/// ```text
/// SignerInfos ::= SET OF SignerInfo
/// ```
pub type SignerInfos<'a> = SetOfVec<SignerInfo<'a>>;


/// `SignerInfo` data type [RFC 5652 § 5.3](https://datatracker.ietf.org/doc/html/rfc5652#section-5.3)
///
/// ```text
/// SignerInfo ::= SEQUENCE {
///     version CMSVersion,
///     sid SignerIdentifier,
///     digestAlgorithm DigestAlgorithmIdentifier,
///     signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
///     signatureAlgorithm SignatureAlgorithmIdentifier,
///     signature SignatureValue,
///     unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SignerInfo<'a> {
    /// the syntax version number.
    pub version: CmsVersion,

    /// the signer identifier
    pub sid: SignerIdentifier<'a>,

    /// the message digest algorithm
    pub digest_algorithm: DigestAlgorithmIdentifier<'a>,

    /// the signed attributes
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub signed_attributes: Option<SignedAttributes<'a>>,

    /// the signature algorithm
    pub signature_algorithm: SignatureAlgorithmIdentifier<'a>,

    /// the signature for content or detached
    pub signature: OctetStringRef<'a>,

    /// the unsigned attributes
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub unsigned_attributes: Option<UnsignedAttributes<'a>>,

}

impl<'a> SignerInfo<'a> {
    pub fn get_signature(&self) -> &[u8] {
        self.signature.as_bytes()
    }
}

// TODO: figure out what ordering makes sense - if any
impl ValueOrd for SignerInfo<'_>  {
    fn value_cmp(&self, _other: &Self) -> der::Result<Ordering> {
        Ok(Ordering::Equal)
    }
}