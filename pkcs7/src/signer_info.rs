//! `encrypted-data` content type [RFC 5652 § 8](https://datatracker.ietf.org/doc/html/rfc5652#section-8)

use core::cmp::Ordering;

use crate::{cms_version::CMSVersion};
use der::{Sequence, Choice, asn1::{OctetStringRef, SetOfVec}, ValueOrd,
};
use spki::{AlgorithmIdentifierRef};
use x509_cert::{ext::pkix::{SubjectKeyIdentifier}, attr::{Attribute}, name::Name};

type DigestAlgorithmIdentifier<'a> = AlgorithmIdentifierRef<'a>;
type SignatureAlgorithmIdentifier<'a> = AlgorithmIdentifierRef<'a>;

type SignedAttributes<'a>  = SetOfVec<Attribute>;
type UnsignedAttributes<'a>  = SetOfVec<Attribute>;

/// ```text
/// SignerIdentifier ::= CHOICE {
//    issuerAndSerialNumber IssuerAndSerialNumber,
//    subjectKeyIdentifier [0] SubjectKeyIdentifier }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Choice)]
pub enum SignerIdentifier<'a> {
    IssuerAndSerialNumber(IssuerAndSerialNumber),

    #[asn1(context_specific = "0")]
    SubjectKeyIdentifier(SubjectKeyIdentifier<'a>),
}


#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct IssuerAndSerialNumber {
    pub name: Name,
    pub serial_number: u8,
}




/// ```text
/// SignerInfos ::= SET OF SignerInfo
/// ```
pub type SignerInfos<'a> = SetOfVec<SignerInfo<'a>>;


/// Encrypted-data content type [RFC 5652 § 8](https://datatracker.ietf.org/doc/html/rfc5652#section-8)
///
/// ```text
/// EncryptedData ::= SEQUENCE {
///   version Version,
///   encryptedContentInfo EncryptedContentInfo }
/// ```
///
/// The encrypted-data content type consists of encrypted content of any
/// type. Unlike the enveloped-data content type, the encrypted-data
/// content type has neither recipients nor encrypted content-encryption
/// keys. Keys are assumed to be managed by other means.
///
/// The fields of type EncryptedData have the following meanings:
///   - [`version`](EncryptedDataContent::version) is the syntax version number.
///   - [`encrypted_content_info`](EncryptedDataContent::encrypted_content_info) is the encrypted content
///     information, as in [EncryptedContentInfo].
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SignerInfo<'a> {
    /// the syntax version number.
    pub version: CMSVersion,

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