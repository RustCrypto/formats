//! SignedData-related types

use crate::cert::{CertificateChoices, IssuerAndSerialNumber};
use crate::content_info::CmsVersion;
use crate::revocation::RevocationInfoChoices;

use alloc::vec;
use core::cmp::Ordering;
use der::asn1::{ObjectIdentifier, OctetString, SetOfVec};
use der::{Any, Choice, DerOrd, Sequence, ValueOrd};
use spki::AlgorithmIdentifierOwned;
use x509_cert::{
    attr::Attributes,
    certificate::{CertificateInner, Profile, Rfc5280},
    ext::pkix::SubjectKeyIdentifier,
    impl_newtype,
};

/// The `SignedData` type is defined in [RFC 5652 Section 5.1].
///
/// ```text
///   SignedData ::= SEQUENCE {
///       version CMSVersion,
///       digestAlgorithms SET OF DigestAlgorithmIdentifier,
///       encapContentInfo EncapsulatedContentInfo,
///       certificates [0] IMPLICIT CertificateSet OPTIONAL,
///       crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
///       signerInfos SignerInfos }
/// ```
///
/// [RFC 5652 Section 5.1]: https://www.rfc-editor.org/rfc/rfc5652#section-5.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct SignedData<P: Profile = Rfc5280> {
    pub version: CmsVersion,
    pub digest_algorithms: DigestAlgorithmIdentifiers,
    pub encap_content_info: EncapsulatedContentInfo,
    //todo consider defer decoding certs and CRLs
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub certificates: Option<CertificateSet<P>>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub crls: Option<RevocationInfoChoices>,
    pub signer_infos: SignerInfos<P>,
}

/// The `DigestAlgorithmIdentifiers` type is defined in [RFC 5652 Section 5.1].
///
/// ```text
/// DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
/// ```
///
/// [RFC 5652 Section 5.1]: https://www.rfc-editor.org/info/rfc5652#section-5.1
pub type DigestAlgorithmIdentifiers = SetOfVec<AlgorithmIdentifierOwned>;

/// CertificateSet structure as defined in [RFC 5652 Section 10.2.3].
///
/// ```text
///   CertificateSet ::= SET OF CertificateChoices
/// ```
///
/// [RFC 5652 Section 10.2.3]: https://www.rfc-editor.org/info/rfc5652#section-10.2.3
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CertificateSet<P: Profile = Rfc5280>(pub SetOfVec<CertificateChoices<P>>);
impl_newtype!(CertificateSet<P>, SetOfVec<CertificateChoices<P>>, P: Profile);

impl<P: Profile> TryFrom<vec::Vec<CertificateChoices<P>>> for CertificateSet<P> {
    type Error = der::Error;

    fn try_from(vec: vec::Vec<CertificateChoices<P>>) -> der::Result<Self> {
        Ok(CertificateSet(SetOfVec::try_from(vec)?))
    }
}

/// The `SignerInfos` type is defined in [RFC 5652 Section 5.1].
///
/// ```text
///   SignerInfos ::= SET OF SignerInfo
/// ```
///
/// [RFC 5652 Section 5.1]: https://www.rfc-editor.org/rfc/rfc5652#section-5.1
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SignerInfos<P: Profile = Rfc5280>(pub SetOfVec<SignerInfo<P>>);
impl_newtype!(SignerInfos<P>, SetOfVec<SignerInfo<P>>, P: Profile);

impl<P: Profile> TryFrom<vec::Vec<SignerInfo<P>>> for SignerInfos<P> {
    type Error = der::Error;

    fn try_from(vec: vec::Vec<SignerInfo<P>>) -> der::Result<Self> {
        Ok(SignerInfos(SetOfVec::try_from(vec)?))
    }
}

/// The `EncapsulatedContentInfo` type is defined in [RFC 5652 Section 5.2].
///
/// ```text
///   EncapsulatedContentInfo ::= SEQUENCE {
///       eContentType       CONTENT-TYPE.&id({ContentSet}),
///       eContent           [0] EXPLICIT OCTET STRING
///               ( CONTAINING CONTENT-TYPE.
///                   &Type({ContentSet}{@eContentType})) OPTIONAL }
/// ```
///
/// [RFC 5652 Section 5.2]: https://www.rfc-editor.org/rfc/rfc5652#section-5.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct EncapsulatedContentInfo {
    pub econtent_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub econtent: Option<Any>,
}

/// The `SignerInfo` type is defined in [RFC 5652 Section 5.3].
///
/// ```text
///   SignerInfo ::= SEQUENCE {
///       version CMSVersion,
///       sid SignerIdentifier,
///       digestAlgorithm DigestAlgorithmIdentifier,
///       signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
///       signatureAlgorithm SignatureAlgorithmIdentifier,
///       signature SignatureValue,
///       unsignedAttrs [1] IMPLICIT Attributes
///           {{UnsignedAttributes}} OPTIONAL }
/// ```
///
/// [RFC 5652 Section 5.3]: https://www.rfc-editor.org/rfc/rfc5652#section-5.3
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct SignerInfo<P: Profile = Rfc5280> {
    pub version: CmsVersion,
    pub sid: SignerIdentifier<P>,
    pub digest_alg: AlgorithmIdentifierOwned,
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub signed_attrs: Option<SignedAttributes>,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature: SignatureValue,
    #[asn1(
        context_specific = "1",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub unsigned_attrs: Option<UnsignedAttributes>,
}

/// The `SignerInfo` type is defined in [RFC 5652 Section 5.3].
///
/// ```text
/// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
/// ```
///
/// [RFC 5652 Section 5.3]: https://www.rfc-editor.org/info/rfc5652#section-5.3
pub type SignedAttributes = Attributes;

/// The `SignerIdentifier` type is defined in [RFC 5652 Section 5.3].
///
/// ```text
/// SignerIdentifier ::= CHOICE {
///   issuerAndSerialNumber IssuerAndSerialNumber,
///   subjectKeyIdentifier \[0\] SubjectKeyIdentifier }
/// ```
///
/// [RFC 5652 Section 5.3]: https://www.rfc-editor.org/info/rfc5652#section-5.3
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(missing_docs)]
pub enum SignerIdentifier<P: Profile = Rfc5280> {
    IssuerAndSerialNumber(IssuerAndSerialNumber<P>),

    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    SubjectKeyIdentifier(SubjectKeyIdentifier),
}

// TODO DEFER ValueOrd is not supported for CHOICE types (see new_enum in value_ord.rs)
impl<P: Profile> ValueOrd for SignerIdentifier<P> {
    fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
        use der::Encode;
        self.to_der()?.der_cmp(&other.to_der()?)
    }
}

impl<P: Profile> From<&CertificateInner<P>> for SignerIdentifier<P> {
    fn from(cert: &CertificateInner<P>) -> Self {
        let tbs = cert.tbs_certificate();

        match tbs.get_extension::<SubjectKeyIdentifier>() {
            Ok(Some((_critical, ski))) => Self::SubjectKeyIdentifier(ski),
            _ => {
                let isn = IssuerAndSerialNumber {
                    issuer: tbs.issuer().clone(),
                    serial_number: tbs.serial_number().clone(),
                };
                Self::IssuerAndSerialNumber(isn)
            }
        }
    }
}

/// The `UnsignedAttributes` type is defined in [RFC 5652 Section 5.3].
///
/// ```text
/// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
/// ```
///
/// [RFC 5652 Section 5.3]: https://www.rfc-editor.org/info/rfc5652#section-5.3
pub type UnsignedAttributes = Attributes;

/// The `SignatureValue` type is defined in [RFC 5652 Section 5.3].
///
/// ```text
///   SignatureValue ::= OCTET STRING
/// ```
///
/// [RFC 5652 Section 5.3]: https://www.rfc-editor.org/info/rfc5652#section-5.3
pub type SignatureValue = OctetString;
