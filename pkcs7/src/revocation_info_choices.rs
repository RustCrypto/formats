//! `RevocationInfoChoices` [RFC 5652 10.2.1](https://datatracker.ietf.org/doc/html/rfc5652#section-10.2.1)

use core::cmp::Ordering;

use der::{Choice,  Sequence,  asn1::{SetOfVec}, ValueOrd, AnyRef,
};
use spki::{ObjectIdentifier};
use x509_cert::{crl::CertificateList};

/// ```text
/// RevocationInfoChoices ::= SET OF RevocationInfoChoice
/// RevocationInfoChoice ::= CHOICE {
///   crl CertificateList,
///   other [1] IMPLICIT OtherRevocationInfoFormat }
/// OtherRevocationInfoFormat ::= SEQUENCE {
///   otherRevInfoFormat OBJECT IDENTIFIER,
///   otherRevInfo ANY DEFINED BY otherRevInfoFormat }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Choice)]
pub enum RevocationInfoChoice<'a> {
    Crl(CertificateList<'a>),

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    Other(OtherRevocationInfoFormat<'a>),
}

/// ```text
/// RevocationInfoChoices ::= SET OF RevocationInfoChoice
/// ```
pub type RevocationInfoChoices<'a> = SetOfVec<RevocationInfoChoice<'a>>;

/// ```text
/// OtherRevocationInfoFormat ::= SEQUENCE {
///   otherRevInfoFormat OBJECT IDENTIFIER,
///   otherRevInfo ANY DEFINED BY otherRevInfoFormat }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct OtherRevocationInfoFormat<'a> {
    other_rev_info_format: ObjectIdentifier,
    other_rev_info: AnyRef<'a>
}

// TODO: figure out what ordering makes sense - if any
impl ValueOrd for RevocationInfoChoice<'_>  {
    fn value_cmp(&self, _other: &Self) -> der::Result<Ordering> {
        Ok(Ordering::Equal)
    }
}