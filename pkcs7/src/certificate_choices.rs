//! `CertificateChoices` [RFC 5652 10.2.2](https://datatracker.ietf.org/doc/html/rfc5652#section-10.2.2)

use core::cmp::Ordering;

use der::{Choice, asn1::{BitStringRef}, ValueOrd, Sequence, AnyRef,
};
use spki::ObjectIdentifier;
use x509_cert::{Certificate};

// TODO (smndtrl): Should come from x509 - for now I haven't found a test case in real world
pub type AttributeCertificateV1<'a> = BitStringRef<'a>;
pub type AttributeCertificateV2<'a> = BitStringRef<'a>;
pub type ExtendedCertificate<'a> = BitStringRef<'a>;


/// ```text
/// OtherCertificateFormat ::= SEQUENCE {
///     otherCertFormat OBJECT IDENTIFIER,
///     otherCert ANY DEFINED BY otherCertFormat }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct OtherCertificateFormat<'a> {
    other_cert_format: ObjectIdentifier,
    other_cert: AnyRef<'a>
}

/// ```text
/// CertificateChoices ::= CHOICE {
///     certificate Certificate,
///     extendedCertificate [0] IMPLICIT ExtendedCertificate,  -- Obsolete
///     v1AttrCert [1] IMPLICIT AttributeCertificateV1,        -- Obsolete
///     v2AttrCert [2] IMPLICIT AttributeCertificateV2,
///     other [3] IMPLICIT OtherCertificateFormat }
/// 
/// OtherCertificateFormat ::= SEQUENCE {
///     otherCertFormat OBJECT IDENTIFIER,
///     otherCert ANY DEFINED BY otherCertFormat }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Choice)]
#[allow(clippy::large_enum_variant)]
pub enum CertificateChoices<'a> {
    Certificate(Certificate<'a>),

    #[deprecated]
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    ExtendedCertificate(ExtendedCertificate<'a>),

    #[deprecated]
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT")]
    V1AttrCert(AttributeCertificateV1<'a>),
    
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
    V2AttrCert(AttributeCertificateV2<'a>),

    #[asn1(context_specific = "3", tag_mode = "IMPLICIT")]
    Other(OtherCertificateFormat<'a>),
}

// TODO: figure out what ordering makes sense - if any
impl ValueOrd for CertificateChoices<'_>  {
    fn value_cmp(&self, _other: &Self) -> der::Result<Ordering> {
        Ok(Ordering::Equal)
    }
}