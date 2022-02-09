use super::name::GeneralNames;

use const_oid::Typed;
use der::asn1::{ObjectIdentifier, UIntBytes};
use der::Sequence;

/// Authority key identifier extension as defined in [RFC 5280 Section 4.2.1.1].
///
/// ```text
/// AuthorityKeyIdentifier ::= SEQUENCE {
///     keyIdentifier             [0] KeyIdentifier           OPTIONAL,
///     authorityCertIssuer       [1] GeneralNames            OPTIONAL,
///     authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL
/// }
///
/// KeyIdentifier ::= OCTET STRING
/// ```
///
/// [RFC 5280 Section 4.2.1.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct AuthorityKeyIdentifier<'a> {
    /// keyIdentifier
    #[asn1(
        context_specific = "0",
        optional = "true",
        tag_mode = "IMPLICIT",
        type = "OCTET STRING"
    )]
    pub key_identifier: Option<&'a [u8]>,

    /// authorityCertIssuer
    #[asn1(context_specific = "1", optional = "true", tag_mode = "IMPLICIT")]
    pub authority_cert_issuer: Option<GeneralNames<'a>>,

    /// authorityCertSerialNumber
    #[asn1(context_specific = "2", optional = "true", tag_mode = "IMPLICIT")]
    pub authority_cert_serial_number: Option<UIntBytes<'a>>,
}

impl Typed for AuthorityKeyIdentifier<'_> {
    const OID: ObjectIdentifier = ObjectIdentifier::new("2.5.29.35");
}
