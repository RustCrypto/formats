use super::name::GeneralNames;

use const_oid::db::rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER;
use const_oid::{AssociatedOid, ObjectIdentifier};
use der::asn1::{OctetString, UInt};
use der::Sequence;

/// AuthorityKeyIdentifier as defined in [RFC 5280 Section 4.2.1.1].
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
#[allow(missing_docs)]
pub struct AuthorityKeyIdentifier {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub key_identifier: Option<OctetString>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub authority_cert_issuer: Option<GeneralNames>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub authority_cert_serial_number: Option<UInt>,
}

impl AssociatedOid for AuthorityKeyIdentifier {
    const OID: ObjectIdentifier = ID_CE_AUTHORITY_KEY_IDENTIFIER;
}
