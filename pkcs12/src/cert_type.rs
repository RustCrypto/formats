//! CertBag-related types

use der::Sequence;
use der::asn1::{ObjectIdentifier, OctetString};

/// The `CertBag` type is defined in [RFC 7292 Section 4.2.3].
///
///```text
/// CertBag ::= SEQUENCE {
///     certId      BAG-TYPE.&id   ({CertTypes}),
///     certValue   [0] EXPLICIT BAG-TYPE.&Type ({CertTypes}{@certId})
/// }
///```
///
/// [RFC 7292 Section 4.2.3]: https://www.rfc-editor.org/rfc/rfc7292#section-4.2.3
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct CertBag {
    pub cert_id: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub cert_value: CertTypes,
}

// todo defer: add sdsiCertificate support
/// The `CertTypes` type is defined in [RFC 7292 Section 4.2.3].
///
///```text
///    x509Certificate BAG-TYPE ::=
///        {OCTET STRING IDENTIFIED BY {certTypes 1}}
///        -- DER-encoded X.509 certificate stored in OCTET STRING
///    sdsiCertificate BAG-TYPE ::=
///        {IA5String IDENTIFIED BY {certTypes 2}}
///        -- Base64-encoded SDSI certificate stored in IA5String
///
///    CertTypes BAG-TYPE ::= {
///        x509Certificate |
///        sdsiCertificate,
///        ... -- For future extensions
///    }
///```
///
/// [RFC 7292 Section 4.2.3]: https://www.rfc-editor.org/rfc/rfc7292#section-4.2.3
pub type CertTypes = OctetString;
