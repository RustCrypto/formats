//! CertBag-related types

use der::Sequence;
use der::asn1::{ObjectIdentifier, OctetString};

/// The `CertBag` type is defined in [RFC 7292 Section 4.2.4].
///
///```text
///     CRLBag ::= SEQUENCE {
///      crlId     BAG-TYPE.&id ({CRLTypes}),
///      crltValue [0] EXPLICIT BAG-TYPE.&Type ({CRLTypes}{@crlId})
///  }
///```
///
/// [RFC 7292 Section 4.2.4]: https://www.rfc-editor.org/rfc/rfc7292#section-4.2.4
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct CrlBag {
    pub crl_id: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub crl_value: CrlTypes,
}

// todo defer: add support for other CRL types
/// The `CRLTypes` type is defined in [RFC 7292 Section 4.2.4].
///
///```text
///  x509CRL BAG-TYPE ::=
///      {OCTET STRING IDENTIFIED BY {crlTypes 1}}
///      -- DER-encoded X.509 CRL stored in OCTET STRING
///
///  CRLTypes BAG-TYPE ::= {
///      x509CRL,
///      ... -- For future extensions
///  }
///```
///
/// [RFC 7292 Section 4.2.4]: https://www.rfc-editor.org/rfc/rfc7292#section-4.2.4
pub type CrlTypes = OctetString;
