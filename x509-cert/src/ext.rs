//! Standardized X.509 Certificate Extensions

use der::{asn1::OctetString, Sequence, ValueOrd};
use spki::ObjectIdentifier;

pub mod pkix;

/// Extension as defined in [RFC 5280 Section 4.1.2.9].
///
/// The ASN.1 definition for Extension objects is below. The extnValue type
/// may be further parsed using a decoder corresponding to the extnID value.
///
/// ```text
/// Extension  ::=  SEQUENCE  {
///     extnID      OBJECT IDENTIFIER,
///     critical    BOOLEAN DEFAULT FALSE,
///     extnValue   OCTET STRING
///                 -- contains the DER encoding of an ASN.1 value
///                 -- corresponding to the extension type identified
///                 -- by extnID
/// }
/// ```
///
/// [RFC 5280 Section 4.1.2.9]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.9
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct Extension {
    pub extn_id: ObjectIdentifier,

    #[asn1(default = "Default::default")]
    pub critical: bool,

    pub extn_value: OctetString,
}

/// Extensions as defined in [RFC 5280 Section 4.1.2.9].
///
/// ```text
/// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
/// ```
///
/// [RFC 5280 Section 4.1.2.9]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.9
pub type Extensions = alloc::vec::Vec<Extension>;
