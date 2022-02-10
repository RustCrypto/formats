//! PKIX X.509 Certificate Extensions (RFC 5280)

pub mod name;
pub mod oids;

mod authkeyid;
mod keyusage;

pub use authkeyid::AuthorityKeyIdentifier;
pub use keyusage::{KeyUsage, KeyUsages};

use der::asn1::OctetString;

/// SubjectKeyIdentifier as defined in [RFC 5280 Section 4.2.1.2].
///
/// This extension is identified by the [`PKIX_CE_SUBJECT_KEY_IDENTIFIER`](constant.PKIX_CE_SUBJECT_KEY_IDENTIFIER.html) OID.
///
/// ```text
/// SubjectKeyIdentifier ::= KeyIdentifier
/// ```
///
/// [RFC 5280 Section 4.2.1.2]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
pub type SubjectKeyIdentifier<'a> = OctetString<'a>;
