use der::{asn1::OctetString, Sequence, ValueOrd};

use crate::cert_type::CertType;

/// ```text
/// CertBag ::= SEQUENCE {
///     certId      BAG-TYPE.&id   ({CertTypes}),
///     certValue   [0] EXPLICIT BAG-TYPE.&Type ({CertTypes}{@certId})
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct CertBagContent {
    /// the cert id
    pub id: CertType,

    /// the cert value
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub bytes: Option<OctetString>,
}
