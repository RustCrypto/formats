//! Extensions [`Extensions`] as defined in RFC 5280

use der::asn1::{ObjectIdentifier, OctetString, SequenceOf};
use der::Sequence;

///    Extension  ::=  SEQUENCE  {
///         extnID      OBJECT IDENTIFIER,
///         critical    BOOLEAN DEFAULT FALSE,
///         extnValue   OCTET STRING
///                     -- contains the DER encoding of an ASN.1 value
///                     -- corresponding to the extension type identified
///                     -- by extnID
///         }
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Extension<'a> {
    /// extnID      OBJECT IDENTIFIER,
    pub extn_id: ObjectIdentifier,

    /// critical    BOOLEAN DEFAULT FALSE,
    pub critical: Option<bool>,

    /// extnValue   OCTET STRING
    pub extn_value: OctetString<'a>,
}

///    Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
pub type Extensions<'a> = SequenceOf<Extension<'a>, 10>;
