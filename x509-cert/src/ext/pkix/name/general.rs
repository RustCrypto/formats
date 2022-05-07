//! GeneralNames as defined in [RFC 5280 Section 4.2.1.6].

use super::{EdiPartyName, OtherName};
use crate::name::Name;

use der::asn1::{Ia5StringRef, ObjectIdentifier, OctetStringRef};
use der::Choice;

/// GeneralNames as defined in [RFC 5280 Section 4.2.1.6].
///
/// ```text
/// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
/// ```
///
/// [RFC 5280 Section 4.2.1.6]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
pub type GeneralNames<'a> = alloc::vec::Vec<GeneralName<'a>>;

/// GeneralName as defined in [RFC 5280 Section 4.2.1.6].
///
/// ```text
/// GeneralName ::= CHOICE {
///     otherName                       [0]     OtherName,
///     rfc822Name                      [1]     IA5String,
///     dNSName                         [2]     IA5String,
///     x400Address                     [3]     ORAddress,
///     directoryName                   [4]     Name,
///     ediPartyName                    [5]     EDIPartyName,
///     uniformResourceIdentifier       [6]     IA5String,
///     iPAddress                       [7]     OCTET STRING,
///     registeredID                    [8]     OBJECT IDENTIFIER
/// }
/// ```
///
/// This implementation does not currently support the `x400Address` choice.
///
/// [RFC 5280 Section 4.2.1.6]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(missing_docs)]
pub enum GeneralName<'a> {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", constructed = "true")]
    OtherName(OtherName<'a>),

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT")]
    Rfc822Name(Ia5StringRef<'a>),

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
    DnsName(Ia5StringRef<'a>),

    #[asn1(context_specific = "4", tag_mode = "EXPLICIT", constructed = "true")]
    DirectoryName(Name<'a>),

    #[asn1(context_specific = "5", tag_mode = "IMPLICIT", constructed = "true")]
    EdiPartyName(EdiPartyName<'a>),

    #[asn1(context_specific = "6", tag_mode = "IMPLICIT")]
    UniformResourceIdentifier(Ia5StringRef<'a>),

    #[asn1(context_specific = "7", tag_mode = "IMPLICIT")]
    IpAddress(OctetStringRef<'a>),

    #[asn1(context_specific = "8", tag_mode = "IMPLICIT")]
    RegisteredId(ObjectIdentifier),
}
