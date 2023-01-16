//! General purpose message-related types

use x509_cert::attr::AttributeTypeAndValue;

/// The `InfoTypeAndValue` type is defined in [RFC 4210 Section 5.3.19]
///
/// ```text
///  InfoTypeAndValue ::= SEQUENCE {
///      infoType    INFO-TYPE-AND-VALUE.
///                      &id({SupportedInfoSet}),
///      infoValue   INFO-TYPE-AND-VALUE.
///                      &Type({SupportedInfoSet}{@infoType}) }
/// ```
///
/// [RFC 4210 Section 5.3.19]: https://www.rfc-editor.org/rfc/rfc4210#section-5.3.19
pub type InfoTypeAndValue = AttributeTypeAndValue;

/// The `GenMsgContent` type is defined in [RFC 4210 Section 5.3.19]
///
/// ```text
///  GenMsgContent ::= SEQUENCE OF InfoTypeAndValue
/// ```
///
/// [RFC 4210 Section 5.3.19]: https://www.rfc-editor.org/rfc/rfc4210#section-5.3.19
pub type GenMsgContent = alloc::vec::Vec<InfoTypeAndValue>;

/// The `GenRepContent` type is defined in [RFC 4210 Section 5.3.20]
///
/// ```text
///  GenRepContent ::= SEQUENCE OF InfoTypeAndValue
/// ```
///
/// [RFC 4210 Section 5.3.20]: https://www.rfc-editor.org/rfc/rfc4210#section-5.3.20
pub type GenRepContent = alloc::vec::Vec<InfoTypeAndValue>;
