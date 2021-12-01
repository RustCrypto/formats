/// GeneralNames as defined in [RFC 5280 Section 4.2.1.6].

use crate::certificate::default_false;
use crate::AttributeTypeAndValue;
use crate::Name;
use crate::RelativeDistinguishedName;
use alloc::prelude::v1::Box;
use der::asn1::{
    Any, BitString, GeneralizedTime, Ia5String, Null, ObjectIdentifier, OctetString, SequenceOf,
    UIntBytes, Utf8String,
};
use der::{
    Choice, Decodable, DecodeValue, Decoder, Enumerated, Length, Sequence, TagMode, TagNumber,
};

/// OtherName as defined in [RFC 5280 Section 4.2.1.6] in support of the Subject Alternative Name extension.
///
/// ```text
///    OtherName ::= SEQUENCE {
///         type-id    OBJECT IDENTIFIER,
///         value      [0] EXPLICIT ANY DEFINED BY type-id }
/// ```
///
/// [RFC 5280 Section 4.2.1.6]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtherName<'a> {
    /// type-id    OBJECT IDENTIFIER,
    pub type_id: ObjectIdentifier,

    /// value      [0] EXPLICIT ANY DEFINED BY type-id }
    pub value: Any<'a>,
}

impl<'a> DecodeValue<'a> for OtherName<'a> {
    fn decode_value(decoder: &mut Decoder<'a>, _length: Length) -> der::Result<Self> {
        let type_id = decoder.decode()?;
        let value = decoder.decode()?;
        Ok(Self { type_id, value })
    }
}

impl<'a> Sequence<'a> for OtherName<'a> {
    fn fields<F, T>(&self, f: F) -> ::der::Result<T>
        where
            F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
    {
        f(&[&self.type_id, &self.value])
    }
}

/// GeneralNames as defined in [RFC 5280 Section 4.2.1.6] in support of the Subject Alternative Name extension.
///
/// ```text
/// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
/// ```
///
/// [RFC 5280 Section 4.2.1.6]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
pub type GeneralNames<'a> = alloc::vec::Vec<GeneralName<'a>>;

/// GeneralName as defined in [RFC 5280 Section 4.2.1.6] in support of the Subject Alternative Name extension.
///
/// ```text
///    GeneralName ::= CHOICE {
///         otherName                       [0]     OtherName,
///         rfc822Name                      [1]     IA5String,
///         dNSName                         [2]     IA5String,
///         x400Address                     [3]     ORAddress,
///         directoryName                   [4]     Name,
///         ediPartyName                    [5]     EDIPartyName,
///         uniformResourceIdentifier       [6]     IA5String,
///         iPAddress                       [7]     OCTET STRING,
///         registeredID                    [8]     OBJECT IDENTIFIER }
/// ```
///
/// [RFC 5280 Section 4.2.1.6]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GeneralName<'a> {
    /// otherName                       [0]     OtherName,
    OtherName(OtherName<'a>),

    /// rfc822Name                      [1]     IA5String,
    Rfc822Name(Ia5String<'a>),

    /// dNSName                         [2]     IA5String,
    DnsName(Ia5String<'a>),

    /// x400Address                     [3]     ORAddress,
    /// Not supporting x400Address

    /// directoryName                   [4]     Name,
    DirectoryName(Name<'a>),

    /// ediPartyName                    [5]     EDIPartyName,
    /// Not supporting ediPartyName

    /// uniformResourceIdentifier       [6]     IA5String,
    UniformResourceIdentifier(Ia5String<'a>),

    /// iPAddress                       [7]     OCTET STRING,
    IpAddress(OctetString<'a>),

    /// registeredID                    [8]     OBJECT IDENTIFIER
    RegisteredId(ObjectIdentifier),
}

const OTHER_NAME_TAG: TagNumber = TagNumber::new(0);
const RFC822_NAME_TAG: TagNumber = TagNumber::new(1);
const DNS_NAME_TAG: TagNumber = TagNumber::new(2);
const DIRECTORY_NAME_TAG: TagNumber = TagNumber::new(4);
const URI_TAG: TagNumber = TagNumber::new(6);
//TODO - implement these
//const IP_ADDRESS_TAG: TagNumber = TagNumber::new(7);
//const REGISTERED_ID_TAG: TagNumber = TagNumber::new(8);

// Custom Decodable to handle implicit context specific fields (this may move to derived later).
impl<'a> Decodable<'a> for GeneralName<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        let t = decoder.peek_tag()?;
        match t.octet() {
            0xA0 => {
                let on =
                    decoder.context_specific::<OtherName<'_>>(OTHER_NAME_TAG, TagMode::Implicit)?;
                Ok(GeneralName::OtherName(on.unwrap()))
            }
            0x81 => {
                let ia5 = decoder
                    .context_specific::<Ia5String<'_>>(RFC822_NAME_TAG, TagMode::Implicit)?;
                Ok(GeneralName::Rfc822Name(ia5.unwrap()))
            }
            0x82 => {
                let ia5 =
                    decoder.context_specific::<Ia5String<'_>>(DNS_NAME_TAG, TagMode::Implicit)?;
                Ok(GeneralName::DnsName(ia5.unwrap()))
            }
            0xA3 => unimplemented!(),
            0xA4 => {
                let ia5 =
                    decoder.context_specific::<Name<'_>>(DIRECTORY_NAME_TAG, TagMode::Explicit)?;
                Ok(GeneralName::DirectoryName(ia5.unwrap()))
            }
            0xA5 => unimplemented!(),
            0x86 => {
                let ia5 = decoder.context_specific::<Ia5String<'_>>(URI_TAG, TagMode::Implicit)?;
                Ok(GeneralName::UniformResourceIdentifier(ia5.unwrap()))
            }
            0x87 => unimplemented!(),
            0x88 => unimplemented!(),
            _ => unimplemented!(),
        }
    }
}

// This stub is required to satisfy use of this type in context-specific fields, i.e., in the
// definition of AuthorityKeyIdentifier
impl<'a> ::der::Sequence<'a> for GeneralName<'a> {
    fn fields<F, T>(&self, _f: F) -> ::der::Result<T>
        where
            F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
    {
        unimplemented!()
    }
}