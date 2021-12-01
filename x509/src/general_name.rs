/// GeneralNames as defined in [RFC 5280 Section 4.2.1.6].
use crate::Name;
use der::asn1::{
    Any, ContextSpecific, Ia5String, ObjectIdentifier, OctetString,
};
use der::{
    Decodable, DecodeValue, Decoder, Length, Sequence, TagMode, TagNumber,
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
//TODO - restore
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

    // x400Address                     [3]     ORAddress,
    // Not supporting x400Address

    /// directoryName                   [4]     Name,
    DirectoryName(Name<'a>),

    // ediPartyName                    [5]     EDIPartyName,
    // Not supporting ediPartyName

    /// uniformResourceIdentifier       [6]     IA5String,
    UniformResourceIdentifier(Ia5String<'a>),

    /// iPAddress                       [7]     OCTET STRING,
    IpAddress(OctetString<'a>),

    // registeredID                    [8]     OBJECT IDENTIFIER
    // Not supporting registeredID
}

const OTHER_NAME_TAG: TagNumber = TagNumber::new(0);
const RFC822_NAME_TAG: TagNumber = TagNumber::new(1);
const DNS_NAME_TAG: TagNumber = TagNumber::new(2);
//const X400_ADDRESS_TAG: TagNumber = TagNumber::new(3);
const DIRECTORY_NAME_TAG: TagNumber = TagNumber::new(4);
//const EDIPI_PARTY_NAME_TAG: TagNumber = TagNumber::new(5);
const URI_TAG: TagNumber = TagNumber::new(6);
const IP_ADDRESS_TAG: TagNumber = TagNumber::new(7);
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
                // Explicit is used because Name is also a CHOICE. Nested CHOICEs are essentially
                // EXPLICIT tags. See section 31.2.7 in X.680.
                let ia5 =
                    decoder.context_specific::<Name<'_>>(DIRECTORY_NAME_TAG, TagMode::Explicit)?;
                Ok(GeneralName::DirectoryName(ia5.unwrap()))
            }
            0xA5 => unimplemented!(),
            0x86 => {
                let ia5 = decoder.context_specific::<Ia5String<'_>>(URI_TAG, TagMode::Implicit)?;
                Ok(GeneralName::UniformResourceIdentifier(ia5.unwrap()))
            }
            0x87 => {
                let os = decoder.context_specific::<OctetString<'_>>(URI_TAG, TagMode::Implicit)?;
                Ok(GeneralName::IpAddress(os.unwrap()))
            },
            _ => unimplemented!(),
        }
    }
}

impl<'a> ::der::Encodable for GeneralName<'a> {
    fn encode(&self, encoder: &mut ::der::Encoder<'_>) -> ::der::Result<()> {
        match self {
            Self::OtherName(variant) => {
                ContextSpecific {
                    tag_number: OTHER_NAME_TAG,
                    tag_mode: TagMode::Implicit,
                    value:variant.clone()
                }.encode(encoder)
            },
            Self::Rfc822Name(variant) => {
                ContextSpecific {
                    tag_number: RFC822_NAME_TAG,
                    tag_mode: TagMode::Implicit,
                    value: ::der::asn1::Ia5String::new(variant)?
                }.encode(encoder)
            },
            Self::DnsName(variant) => {
                ContextSpecific {
                    tag_number: DNS_NAME_TAG,
                    tag_mode: TagMode::Implicit,
                    value: ::der::asn1::Ia5String::new(variant)?
                }.encode(encoder)
            },
            // Explicit is used because Name is also a CHOICE. Nested CHOICEs are essentially
            // EXPLICIT tags. See section 31.2.7 in X.680.
            Self::DirectoryName(variant) => {
                ContextSpecific {
                    tag_number: DIRECTORY_NAME_TAG,
                    tag_mode: TagMode::Explicit,
                    value: variant.clone()
                }.encode(encoder)
            },
            Self::UniformResourceIdentifier(variant) => {
                ContextSpecific {
                    tag_number: URI_TAG,
                    tag_mode: TagMode::Implicit,
                    value: ::der::asn1::Ia5String::new(variant)?
                }.encode(encoder)
            },
            Self::IpAddress(variant) => {
                ContextSpecific {
                    tag_number: IP_ADDRESS_TAG,
                    tag_mode: TagMode::Implicit,
                    value: ::der::asn1::OctetString::new(variant.as_bytes())?
                }.encode(encoder)},
        }
    }
    fn encoded_len(&self) -> ::der::Result<::der::Length> {
        match self {
            Self::OtherName(variant) => { ContextSpecific {
                tag_number: OTHER_NAME_TAG,
                tag_mode: TagMode::Implicit,
                value:variant.clone()
            }.encoded_len()},
            Self::Rfc822Name(variant) => {ContextSpecific {
                tag_number: RFC822_NAME_TAG,
                tag_mode: TagMode::Implicit,
                value: ::der::asn1::Ia5String::new(variant)?
            }.encoded_len()},
            Self::DnsName(variant) => {ContextSpecific {
                tag_number: DNS_NAME_TAG,
                tag_mode: TagMode::Implicit,
                value: ::der::asn1::Ia5String::new(variant)?
            }.encoded_len()},
            // Explicit is used because Name is also a CHOICE. Nested CHOICEs are essentially
            // EXPLICIT tags. See section 31.2.7 in X.680.
            Self::DirectoryName(variant) => { ContextSpecific {
                tag_number: DIRECTORY_NAME_TAG,
                tag_mode: TagMode::Explicit,
                value: variant.clone()
            }.encoded_len()},
            Self::UniformResourceIdentifier(variant) => {ContextSpecific {
                tag_number: URI_TAG,
                tag_mode: TagMode::Implicit,
                value: ::der::asn1::Ia5String::new(variant)?
            }.encoded_len()},
            Self::IpAddress(variant) => {variant.encoded_len()},
        }
    }
}
impl<'a> ::der::Tagged for GeneralName<'a> {
    fn tag(&self) -> ::der::Tag {
        match self {
            Self::OtherName(_) => ::der::Tag::Sequence,
            Self::Rfc822Name(_) => ::der::Tag::Ia5String,
            Self::DnsName(_) => ::der::Tag::Ia5String,
            Self::DirectoryName(_) => ::der::Tag::Sequence,
            Self::UniformResourceIdentifier(_) => ::der::Tag::Ia5String,
            Self::IpAddress(_) => ::der::Tag::OctetString,
        }
    }
}

#[test]
fn reencode_cert() {
    use hex_literal::hex;
    use der::Encodable;
    use crate::AttributeTypeAndValue;
    use crate::RelativeDistinguishedName;

    // RFC822Name
    let der_encoded_gn =
        GeneralName::from_der(&hex!(
        "8117456D61696C5F353238343037373733406468732E676F76"
    )).unwrap();
    let reencoded_gn = der_encoded_gn.to_vec().unwrap();
    assert_eq!(&hex!("8117456D61696C5F353238343037373733406468732E676F76"), reencoded_gn.as_slice());

    let der_encoded_gns =
        GeneralNames::from_der(&hex!(
        "30198117456D61696C5F353238343037373733406468732E676F76"
    )).unwrap();
    let reencoded_gns = der_encoded_gns.to_vec().unwrap();
    assert_eq!(&hex!("30198117456D61696C5F353238343037373733406468732E676F76"), reencoded_gns.as_slice());

    // DNSName
    let der_encoded_gn =
        GeneralName::from_der(&hex!(
        "8217456D61696C5F353238343037373733406468732E676F76"
    )).unwrap();
    let reencoded_gn = der_encoded_gn.to_vec().unwrap();
    assert_eq!(&hex!("8217456D61696C5F353238343037373733406468732E676F76"), reencoded_gn.as_slice());

    let der_encoded_gns =
        GeneralNames::from_der(&hex!(
        "30198217456D61696C5F353238343037373733406468732E676F76"
    )).unwrap();
    let reencoded_gns = der_encoded_gns.to_vec().unwrap();
    assert_eq!(&hex!("30198217456D61696C5F353238343037373733406468732E676F76"), reencoded_gns.as_slice());

    // DNSName
    let der_encoded_gn =
        GeneralName::from_der(&hex!(
        "8617456D61696C5F353238343037373733406468732E676F76"
    )).unwrap();
    let reencoded_gn = der_encoded_gn.to_vec().unwrap();
    assert_eq!(&hex!("8617456D61696C5F353238343037373733406468732E676F76"), reencoded_gn.as_slice());

    let der_encoded_gns =
        GeneralNames::from_der(&hex!(
        "30198617456D61696C5F353238343037373733406468732E676F76"
    )).unwrap();
    let reencoded_gns = der_encoded_gns.to_vec().unwrap();
    assert_eq!(&hex!("30198617456D61696C5F353238343037373733406468732E676F76"), reencoded_gns.as_slice());

    // ATAV
    let der_encoded_atav =
        AttributeTypeAndValue::from_der(&hex!(
        "30110603550403130A5447562D452D31323930"
    )).unwrap();
    let reencoded_atav = der_encoded_atav.to_vec().unwrap();
    assert_eq!(&hex!("30110603550403130A5447562D452D31323930"), reencoded_atav.as_slice());

    // RDN
    let der_encoded_rdn =
        RelativeDistinguishedName::from_der(&hex!(
        "311330110603550403130A5447562D452D31323930"
    )).unwrap();
    let reencoded_rdn = der_encoded_rdn.to_vec().unwrap();
    assert_eq!(&hex!("311330110603550403130A5447562D452D31323930"), reencoded_rdn.as_slice());

    // Name
    let der_encoded_gn =
        GeneralName::from_der(&hex!(
        "A4173015311330110603550403130A5447562D452D31323930"
    )).unwrap();
    let reencoded_gn = der_encoded_gn.to_vec().unwrap();
    assert_eq!(&hex!("A4173015311330110603550403130A5447562D452D31323930"), reencoded_gn.as_slice());

    let der_encoded_gns =
        GeneralNames::from_der(&hex!(
        "3019A4173015311330110603550403130A5447562D452D31323930"
    )).unwrap();
    let reencoded_gns = der_encoded_gns.to_vec().unwrap();
    assert_eq!(&hex!("3019A4173015311330110603550403130A5447562D452D31323930"), reencoded_gns.as_slice());
}