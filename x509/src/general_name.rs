//! GeneralNames as defined in [RFC 5280 Section 4.2.1.6].

use alloc::string::ToString;
use alloc::vec::Vec;
use der::asn1::{Any, ContextSpecific, Ia5String, ObjectIdentifier, OctetString};
use der::{Decodable, DecodeValue, Decoder, ErrorKind, Length, Sequence, TagMode, TagNumber};
use x501::name::Name;

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
pub type GeneralNames<'a> = Vec<GeneralName<'a>>;

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

    /// registeredID                    [8]     OBJECT IDENTIFIER
    RegisteredId(ObjectIdentifier),
}

const OTHER_NAME_TAG: TagNumber = TagNumber::new(0);
const RFC822_NAME_TAG: TagNumber = TagNumber::new(1);
const DNS_NAME_TAG: TagNumber = TagNumber::new(2);
//const X400_ADDRESS_TAG: TagNumber = TagNumber::new(3);
const DIRECTORY_NAME_TAG: TagNumber = TagNumber::new(4);
//const EDIPI_PARTY_NAME_TAG: TagNumber = TagNumber::new(5);
const URI_TAG: TagNumber = TagNumber::new(6);
const IP_ADDRESS_TAG: TagNumber = TagNumber::new(7);
const REGISTERED_ID_TAG: TagNumber = TagNumber::new(8);

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
            //0xA3 => Not supporting x400Address,
            0xA4 => {
                // Explicit is used because Name is also a CHOICE. Nested CHOICEs are essentially
                // EXPLICIT tags. See section 31.2.7 in X.680.
                let ia5 =
                    decoder.context_specific::<Name<'_>>(DIRECTORY_NAME_TAG, TagMode::Explicit)?;
                Ok(GeneralName::DirectoryName(ia5.unwrap()))
            }
            //0xA5 => Not supporting ediPartyName,
            0x86 => {
                let ia5 = decoder.context_specific::<Ia5String<'_>>(URI_TAG, TagMode::Implicit)?;
                Ok(GeneralName::UniformResourceIdentifier(ia5.unwrap()))
            }
            0x87 => {
                let os = decoder
                    .context_specific::<OctetString<'_>>(IP_ADDRESS_TAG, TagMode::Implicit)?;
                Ok(GeneralName::IpAddress(os.unwrap()))
            }
            0x88 => {
                let os = decoder
                    .context_specific::<ObjectIdentifier>(REGISTERED_ID_TAG, TagMode::Implicit)?;
                Ok(GeneralName::RegisteredId(os.unwrap()))
            }
            _ => Err(ErrorKind::TagUnknown { byte: t.octet() }.into()),
        }
    }
}

impl<'a> ::der::Encodable for GeneralName<'a> {
    fn encode(&self, encoder: &mut ::der::Encoder<'_>) -> ::der::Result<()> {
        match self {
            Self::OtherName(variant) => ContextSpecific {
                tag_number: OTHER_NAME_TAG,
                tag_mode: TagMode::Implicit,
                value: variant.clone(),
            }
            .encode(encoder),
            Self::Rfc822Name(variant) => ContextSpecific {
                tag_number: RFC822_NAME_TAG,
                tag_mode: TagMode::Implicit,
                value: ::der::asn1::Ia5String::new(variant)?,
            }
            .encode(encoder),
            Self::DnsName(variant) => ContextSpecific {
                tag_number: DNS_NAME_TAG,
                tag_mode: TagMode::Implicit,
                value: ::der::asn1::Ia5String::new(variant)?,
            }
            .encode(encoder),
            // Explicit is used because Name is also a CHOICE. Nested CHOICEs are essentially
            // EXPLICIT tags. See section 31.2.7 in X.680.
            Self::DirectoryName(variant) => ContextSpecific {
                tag_number: DIRECTORY_NAME_TAG,
                tag_mode: TagMode::Explicit,
                value: variant.clone(),
            }
            .encode(encoder),
            Self::UniformResourceIdentifier(variant) => ContextSpecific {
                tag_number: URI_TAG,
                tag_mode: TagMode::Implicit,
                value: ::der::asn1::Ia5String::new(variant)?,
            }
            .encode(encoder),
            Self::IpAddress(variant) => ContextSpecific {
                tag_number: IP_ADDRESS_TAG,
                tag_mode: TagMode::Implicit,
                value: ::der::asn1::OctetString::new(variant.as_bytes())?,
            }
            .encode(encoder),
            Self::RegisteredId(variant) => ContextSpecific {
                tag_number: REGISTERED_ID_TAG,
                tag_mode: TagMode::Implicit,
                value: ::der::asn1::ObjectIdentifier::new(variant.to_string().as_str()),
            }
            .encode(encoder),
        }
    }
    fn encoded_len(&self) -> ::der::Result<::der::Length> {
        // Could just do variant.encode for the implicitly tagged fields
        match self {
            Self::OtherName(variant) => ContextSpecific {
                tag_number: OTHER_NAME_TAG,
                tag_mode: TagMode::Implicit,
                value: variant.clone(),
            }
            .encoded_len(),
            Self::Rfc822Name(variant) => ContextSpecific {
                tag_number: RFC822_NAME_TAG,
                tag_mode: TagMode::Implicit,
                value: ::der::asn1::Ia5String::new(variant)?,
            }
            .encoded_len(),
            Self::DnsName(variant) => ContextSpecific {
                tag_number: DNS_NAME_TAG,
                tag_mode: TagMode::Implicit,
                value: ::der::asn1::Ia5String::new(variant)?,
            }
            .encoded_len(),
            // Explicit is used because Name is also a CHOICE. Nested CHOICEs are essentially
            // EXPLICIT tags. See section 31.2.7 in X.680.
            Self::DirectoryName(variant) => ContextSpecific {
                tag_number: DIRECTORY_NAME_TAG,
                tag_mode: TagMode::Explicit,
                value: variant.clone(),
            }
            .encoded_len(),
            Self::UniformResourceIdentifier(variant) => ContextSpecific {
                tag_number: URI_TAG,
                tag_mode: TagMode::Implicit,
                value: ::der::asn1::Ia5String::new(variant)?,
            }
            .encoded_len(),
            Self::IpAddress(variant) => ContextSpecific {
                tag_number: IP_ADDRESS_TAG,
                tag_mode: TagMode::Implicit,
                value: ::der::asn1::OctetString::new(variant.as_bytes())?,
            }
            .encoded_len(),
            Self::RegisteredId(variant) => ContextSpecific {
                tag_number: REGISTERED_ID_TAG,
                tag_mode: TagMode::Implicit,
                value: ::der::asn1::ObjectIdentifier::new(variant.to_string().as_str()),
            }
            .encoded_len(),
        }
    }
}

#[test]
fn reencode_gn() {
    use der::Encodable;
    use hex_literal::hex;

    // OtherName
    //   0  27: [0] {
    //   2   5:   OBJECT IDENTIFIER '2 16 862 2 2'
    //   9  18:   [0] {
    //  11  16:     UTF8String 'RIF-G-20004036-0'
    //        :     }
    //        :   }
    let decoded_other_name = GeneralName::from_der(&hex!(
        "A01B060560865E0202A0120C105249462D472D32303030343033362D30"
    ))
    .unwrap();
    let reencoded_other_name = decoded_other_name.to_vec().unwrap();
    assert_eq!(
        &hex!("A01B060560865E0202A0120C105249462D472D32303030343033362D30"),
        reencoded_other_name.as_slice()
    );

    let gns_other_name = GeneralNames::from_der(&hex!(
        "30198117456D61696C5F353238343037373733406468732E676F76"
    ))
    .unwrap();
    let reencoded_gns_other_name = gns_other_name.to_vec().unwrap();
    assert_eq!(
        &hex!("30198117456D61696C5F353238343037373733406468732E676F76"),
        reencoded_gns_other_name.as_slice()
    );

    // Rfc822Name
    //  0  23: [1] 'Email_528407773@dhs.gov'
    let decoded_rfc822_name =
        GeneralName::from_der(&hex!("8117456D61696C5F353238343037373733406468732E676F76")).unwrap();
    let reencoded_rfc822_name = decoded_rfc822_name.to_vec().unwrap();
    assert_eq!(
        &hex!("8117456D61696C5F353238343037373733406468732E676F76"),
        reencoded_rfc822_name.as_slice()
    );

    let gns_rfc822_name = GeneralNames::from_der(&hex!(
        "30198117456D61696C5F353238343037373733406468732E676F76"
    ))
    .unwrap();
    let reencoded_gns_rfc822_name = gns_rfc822_name.to_vec().unwrap();
    assert_eq!(
        &hex!("30198117456D61696C5F353238343037373733406468732E676F76"),
        reencoded_gns_rfc822_name.as_slice()
    );

    // DnsName
    //  0  34: [2] 'unternehmensnachfolge-in-bayern.de'
    let decoded_dns_name = GeneralName::from_der(&hex!(
        "8222756E7465726E65686D656E736E616368666F6C67652D696E2D62617965726E2E6465"
    ))
    .unwrap();
    let reencoded_dns_name = decoded_dns_name.to_vec().unwrap();
    assert_eq!(
        &hex!("8222756E7465726E65686D656E736E616368666F6C67652D696E2D62617965726E2E6465"),
        reencoded_dns_name.as_slice()
    );

    let gns_dns_name = GeneralNames::from_der(&hex!(
        "30248222756E7465726E65686D656E736E616368666F6C67652D696E2D62617965726E2E6465"
    ))
    .unwrap();
    let reencoded_gns_dns_name = gns_dns_name.to_vec().unwrap();
    assert_eq!(
        &hex!("30248222756E7465726E65686D656E736E616368666F6C67652D696E2D62617965726E2E6465"),
        reencoded_gns_dns_name.as_slice()
    );

    // DirectoryName
    //   0  59: [4] {
    //   2  57:   SEQUENCE {
    //   4  11:     SET {
    //   6   9:       SEQUENCE {
    //   8   3:         OBJECT IDENTIFIER countryName (2 5 4 6)
    //  13   2:         PrintableString 'DE'
    //        :         }
    //        :       }
    //  17  15:     SET {
    //  19  13:       SEQUENCE {
    //  21   3:         OBJECT IDENTIFIER stateOrProvinceName (2 5 4 8)
    //  26   6:         UTF8String 'Bayern'
    //        :         }
    //        :       }
    //  34  25:     SET {
    //  36  23:       SEQUENCE {
    //  38   3:         OBJECT IDENTIFIER organizationName (2 5 4 10)
    //  43  16:         UTF8String 'Freistaat Bayern'
    //        :         }
    //        :       }
    //        :     }
    //        :   }
    let decoded_dn =
        GeneralName::from_der(&hex!("A43B3039310B3009060355040613024445310F300D06035504080C0642617965726E31193017060355040A0C104672656973746161742042617965726E")).unwrap();
    let reencoded_dn = decoded_dn.to_vec().unwrap();
    assert_eq!(
        &hex!("A43B3039310B3009060355040613024445310F300D06035504080C0642617965726E31193017060355040A0C104672656973746161742042617965726E"),
        reencoded_dn.as_slice()
    );

    let gns_dn = GeneralNames::from_der(&hex!(
        "303DA43B3039310B3009060355040613024445310F300D06035504080C0642617965726E31193017060355040A0C104672656973746161742042617965726E"
    ))
        .unwrap();
    let reencoded_gns_dn = gns_dn.to_vec().unwrap();
    assert_eq!(
        &hex!("303DA43B3039310B3009060355040613024445310F300D06035504080C0642617965726E31193017060355040A0C104672656973746161742042617965726E"),
        reencoded_gns_dn.as_slice()
    );

    // UniformResourceIdentifier
    //  0  42: [6]
    //  :   'http://crl.quovadisglobal.com/qvrca2g3.crl'
    let decoded_uri = GeneralName::from_der(&hex!(
        "862A687474703A2F2F63726C2E71756F7661646973676C6F62616C2E636F6D2F71767263613267332E63726C"
    ))
    .unwrap();
    let reencoded_uri = decoded_uri.to_vec().unwrap();
    assert_eq!(
        &hex!("862A687474703A2F2F63726C2E71756F7661646973676C6F62616C2E636F6D2F71767263613267332E63726C"),
        reencoded_uri.as_slice()
    );

    let gns_uri = GeneralNames::from_der(&hex!(
        "302C862A687474703A2F2F63726C2E71756F7661646973676C6F62616C2E636F6D2F71767263613267332E63726C"
    ))
        .unwrap();
    let reencoded_gns_uri = gns_uri.to_vec().unwrap();
    assert_eq!(
        &hex!("302C862A687474703A2F2F63726C2E71756F7661646973676C6F62616C2E636F6D2F71767263613267332E63726C"),
        reencoded_gns_uri.as_slice()
    );

    // IP Address
    //  0  32: [7]
    //        :   2A 02 10 2C 00 00 00 00 00 00 00 00 00 00 00 00
    //        :   FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00
    let decoded_ip = GeneralName::from_der(&hex!(
        "87202A02102C000000000000000000000000FFFFFFFF000000000000000000000000"
    ))
    .unwrap();
    let reencoded_ip = decoded_ip.to_vec().unwrap();
    assert_eq!(
        &hex!("87202A02102C000000000000000000000000FFFFFFFF000000000000000000000000"),
        reencoded_ip.as_slice()
    );

    let gns_ip = GeneralNames::from_der(&hex!(
        "302287202A02102C000000000000000000000000FFFFFFFF000000000000000000000000"
    ))
    .unwrap();
    let reencoded_gns_ip = gns_ip.to_vec().unwrap();
    assert_eq!(
        &hex!("302287202A02102C000000000000000000000000FFFFFFFF000000000000000000000000"),
        reencoded_gns_ip.as_slice()
    );

    // RegisteredId
    // TODO
}
