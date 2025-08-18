//! Name tests

use const_oid::ObjectIdentifier;
use der::{
    Any, Decode, Encode, Tag, Tagged,
    asn1::{Ia5StringRef, OctetStringRef, PrintableStringRef, SetOfVec, Utf8StringRef},
};
use hex_literal::hex;
use x509_cert::{
    attr::AttributeTypeAndValue,
    name::{Name, RdnSequence, RelativeDistinguishedName},
};

#[test]
fn decode_name() {
    // 134  64:     SEQUENCE {
    // 136  11:       SET {
    // 138   9:         SEQUENCE {
    // 140   3:           OBJECT IDENTIFIER countryName (2 5 4 6)
    // 145   2:           PrintableString 'US'
    //        :           }
    //        :         }
    // 149  31:       SET {
    // 151  29:         SEQUENCE {
    // 153   3:           OBJECT IDENTIFIER organizationName (2 5 4 10)
    // 158  22:           PrintableString 'Test Certificates 2011'
    //        :           }
    //        :         }
    // 182  16:       SET {
    // 184  14:         SEQUENCE {
    // 186   3:           OBJECT IDENTIFIER commonName (2 5 4 3)
    // 191   7:           PrintableString 'Good CA'
    //        :           }
    //        :         }
    //        :       }
    let rdn1 = Name::from_der(
        &hex!(
            "3040310B3009060355040613025553311F301D060355040A1316546573742043657274696669636174657320323031313110300E06035504031307476F6F64204341"
        )[..],
    );
    let rdn1a = rdn1.unwrap();

    for (counter, atav) in rdn1a.iter().enumerate() {
        if 0 == counter {
            assert_eq!(atav.oid.to_string(), "2.5.4.6");
            assert_eq!(
                PrintableStringRef::try_from(&atav.value)
                    .unwrap()
                    .to_string(),
                "US"
            );
        } else if 1 == counter {
            assert_eq!(atav.oid.to_string(), "2.5.4.10");
            assert_eq!(
                PrintableStringRef::try_from(&atav.value)
                    .unwrap()
                    .to_string(),
                "Test Certificates 2011"
            );
        } else if 2 == counter {
            assert_eq!(atav.oid.to_string(), "2.5.4.3");
            assert_eq!(
                PrintableStringRef::try_from(&atav.value)
                    .unwrap()
                    .to_string(),
                "Good CA"
            );
        }
    }

    #[cfg(feature = "std")]
    {
        // https://datatracker.ietf.org/doc/html/rfc4514.html#section-2.1
        // If the RDNSequence is an empty sequence, the result is the empty or
        // zero-length string.
        // Otherwise, the output consists of the string encodings of each
        // RelativeDistinguishedName in the RDNSequence (according to Section 2.2),
        // starting with the last element of the sequence and moving backwards
        // toward the first.
        // The encodings of adjoining RelativeDistinguishedNames are separated by
        // a comma (',' U+002C) character.
        let name = rdn1a.to_string();
        assert_eq!(name, "CN=Good CA,O=Test Certificates 2011,C=US");

        // https://github.com/RustCrypto/formats/issues/1121
        let rdn1 = Name::from_der(
            &hex!(
                "3081c0310b30090603550406130255533113301106035504080c0a43616c69666f726e69613116301406035504070c0d4d6f756e7461696e205669657731133011060355040a0c0a476f6f676c65204c4c43311e301c06035504030c154f51464176444e4457732e676f6f676c652e636f6d31243022060355040b0c1b6d616e6167656d656e743a64732e67726f75702e3338393131313131293027060a0992268993f22c6401010c196964656e746974793a64732e67726f75702e33383931313131"
            )[..],
        );
        let rdn1a = rdn1.unwrap();
        let name = rdn1a.to_string();
        assert_eq!(
            name,
            "UID=identity:ds.group.3891111,OU=management:ds.group.3891111,CN=OQFAvDNDWs.google.com,O=Google LLC,L=Mountain View,ST=California,C=US"
        );
    }
}

#[test]
fn decode_rdn() {
    //  0  11: SET {
    //   2   9:   SEQUENCE {
    //   4   3:     OBJECT IDENTIFIER countryName (2 5 4 6)
    //   9   2:     PrintableString 'US'
    //        :     }
    //        :   }
    let rdn1 =
        RelativeDistinguishedName::from_der(&hex!("310B3009060355040613025553")[..]).unwrap();
    let i = rdn1.iter();
    for atav in i {
        let oid = atav.oid;
        assert_eq!(oid.to_string(), "2.5.4.6");
        let value = &atav.value;
        assert_eq!(value.tag(), Tag::PrintableString);
        let ps = PrintableStringRef::try_from(value).unwrap();
        assert_eq!(ps.to_string(), "US");
    }

    //  0  31: SET {
    //   2  17:   SEQUENCE {
    //   4   3:     OBJECT IDENTIFIER commonName (2 5 4 3)
    //   9  10:     UTF8String 'JOHN SMITH'
    //        :     }
    //  21  10:   SEQUENCE {
    //  23   3:     OBJECT IDENTIFIER organizationName (2 5 4 10)
    //  28   3:     UTF8String '123'
    //        :     }
    //        :   }

    // reordered the encoding so second element above appears first so parsing can succeed
    let rdn2a = RelativeDistinguishedName::from_der(
        &hex!("311F300A060355040A0C03313233301106035504030C0A4A4F484E20534D495448")[..],
    )
    .unwrap();
    let mut i = rdn2a.iter();
    let atav1a = i.next().unwrap();
    let oid2 = atav1a.oid;
    assert_eq!(oid2.to_string(), "2.5.4.10");
    let value2 = &atav1a.value;
    assert_eq!(value2.tag(), Tag::Utf8String);
    let utf8b = Utf8StringRef::try_from(value2).unwrap();
    assert_eq!(utf8b.to_string(), "123");

    let atav2a = i.next().unwrap();
    let oid1 = atav2a.oid;
    assert_eq!(oid1.to_string(), "2.5.4.3");
    let value1 = &atav2a.value;
    assert_eq!(value1.tag(), Tag::Utf8String);
    let utf8a = Utf8StringRef::try_from(value1).unwrap();
    assert_eq!(utf8a.to_string(), "JOHN SMITH");

    let mut from_scratch = RelativeDistinguishedName::default();
    assert!(from_scratch.insert(atav1a.clone()).is_ok());
    assert!(from_scratch.insert(atav2a.clone()).is_ok());
    let reencoded = from_scratch.to_der().unwrap();
    assert_eq!(
        reencoded,
        &hex!("311F300A060355040A0C03313233301106035504030C0A4A4F484E20534D495448")
    );

    let mut from_scratch2 = RelativeDistinguishedName::default();
    assert!(from_scratch2.insert(atav2a.clone()).is_ok());

    // allow out-of-order RDNs (see: RustCrypto/formats#625)
    assert!(
        RelativeDistinguishedName::from_der(
            &hex!("311F301106035504030C0A4A4F484E20534D495448300A060355040A0C03313233")[..],
        )
        .is_ok()
    );
}

// #[test]
// fn encode_atav() {
//     //  0  11: SET {
//     //   2   9:   SEQUENCE {
//     //   4   3:     OBJECT IDENTIFIER countryName (2 5 4 6)
//     //   9   2:     PrintableString 'US'
//     //        :     }
//     //        :   }
//     let rdn1 =
//         RelativeDistinguishedName::from_der(&hex!("310B3009060355040613025553")[..]).unwrap();
//
//     // Re-encode and compare to reference
//     let b1 = rdn1.to_vec().unwrap();
//     assert_eq!(b1, &hex!("310B3009060355040613025553")[..]);
//     let mut i = rdn1.iter();
//     let atav1 = i.next().unwrap();
//
//     //  0  31: SET {
//     //   2  17:   SEQUENCE {
//     //   4   3:     OBJECT IDENTIFIER commonName (2 5 4 3)
//     //   9  10:     UTF8String 'JOHN SMITH'
//     //        :     }
//     //  21  10:   SEQUENCE {
//     //  23   3:     OBJECT IDENTIFIER organizationName (2 5 4 10)
//     //  28   3:     UTF8String '123'
//     //        :     }
//     //        :   }
//     let rdn2 = RelativeDistinguishedName::from_der(
//         &hex!("311F301106035504030C0A4A4F484E20534D495448300A060355040A0C03313233")[..],
//     )
//     .unwrap();
//
//     // Re-encode and compare to reference
//     let b1 = rdn2.to_vec().unwrap();
//     assert_eq!(
//         b1,
//         &hex!("311F301106035504030C0A4A4F484E20534D495448300A060355040A0C03313233")[..]
//     );
//
//     let mut i = rdn2.iter();
//     let atav2 = i.next().unwrap();
//
//     // Create new AttributeTypeAndValue with OID from second item above and value from first
//     let atav3: AttributeTypeAndValue = AttributeTypeAndValue {
//         oid: atav2.oid,
//         value: atav1.value,
//     };
//     let b3 = atav3.to_vec().unwrap();
//     assert_eq!(b3, &hex!("3009060355040313025553")[..]);
// }

/// Tests RdnSequence string serialization and deserialization
#[test]
fn rdns_serde() {
    #[allow(clippy::type_complexity)]
    let values: &[(&[&str], &str, &[&[AttributeTypeAndValue]])] = &[
        (
            &[
                "CN=foo,SN=bar,C=baz+L=bat",
                "commonName=foo,sn=bar,COUNTRYNAME=baz+l=bat",
            ],
            "CN=foo,SN=bar,C=baz+L=bat",
            &[
                &[
                    AttributeTypeAndValue {
                        oid: const_oid::db::rfc4519::C,
                        value: Any::from(PrintableStringRef::new("baz").unwrap()),
                    },
                    AttributeTypeAndValue {
                        oid: const_oid::db::rfc4519::L,
                        value: Any::from(Utf8StringRef::new("bat").unwrap()),
                    },
                ],
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::SN,
                    value: Any::from(Utf8StringRef::new("bar").unwrap()),
                }],
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::CN,
                    value: Any::from(Utf8StringRef::new("foo").unwrap()),
                }],
            ],
        ),
        (
            &["UID=jsmith,DC=example,DC=net"],
            "UID=jsmith,DC=example,DC=net",
            &[
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::DC,
                    value: Any::from(Ia5StringRef::new("net").unwrap()),
                }],
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::DC,
                    value: Any::from(Ia5StringRef::new("example").unwrap()),
                }],
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::UID,
                    value: Any::from(Utf8StringRef::new("jsmith").unwrap()),
                }],
            ],
        ),
        (
            &["OU=Sales+CN=J.  Smith,DC=example,DC=net"],
            "OU=Sales+CN=J.  Smith,DC=example,DC=net",
            &[
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::DC,
                    value: Any::from(Ia5StringRef::new("net").unwrap()),
                }],
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::DC,
                    value: Any::from(Ia5StringRef::new("example").unwrap()),
                }],
                &[
                    AttributeTypeAndValue {
                        oid: const_oid::db::rfc4519::OU,
                        value: Any::from(Utf8StringRef::new("Sales").unwrap()),
                    },
                    AttributeTypeAndValue {
                        oid: const_oid::db::rfc4519::CN,
                        value: Any::from(Utf8StringRef::new("J.  Smith").unwrap()),
                    },
                ],
            ],
        ),
        (
            &["CN=James \\\"Jim\\\" Smith\\, III,DC=example,DC=net"],
            "CN=James \\\"Jim\\\" Smith\\, III,DC=example,DC=net",
            &[
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::DC,
                    value: Any::from(Ia5StringRef::new("net").unwrap()),
                }],
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::DC,
                    value: Any::from(Ia5StringRef::new("example").unwrap()),
                }],
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::CN,
                    value: Any::from(Utf8StringRef::new(r#"James "Jim" Smith, III"#).unwrap()),
                }],
            ],
        ),
        (
            &["CN=Before\\0dAfter,DC=example,DC=net"],
            "CN=Before\\0dAfter,DC=example,DC=net",
            &[
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::DC,
                    value: Any::from(Ia5StringRef::new("net").unwrap()),
                }],
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::DC,
                    value: Any::from(Ia5StringRef::new("example").unwrap()),
                }],
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::CN,
                    value: Any::from(Utf8StringRef::new("Before\rAfter").unwrap()),
                }],
            ],
        ),
        (
            &["1.3.6.1.4.1.1466.0=#04024869"],
            "1.3.6.1.4.1.1466.0=#04024869",
            &[&[AttributeTypeAndValue {
                oid: ObjectIdentifier::new("1.3.6.1.4.1.1466.0").unwrap(),
                value: Any::from(OctetStringRef::new(b"Hi").unwrap()),
            }]],
        ),
    ];

    for (inputs, output, rdns) in values {
        let mut brdns = RdnSequence::default();
        for rdn in rdns.iter() {
            let sofv = SetOfVec::try_from(rdn.to_vec()).unwrap();
            brdns.push(RelativeDistinguishedName::from(sofv));
        }

        // Check that serialization matches the expected output.
        eprintln!("output: {output}");
        assert_eq!(*output, format!("{brdns}"));

        // Check that all inputs deserializize as expected.
        for input in inputs.iter() {
            eprintln!("input: {input}");

            let der = input
                .parse::<RdnSequence>()
                .and_then(|rdn| rdn.to_der())
                .unwrap();

            let rdns = RdnSequence::from_der(&der).unwrap();

            for (l, r) in brdns.iter().zip(rdns.iter()) {
                for (ll, rr) in l.iter().zip(r.iter()) {
                    assert_eq!(ll, rr);
                }

                assert_eq!(l, r);
            }

            assert_eq!(brdns, rdns);
        }
    }
}

#[cfg(feature = "std")]
#[test]
fn access_attributes() {
    use std::str::FromStr;

    let name = Name::from_str("emailAddress=foo@example.com,UID=identity:ds.group.3891111,OU=management:ds.group.3891111,CN=OQFAvDNDWs.google.com,O=Google LLC,L=Mountain View,ST=California,C=US").unwrap();

    assert_eq!(
        name.common_name().unwrap().unwrap().value(),
        "OQFAvDNDWs.google.com"
    );

    assert_eq!(
        <_ as AsRef<str>>::as_ref(&name.country().unwrap().unwrap()),
        "US"
    );

    assert_eq!(
        name.state_or_province().unwrap().unwrap().value(),
        "California"
    );

    assert_eq!(name.locality().unwrap().unwrap().value(), "Mountain View");

    assert_eq!(name.organization().unwrap().unwrap().value(), "Google LLC");

    assert_eq!(
        name.organization_unit().unwrap().unwrap().value(),
        "management:ds.group.3891111"
    );

    assert_eq!(
        <_ as AsRef<str>>::as_ref(&name.email_address().unwrap().unwrap()),
        "foo@example.com"
    );

    let name = Name::from_str("C=DE,C=US").unwrap();

    assert_eq!(
        <_ as AsRef<str>>::as_ref(&name.country().unwrap().unwrap()),
        "US"
    );
}

#[cfg(feature = "std")]
#[test]
fn decode_given_name() {
    use std::str::FromStr;

    Name::from_str("GN=my_name,SN=my_sn").unwrap();
    Name::from_str("givenName=my_name,SN=my_sn").unwrap();
}
