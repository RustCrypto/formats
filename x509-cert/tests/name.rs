//! Name tests

use const_oid::ObjectIdentifier;
use der::asn1::{Ia5StringRef, OctetStringRef, PrintableStringRef, SetOfVec, Utf8StringRef};
use der::{AnyRef, Decode, Encode, Tag, Tagged};
use hex_literal::hex;
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};

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
    let rdn1 =
        Name::from_der(&hex!("3040310B3009060355040613025553311F301D060355040A1316546573742043657274696669636174657320323031313110300E06035504031307476F6F64204341")[..]);
    let rdn1a = rdn1.unwrap();

    let mut counter = 0;
    let i = rdn1a.0.iter();
    for rdn in i {
        let i1 = rdn.0.iter();
        for atav in i1 {
            if 0 == counter {
                assert_eq!(atav.oid.to_string(), "2.5.4.6");
                assert_eq!(atav.value.printable_string().unwrap().to_string(), "US");
            } else if 1 == counter {
                assert_eq!(atav.oid.to_string(), "2.5.4.10");
                assert_eq!(
                    atav.value.printable_string().unwrap().to_string(),
                    "Test Certificates 2011"
                );
            } else if 2 == counter {
                assert_eq!(atav.oid.to_string(), "2.5.4.3");
                assert_eq!(
                    atav.value.printable_string().unwrap().to_string(),
                    "Good CA"
                );
            }
            counter += 1;
        }
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
    let i = rdn1.0.iter();
    for atav in i {
        let oid = atav.oid;
        assert_eq!(oid.to_string(), "2.5.4.6");
        let value = atav.value;
        assert_eq!(value.tag(), Tag::PrintableString);
        let ps = value.printable_string().unwrap();
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
    let mut i = rdn2a.0.iter();
    let atav1a = i.next().unwrap();
    let oid2 = atav1a.oid;
    assert_eq!(oid2.to_string(), "2.5.4.10");
    let value2 = atav1a.value;
    assert_eq!(value2.tag(), Tag::Utf8String);
    let utf8b = value2.utf8_string().unwrap();
    assert_eq!(utf8b.to_string(), "123");

    let atav2a = i.next().unwrap();
    let oid1 = atav2a.oid;
    assert_eq!(oid1.to_string(), "2.5.4.3");
    let value1 = atav2a.value;
    assert_eq!(value1.tag(), Tag::Utf8String);
    let utf8a = value1.utf8_string().unwrap();
    assert_eq!(utf8a.to_string(), "JOHN SMITH");

    let mut from_scratch = RelativeDistinguishedName::default();
    assert!(from_scratch.0.add(*atav1a).is_ok());
    assert!(from_scratch.0.add(*atav2a).is_ok());
    let reencoded = from_scratch.to_vec().unwrap();
    assert_eq!(
        reencoded,
        &hex!("311F300A060355040A0C03313233301106035504030C0A4A4F484E20534D495448")
    );

    let mut from_scratch2 = RelativeDistinguishedName::default();
    assert!(from_scratch2.0.add(*atav2a).is_ok());
    // fails when caller adds items not in DER lexicographical order
    assert!(from_scratch2.0.add(*atav1a).is_err());

    // allow out-of-order RDNs (see: RustCrypto/formats#625)
    assert!(RelativeDistinguishedName::from_der(
        &hex!("311F301106035504030C0A4A4F484E20534D495448300A060355040A0C03313233")[..],
    )
    .is_ok());
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
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::CN,
                    value: AnyRef::from(Utf8StringRef::new("foo").unwrap()),
                }],
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::SN,
                    value: AnyRef::from(Utf8StringRef::new("bar").unwrap()),
                }],
                &[
                    AttributeTypeAndValue {
                        oid: const_oid::db::rfc4519::C,
                        value: AnyRef::from(PrintableStringRef::new("baz").unwrap()),
                    },
                    AttributeTypeAndValue {
                        oid: const_oid::db::rfc4519::L,
                        value: AnyRef::from(Utf8StringRef::new("bat").unwrap()),
                    },
                ],
            ],
        ),
        (
            &["UID=jsmith,DC=example,DC=net"],
            "UID=jsmith,DC=example,DC=net",
            &[
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::UID,
                    value: AnyRef::from(Utf8StringRef::new("jsmith").unwrap()),
                }],
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::DC,
                    value: AnyRef::from(Ia5StringRef::new("example").unwrap()),
                }],
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::DC,
                    value: AnyRef::from(Ia5StringRef::new("net").unwrap()),
                }],
            ],
        ),
        (
            &["OU=Sales+CN=J.  Smith,DC=example,DC=net"],
            "OU=Sales+CN=J.  Smith,DC=example,DC=net",
            &[
                &[
                    AttributeTypeAndValue {
                        oid: const_oid::db::rfc4519::OU,
                        value: AnyRef::from(Utf8StringRef::new("Sales").unwrap()),
                    },
                    AttributeTypeAndValue {
                        oid: const_oid::db::rfc4519::CN,
                        value: AnyRef::from(Utf8StringRef::new("J.  Smith").unwrap()),
                    },
                ],
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::DC,
                    value: AnyRef::from(Ia5StringRef::new("example").unwrap()),
                }],
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::DC,
                    value: AnyRef::from(Ia5StringRef::new("net").unwrap()),
                }],
            ],
        ),
        (
            &["CN=James \\\"Jim\\\" Smith\\, III,DC=example,DC=net"],
            "CN=James \\\"Jim\\\" Smith\\, III,DC=example,DC=net",
            &[
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::CN,
                    value: AnyRef::from(Utf8StringRef::new(r#"James "Jim" Smith, III"#).unwrap()),
                }],
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::DC,
                    value: AnyRef::from(Ia5StringRef::new("example").unwrap()),
                }],
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::DC,
                    value: AnyRef::from(Ia5StringRef::new("net").unwrap()),
                }],
            ],
        ),
        (
            &["CN=Before\\0dAfter,DC=example,DC=net"],
            "CN=Before\\0dAfter,DC=example,DC=net",
            &[
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::CN,
                    value: AnyRef::from(Utf8StringRef::new("Before\rAfter").unwrap()),
                }],
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::DC,
                    value: AnyRef::from(Ia5StringRef::new("example").unwrap()),
                }],
                &[AttributeTypeAndValue {
                    oid: const_oid::db::rfc4519::DC,
                    value: AnyRef::from(Ia5StringRef::new("net").unwrap()),
                }],
            ],
        ),
        (
            &["1.3.6.1.4.1.1466.0=#04024869"],
            "1.3.6.1.4.1.1466.0=#04024869",
            &[&[AttributeTypeAndValue {
                oid: ObjectIdentifier::new("1.3.6.1.4.1.1466.0").unwrap(),
                value: AnyRef::from(OctetStringRef::new(&[b'H', b'i']).unwrap()),
            }]],
        ),
    ];

    for (inputs, output, rdns) in values {
        let mut brdns = RdnSequence::default();
        for rdn in rdns.iter() {
            let sofv = SetOfVec::try_from(rdn.to_vec()).unwrap();
            brdns.0.push(RelativeDistinguishedName::from(sofv));
        }

        // Check that serialization matches the expected output.
        eprintln!("output: {}", output);
        assert_eq!(*output, format!("{}", brdns));

        // Check that all inputs deserializize as expected.
        for input in inputs.iter() {
            eprintln!("input: {}", input);

            let der = RdnSequence::encode_from_string(input).unwrap();
            let rdns = RdnSequence::from_der(&der).unwrap();

            for (l, r) in brdns.0.iter().zip(rdns.0.iter()) {
                for (ll, rr) in l.0.iter().zip(r.0.iter()) {
                    assert_eq!(ll, rr);
                }

                assert_eq!(l, r);
            }

            assert_eq!(brdns, rdns);
        }
    }
}
