//! Name tests
//use der::asn1::{SetOf, SequenceOfIter, SequenceOf};
use der::{Decodable, Tag, Tagged}; //, Encodable};
use hex_literal::hex;
use x509::{Name, RelativeDistinguishedName}; //, AttributeTypeAndValue;

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
    let i = rdn1a.iter();
    for rdn in i {
        let i1 = rdn.iter();
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
    let i = rdn1.iter();
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

    // TODO - restore
    // let rdn2 = RelativeDistinguishedName::from_der(
    //     &hex!("311F301106035504030C0A4A4F484E20534D495448300A060355040A0C03313233")[..],
    // )
    // .unwrap();
    // let mut i = rdn2.iter();
    // let atav1 = i.next().unwrap();
    // let oid1 = atav1.oid;
    // assert_eq!(oid1.to_string(), "2.5.4.3");
    // let value1 = atav1.value;
    // assert_eq!(value1.tag(), Tag::Utf8String);
    // let utf8a = value1.utf8_string().unwrap();
    // assert_eq!(utf8a.to_string(), "JOHN SMITH");
    //
    // let atav2 = i.next().unwrap();
    // let oid2 = atav2.oid;
    // assert_eq!(oid2.to_string(), "2.5.4.10");
    // let value2 = atav2.value;
    // assert_eq!(value2.tag(), Tag::Utf8String);
    // let utf8b = value2.utf8_string().unwrap();
    // assert_eq!(utf8b.to_string(), "123");
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
