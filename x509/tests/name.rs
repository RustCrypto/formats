// //! Validity tests
// use der::asn1::SetOf;
// use der::{Decodable, Encodable, Tag};
// use hex_literal::hex;
// use x509::{AttributeTypeAndValue, RelativeDistinguishedName};
//
// #[test]
// fn decode_rdn() {
//     //  0  11: SET {
//     //   2   9:   SEQUENCE {
//     //   4   3:     OBJECT IDENTIFIER countryName (2 5 4 6)
//     //   9   2:     PrintableString 'US'
//     //        :     }
//     //        :   }
//     let rdn1 =
//         RelativeDistinguishedName::from_der(&hex!("310B3009060355040613025553")[..]).unwrap();
//     let i = rdn1.elements();
//     for atav in i {
//         let oid = atav.oid;
//         assert_eq!(oid.to_string(), "2.5.4.6");
//         let value = atav.value;
//         assert_eq!(value.tag(), Tag::PrintableString);
//         let ps = value.printable_string().unwrap();
//         assert_eq!(ps.to_string(), "US");
//     }
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
//     let mut i = rdn2.elements();
//     let atav1 = i.next().unwrap();
//     let oid1 = atav1.oid;
//     assert_eq!(oid1.to_string(), "2.5.4.3");
//     let value1 = atav1.value;
//     assert_eq!(value1.tag(), Tag::Utf8String);
//     let utf8a = value1.utf8_string().unwrap();
//     assert_eq!(utf8a.to_string(), "JOHN SMITH");
//
//     let atav2 = i.next().unwrap();
//     let oid2 = atav2.oid;
//     assert_eq!(oid2.to_string(), "2.5.4.10");
//     let value2 = atav2.value;
//     assert_eq!(value2.tag(), Tag::Utf8String);
//     let utf8b = value2.utf8_string().unwrap();
//     assert_eq!(utf8b.to_string(), "123");
// }
//
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
//     let mut i = rdn1.elements();
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
//     let mut i = rdn2.elements();
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
