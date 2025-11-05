//! Tests for clarify pretty-printing support.
#![cfg(all(feature = "derive", feature = "alloc", feature = "clarify"))]
// TODO: fix needless_question_mark in the derive crate
#![allow(clippy::needless_question_mark)]

pub mod sequence {
    use std::{borrow::Cow, println, str::FromStr};

    use const_oid::ObjectIdentifier;
    use der::{
        AnyRef, ClarifyFlavor, ClarifyHook, Decode, EncodeClarifyExt, Sequence, TagNumber,
        ValueOrd,
        asn1::{OctetString, SetOf},
    };
    use hex_literal::hex;

    /// X.509 `AlgorithmIdentifier`
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
    pub struct AlgorithmIdentifier<'a> {
        pub algorithm: ObjectIdentifier,
        pub parameters: Option<AnyRef<'a>>,
    }

    /// PKCS#8v2 `OneAsymmetricKey`
    #[derive(Sequence)]
    pub struct OneAsymmetricKey<'a> {
        pub version: u8,
        pub private_key_algorithm: AlgorithmIdentifier<'a>,
        #[asn1(type = "OCTET STRING")]
        pub private_key: &'a [u8],
        #[asn1(context_specific = "0", extensible = "true", optional = "true")]
        pub attributes: Option<SetOf<AnyRef<'a>, 1>>,
        #[asn1(
            context_specific = "1",
            extensible = "true",
            optional = "true",
            type = "BIT STRING"
        )]
        pub public_key: Option<&'a [u8]>,
    }

    #[test]
    fn clarify_simple_octetstring_javacomments() {
        let obj = OctetString::new(hex!("AA BB CC")).unwrap();

        let clarified = obj
            .to_der_clarify(ClarifyFlavor::JavaComments)
            .expect("encoded DER");

        assert_eq!(
            clarified,
            "\n04 03 // tag: OCTET STRING type: der::asn1::octet_string::allocating::OctetString \n\tAA BB CC"
        )
    }

    #[test]
    fn clarify_simple_octetstring_rusthex() {
        let obj = OctetString::new(hex!("AA BB CC")).unwrap();

        let clarified = obj
            .to_der_clarify(ClarifyFlavor::RustHex)
            .expect("encoded DER");

        assert_eq!(
            clarified,
            "\n\"04 03\" // tag: OCTET STRING type: der::asn1::octet_string::allocating::OctetString \n\t\"AA BB CC\""
        )
    }

    #[test]
    fn clarify_simple_octetstring_long_rusthex() {
        let obj = OctetString::from_der(&hex!(
            "04 11" // tag: OCTET STRING len: 17 type: OctetString
                "00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
                01"
            "" // end: OctetString
        ))
        .unwrap();

        let clarified = obj
            .to_der_clarify(ClarifyFlavor::RustHex)
            .expect("encoded DER");

        println!("clarified: {clarified}");
        assert_eq!(
            clarified,
            "\n\"04 11\" // tag: OCTET STRING len: 17 type: der::asn1::octet_string::allocating::OctetString \n\t\"00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF \n\t 01\"\n\"\" // end: der::asn1::octet_string::allocating::OctetString "
        );
    }
    #[test]
    fn clarify_one_asymmetric_key_rusthex() {
        let obj = OneAsymmetricKey {
            version: 1,
            private_key_algorithm: AlgorithmIdentifier {
                algorithm: ObjectIdentifier::from_str("1.2.3.4.5.6.7.8").expect("valid oid"),
                parameters: Some(
                    AnyRef::new(
                        der::Tag::ContextSpecific {
                            constructed: true,
                            number: TagNumber(0),
                        },
                        &[0xAA, 0xBB],
                    )
                    .expect("valid length"),
                ),
            },
            private_key: &[
                0x00, 0x11, 0x22, 0x33, 0x00, 0x11, 0x22, 0x33, 0x00, 0x11, 0x22, 0x33, 0x00, 0x11,
                0x22, 0x33, 0x00, 0x11, 0x22, 0x33, 0x00, 0x11, 0x22, 0x33, 0x00, 0x11, 0x22, 0x33,
            ],
            attributes: None,
            public_key: Some(&[
                0x44, 0x55, 0x66, 0x77, 0x44, 0x55, 0x66, 0x77, 0x44, 0x55, 0x66, 0x77, 0x44, 0x55,
                0x66, 0x77, 0x44, 0x55, 0x66, 0x77, 0x44, 0x55, 0x66, 0x77, 0x44, 0x55, 0x66, 0x77,
            ]),
        };
        let clarified = obj.to_der_clarify_err_ignorant(der::ClarifyOptions {
            flavor: ClarifyFlavor::RustHex,
            hook: TynmClarifyHook::default(),
        });

        clarified.raw.expect("encoded DER");
        let clarified = String::from_utf8(clarified.clarify_buf).expect("utf-8");
        println!("clarified: {clarified}");

        assert!(clarified.contains("type: OneAsymmetricKey"));
        assert!(clarified.contains("tag: CONTEXT-SPECIFIC [0] (constructed)"));
        assert!(clarified.contains("tag: CONTEXT-SPECIFIC [1] (constructed)"));
        assert!(clarified.contains("type: AlgorithmIdentifier"));
        assert!(clarified.contains("tag: OBJECT IDENTIFIER"));
        assert!(clarified.contains("type: ObjectIdentifier"));
        assert!(clarified.contains("end: OneAsymmetricKey"));

        hex!(
            "30 51" // tag: SEQUENCE len: 81 type: OneAsymmetricKey
                "02 01" // tag: INTEGER type: u8
                        "01"
                "30 0D" // tag: SEQUENCE len: 13 type: AlgorithmIdentifier
                        "06 07" // tag: OBJECT IDENTIFIER type: ObjectIdentifier
                                "2A 03 04 05 06 07 08"
                        "A0 02" // tag: CONTEXT-SPECIFIC [0] (constructed) type: AnyRef
                                "AA BB"
                "04 1C" // tag: OCTET STRING len: 28 type: OctetStringRef
                        "00 11 22 33 00 11 22 33 00 11 22 33 00 11 22 33
                         00 11 22 33 00 11 22 33 00 11 22 33"
                "" // end: OctetStringRef
                "A1 1F" // tag: CONTEXT-SPECIFIC [1] (constructed) len: 31 type: ContextSpecificRef<BitStringRef>
                        "03 1D" // tag: BIT STRING len: 29 type: BitStringRef
                                "00"
                                "44 55 66 77 44 55 66 77 44 55 66 77 44 55 66 77
                                 44 55 66 77 44 55 66 77 44 55 66 77"
                        "" // end: BitStringRef
                "" // end: ContextSpecificRef<BitStringRef>
            "" // end: OneAsymmetricKey
        );
    }

    #[derive(Default)]
    struct TynmClarifyHook {}
    impl ClarifyHook for TynmClarifyHook {
        fn type_name<T: ?Sized>() -> Cow<'static, str> {
            Cow::Owned(tynm::type_name::<T>())
        }
    }
}
