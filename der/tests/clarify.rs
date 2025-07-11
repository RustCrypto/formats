//! Tests for clarify pretty-printing support.
#![cfg(all(feature = "derive", feature = "alloc", feature = "clarify"))]

pub mod sequence {
    use std::println;

    use const_oid::ObjectIdentifier;
    use der::{
        AnyRef, ClarifyFlavor, EncodeClarifyExt, Sequence, ValueOrd,
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
        let obj = OctetString::new(&[0xAA, 0xBB, 0xCC]).unwrap();

        let clarified = obj
            .to_der_clarify(ClarifyFlavor::JavaComments)
            .expect("encoded DER");

        assert_eq!(
            clarified,
            "\n04 03 // tag: OCTET STRING type: OctetString \n\tAA BB CC"
        )
    }

    #[test]
    fn clarify_simple_octetstring_rusthex() {
        let obj = OctetString::new(&[0xAA, 0xBB, 0xCC]).unwrap();

        let clarified = obj
            .to_der_clarify(ClarifyFlavor::RustHex)
            .expect("encoded DER");

        assert_eq!(
            clarified,
            "\n\"04 03\" // tag: OCTET STRING type: OctetString \n\t\"AA BB CC\""
        )
    }

    #[test]
    fn clarify_simple_octetstring_long_rusthex() {
        let obj = OctetString::new(&[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x01,
        ])
        .unwrap();

        let clarified = obj
            .to_der_clarify(ClarifyFlavor::RustHex)
            .expect("encoded DER");

        println!("clarified: {clarified}");
        assert_eq!(
            clarified,
            "\n\"04 11\" // tag: OCTET STRING len: 17 type: OctetString \n\t\"00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF \n\t01\"\n\"\" // end: OctetString "
        );

        // use-case example:
        hex!(
            "04 11" // tag: OCTET STRING len: 17 type: OctetString
                "00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
                01"
            "" // end: OctetString
        );
    }
}
