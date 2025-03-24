//! Tests for custom derive support.
//!
//! # Debugging with `cargo expand`
//!
//! To expand the Rust code generated by the proc macro when debugging
//! issues related to these tests, run:
//!
//! $ cargo expand --test derive --all-features

#![cfg(all(feature = "derive", feature = "alloc"))]
// TODO: fix needless_question_mark in the derive crate
#![allow(clippy::bool_assert_comparison, clippy::needless_question_mark)]

#[derive(Debug)]
#[allow(dead_code)]
pub struct CustomError(der::Error);

impl From<der::Error> for CustomError {
    fn from(value: der::Error) -> Self {
        Self(value)
    }
}

impl From<std::convert::Infallible> for CustomError {
    fn from(_value: std::convert::Infallible) -> Self {
        unreachable!()
    }
}

/// Custom derive test cases for the `Choice` macro.
mod choice {
    use super::CustomError;

    /// `Choice` with `EXPLICIT` tagging.
    mod explicit {
        use super::CustomError;
        use der::{
            Choice, Decode, Encode, SliceWriter,
            asn1::{GeneralizedTime, UtcTime},
        };
        use hex_literal::hex;
        use std::time::Duration;

        /// Custom derive test case for the `Choice` macro.
        ///
        /// Based on `Time` as defined in RFC 5280:
        /// <https://tools.ietf.org/html/rfc5280#page-117>
        ///
        /// ```text
        /// Time ::= CHOICE {
        ///      utcTime        UTCTime,
        ///      generalTime    GeneralizedTime }
        /// ```
        #[derive(Choice)]
        pub enum Time {
            #[asn1(type = "UTCTime")]
            UtcTime(UtcTime),

            #[asn1(type = "GeneralizedTime")]
            GeneralTime(GeneralizedTime),
        }

        impl Time {
            fn to_unix_duration(&self) -> Duration {
                match self {
                    Time::UtcTime(t) => t.to_unix_duration(),
                    Time::GeneralTime(t) => t.to_unix_duration(),
                }
            }
        }

        #[derive(Choice)]
        #[asn1(error = CustomError)]
        pub enum WithCustomError {
            #[asn1(type = "GeneralizedTime")]
            Foo(GeneralizedTime),
        }

        const UTC_TIMESTAMP_DER: &[u8] = &hex!("17 0d 39 31 30 35 30 36 32 33 34 35 34 30 5a");
        const GENERAL_TIMESTAMP_DER: &[u8] =
            &hex!("18 0f 31 39 39 31 30 35 30 36 32 33 34 35 34 30 5a");

        #[test]
        fn decode() {
            let utc_time = Time::from_der(UTC_TIMESTAMP_DER).unwrap();
            assert_eq!(utc_time.to_unix_duration().as_secs(), 673573540);

            let general_time = Time::from_der(GENERAL_TIMESTAMP_DER).unwrap();
            assert_eq!(general_time.to_unix_duration().as_secs(), 673573540);

            let WithCustomError::Foo(with_custom_error) =
                WithCustomError::from_der(GENERAL_TIMESTAMP_DER).unwrap();
            assert_eq!(with_custom_error.to_unix_duration().as_secs(), 673573540);
        }

        #[test]
        fn encode() {
            let mut buf = [0u8; 128];

            let utc_time = Time::from_der(UTC_TIMESTAMP_DER).unwrap();
            let mut encoder = SliceWriter::new(&mut buf);
            utc_time.encode(&mut encoder).unwrap();
            assert_eq!(UTC_TIMESTAMP_DER, encoder.finish().unwrap());

            let general_time = Time::from_der(GENERAL_TIMESTAMP_DER).unwrap();
            let mut encoder = SliceWriter::new(&mut buf);
            general_time.encode(&mut encoder).unwrap();
            assert_eq!(GENERAL_TIMESTAMP_DER, encoder.finish().unwrap());
        }
    }

    /// `Choice` with `IMPLICIT` tagging.
    mod implicit {
        use der::{
            Choice, Decode, Encode, SliceWriter,
            asn1::{BitStringRef, GeneralizedTime},
        };
        use hex_literal::hex;

        /// `Choice` macro test case for `IMPLICIT` tagging.
        #[derive(Choice, Debug, Eq, PartialEq)]
        #[asn1(tag_mode = "IMPLICIT")]
        pub enum ImplicitChoice<'a> {
            #[asn1(context_specific = "0", type = "BIT STRING")]
            BitString(BitStringRef<'a>),

            #[asn1(context_specific = "1", type = "GeneralizedTime")]
            Time(GeneralizedTime),

            #[asn1(context_specific = "2", type = "UTF8String")]
            Utf8String(String),
        }

        impl<'a> ImplicitChoice<'a> {
            pub fn bit_string(&self) -> Option<BitStringRef<'a>> {
                match self {
                    Self::BitString(bs) => Some(*bs),
                    _ => None,
                }
            }

            pub fn time(&self) -> Option<GeneralizedTime> {
                match self {
                    Self::Time(time) => Some(*time),
                    _ => None,
                }
            }
        }

        const BITSTRING_DER: &[u8] = &hex!("80 04 00 01 02 03");
        const TIME_DER: &[u8] = &hex!("81 0f 31 39 39 31 30 35 30 36 32 33 34 35 34 30 5a");

        #[test]
        fn decode() {
            let cs_bit_string = ImplicitChoice::from_der(BITSTRING_DER).unwrap();
            assert_eq!(
                cs_bit_string.bit_string().unwrap().as_bytes().unwrap(),
                &[1, 2, 3]
            );

            let cs_time = ImplicitChoice::from_der(TIME_DER).unwrap();
            assert_eq!(
                cs_time.time().unwrap().to_unix_duration().as_secs(),
                673573540
            );
        }

        #[test]
        fn encode() {
            let mut buf = [0u8; 128];

            let cs_bit_string = ImplicitChoice::from_der(BITSTRING_DER).unwrap();
            let mut encoder = SliceWriter::new(&mut buf);
            cs_bit_string.encode(&mut encoder).unwrap();
            assert_eq!(BITSTRING_DER, encoder.finish().unwrap());

            let cs_time = ImplicitChoice::from_der(TIME_DER).unwrap();
            let mut encoder = SliceWriter::new(&mut buf);
            cs_time.encode(&mut encoder).unwrap();
            assert_eq!(TIME_DER, encoder.finish().unwrap());
        }
    }
}

/// Custom derive test cases for the `Enumerated` macro.
mod enumerated {
    use super::CustomError;
    use der::{Decode, Encode, Enumerated, SliceWriter};
    use hex_literal::hex;

    /// X.509 `CRLReason`.
    #[derive(Enumerated, Copy, Clone, Debug, Eq, PartialEq)]
    #[repr(u32)]
    pub enum CrlReason {
        Unspecified = 0,
        KeyCompromise = 1,
        CaCompromise = 2,
        AffiliationChanged = 3,
        Superseded = 4,
        CessationOfOperation = 5,
        CertificateHold = 6,
        RemoveFromCrl = 8,
        PrivilegeWithdrawn = 9,
        AaCompromised = 10,
    }

    const UNSPECIFIED_DER: &[u8] = &hex!("0a 01 00");
    const KEY_COMPROMISE_DER: &[u8] = &hex!("0a 01 01");

    #[derive(Enumerated, Copy, Clone, Eq, PartialEq, Debug)]
    #[asn1(error = CustomError)]
    #[repr(u32)]
    pub enum EnumWithCustomError {
        Unspecified = 0,
        Specified = 1,
    }

    #[test]
    fn decode() {
        let unspecified = CrlReason::from_der(UNSPECIFIED_DER).unwrap();
        assert_eq!(CrlReason::Unspecified, unspecified);

        let key_compromise = CrlReason::from_der(KEY_COMPROMISE_DER).unwrap();
        assert_eq!(CrlReason::KeyCompromise, key_compromise);

        let custom_error_enum = EnumWithCustomError::from_der(UNSPECIFIED_DER).unwrap();
        assert_eq!(custom_error_enum, EnumWithCustomError::Unspecified);
    }

    #[test]
    fn encode() {
        let mut buf = [0u8; 128];

        let mut encoder = SliceWriter::new(&mut buf);
        CrlReason::Unspecified.encode(&mut encoder).unwrap();
        assert_eq!(UNSPECIFIED_DER, encoder.finish().unwrap());

        let mut encoder = SliceWriter::new(&mut buf);
        CrlReason::KeyCompromise.encode(&mut encoder).unwrap();
        assert_eq!(KEY_COMPROMISE_DER, encoder.finish().unwrap());
    }
}

/// Custom derive test cases for the `Sequence` macro.
#[cfg(feature = "oid")]
mod sequence {
    use super::CustomError;
    use core::marker::PhantomData;
    use der::{
        Decode, Encode, Sequence, ValueOrd,
        asn1::{AnyRef, ObjectIdentifier, SetOf},
    };
    use hex_literal::hex;

    pub fn default_false_example() -> bool {
        false
    }

    // Issuing distribution point extension as defined in [RFC 5280 Section 5.2.5] and as identified by the [`PKIX_PE_SUBJECTINFOACCESS`](constant.PKIX_PE_SUBJECTINFOACCESS.html) OID.
    //
    // ```text
    // IssuingDistributionPoint ::= SEQUENCE {
    //      distributionPoint          [0] DistributionPointName OPTIONAL,
    //      onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
    //      onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
    //      onlySomeReasons            [3] ReasonFlags OPTIONAL,
    //      indirectCRL                [4] BOOLEAN DEFAULT FALSE,
    //      onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
    //      -- at most one of onlyContainsUserCerts, onlyContainsCACerts,
    //      -- and onlyContainsAttributeCerts may be set to TRUE.
    // ```
    //
    // [RFC 5280 Section 5.2.5]: https://datatracker.ietf.org/doc/html/rfc5280#section-5.2.5
    #[derive(Sequence)]
    pub struct IssuingDistributionPointExample {
        // Omit distributionPoint and only_some_reasons because corresponding structs are not
        // available here and are not germane to the example
        // distributionPoint          [0] DistributionPointName OPTIONAL,
        //#[asn1(context_specific="0", optional="true", tag_mode="IMPLICIT")]
        //pub distribution_point: Option<DistributionPointName<'a>>,
        /// onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
        #[asn1(
            context_specific = "1",
            default = "default_false_example",
            tag_mode = "IMPLICIT"
        )]
        pub only_contains_user_certs: bool,

        /// onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
        #[asn1(
            context_specific = "2",
            default = "default_false_example",
            tag_mode = "IMPLICIT"
        )]
        pub only_contains_cacerts: bool,

        // onlySomeReasons            [3] ReasonFlags OPTIONAL,
        //#[asn1(context_specific="3", optional="true", tag_mode="IMPLICIT")]
        //pub only_some_reasons: Option<ReasonFlags<'a>>,
        /// indirectCRL                [4] BOOLEAN DEFAULT FALSE,
        #[asn1(
            context_specific = "4",
            default = "default_false_example",
            tag_mode = "IMPLICIT"
        )]
        pub indirect_crl: bool,

        /// onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE
        #[asn1(
            context_specific = "5",
            default = "default_false_example",
            tag_mode = "IMPLICIT"
        )]
        pub only_contains_attribute_certs: bool,

        /// Test handling of PhantomData.
        pub phantom: PhantomData<()>,
    }

    // Extension as defined in [RFC 5280 Section 4.1.2.9].
    //
    // The ASN.1 definition for Extension objects is below. The extnValue type may be further parsed using a decoder corresponding to the extnID value.
    //
    // ```text
    //    Extension  ::=  SEQUENCE  {
    //         extnID      OBJECT IDENTIFIER,
    //         critical    BOOLEAN DEFAULT FALSE,
    //         extnValue   OCTET STRING
    //                     -- contains the DER encoding of an ASN.1 value
    //                     -- corresponding to the extension type identified
    //                     -- by extnID
    //         }
    // ```
    //
    // [RFC 5280 Section 4.1.2.9]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.9
    #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
    pub struct ExtensionExample<'a> {
        /// extnID      OBJECT IDENTIFIER,
        pub extn_id: ObjectIdentifier,

        /// critical    BOOLEAN DEFAULT FALSE,
        #[asn1(default = "default_false_example")]
        pub critical: bool,

        /// extnValue   OCTET STRING
        #[asn1(type = "OCTET STRING")]
        pub extn_value: &'a [u8],
    }

    /// X.509 `AlgorithmIdentifier`
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
    pub struct AlgorithmIdentifier<'a> {
        pub algorithm: ObjectIdentifier,
        pub parameters: Option<AnyRef<'a>>,
    }

    /// X.509 `SubjectPublicKeyInfo` (SPKI)
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
    pub struct SubjectPublicKeyInfo<'a> {
        pub algorithm: AlgorithmIdentifier<'a>,
        #[asn1(type = "BIT STRING")]
        pub subject_public_key: &'a [u8],
    }

    #[test]
    fn decode_spki() {
        let spki_bytes = hex!(
        // first SPKI
        "30 1A
            30 0D 
                06 09
                    2A 86 48 86 F7 0D 01 01 01 
                05 00
            03 09
                00 A0 A1 A2 A3 A4 A5 A6 A7"
        // second SPKI
        "30 1A
            30 0D 
                06 09
                    2A 86 48 86 F7 0D 01 01 01 
                05 00
            03 09
                00 B0 B1 B2 B3 B4 B5 B6 B7");

        // decode first
        let (spki, remaining) = SubjectPublicKeyInfo::from_der_partial(&spki_bytes).unwrap();
        assert_eq!(spki.subject_public_key, hex!("A0 A1 A2 A3 A4 A5 A6 A7"));

        // decode second
        let (spki, _) = SubjectPublicKeyInfo::from_der_partial(remaining).unwrap();
        assert_eq!(spki.subject_public_key, hex!("B0 B1 B2 B3 B4 B5 B6 B7"));
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

    /// X.509 extension
    // TODO(tarcieri): tests for code derived with the `default` attribute
    #[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
    pub struct Extension<'a> {
        extn_id: ObjectIdentifier,
        #[asn1(default = "critical_default")]
        critical: bool,
        #[asn1(type = "OCTET STRING")]
        extn_value: &'a [u8],
    }

    /// Default value of the `critical` bit
    fn critical_default() -> bool {
        false
    }

    const ID_EC_PUBLIC_KEY_OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

    const PRIME256V1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

    const ALGORITHM_IDENTIFIER_DER: &[u8] =
        &hex!("30 13 06 07 2a 86 48 ce 3d 02 01 06 08 2a 86 48 ce 3d 03 01 07");

    #[derive(Sequence, Default, Eq, PartialEq, Debug)]
    #[asn1(tag_mode = "IMPLICIT")]
    pub struct TypeCheckExpandedSequenceFieldAttributeCombinations<'a> {
        pub simple: bool,
        #[asn1(type = "BIT STRING")]
        pub typed: &'a [u8],
        #[asn1(context_specific = "0")]
        pub context_specific: bool,
        #[asn1(optional = "true")]
        pub optional: Option<bool>,
        #[asn1(default = "default_false_example")]
        pub default: bool,
        #[asn1(type = "BIT STRING", context_specific = "1")]
        pub typed_context_specific: &'a [u8],
        #[asn1(context_specific = "2", optional = "true")]
        pub context_specific_optional: Option<bool>,
        #[asn1(context_specific = "3", default = "default_false_example")]
        pub context_specific_default: bool,
        #[asn1(type = "BIT STRING", context_specific = "4", optional = "true")]
        pub typed_context_specific_optional_bits: Option<&'a [u8]>,
        #[asn1(type = "OCTET STRING", context_specific = "5", optional = "true")]
        pub typed_context_specific_optional_implicit: Option<&'a [u8]>,
        #[asn1(
            type = "OCTET STRING",
            context_specific = "6",
            optional = "true",
            tag_mode = "EXPLICIT"
        )]
        pub typed_context_specific_optional_explicit: Option<&'a [u8]>,
    }

    #[test]
    fn type_combinations_instance() {
        let obj = TypeCheckExpandedSequenceFieldAttributeCombinations {
            context_specific_optional: Some(true),
            typed_context_specific: &[0, 1],
            typed_context_specific_optional_bits: Some(&[2, 3]),
            typed_context_specific_optional_implicit: Some(&[4, 5, 6]),
            typed_context_specific_optional_explicit: Some(&[7, 8]),

            ..Default::default()
        };

        let der_encoded = obj.to_der().unwrap();
        let obj_decoded =
            TypeCheckExpandedSequenceFieldAttributeCombinations::from_der(&der_encoded).unwrap();
        assert_eq!(obj, obj_decoded);
    }

    #[derive(Sequence, Default, Eq, PartialEq, Debug)]
    #[asn1(tag_mode = "IMPLICIT")]
    pub struct TypeCheckOwnedSequenceFieldAttributeCombinations {
        /// Without deref = "true" macro generates an error:
        ///
        /// the trait `From<Vec<u8>>` is not implemented for `BitStringRef<'_>`
        #[asn1(type = "OCTET STRING", deref = "true")]
        pub owned_bytes: Vec<u8>,

        #[asn1(type = "BIT STRING", deref = "true")]
        pub owned_bits: Vec<u8>,

        /// pure Vec<.> Needs additional deref in the derive macro
        /// for the `OctetStringRef::try_from`
        #[asn1(type = "OCTET STRING", context_specific = "0", deref = "true")]
        pub owned_implicit_bytes: Vec<u8>,

        /// deref
        #[asn1(type = "BIT STRING", context_specific = "1", deref = "true")]
        pub owned_implicit_bits: Vec<u8>,

        /// deref
        #[asn1(
            type = "OCTET STRING",
            context_specific = "2",
            deref = "true",
            tag_mode = "EXPLICIT"
        )]
        pub owned_explicit_bytes: Vec<u8>,

        /// deref
        #[asn1(
            type = "BIT STRING",
            context_specific = "3",
            deref = "true",
            tag_mode = "EXPLICIT"
        )]
        pub owned_explicit_bits: Vec<u8>,

        /// Option<Vec<..>> does not need deref
        #[asn1(type = "BIT STRING", context_specific = "4", optional = "true")]
        pub owned_optional_implicit_bits: Option<Vec<u8>>,
        #[asn1(type = "OCTET STRING", context_specific = "5", optional = "true")]
        pub owned_optional_implicit_bytes: Option<Vec<u8>>,

        #[asn1(
            type = "BIT STRING",
            context_specific = "6",
            optional = "true",
            tag_mode = "EXPLICIT"
        )]
        pub owned_optional_explicit_bits: Option<Vec<u8>>,
        #[asn1(
            type = "OCTET STRING",
            context_specific = "7",
            optional = "true",
            tag_mode = "EXPLICIT"
        )]
        pub owned_optional_explicit_bytes: Option<Vec<u8>>,
    }

    #[test]
    fn type_combinations_alloc_instance() {
        let obj = TypeCheckOwnedSequenceFieldAttributeCombinations {
            owned_bytes: vec![0xAA, 0xBB],
            owned_bits: vec![0xCC, 0xDD],

            owned_implicit_bytes: vec![0, 1],
            owned_implicit_bits: vec![2, 3],

            owned_explicit_bytes: vec![4, 5],
            owned_explicit_bits: vec![6, 7],

            owned_optional_implicit_bits: Some(vec![8, 9]),
            owned_optional_implicit_bytes: Some(vec![10, 11]),

            owned_optional_explicit_bits: Some(vec![12, 13]),
            owned_optional_explicit_bytes: Some(vec![14, 15]),
        };

        let der_encoded = obj.to_der().unwrap();
        let obj_decoded =
            TypeCheckOwnedSequenceFieldAttributeCombinations::from_der(&der_encoded).unwrap();
        assert_eq!(obj, obj_decoded);
    }

    #[derive(Sequence)]
    #[asn1(error = CustomError)]
    pub struct TypeWithCustomError {
        pub simple: bool,
    }

    #[test]
    fn idp_test() {
        let idp = IssuingDistributionPointExample::from_der(&hex!("30038101FF")).unwrap();
        assert_eq!(idp.only_contains_user_certs, true);
        assert_eq!(idp.only_contains_cacerts, false);
        assert_eq!(idp.indirect_crl, false);
        assert_eq!(idp.only_contains_attribute_certs, false);

        let idp = IssuingDistributionPointExample::from_der(&hex!("30038201FF")).unwrap();
        assert_eq!(idp.only_contains_user_certs, false);
        assert_eq!(idp.only_contains_cacerts, true);
        assert_eq!(idp.indirect_crl, false);
        assert_eq!(idp.only_contains_attribute_certs, false);

        let idp = IssuingDistributionPointExample::from_der(&hex!("30038401FF")).unwrap();
        assert_eq!(idp.only_contains_user_certs, false);
        assert_eq!(idp.only_contains_cacerts, false);
        assert_eq!(idp.indirect_crl, true);
        assert_eq!(idp.only_contains_attribute_certs, false);

        let idp = IssuingDistributionPointExample::from_der(&hex!("30038501FF")).unwrap();
        assert_eq!(idp.only_contains_user_certs, false);
        assert_eq!(idp.only_contains_cacerts, false);
        assert_eq!(idp.indirect_crl, false);
        assert_eq!(idp.only_contains_attribute_certs, true);
    }

    // demonstrates default field that is not context specific
    #[test]
    fn extension_test() {
        let ext1 = ExtensionExample::from_der(&hex!(
            "300F"        //  0  15: SEQUENCE {
            "0603551D13"  //  2   3:   OBJECT IDENTIFIER basicConstraints (2 5 29 19)
            "0101FF"      //  7   1:   BOOLEAN TRUE
            "0405"        //  10   5:   OCTET STRING, encapsulates {
            "3003"        //  12   3:     SEQUENCE {
            "0101FF"      //  14   1:       BOOLEAN TRUE
        ))
        .unwrap();
        assert_eq!(ext1.critical, true);

        let ext2 = ExtensionExample::from_der(&hex!(
            "301F"                                            //  0  31: SEQUENCE {
            "0603551D23"                                      //  2   3:   OBJECT IDENTIFIER authorityKeyIdentifier (2 5 29 35)
            "0418"                                            //  7  24:   OCTET STRING, encapsulates {
            "3016"                                            //  9  22:     SEQUENCE {
            "8014E47D5FD15C9586082C05AEBE75B665A7D95DA866"    // 11  20:       [0] E4 7D 5F D1 5C 95 86 08 2C 05 AE BE 75 B6 65 A7 D9 5D A8 66
        ))
        .unwrap();
        assert_eq!(ext2.critical, false);
    }

    #[test]
    fn decode() {
        let algorithm_identifier = AlgorithmIdentifier::from_der(ALGORITHM_IDENTIFIER_DER).unwrap();

        assert_eq!(ID_EC_PUBLIC_KEY_OID, algorithm_identifier.algorithm);
        assert_eq!(
            PRIME256V1_OID,
            ObjectIdentifier::try_from(algorithm_identifier.parameters.unwrap()).unwrap()
        );

        let t = TypeWithCustomError::from_der(&hex!("30030101FF")).unwrap();
        assert!(t.simple);
    }

    #[test]
    fn encode() {
        let parameters_oid = PRIME256V1_OID;

        let algorithm_identifier = AlgorithmIdentifier {
            algorithm: ID_EC_PUBLIC_KEY_OID,
            parameters: Some(AnyRef::from(&parameters_oid)),
        };

        assert_eq!(
            ALGORITHM_IDENTIFIER_DER,
            algorithm_identifier.to_der().unwrap()
        );
    }
}

/// Custom derive test cases for the `EncodeValue` macro.
mod encode_value {
    use der::{Encode, EncodeValue, FixedTag, Tag};
    use hex_literal::hex;

    #[derive(EncodeValue, Default, Eq, PartialEq, Debug)]
    #[asn1(tag_mode = "IMPLICIT")]
    pub struct EncodeOnlyCheck<'a> {
        #[asn1(type = "OCTET STRING", context_specific = "5")]
        pub field: &'a [u8],
    }
    impl FixedTag for EncodeOnlyCheck<'_> {
        const TAG: Tag = Tag::Sequence;
    }

    #[test]
    fn sequence_encode_only_to_der() {
        let obj = EncodeOnlyCheck {
            field: &[0x33, 0x44],
        };

        let der_encoded = obj.to_der().unwrap();

        assert_eq!(der_encoded, hex!("30 04 85 02 33 44"));
    }
}

/// Custom derive test cases for the `DecodeValue` macro.
mod decode_value {
    use der::{Decode, DecodeValue, FixedTag, Tag};
    use hex_literal::hex;

    #[derive(DecodeValue, Default, Eq, PartialEq, Debug)]
    #[asn1(tag_mode = "IMPLICIT")]
    pub struct DecodeOnlyCheck<'a> {
        #[asn1(type = "OCTET STRING", context_specific = "5")]
        pub field: &'a [u8],
    }
    impl FixedTag for DecodeOnlyCheck<'_> {
        const TAG: Tag = Tag::Sequence;
    }

    #[test]
    fn sequence_decode_only_from_der() {
        let obj = DecodeOnlyCheck::from_der(&hex!("30 04 85 02 33 44")).unwrap();

        assert_eq!(obj.field, &[0x33, 0x44]);
    }
}

/// Custom derive test cases for the `BitString` macro.
#[cfg(feature = "std")]
mod bitstring {
    use der::BitString;
    use der::Decode;
    use der::Encode;
    use hex_literal::hex;

    const BITSTRING_EXAMPLE: &[u8] = &hex!("03 03 06 03 80");

    // this BitString allows only 10..=10 bits
    #[derive(BitString)]
    pub struct MyBitStringTest {
        pub first_bit: bool,
        pub second_bit: bool,
        pub third_bit: bool,
        pub fourth_bit: bool,
        pub a: bool,
        pub b: bool,
        pub almost_least_significant: bool,
        pub least_significant_bit: bool,

        // second byte
        pub second_byte_bit: bool,
        pub second_byte_bit2: bool,
    }

    #[test]
    fn decode_bitstring() {
        let test_flags = MyBitStringTest::from_der(BITSTRING_EXAMPLE).unwrap();

        assert!(!test_flags.first_bit);

        assert!(test_flags.almost_least_significant);
        assert!(test_flags.least_significant_bit);
        assert!(test_flags.second_byte_bit);
        assert!(!test_flags.second_byte_bit2);

        let reencoded = test_flags.to_der().unwrap();

        assert_eq!(reencoded, BITSTRING_EXAMPLE);
    }

    /// this BitString will allow only 3..=4 bits in Decode
    ///
    /// but will always Encode 4 bits
    #[derive(BitString)]
    pub struct MyBitString3or4 {
        pub bit_0: bool,
        pub bit_1: bool,
        pub bit_2: bool,

        #[asn1(optional = "true")]
        pub bit_3: bool,
    }

    #[test]
    fn decode_bitstring_3_used_first_lit() {
        // 5 unused bits, so 3 used
        let bits_3 = MyBitString3or4::from_der(&hex!("03 02 05 80")).unwrap();

        assert!(bits_3.bit_0);
        assert!(!bits_3.bit_1);
        assert!(!bits_3.bit_2);
        assert!(!bits_3.bit_3);
    }
    #[test]
    fn decode_bitstring_3_used_all_lit() {
        // 5 unused bits, so 3 used
        let bits_3 = MyBitString3or4::from_der(&hex!("03 02 05 FF")).unwrap();

        assert!(bits_3.bit_0);
        assert!(bits_3.bit_1);
        assert!(bits_3.bit_2);
        assert!(!bits_3.bit_3);
    }

    #[test]
    fn decode_bitstring_4_used_all_lit() {
        // 4 unused bits, so 4 used
        let bits_3 = MyBitString3or4::from_der(&hex!("03 02 04 FF")).unwrap();

        assert!(bits_3.bit_0);
        assert!(bits_3.bit_1);
        assert!(bits_3.bit_2);
        assert!(bits_3.bit_3);
    }

    #[test]
    fn decode_invalid_bitstring_5_used() {
        // 3 unused bits, so 5 used
        assert!(MyBitString3or4::from_der(&hex!("03 02 03 FF")).is_err());
    }

    #[test]
    fn decode_invalid_bitstring_2_used() {
        // 6 unused bits, so 2 used
        assert!(MyBitString3or4::from_der(&hex!("03 02 06 FF")).is_err());
    }

    #[test]
    fn encode_3_zero_bits() {
        let encoded_3_zeros = MyBitString3or4 {
            bit_0: false,
            bit_1: false,
            bit_2: false,
            bit_3: false,
        }
        .to_der()
        .unwrap();

        // 4 bits used, 4 unused
        assert_eq!(encoded_3_zeros, hex!("03 02 04 00"));
    }

    #[test]
    fn encode_3_one_bits() {
        let encoded_3_zeros = MyBitString3or4 {
            bit_0: true,
            bit_1: true,
            bit_2: true,
            bit_3: false,
        }
        .to_der()
        .unwrap();

        // 4 bits used, 4 unused
        assert_eq!(encoded_3_zeros, hex!("03 02 04 E0"));
    }

    #[test]
    fn encode_4_one_bits() {
        let encoded_4_zeros = MyBitString3or4 {
            bit_0: true,
            bit_1: true,
            bit_2: true,
            bit_3: true,
        }
        .to_der()
        .unwrap();

        // 4 bits used, 4 unused
        assert_eq!(encoded_4_zeros, hex!("03 02 04 F0"));
    }

    #[test]
    fn encode_optional_one_4_used() {
        let encoded_4_zeros = MyBitString3or4 {
            bit_0: false,
            bit_1: false,
            bit_2: false,
            bit_3: true,
        }
        .to_der()
        .unwrap();

        // 4 bits used, 4 unused
        assert_eq!(encoded_4_zeros, hex!("03 02 04 10"));
    }

    /// ```asn1
    /// PasswordFlags ::= BIT STRING {
    ///     case-sensitive (0),
    ///     local (1),
    ///     change-disabled (2),
    ///     unblock-disabled (3),
    ///     initialized (4),
    ///     needs-padding (5),
    ///     unblockingPassword (6),
    ///     soPassword (7),
    ///     disable-allowed (8),
    ///     integrity-protected (9),
    ///     confidentiality-protected (10),
    ///     exchangeRefData (11),
    ///     resetRetryCounter1 (12),
    ///     resetRetryCounter2 (13),
    ///     context-dependent (14),
    ///     multiStepProtocol (15)
    /// }
    ///  ```
    #[derive(Clone, Debug, Eq, PartialEq, BitString)]
    pub struct PasswordFlags {
        /// case-sensitive (0)
        pub case_sensitive: bool,

        /// local (1)
        pub local: bool,

        /// change-disabled (2)
        pub change_disabled: bool,

        /// unblock-disabled (3)
        pub unblock_disabled: bool,

        /// initialized (4)
        pub initialized: bool,

        /// needs-padding (5)
        pub needs_padding: bool,

        /// unblockingPassword (6)
        pub unblocking_password: bool,

        /// soPassword (7)
        pub so_password: bool,

        /// disable-allowed (8)
        pub disable_allowed: bool,

        /// integrity-protected (9)
        pub integrity_protected: bool,

        /// confidentiality-protected (10)
        pub confidentiality_protected: bool,

        /// exchangeRefData (11)
        pub exchange_ref_data: bool,

        /// Second edition 2016-05-15
        /// resetRetryCounter1 (12)
        #[asn1(optional = "true")]
        pub reset_retry_counter1: bool,

        /// resetRetryCounter2 (13)
        #[asn1(optional = "true")]
        pub reset_retry_counter2: bool,

        /// context-dependent (14)
        #[asn1(optional = "true")]
        pub context_dependent: bool,

        /// multiStepProtocol (15)
        #[asn1(optional = "true")]
        pub multi_step_protocol: bool,

        /// fake_bit_for_testing (16)
        #[asn1(optional = "true")]
        pub fake_bit_for_testing: bool,
    }

    const PASS_FLAGS_EXAMPLE_IN: &[u8] = &hex!("03 03 04 FF FF");
    const PASS_FLAGS_EXAMPLE_OUT: &[u8] = &hex!("03 04 07 FF F0 00");

    #[test]
    fn decode_short_bitstring_2_bytes() {
        let pass_flags = PasswordFlags::from_der(PASS_FLAGS_EXAMPLE_IN).unwrap();

        // case-sensitive (0)
        assert!(pass_flags.case_sensitive);

        // exchangeRefData (11)
        assert!(pass_flags.exchange_ref_data);

        // resetRetryCounter1 (12)
        assert!(!pass_flags.reset_retry_counter1);

        let reencoded = pass_flags.to_der().unwrap();

        assert_eq!(reencoded, PASS_FLAGS_EXAMPLE_OUT);
    }
}
mod infer_default {
    //! When another crate might define a PartialEq for another type, the use of
    //! `default="Default::default"` in the der derivation will not provide enough
    //! information for `der_derive` crate to figure out.
    //!
    //! This provides a reproduction for that case. This is intended to fail when we
    //! compile tests.
    //! ```
    //! error[E0282]: type annotations needed
    //!   --> der/tests/derive.rs:480:26
    //!    |
    //!480 |         #[asn1(default = "Default::default")]
    //!    |                          ^^^^^^^^^^^^^^^^^^ cannot infer type
    //!
    //!error[E0283]: type annotations needed
    //!   --> der/tests/derive.rs:478:14
    //!    |
    //!478 |     #[derive(Sequence)]
    //!    |              ^^^^^^^^ cannot infer type
    //!    |
    //!note: multiple `impl`s satisfying `bool: PartialEq<_>` found
    //!   --> der/tests/derive.rs:472:5
    //!    |
    //!472 |     impl PartialEq<BooleanIsh> for bool {
    //!    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    //!    = note: and another `impl` found in the `core` crate:
    //!            - impl<host> PartialEq for bool
    //!              where the constant `host` has type `bool`;
    //!    = note: required for `&bool` to implement `PartialEq<&_>`
    //!    = note: this error originates in the derive macro `Sequence` (in Nightly builds, run with -Z macro-backtrace for more info)
    //! ```

    use der::Sequence;

    struct BooleanIsh;

    impl PartialEq<BooleanIsh> for bool {
        fn eq(&self, _other: &BooleanIsh) -> bool {
            unimplemented!("This is only here to mess up the compiler's type inference")
        }
    }

    #[derive(Sequence)]
    struct Foo {
        #[asn1(default = "Default::default")]
        pub use_default_default: bool,

        #[asn1(default = "something_true")]
        pub use_custom: bool,
    }

    fn something_true() -> bool {
        todo!()
    }
}
