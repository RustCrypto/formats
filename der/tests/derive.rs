//! Tests for custom derive support.
//!
//! # Debugging with `cargo expand`
//!
//! To expand the Rust code generated by the proc macro when debugging
//! issues related to these tests, run:
//!
//! $ cargo expand --test derive --all-features

#![cfg(feature = "derive")]

/// Custom derive test cases for the `Choice` macro.
mod choice {
    /// `Choice` with `EXPLICIT` tagging.
    mod explicit {
        use der::{
            asn1::{GeneralizedTime, UtcTime},
            Choice, Decodable, Encodable, Encoder,
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
            fn to_unix_duration(self) -> Duration {
                match self {
                    Time::UtcTime(t) => t.to_unix_duration(),
                    Time::GeneralTime(t) => t.to_unix_duration(),
                }
            }
        }

        const UTC_TIMESTAMP_DER: &'static [u8] =
            &hex!("17 0d 39 31 30 35 30 36 32 33 34 35 34 30 5a");
        const GENERAL_TIMESTAMP_DER: &'static [u8] =
            &hex!("18 0f 31 39 39 31 30 35 30 36 32 33 34 35 34 30 5a");

        #[test]
        fn decode() {
            let utc_time = Time::from_der(UTC_TIMESTAMP_DER).unwrap();
            assert_eq!(utc_time.to_unix_duration().as_secs(), 673573540);

            let general_time = Time::from_der(GENERAL_TIMESTAMP_DER).unwrap();
            assert_eq!(general_time.to_unix_duration().as_secs(), 673573540);
        }

        #[test]
        fn encode() {
            let mut buf = [0u8; 128];

            let utc_time = Time::from_der(UTC_TIMESTAMP_DER).unwrap();
            let mut encoder = Encoder::new(&mut buf);
            utc_time.encode(&mut encoder).unwrap();
            assert_eq!(UTC_TIMESTAMP_DER, encoder.finish().unwrap());

            let general_time = Time::from_der(GENERAL_TIMESTAMP_DER).unwrap();
            let mut encoder = Encoder::new(&mut buf);
            general_time.encode(&mut encoder).unwrap();
            assert_eq!(GENERAL_TIMESTAMP_DER, encoder.finish().unwrap());
        }
    }

    /// `Choice` with `IMPLICIT` tagging.
    mod implicit {
        use der::{
            asn1::{BitString, GeneralizedTime},
            Choice, Decodable, Encodable, Encoder,
        };
        use hex_literal::hex;

        /// `Choice` macro test case for `IMPLICIT` tagging.
        #[derive(Choice, Debug, Eq, PartialEq)]
        #[asn1(tag_mode = "IMPLICIT")]
        pub enum ImplicitChoice<'a> {
            #[asn1(context_specific = "0", type = "BIT STRING")]
            BitString(BitString<'a>),

            #[asn1(context_specific = "1", type = "GeneralizedTime")]
            Time(GeneralizedTime),

            #[asn1(context_specific = "2", type = "UTF8String")]
            Utf8String(String),
        }

        impl<'a> ImplicitChoice<'a> {
            pub fn bit_string(&self) -> Option<BitString<'a>> {
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

        const BITSTRING_DER: &'static [u8] = &hex!("80 04 00 01 02 03");
        const TIME_DER: &'static [u8] = &hex!("81 0f 31 39 39 31 30 35 30 36 32 33 34 35 34 30 5a");

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
            let mut encoder = Encoder::new(&mut buf);
            cs_bit_string.encode(&mut encoder).unwrap();
            assert_eq!(BITSTRING_DER, encoder.finish().unwrap());

            let cs_time = ImplicitChoice::from_der(TIME_DER).unwrap();
            let mut encoder = Encoder::new(&mut buf);
            cs_time.encode(&mut encoder).unwrap();
            assert_eq!(TIME_DER, encoder.finish().unwrap());
        }
    }
}

/// Custom derive test cases for the `Enumerated` macro.
mod enumerated {
    use der::{Decodable, Encodable, Encoder, Enumerated};
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

    #[test]
    fn decode() {
        let unspecified = CrlReason::from_der(UNSPECIFIED_DER).unwrap();
        assert_eq!(CrlReason::Unspecified, unspecified);

        let key_compromise = CrlReason::from_der(KEY_COMPROMISE_DER).unwrap();
        assert_eq!(CrlReason::KeyCompromise, key_compromise);
    }

    #[test]
    fn encode() {
        let mut buf = [0u8; 128];

        let mut encoder = Encoder::new(&mut buf);
        CrlReason::Unspecified.encode(&mut encoder).unwrap();
        assert_eq!(UNSPECIFIED_DER, encoder.finish().unwrap());

        let mut encoder = Encoder::new(&mut buf);
        CrlReason::KeyCompromise.encode(&mut encoder).unwrap();
        assert_eq!(KEY_COMPROMISE_DER, encoder.finish().unwrap());
    }
}

/// Custom derive test cases for the `Sequence` macro.
mod sequence {
    use der::{
        asn1::{Any, ObjectIdentifier, SetOf},
        Decodable, Encodable, Sequence, ValueOrd,
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
        pub parameters: Option<Any<'a>>,
    }

    /// X.509 `SubjectPublicKeyInfo` (SPKI)
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
    pub struct SubjectPublicKeyInfo<'a> {
        pub algorithm: AlgorithmIdentifier<'a>,
        #[asn1(type = "BIT STRING")]
        pub subject_public_key: &'a [u8],
    }

    /// PKCS#8v2 `OneAsymmetricKey`
    #[derive(Sequence)]
    pub struct OneAsymmetricKey<'a> {
        pub version: u8,
        pub private_key_algorithm: AlgorithmIdentifier<'a>,
        #[asn1(type = "OCTET STRING")]
        pub private_key: &'a [u8],
        #[asn1(context_specific = "0", extensible = "true", optional = "true")]
        pub attributes: Option<SetOf<Any<'a>, 1>>,
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

    const ID_EC_PUBLIC_KEY_OID: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.2.1");
    const PRIME256V1_OID: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.3.1.7");

    const ALGORITHM_IDENTIFIER_DER: &[u8] =
        &hex!("30 13 06 07 2a 86 48 ce 3d 02 01 06 08 2a 86 48 ce 3d 03 01 07");

    #[derive(Sequence)]
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
        pub typed_context_specific_optional: Option<&'a [u8]>,
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
            "
            300F        //  0  15: SEQUENCE {
            0603551D13  //  2   3:   OBJECT IDENTIFIER basicConstraints (2 5 29 19)
            0101FF      //  7   1:   BOOLEAN TRUE
            0405        //  10   5:   OCTET STRING, encapsulates {
            3003        //  12   3:     SEQUENCE {
            0101FF      //  14   1:       BOOLEAN TRUE
            "
        ))
        .unwrap();
        assert_eq!(ext1.critical, true);

        let ext2 = ExtensionExample::from_der(&hex!(
            "
            301F                                            //  0  31: SEQUENCE {
            0603551D23                                      //  2   3:   OBJECT IDENTIFIER authorityKeyIdentifier (2 5 29 35)
            0418                                            //  7  24:   OCTET STRING, encapsulates {
            3016                                            //  9  22:     SEQUENCE {
            8014E47D5FD15C9586082C05AEBE75B665A7D95DA866    // 11  20:       [0] E4 7D 5F D1 5C 95 86 08 2C 05 AE BE 75 B6 65 A7 D9 5D A8 66
            "
        ))
        .unwrap();
        assert_eq!(ext2.critical, false);
    }

    #[test]
    fn decode() {
        let algorithm_identifier =
            AlgorithmIdentifier::from_der(&ALGORITHM_IDENTIFIER_DER).unwrap();

        assert_eq!(ID_EC_PUBLIC_KEY_OID, algorithm_identifier.algorithm);
        assert_eq!(
            PRIME256V1_OID,
            ObjectIdentifier::try_from(algorithm_identifier.parameters.unwrap()).unwrap()
        );
    }

    #[test]
    fn encode() {
        let parameters_oid = PRIME256V1_OID;

        let algorithm_identifier = AlgorithmIdentifier {
            algorithm: ID_EC_PUBLIC_KEY_OID,
            parameters: Some(Any::from(&parameters_oid)),
        };

        assert_eq!(
            ALGORITHM_IDENTIFIER_DER,
            algorithm_identifier.to_vec().unwrap()
        );
    }
}
