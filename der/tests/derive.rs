//! Tests for custom derive support.
//!
//! # Debugging with `cargo expand`
//!
//! To expand the Rust code generated by the proc macro when debugging
//! issues related to these tests, run:
//!
//! $ cargo +nightly expand --test derive --all-features

// TODO(tarcieri): test all types supported by `der_derive`

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
        asn1::{Any, ObjectIdentifier},
        Decodable, Encodable, Sequence,
    };
    use hex_literal::hex;

    /// X.509 `AlgorithmIdentifier`
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence)]
    pub struct AlgorithmIdentifier<'a> {
        pub algorithm: ObjectIdentifier,
        pub parameters: Option<Any<'a>>,
    }

    /// X.509 `SubjectPublicKeyInfo` (SPKI)
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence)]
    pub struct SubjectPublicKeyInfo<'a> {
        pub algorithm: AlgorithmIdentifier<'a>,

        #[asn1(type = "BIT STRING")]
        pub subject_public_key: &'a [u8],
    }

    const ID_EC_PUBLIC_KEY_OID: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.2.1");
    const PRIME256V1_OID: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.3.1.7");

    const ALGORITHM_IDENTIFIER_DER: &[u8] =
        &hex!("30 13 06 07 2a 86 48 ce 3d 02 01 06 08 2a 86 48 ce 3d 03 01 07");

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
