//! TOML-specific tests.

#![cfg(feature = "alloc")]

use crypto_serde::{array, slice};
use hex_literal::hex;
use proptest::{array::*, collection::vec, prelude::*};
use serde::{Deserialize, Serialize};

/// Example input to be serialized.
const EXAMPLE_BYTES: [u8; 16] = hex!("000102030405060708090A0B0C0D0E0F");

/// Lower-case hex serialization of [`EXAMPLE_BYTES`].
const HEX_LOWER: &str = "\"000102030405060708090a0b0c0d0e0f\"";

/// Upper-case hex serialization of [`EXAMPLE_BYTES`].
const HEX_UPPER: &str = "\"000102030405060708090A0B0C0D0E0F\"";

#[test]
fn serialize_slice() {
    let serialized = toml::to_string(&slice::HexLowerOrBin::from(EXAMPLE_BYTES.as_ref())).unwrap();
    assert_eq!(serialized, HEX_LOWER);

    let serialized = toml::to_string(&slice::HexUpperOrBin::from(EXAMPLE_BYTES.as_ref())).unwrap();
    assert_eq!(serialized, HEX_UPPER);
}

#[test]
fn serialize_array() {
    let serialized = toml::to_string(&array::HexLowerOrBin::from(EXAMPLE_BYTES)).unwrap();
    assert_eq!(serialized, HEX_LOWER);

    let serialized = toml::to_string(&array::HexUpperOrBin::from(EXAMPLE_BYTES)).unwrap();
    assert_eq!(serialized, HEX_UPPER);
}

#[test]
fn deserialize_slice() {
    #[derive(Deserialize, Serialize)]
    pub struct Test {
        lower: slice::HexLowerOrBin,
        upper: slice::HexUpperOrBin,
    }

    let deserialized =
        toml::from_str::<Test>(&format!("lower={}\nupper={}", HEX_LOWER, HEX_UPPER)).unwrap();

    assert_eq!(deserialized.lower.0, EXAMPLE_BYTES);
    assert_eq!(deserialized.upper.0, EXAMPLE_BYTES);
}

#[test]
fn deserialize_array() {
    #[derive(Deserialize, Serialize)]
    pub struct Test {
        lower: array::HexLowerOrBin<16>,
        upper: array::HexUpperOrBin<16>,
    }

    let deserialized =
        toml::from_str::<Test>(&format!("lower={}\nupper={}", HEX_LOWER, HEX_UPPER)).unwrap();

    assert_eq!(deserialized.lower.0, EXAMPLE_BYTES);
    assert_eq!(deserialized.upper.0, EXAMPLE_BYTES);
}

proptest! {
    #[test]
    fn round_trip_slice_lower(bytes in vec(any::<u8>(), 0..1024)) {
        #[derive(Debug, Deserialize, PartialEq, Serialize)]
        pub struct Test {
            test: slice::HexLowerOrBin,
        }

        let test = Test { test: slice::HexLowerOrBin::from(bytes.as_ref()) };

        let serialized = toml::to_string(&test).unwrap();
        let deserialized = toml::from_str::<Test>(&serialized).unwrap();
        prop_assert_eq!(test, deserialized);
    }

    #[test]
    fn round_trip_slice_upper(bytes in vec(any::<u8>(), 0..1024)) {
        #[derive(Debug, Deserialize, PartialEq, Serialize)]
        pub struct Test {
            test: slice::HexUpperOrBin,
        }

        let test = Test { test: slice::HexUpperOrBin::from(bytes.as_ref()) };

        let serialized = toml::to_string(&test).unwrap();
        let deserialized = toml::from_str::<Test>(&serialized).unwrap();
        prop_assert_eq!(test, deserialized);
    }

    #[test]
    fn round_trip_array_lower(bytes in uniform32(0u8..)) {
        #[derive(Debug, Deserialize, PartialEq, Serialize)]
        pub struct Test {
            test: array::HexLowerOrBin<32>,
        }

        let test = Test { test: array::HexLowerOrBin::from(bytes) };

        let serialized = toml::to_string(&test).unwrap();
        let deserialized = toml::from_str::<Test>(&serialized).unwrap();
        prop_assert_eq!(test, deserialized);
    }

    #[test]
    fn round_trip_array_upper(bytes in uniform32(0u8..)) {
        #[derive(Debug, Deserialize, PartialEq, Serialize)]
        pub struct Test {
            test: array::HexUpperOrBin<32>,
        }

        let test = Test { test: array::HexUpperOrBin::from(bytes) };

        let serialized = toml::to_string(&test).unwrap();
        let deserialized = toml::from_str::<Test>(&serialized).unwrap();
        prop_assert_eq!(test, deserialized);
    }
}
