//! JSON-specific tests.

#![cfg(feature = "alloc")]

use crypto_serde::slice::{HexLowerOrBin, HexUpperOrBin};
use hex_literal::hex;
use proptest::{prelude::*, string::*};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json as json;

/// Example input to be serialized.
const EXAMPLE_BYTES: [u8; 16] = hex!("000102030405060708090A0B0C0D0E0F");

/// Lower-case hex serialization of [`EXAMPLE_BYTES`].
const HEX_LOWER: &str = "\"000102030405060708090a0b0c0d0e0f\"";

/// Upper-case hex serialization of [`EXAMPLE_BYTES`].
const HEX_UPPER: &str = "\"000102030405060708090A0B0C0D0E0F\"";

#[test]
fn hex_lower() {
    let serialized = json::to_string(&HexLowerOrBin::from(EXAMPLE_BYTES.as_ref())).unwrap();
    assert_eq!(serialized, HEX_LOWER);

    let deserialized = json::from_str::<HexLowerOrBin>(&serialized).unwrap();
    assert_eq!(deserialized.as_ref(), EXAMPLE_BYTES);
}

#[test]
fn hex_upper() {
    let serialized = json::to_string(&HexUpperOrBin::from(EXAMPLE_BYTES.as_ref())).unwrap();
    assert_eq!(serialized, HEX_UPPER);

    let deserialized = json::from_str::<HexUpperOrBin>(&serialized).unwrap();
    assert_eq!(deserialized.as_ref(), EXAMPLE_BYTES);
}

#[test]
fn array() {
    struct Test([u8; 16]);

    impl<'de> Deserialize<'de> for Test {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            crypto_serde::array::deserialize_hex_or_bin::<_, 16>(deserializer).map(Self)
        }
    }

    impl Serialize for Test {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            crypto_serde::array::serialize_hex_lower_or_bin(&self.0, serializer)
        }
    }

    let serialized = json::to_string(&Test(EXAMPLE_BYTES)).unwrap();
    assert_eq!(serialized, HEX_LOWER);

    let deserialized = json::from_str::<Test>(&serialized).unwrap();
    assert_eq!(deserialized.0, EXAMPLE_BYTES);
}

proptest! {
    #[test]
    fn round_trip_lower(bytes in bytes_regex(".{0,256}").unwrap()) {
        let serialized = json::to_string(&HexLowerOrBin::from(bytes.as_ref())).unwrap();
        let deserialized = json::from_str::<HexLowerOrBin>(&serialized).unwrap();
        prop_assert_eq!(bytes, deserialized.0);
    }

    #[test]
    fn round_trip_upper(bytes in bytes_regex(".{0,256}").unwrap()) {
        let serialized = json::to_string(&HexUpperOrBin::from(bytes.as_ref())).unwrap();
        let deserialized = json::from_str::<HexUpperOrBin>(&serialized).unwrap();
        prop_assert_eq!(bytes, deserialized.0);
    }
}
