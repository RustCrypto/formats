//! JSON-specific tests.

#![cfg(feature = "alloc")]

use crypto_serde::slice::{HexLowerOrBin, HexUpperOrBin};
use hex_literal::hex;
use proptest::{prelude::*, string::*};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json_core as json;

/// Example input to be serialized.
const EXAMPLE_BYTES: [u8; 16] = hex!("000102030405060708090A0B0C0D0E0F");

/// Lower-case hex serialization of [`EXAMPLE_BYTES`].
const HEX_LOWER: &str = "\"000102030405060708090a0b0c0d0e0f\"";

/// Upper-case hex serialization of [`EXAMPLE_BYTES`].
const HEX_UPPER: &str = "\"000102030405060708090A0B0C0D0E0F\"";

fn serialize<T>(value: &T) -> String
where
    T: Serialize + ?Sized,
{
    // Make sure proptest doesn't fail.
    let mut buffer = [0; 2048];
    let size = json::to_slice(value, &mut buffer).unwrap();
    std::str::from_utf8(&buffer[..size]).unwrap().to_string()
}

#[test]
fn hex_lower() {
    let serialized = serialize(&HexLowerOrBin::from(EXAMPLE_BYTES.as_ref()));
    assert_eq!(serialized, HEX_LOWER);

    let deserialized = json::from_str::<HexLowerOrBin>(&serialized).unwrap().0;
    assert_eq!(deserialized.as_ref(), EXAMPLE_BYTES);
}

#[test]
fn hex_upper() {
    let serialized = serialize(&HexUpperOrBin::from(EXAMPLE_BYTES.as_ref()));
    assert_eq!(serialized, HEX_UPPER);

    let deserialized = json::from_str::<HexUpperOrBin>(&serialized).unwrap().0;
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

    let serialized = serialize(&Test(EXAMPLE_BYTES));
    assert_eq!(serialized, HEX_LOWER);

    let deserialized = json::from_str::<Test>(&serialized).unwrap().0;
    assert_eq!(deserialized.0, EXAMPLE_BYTES);
}

proptest! {
    #[test]
    fn round_trip_lower(bytes in bytes_regex(".{0,256}").unwrap()) {
        let serialized = serialize(&HexLowerOrBin::from(bytes.as_ref()));
        let deserialized = json::from_str::<HexLowerOrBin>(&serialized).unwrap().0;
        prop_assert_eq!(bytes, deserialized.0);
    }

    #[test]
    fn round_trip_upper(bytes in bytes_regex(".{0,256}").unwrap()) {
        let serialized = serialize(&HexUpperOrBin::from(bytes.as_ref()));
        let deserialized = json::from_str::<HexUpperOrBin>(&serialized).unwrap().0;
        prop_assert_eq!(bytes, deserialized.0);
    }
}
