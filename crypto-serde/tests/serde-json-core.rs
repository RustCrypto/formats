//! JSON-specific tests.

#![cfg(feature = "alloc")]

use crypto_serde::{array, slice};
use hex_literal::hex;
use proptest::{prelude::*, string::*};
use serde::Serialize;
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
    let serialized = serialize(&slice::HexLowerOrBin::from(EXAMPLE_BYTES.as_ref()));
    assert_eq!(serialized, HEX_LOWER);

    let deserialized = json::from_str::<slice::HexLowerOrBin>(&serialized)
        .unwrap()
        .0;
    assert_eq!(deserialized.as_ref(), EXAMPLE_BYTES);
}

#[test]
fn hex_upper() {
    let serialized = serialize(&slice::HexUpperOrBin::from(EXAMPLE_BYTES.as_ref()));
    assert_eq!(serialized, HEX_UPPER);

    let deserialized = json::from_str::<slice::HexUpperOrBin>(&serialized)
        .unwrap()
        .0;
    assert_eq!(deserialized.as_ref(), EXAMPLE_BYTES);
}

#[test]
fn array() {
    let serialized = serialize(&array::HexLowerOrBin::from(EXAMPLE_BYTES));
    assert_eq!(serialized, HEX_LOWER);

    let deserialized = json::from_str::<array::HexLowerOrBin<16>>(&serialized)
        .unwrap()
        .0;
    assert_eq!(deserialized.0, EXAMPLE_BYTES);
}

proptest! {
    #[test]
    fn round_trip_lower(bytes in bytes_regex(".{0,256}").unwrap()) {
        let serialized = serialize(&slice::HexLowerOrBin::from(bytes.as_ref()));
        let deserialized = json::from_str::<slice::HexLowerOrBin>(&serialized).unwrap().0;
        prop_assert_eq!(bytes, deserialized.0);
    }

    #[test]
    fn round_trip_upper(bytes in bytes_regex(".{0,256}").unwrap()) {
        let serialized = serialize(&slice::HexUpperOrBin::from(bytes.as_ref()));
        let deserialized = json::from_str::<slice::HexUpperOrBin>(&serialized).unwrap().0;
        prop_assert_eq!(bytes, deserialized.0);
    }
}
