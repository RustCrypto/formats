//! bincode-specific tests.

#![cfg(feature = "alloc")]

use crypto_serde::{array, slice};
use hex_literal::hex;
use proptest::{prelude::*, string::*};

/// Example input to be serialized.
const EXAMPLE_BYTES: [u8; 16] = hex!("000102030405060708090A0B0C0D0E0F");

/// bincode serialization of [`EXAMPLE_BYTES`] as a slice.
const BINCODE_SLICE: [u8; 24] = hex!("1000000000000000000102030405060708090A0B0C0D0E0F");

/// bincode serialization of [`EXAMPLE_BYTES`] as an array.
const BINCODE_ARRAY: [u8; 16] = EXAMPLE_BYTES;

#[test]
fn deserialize() {
    let deserialized = bincode::deserialize::<slice::HexUpperOrBin>(&BINCODE_SLICE).unwrap();
    assert_eq!(deserialized.as_ref(), EXAMPLE_BYTES);
}

#[test]
fn deserialize_owned() {
    let deserialized =
        bincode::deserialize_from::<_, slice::HexUpperOrBin>(BINCODE_SLICE.as_ref()).unwrap();
    assert_eq!(deserialized.as_ref(), EXAMPLE_BYTES);
}

#[test]
fn deserialize_array() {
    let deserialized = bincode::deserialize::<array::HexUpperOrBin<16>>(&BINCODE_ARRAY).unwrap();
    assert_eq!(deserialized.0, EXAMPLE_BYTES);

    let deserialized =
        bincode::deserialize_from::<_, array::HexUpperOrBin<16>>(BINCODE_ARRAY.as_ref()).unwrap();
    assert_eq!(deserialized.0, EXAMPLE_BYTES);
}

#[test]
fn serialize() {
    let serialized =
        bincode::serialize(&slice::HexUpperOrBin::from(EXAMPLE_BYTES.as_ref())).unwrap();
    assert_eq!(&serialized, &BINCODE_SLICE);
}

#[test]
fn serialize_array() {
    let serialized = bincode::serialize(&array::HexUpperOrBin::from(EXAMPLE_BYTES)).unwrap();
    assert_eq!(&serialized, &BINCODE_ARRAY);
}

proptest! {
    #[test]
    fn round_trip(bytes in bytes_regex(".{0,256}").unwrap()) {
        let serialized = bincode::serialize(&slice::HexUpperOrBin::from(bytes.as_ref())).unwrap();
        let deserialized = bincode::deserialize::<slice::HexUpperOrBin>(&serialized).unwrap();
        prop_assert_eq!(bytes, deserialized.0);
    }
}
