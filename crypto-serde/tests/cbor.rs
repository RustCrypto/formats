//! CBOR-specific tests.

#![cfg(feature = "alloc")]

use ciborium::{de, ser};
use crypto_serde::{array, slice};
use hex_literal::hex;
use proptest::{prelude::*, string::*};

/// Example input to be serialized.
const EXAMPLE_BYTES: [u8; 16] = hex!("000102030405060708090A0B0C0D0E0F");

/// CBOR serialization of [`EXAMPLE_BYTES`] as a slice.
const CBOR_SLICE: [u8; 17] = hex!("90000102030405060708090A0B0C0D0E0F");

/// CBOR serialization of [`EXAMPLE_BYTES`] as an array.
const CBOR_ARRAY: [u8; 17] = CBOR_SLICE;

#[test]
fn deserialize() {
    let deserialized = de::from_reader::<slice::HexUpperOrBin, _>(CBOR_SLICE.as_ref()).unwrap();
    assert_eq!(deserialized.as_ref(), EXAMPLE_BYTES);
}

#[test]
fn deserialize_array() {
    let deserialized = de::from_reader::<array::HexUpperOrBin<16>, _>(CBOR_SLICE.as_ref()).unwrap();
    assert_eq!(deserialized.as_ref(), EXAMPLE_BYTES);
}

#[test]
fn serialize() {
    let mut serialized = Vec::new();
    ser::into_writer(
        &slice::HexUpperOrBin::from(EXAMPLE_BYTES.as_ref()),
        &mut serialized,
    )
    .unwrap();
    assert_eq!(&serialized, &CBOR_SLICE);
}

#[test]
fn serialize_array() {
    let mut serialized = Vec::new();
    ser::into_writer(&array::HexUpperOrBin::from(EXAMPLE_BYTES), &mut serialized).unwrap();
    assert_eq!(&serialized, &CBOR_ARRAY);
}

proptest! {
    #[test]
    fn round_trip(bytes in bytes_regex(".{0,256}").unwrap()) {
        let mut serialized = Vec::new();
        ser::into_writer(&slice::HexUpperOrBin::from(bytes.as_ref()), &mut serialized).unwrap();

        let deserialized = de::from_reader::<slice::HexUpperOrBin, _>(serialized.as_slice()).unwrap();
        prop_assert_eq!(bytes, deserialized.0);
    }
}
