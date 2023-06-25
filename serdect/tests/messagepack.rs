//! messagepack-specific tests.

#![cfg(feature = "alloc")]

use hex_literal::hex;
use proptest::{array::*, collection::vec, prelude::*};
use serdect::{array, slice};

/// Example input to be serialized.
/// Last byte is `0xFF` to test that no packing is performed for values under 128.
const EXAMPLE_BYTES: [u8; 16] = hex!("000102030405060708090A0B0C0D0EFF");

/// messagepack serialization of [`EXAMPLE_BYTES`] as a slice.
const MESSAGEPACK_SLICE: [u8; 18] = hex!("C410000102030405060708090A0B0C0D0EFF");

/// messagepack serialization of [`EXAMPLE_BYTES`] as an array.
/// Note the 0xCC marker before 0xFF, denoting that the integers are dynamically sized.
const MESSAGEPACK_ARRAY: [u8; 20] = hex!("DC0010000102030405060708090A0B0C0D0ECCFF");

#[test]
fn deserialize_slice() {
    let deserialized =
        rmp_serde::decode::from_slice::<slice::HexUpperOrBin>(&MESSAGEPACK_SLICE).unwrap();
    assert_eq!(deserialized.0, EXAMPLE_BYTES);
}

#[test]
fn deserialize_array() {
    let deserialized =
        rmp_serde::decode::from_slice::<array::HexUpperOrBin<16>>(&MESSAGEPACK_ARRAY).unwrap();
    assert_eq!(deserialized.0, EXAMPLE_BYTES);
}

#[test]
fn serialize_slice() {
    let serialized =
        rmp_serde::encode::to_vec(&slice::HexUpperOrBin::from(EXAMPLE_BYTES.as_ref())).unwrap();
    assert_eq!(&serialized, &MESSAGEPACK_SLICE);
}

#[test]
fn serialize_array() {
    let serialized = rmp_serde::encode::to_vec(&array::HexUpperOrBin::from(EXAMPLE_BYTES)).unwrap();
    assert_eq!(&serialized, &MESSAGEPACK_ARRAY);
}

proptest! {
    #[test]
    fn round_trip_slice(bytes in vec(any::<u8>(), 0..1024)) {
        let serialized = rmp_serde::encode::to_vec(&slice::HexUpperOrBin::from(bytes.as_ref())).unwrap();
        let deserialized = rmp_serde::decode::from_slice::<slice::HexUpperOrBin>(&serialized).unwrap();
        prop_assert_eq!(bytes, deserialized.0);
    }

    #[test]
    fn round_trip_array(bytes in uniform32(0u8..)) {
        let serialized = rmp_serde::encode::to_vec(&array::HexUpperOrBin::from(bytes)).unwrap();
        let deserialized = rmp_serde::decode::from_slice::<array::HexUpperOrBin<32>>(&serialized).unwrap();
        prop_assert_eq!(bytes, deserialized.0);
    }
}
