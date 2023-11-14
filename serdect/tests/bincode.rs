//! bincode-specific tests.

#![cfg(feature = "alloc")]

use hex_literal::hex;
use proptest::{array::*, collection::vec, prelude::*};
use serdect::{array, slice};

/// Example input to be serialized.
/// Last byte is `0xFF` to test that no packing is performed for values under 128.
const EXAMPLE_BYTES: [u8; 16] = hex!("000102030405060708090A0B0C0D0EFF");

/// bincode serialization of [`EXAMPLE_BYTES`] as a slice.
const BINCODE_SLICE: [u8; 24] = hex!("1000000000000000000102030405060708090A0B0C0D0EFF");

#[test]
fn deserialize_slice() {
    let deserialized = bincode::deserialize::<slice::HexUpperOrBin>(&BINCODE_SLICE).unwrap();
    assert_eq!(deserialized.0, EXAMPLE_BYTES);
}

#[test]
fn deserialize_slice_owned() {
    let deserialized =
        bincode::deserialize_from::<_, slice::HexUpperOrBin>(BINCODE_SLICE.as_ref()).unwrap();
    assert_eq!(deserialized.0, EXAMPLE_BYTES);
}

#[test]
fn deserialize_array() {
    let deserialized = bincode::deserialize::<array::HexUpperOrBin<16>>(&BINCODE_SLICE).unwrap();
    assert_eq!(deserialized.0, EXAMPLE_BYTES);
}

#[test]
fn deserialize_array_owned() {
    let deserialized =
        bincode::deserialize_from::<_, array::HexUpperOrBin<16>>(BINCODE_SLICE.as_ref()).unwrap();
    assert_eq!(deserialized.0, EXAMPLE_BYTES);
}

#[test]
fn serialize_slice() {
    let serialized =
        bincode::serialize(&slice::HexUpperOrBin::from(EXAMPLE_BYTES.as_ref())).unwrap();
    assert_eq!(&serialized, &BINCODE_SLICE);
}

#[test]
fn serialize_array() {
    let serialized = bincode::serialize(&array::HexUpperOrBin::from(EXAMPLE_BYTES)).unwrap();
    assert_eq!(&serialized, &BINCODE_SLICE);
}

proptest! {
    #[test]
    fn round_trip_slice(bytes in vec(any::<u8>(), 0..1024)) {
        let serialized = bincode::serialize(&slice::HexUpperOrBin::from(bytes.as_ref())).unwrap();
        let deserialized = bincode::deserialize::<slice::HexUpperOrBin>(&serialized).unwrap();
        prop_assert_eq!(bytes, deserialized.0);
    }

    #[test]
    fn round_trip_array(bytes in uniform32(0u8..)) {
        let serialized = bincode::serialize(&array::HexUpperOrBin::from(bytes)).unwrap();
        let deserialized = bincode::deserialize::<array::HexUpperOrBin<32>>(&serialized).unwrap();
        prop_assert_eq!(bytes, deserialized.0);
        // 8 bytes for the length tag + 32 bytes of data
        prop_assert_eq!(serialized.len(), 8 + 32);
    }
}
