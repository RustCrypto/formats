//! bincode-specific tests.

#![cfg(feature = "alloc")]

use crypto_serde::HexUpperOrBin;
use hex_literal::hex;
use proptest::{prelude::*, string::*};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Example input to be serialized.
const EXAMPLE_BYTES: [u8; 16] = hex!("000102030405060708090A0B0C0D0E0F");

/// bincode serialization of [`EXAMPLE_BYTES`] as a slice.
const BINCODE_SLICE: [u8; 24] = hex!("1000000000000000000102030405060708090A0B0C0D0E0F");

/// bincode serialization of [`EXAMPLE_BYTES`] as an array.
const BINCODE_ARRAY: [u8; 16] = EXAMPLE_BYTES;

#[test]
fn deserialize() {
    let deserialized = bincode::deserialize::<HexUpperOrBin>(&BINCODE_SLICE).unwrap();
    assert_eq!(deserialized.as_ref(), EXAMPLE_BYTES);
}

#[test]
fn deserialize_owned() {
    let deserialized =
        bincode::deserialize_from::<_, HexUpperOrBin>(BINCODE_SLICE.as_slice()).unwrap();
    assert_eq!(deserialized.as_ref(), EXAMPLE_BYTES);
}

#[test]
fn deserialize_array() {
    struct Test([u8; 16]);

    impl<'de> Deserialize<'de> for Test {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            crypto_serde::deserialize_array_hex_or_bin::<16, _>(deserializer).map(Self)
        }
    }

    let deserialized = bincode::deserialize::<Test>(&BINCODE_ARRAY).unwrap();
    assert_eq!(deserialized.0, EXAMPLE_BYTES);

    let deserialized = bincode::deserialize_from::<_, Test>(BINCODE_ARRAY.as_slice()).unwrap();
    assert_eq!(deserialized.0, EXAMPLE_BYTES);
}

#[test]
fn serialize() {
    let serialized = bincode::serialize(&HexUpperOrBin::from(EXAMPLE_BYTES.as_slice())).unwrap();
    assert_eq!(&serialized, &BINCODE_SLICE);
}

#[test]
fn serialize_array() {
    struct Test([u8; 16]);

    impl Serialize for Test {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            crypto_serde::serialize_array_hex_upper_or_bin(&self.0, serializer)
        }
    }

    let serialized = bincode::serialize(&Test(EXAMPLE_BYTES)).unwrap();
    assert_eq!(&serialized, &BINCODE_ARRAY);
}

proptest! {
    #[test]
    fn round_trip(bytes in bytes_regex(".{0,256}").unwrap()) {
        let serialized = bincode::serialize(&HexUpperOrBin::from(bytes.as_ref())).unwrap();
        let deserialized = bincode::deserialize::<HexUpperOrBin>(&serialized).unwrap();
        prop_assert_eq!(bytes, deserialized.0);
    }
}
