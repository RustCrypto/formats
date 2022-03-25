//! CBOR-specific tests.

use ciborium::{de, ser};
use crypto_serde::HexUpperOrBin;
use hex_literal::hex;
use proptest::{prelude::*, string::*};

/// Example input to be serialized.
const EXAMPLE_BYTES: &[u8] = &hex!("000102030405060708090A0B0C0D0E0F");

/// CBOR serialization of [`EXAMPLE_BYTES`].
const CBOR_BYTES: &[u8] = &hex!("90000102030405060708090A0B0C0D0E0F");

#[test]
fn deserialize() {
    let deserialized = de::from_reader::<HexUpperOrBin, _>(CBOR_BYTES).unwrap();
    assert_eq!(deserialized.as_ref(), EXAMPLE_BYTES);
}

#[test]
fn serialize() {
    let mut serialized = Vec::new();
    ser::into_writer(&HexUpperOrBin::from(EXAMPLE_BYTES), &mut serialized).unwrap();
    assert_eq!(&serialized, CBOR_BYTES);
}

proptest! {
    #[test]
    fn round_trip(bytes in bytes_regex(".{0,256}").unwrap()) {
        let mut serialized = Vec::new();
        ser::into_writer(&HexUpperOrBin::from(bytes.as_ref()), &mut serialized).unwrap();

        let deserialized = de::from_reader::<HexUpperOrBin, _>(serialized.as_slice()).unwrap();
        prop_assert_eq!(bytes, deserialized.0);
    }
}
