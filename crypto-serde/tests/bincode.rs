//! bincode-specific tests.

#![cfg(feature = "alloc")]

use crypto_serde::HexUpperOrBin;
use hex_literal::hex;
use proptest::{prelude::*, string::*};

/// Example input to be serialized.
const EXAMPLE_BYTES: &[u8] = &hex!("000102030405060708090A0B0C0D0E0F");

/// bincode serialization of [`EXAMPLE_BYTES`].
const BINCODE_BYTES: &[u8] = &hex!("1000000000000000000102030405060708090A0B0C0D0E0F");

#[test]
fn deserialize() {
    let deserialized = bincode::deserialize::<HexUpperOrBin>(BINCODE_BYTES).unwrap();
    assert_eq!(deserialized.as_ref(), EXAMPLE_BYTES);
}

#[test]
fn serialize() {
    let serialized = bincode::serialize(&HexUpperOrBin::from(EXAMPLE_BYTES)).unwrap();
    assert_eq!(&serialized, BINCODE_BYTES);
}

proptest! {
    #[test]
    fn round_trip(bytes in bytes_regex(".{0,256}").unwrap()) {
        let serialized = bincode::serialize(&HexUpperOrBin::from(bytes.as_ref())).unwrap();
        let deserialized = bincode::deserialize::<HexUpperOrBin>(&serialized).unwrap();
        prop_assert_eq!(bytes, deserialized.0);
    }
}
