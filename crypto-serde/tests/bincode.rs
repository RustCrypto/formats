//! bincode-specific tests.

use crypto_serde::HexUpperOrBin;
use hex_literal::hex;

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
