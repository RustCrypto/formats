//! TOML-specific tests.

#![cfg(feature = "alloc")]

use crypto_serde::{HexLowerOrBin, HexUpperOrBin};
use hex_literal::hex;
use serde::{Deserialize, Serialize};

/// Example input to be serialized.
const EXAMPLE_BYTES: &[u8] = &hex!("000102030405060708090A0B0C0D0E0F");

/// Lower-case hex serialization of [`EXAMPLE_BYTES`].
const HEX_LOWER: &str = "\"000102030405060708090a0b0c0d0e0f\"";

/// Upper-case hex serialization of [`EXAMPLE_BYTES`].
const HEX_UPPER: &str = "\"000102030405060708090A0B0C0D0E0F\"";

/// Example table type for testing.
#[derive(Serialize, Deserialize)]
pub struct ExampleTable {
    /// Example field.
    example_field: HexUpperOrBin,
}

#[test]
fn hex_lower() {
    let serialized = toml::to_string(&HexLowerOrBin::from(EXAMPLE_BYTES)).unwrap();
    assert_eq!(serialized, HEX_LOWER);
}

#[test]
fn hex_upper() {
    let serialized = toml::to_string(&HexUpperOrBin::from(EXAMPLE_BYTES)).unwrap();
    assert_eq!(serialized, HEX_UPPER);

    let deserialized =
        toml::from_str::<ExampleTable>(&format!("example_field={}", HEX_UPPER)).unwrap();

    assert_eq!(deserialized.example_field.as_ref(), EXAMPLE_BYTES);
}
