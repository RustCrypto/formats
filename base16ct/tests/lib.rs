//! Integration tests.

#![cfg(feature = "alloc")]

use base16ct::{Base16, Error};

/// Hexadecimal test vectors
struct HexVector {
    /// Raw bytes
    raw: &'static [u8],

    /// Hex encoded
    hex: &'static [u8],
}

const HEX_TEST_VECTORS: &[HexVector] = &[
    HexVector { raw: b"", hex: b"" },
    HexVector {
        raw: b"\0",
        hex: b"00",
    },
    HexVector {
        raw: b"***",
        hex: b"2a2a2a",
    },
    HexVector {
        raw: b"\x01\x02\x03\x04",
        hex: b"01020304",
    },
    HexVector {
        raw: b"\xAD\xAD\xAD\xAD\xAD",
        hex: b"adadadadad",
    },
    HexVector {
        raw: b"\xFF\xFF\xFF\xFF\xFF",
        hex: b"ffffffffff",
    },
];

#[test]
fn encode_test_vectors() {
    for vector in HEX_TEST_VECTORS {
        // 10 is the size of the largest encoded test vector
        let mut buf = [0u8; 10];
        let out = Base16::lower_case().encode(vector.raw, &mut buf).unwrap();
        assert_eq!(vector.hex, out);
    }
}

#[test]
fn decode_test_vectors() {
    for vector in HEX_TEST_VECTORS {
        // 5 is the size of the largest decoded test vector
        let mut buf = [0u8; 5];
        let out = Base16::lower_case().decode(vector.hex, &mut buf).unwrap();
        assert_eq!(vector.raw, out);
    }
}

#[test]
fn reject_odd_size_input() {
    let mut out = [0u8; 3];
    assert_eq!(
        Error::InvalidLength,
        Base16::lower_case()
            .decode(b"12345", &mut out)
            .err()
            .unwrap(),
    )
}

#[test]
fn encode_and_decode_various_lengths() {
    let data = [b'X'; 64];

    for i in 0..data.len() {
        let encoded = Base16::lower_case().encode_string(&data[..i]);

        // Make sure it round trips
        let decoded = Base16::lower_case().decode_vec(encoded).unwrap();

        assert_eq!(decoded.as_slice(), &data[..i]);
    }
}
