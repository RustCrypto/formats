//! Test vectors.

#![cfg(feature = "alloc")]

use base32ct::{Base32, Base32Unpadded, Base32Upper, Base32UpperUnpadded, Encoding, Error};

#[derive(Debug)]
struct TestVector {
    decoded: &'static [u8],
    encoded: &'static str,
}

const LOWER_PADDED_VECTORS: &[TestVector] = &[
    TestVector {
        decoded: &[0],
        encoded: "aa======",
    },
    TestVector {
        decoded: &[1, 2, 3, 5, 9, 17, 33, 65, 129],
        encoded: "aebagbijcequdai=",
    },
    TestVector {
        decoded: &[32, 7],
        encoded: "eadq====",
    },
    TestVector {
        decoded: &[0x12, 0x34, 0x56],
        encoded: "ci2fm===",
    },
    TestVector {
        decoded: &[0x12, 0x34, 0x56, 0x78, 0x9a],
        encoded: "ci2fm6e2",
    },
    TestVector {
        decoded: &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc],
        encoded: "ci2fm6e2xq======",
    },
];

const LOWER_UNPADDED_VECTORS: &[TestVector] = &[
    TestVector {
        decoded: &[0],
        encoded: "aa",
    },
    TestVector {
        decoded: &[1, 2, 3, 5, 9, 17, 33, 65, 129],
        encoded: "aebagbijcequdai",
    },
    TestVector {
        decoded: &[32, 7],
        encoded: "eadq",
    },
    TestVector {
        decoded: &[0x12, 0x34, 0x56],
        encoded: "ci2fm",
    },
    TestVector {
        decoded: &[0x12, 0x34, 0x56, 0x78, 0x9a],
        encoded: "ci2fm6e2",
    },
    TestVector {
        decoded: &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc],
        encoded: "ci2fm6e2xq",
    },
];

const UPPER_PADDED_VECTORS: &[TestVector] = &[
    TestVector {
        decoded: &[0],
        encoded: "AA======",
    },
    TestVector {
        decoded: &[1, 2, 3, 5, 9, 17, 33, 65, 129],
        encoded: "AEBAGBIJCEQUDAI=",
    },
    TestVector {
        decoded: &[32, 7],
        encoded: "EADQ====",
    },
    TestVector {
        decoded: &[0x12, 0x34, 0x56],
        encoded: "CI2FM===",
    },
    TestVector {
        decoded: &[0x12, 0x34, 0x56, 0x78, 0x9a],
        encoded: "CI2FM6E2",
    },
    TestVector {
        decoded: &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc],
        encoded: "CI2FM6E2XQ======",
    },
];

const UPPER_UNPADDED_VECTORS: &[TestVector] = &[
    TestVector {
        decoded: &[0],
        encoded: "AA",
    },
    TestVector {
        decoded: &[1, 2, 3, 5, 9, 17, 33, 65, 129],
        encoded: "AEBAGBIJCEQUDAI",
    },
    TestVector {
        decoded: &[32, 7],
        encoded: "EADQ",
    },
    TestVector {
        decoded: &[0x12, 0x34, 0x56],
        encoded: "CI2FM",
    },
    TestVector {
        decoded: &[0x12, 0x34, 0x56, 0x78, 0x9a],
        encoded: "CI2FM6E2",
    },
    TestVector {
        decoded: &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc],
        encoded: "CI2FM6E2XQ",
    },
];

#[test]
fn decode_valid_base32() {
    for vector in LOWER_PADDED_VECTORS {
        assert_eq!(&Base32::decode_vec(vector.encoded).unwrap(), vector.decoded);
    }

    for vector in LOWER_UNPADDED_VECTORS {
        assert_eq!(
            &Base32Unpadded::decode_vec(vector.encoded).unwrap(),
            vector.decoded
        );
    }

    for vector in UPPER_PADDED_VECTORS {
        assert_eq!(
            &Base32Upper::decode_vec(vector.encoded).unwrap(),
            vector.decoded
        );
    }

    for vector in UPPER_UNPADDED_VECTORS {
        assert_eq!(
            &Base32UpperUnpadded::decode_vec(vector.encoded).unwrap(),
            vector.decoded
        );
    }
}

#[test]
fn decode_padding_error() {
    let truncated =
        &LOWER_PADDED_VECTORS[0].encoded[..(&LOWER_PADDED_VECTORS[0].encoded.len() - 1)];
    assert_eq!(Base32::decode_vec(truncated), Err(Error::InvalidEncoding));
}

#[test]
fn decode_range_error() {
    assert_eq!(
        Base32::decode_vec(core::str::from_utf8(&[0, 0, 0]).unwrap()),
        Err(Error::InvalidEncoding)
    );
}

#[test]
fn encode_base32() {
    for vector in LOWER_PADDED_VECTORS {
        assert_eq!(&Base32::encode_string(vector.decoded), vector.encoded);
    }

    for vector in LOWER_UNPADDED_VECTORS {
        assert_eq!(
            &Base32Unpadded::encode_string(vector.decoded),
            vector.encoded
        );
    }

    for vector in UPPER_PADDED_VECTORS {
        assert_eq!(&Base32Upper::encode_string(vector.decoded), vector.encoded);
    }

    for vector in UPPER_UNPADDED_VECTORS {
        assert_eq!(
            &Base32UpperUnpadded::encode_string(vector.decoded),
            vector.encoded
        );
    }
}

#[test]
fn decode_unpadded_truncated() {
    let string = "foobarba";
    for length in 1..=7 {
        let s = &string[..length];
        let s_padded: String = s.chars().chain(std::iter::repeat('=')).take(8).collect();
        assert!(s_padded.starts_with(s));
        assert_eq!(s_padded.len(), 8);
        assert_eq!(Base32::decode_vec(s), Err(base32ct::Error::InvalidEncoding));
        assert_eq!(Base32Unpadded::decode_vec(s), Base32::decode_vec(&s_padded));
    }
}
