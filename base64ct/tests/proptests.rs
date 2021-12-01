//! Equivalence tests between `base64` crate and `base64ct`.

#![cfg(feature = "std")]

use base64ct::{Base64 as Base64ct, Encoding};
use proptest::{prelude::*, string::*};
use std::iter;

/// Incremental Base64 decoder.
type Decoder<'a> = base64ct::Decoder<'a, Base64ct>;

proptest! {
    /// Ensure `base64ct` decodes data encoded by `base64` ref crate
    #[test]
    fn decode_equiv(bytes in bytes_regex(".{0,256}").unwrap()) {
        let encoded = base64::encode(&bytes);
        let decoded = Base64ct::decode_vec(&encoded).unwrap();
        prop_assert_eq!(bytes, decoded);
    }

    /// Ensure that `base64ct`'s incremental decoder is able to decode randomly
    /// generated inputs encoded by the `base64` ref crate
    #[test]
    fn decode_incremental(bytes in bytes_regex(".{1,256}").unwrap(), chunk_size in 1..256usize) {
        let encoded = base64::encode(&bytes);
        let chunk_size = match chunk_size % bytes.len() {
            0 => 1,
            n => n
        };

        let mut buffer = [0u8; 384];
        let mut decoder = Decoder::new(encoded.as_bytes()).unwrap();

        for chunk in bytes.chunks(chunk_size) {
            prop_assert!(!decoder.is_finished());
            match decoder.decode_partial(&mut buffer[..chunk_size]) {
                Ok(Some(decoded)) => prop_assert_eq!(chunk, decoded),
                other => panic!("decode failed: {:?}", other),
            }
        }

        prop_assert!(decoder.is_finished());
    }

    /// Ensure `base64ct` and `base64` ref crate decode randomly generated
    /// inputs equivalently.
    ///
    /// Inputs are selected to be valid characters in the standard Base64
    /// padded alphabet, but are not necessarily valid Base64.
    #[test]
    fn decode_random(base64ish in string_regex("[A-Za-z0-9+/]{0,256}").unwrap()) {
        let base64ish_padded = match base64ish.len() % 4 {
            0 => base64ish,
            n => {
                let padding_len = 4 - n;
                base64ish + &iter::repeat("=").take(padding_len).collect::<String>()
            }
        };

        let decoded_ct = Base64ct::decode_vec(&base64ish_padded).ok();
        let decoded_ref = base64::decode(&base64ish_padded).ok();
        prop_assert_eq!(decoded_ct, decoded_ref);
    }

    /// Ensure `base64ct` and the `base64` ref crate encode randomly generated
    /// inputs equivalently.
    #[test]
    fn encode_equiv(bytes in bytes_regex(".{0,256}").unwrap()) {
        let encoded_ct = Base64ct::encode_string(&bytes);
        let encoded_ref = base64::encode(&bytes);
        prop_assert_eq!(encoded_ct, encoded_ref);
    }
}
