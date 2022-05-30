//! Equivalence tests between `base32` crate and `base32ct`.

#![cfg(feature = "alloc")]

use base32::Alphabet;
use base32ct::{Base32 as Base32ct, Encoding};
use proptest::{prelude::*, string::*};

const RFC4648_PADDED: Alphabet = Alphabet::RFC4648 { padding: true };
//const RFC4648_UNPADDED: Alphabet = Alphabet::RFC4648 { padding: false };

proptest! {
    /// Ensure `base32ct` decodes data encoded by `base32` ref crate
    #[test]
    fn decode_equiv(bytes in bytes_regex(".{0,256}").unwrap()) {
        let encoded = base32::encode(RFC4648_PADDED, &bytes).to_lowercase();
        let decoded = Base32ct::decode_vec(&encoded);
        prop_assert_eq!(Ok(bytes), decoded);
    }

    /// Ensure `base32ct` and the `base32` ref crate encode randomly generated
    /// inputs equivalently.
    #[test]
    fn encode_equiv(bytes in bytes_regex(".{0,256}").unwrap()) {
        let actual = Base32ct::encode_string(&bytes);
        let expected = base32::encode(RFC4648_PADDED, &bytes).to_lowercase();
        prop_assert_eq!(actual, expected);
    }
}
