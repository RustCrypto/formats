//! Equivalence tests between `base32` crate and `base32ct`.

#![cfg(feature = "alloc")]

use base32::Alphabet;
use base32ct::{Base32 as Base32Ct, Base32Unpadded as Base32UnpaddedCt, Encoding};
use proptest::{prelude::*, string::*};

const RFC4648_PADDED: Alphabet = Alphabet::Rfc4648 { padding: true };
const RFC4648_UNPADDED: Alphabet = Alphabet::Rfc4648 { padding: false };

proptest! {
    /// Ensure `base32ct` decodes padded data encoded by `base32` ref crate.
    #[test]
    fn decode_equiv_padded(bytes in bytes_regex(".{0,256}").unwrap()) {
        let encoded = base32::encode(RFC4648_PADDED, &bytes).to_lowercase();
        let decoded = Base32Ct::decode_vec(&encoded);
        prop_assert_eq!(Ok(bytes), decoded);
    }

    /// Ensure `base32ct` decodes unpadded data encoded by `base32` ref crate.
    #[test]
    fn decode_equiv_unpadded(bytes in bytes_regex(".{0,256}").unwrap()) {
        let encoded = base32::encode(RFC4648_UNPADDED, &bytes).to_lowercase();
        let decoded = Base32UnpaddedCt::decode_vec(&encoded);
        prop_assert_eq!(Ok(bytes), decoded);
    }

    /// Ensure `base32ct` and the `base32` ref crate encode randomly generated
    /// inputs equivalently (with padding).
    #[test]
    fn encode_equiv_padded(bytes in bytes_regex(".{0,256}").unwrap()) {
        let actual = Base32Ct::encode_string(&bytes);
        let expected = base32::encode(RFC4648_PADDED, &bytes).to_lowercase();
        prop_assert_eq!(actual, expected);
    }

    /// Make sure that, if base32ct and base32 _both_ decode a value
    /// when expecting padded inputs, they give the same output.
    ///
    /// TODO: It might be desirable to ensure that they both decode the
    /// _same_ values: that is, that they are equivalently strict about
    /// which inputs they accept.  But first, we should verify that
    /// `base32`'s behavior is actually what we want.
    #[test]
    fn decode_arbitrary_padded(string in string_regex("[a-z0-9]{0,32}={0,8}").unwrap()) {
        let actual = Base32Ct::decode_vec(&string);
        let expected = base32::decode(RFC4648_PADDED, &string);
        // assert_eq!(actual.ok(), expected);
        if let (Ok(a), Some(b)) = (actual, expected) {
            assert_eq!(a, b);
        }
    }

    /// Make sure that, if base32ct and base32 _both_ decode a value
    /// when expecting unpadded inputs, they give the same output.
    ///
    /// TODO: See note above.
    #[test]
    fn decode_arbitrary_unpadded(string in string_regex("[a-z0-9]{0,32}={0,8}").unwrap()) {
        let actual = Base32UnpaddedCt::decode_vec(&string);
        let expected = base32::decode(RFC4648_UNPADDED, &string);
        // assert_eq!(actual.ok(), expected);
        if let (Ok(a), Some(b)) = (actual, expected) {
            assert_eq!(a, b);
        }
    }

    /// Every accepted input is the canonical encoding of its output (RFC 4648 3.5: the unused
    /// bits of the last symbol are zero), so decode-then-encode gives the input back.
    #[test]
    fn decode_is_canonical(string in string_regex("[a-z2-7]{0,32}").unwrap()) {
        if let Ok(bytes) = Base32UnpaddedCt::decode_vec(&string) {
            prop_assert_eq!(Base32UnpaddedCt::encode_string(&bytes), string.clone());
        }
        let padded = format!("{string}{}", "=".repeat((8 - string.len() % 8) % 8));
        if let Ok(bytes) = Base32Ct::decode_vec(&padded) {
            prop_assert_eq!(Base32Ct::encode_string(&bytes), padded);
        }
    }
}

/// "me" is the canonical encoding of "a" (0x61 = 01100 001|00); "mf" and "mh" set the unused
/// low bits of the last symbol and must be rejected.
#[test]
fn reject_non_zero_trailing_bits() {
    assert_eq!(Base32UnpaddedCt::decode_vec("me").unwrap(), b"a");
    assert!(Base32UnpaddedCt::decode_vec("mf").is_err());
    assert!(Base32UnpaddedCt::decode_vec("mh").is_err());
    assert_eq!(Base32Ct::decode_vec("me======").unwrap(), b"a");
    assert!(Base32Ct::decode_vec("mf======").is_err());
}
