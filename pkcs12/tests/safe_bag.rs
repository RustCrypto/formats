//! `SafeBag` encoding tests.

use der::{Decode, Encode};
use hex_literal::hex;
use pkcs12::safe_bag::SafeBag;

/// `bag_value` holds the whole `[0] EXPLICIT` TLV on decode, and encoding writes it back
/// unchanged: a decoded `SafeBag` re-encodes to its input.
#[test]
fn safe_bag_round_trip() {
    // SafeBag { keyBag, [0] { OCTET STRING 01 02 } }
    let der = hex!("3013 060b2a864886f70d010c0a0101 a004 04020102");
    let bag = SafeBag::from_der(&der).unwrap();
    assert_eq!(bag.bag_value, hex!("a004 04020102"));
    assert_eq!(bag.to_der().unwrap(), der);
}

/// `bagValue` is `[0] EXPLICIT`; any other tag is rejected on decode and on encode.
#[test]
fn safe_bag_value_must_be_explicit_0() {
    // bagValue is a bare OCTET STRING
    let der = hex!("3011 060b2a864886f70d010c0a0101 04020102");
    assert!(SafeBag::from_der(&der).is_err());

    let mut bag =
        SafeBag::from_der(&hex!("3013 060b2a864886f70d010c0a0101 a004 04020102")).unwrap();
    bag.bag_value = hex!("04020102").to_vec();
    assert!(bag.to_der().is_err());
}
