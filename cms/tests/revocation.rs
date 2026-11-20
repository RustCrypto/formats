//! RevocationInfoChoice tests.

use cms::revocation::RevocationInfoChoice;
use der::{Any, Decode, Encode};
use hex_literal::hex;

#[test]
fn other_revocation_info_round_trip() {
    // [1] IMPLICIT OtherRevocationInfoFormat { format 1.2.3, value NULL }
    let der = hex!("a106 0602 2a03 0500");
    let choice = RevocationInfoChoice::from_der(&der).unwrap();
    let RevocationInfoChoice::Other(info) = &choice else {
        panic!("expected other revocation info");
    };
    assert_eq!(info.other, Any::null());
    assert_eq!(choice.to_der().unwrap(), der);
}

#[test]
fn rejects_sequence_wrapped_format_oid() {
    let der = hex!("a108 3004 0602 2a03 0500");
    assert!(RevocationInfoChoice::from_der(&der).is_err());
}
