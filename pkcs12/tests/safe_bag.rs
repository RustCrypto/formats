//! `SafeBag` encoding tests.

use der::asn1::OctetString;
use der::{Any, Decode, Encode};
use hex_literal::hex;
use pkcs12::CertBag;
use pkcs12::safe_bag::SafeBag;

/// A decoded `SafeBag` re-encodes to its input, and `bag_value` holds the value inside the
/// `[0] EXPLICIT` wrapper.
#[test]
fn safe_bag_round_trip() {
    // SafeBag { keyBag, [0] { OCTET STRING 01 02 } }
    let der = hex!("3013 060b2a864886f70d010c0a0101 a004 04020102");
    let bag = SafeBag::from_der(&der).unwrap();
    assert_eq!(bag.bag_value.to_der().unwrap(), hex!("04020102"));
    assert_eq!(bag.to_der().unwrap(), der);
}

/// A `SafeBag` built from the inner bag value encodes with a single `[0] EXPLICIT` wrapper.
#[test]
fn safe_bag_built_from_inner_value_encodes() {
    let cert = include_bytes!("examples/cert.der");
    let cert_bag = CertBag {
        cert_id: pkcs12::PKCS_12_X509_CERT_OID,
        cert_value: OctetString::new(cert.as_slice()).unwrap(),
    };
    let bag = SafeBag {
        bag_id: pkcs12::PKCS_12_CERT_BAG_OID,
        bag_value: Any::encode_from(&cert_bag).unwrap(),
        bag_attributes: None,
    };
    let der = bag.to_der().unwrap();

    let decoded = SafeBag::from_der(&der).unwrap();
    let cb: CertBag = decoded.bag_value.decode_as().unwrap();
    assert_eq!(cert.as_slice(), cb.cert_value.as_bytes());
}

/// `bagValue` is `[0] EXPLICIT` around exactly one value.
#[test]
fn safe_bag_value_must_be_one_explicit_0_value() {
    // bagValue is a bare OCTET STRING
    let der = hex!("3011 060b2a864886f70d010c0a0101 04020102");
    assert!(SafeBag::from_der(&der).is_err());

    // [0] { [0] { OCTET STRING 01 02 } }: the SafeBag layer sees one value (a [0]), and
    // decoding the bag value as its type then fails.
    let der = hex!("3015 060b2a864886f70d010c0a0101 a006 a004 04020102");
    let bag = SafeBag::from_der(&der).unwrap();
    assert!(bag.bag_value.decode_as::<OctetString>().is_err());
    let single = SafeBag::from_der(&hex!("3013 060b2a864886f70d010c0a0101 a004 04020102")).unwrap();
    assert!(single.bag_value.decode_as::<OctetString>().is_ok());

    // [0] { OCTET STRING aa, OCTET STRING bb }
    let der = hex!("3015 060b2a864886f70d010c0a0101 a006 0401aa 0401bb");
    assert!(SafeBag::from_der(&der).is_err());
}
