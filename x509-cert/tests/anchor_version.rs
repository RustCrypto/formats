//! RFC 5914's `TrustAnchorInfoVersion`: `INTEGER { v1(1) }`, and v1 is the
//! DEFAULT, so a DER encoding of a v1 anchor leaves the field out. A
//! written INTEGER 0 is not a defined value and must not decode as v1.

use der::{Decode, Encode};
use x509_cert::anchor::{TrustAnchorInfo, Version};
use x509_cert::certificate::Rfc5280;

type AnchorInfo = TrustAnchorInfo<Rfc5280>;

/// A minimal SubjectPublicKeyInfo: rsaEncryption with an empty BIT STRING.
fn spki() -> Vec<u8> {
    let mut inner = vec![
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    inner.extend_from_slice(&[0x03, 0x01, 0x00]);
    let mut out = vec![0x30, inner.len() as u8];
    out.extend_from_slice(&inner);
    out
}

/// TrustAnchorInfo DER: the explicit version octets when given, then the
/// SubjectPublicKeyInfo, then a one-octet keyId.
fn anchor(version: Option<u8>) -> Vec<u8> {
    let mut inner = Vec::new();
    if let Some(version) = version {
        inner.extend_from_slice(&[0x02, 0x01, version]);
    }
    inner.extend_from_slice(&spki());
    inner.extend_from_slice(&[0x04, 0x01, 0x42]);

    let mut out = vec![0x30, inner.len() as u8];
    out.extend_from_slice(&inner);
    out
}

#[test]
fn v1_is_the_integer_one() {
    // RFC 5914 section 2: TrustAnchorInfoVersion ::= INTEGER { v1(1) }
    assert_eq!(Version::V1.to_der().unwrap(), [0x02, 0x01, 0x01]);
}

#[test]
fn absent_version_decodes_as_v1_and_stays_absent_on_encode() {
    let der = anchor(None);
    let info = AnchorInfo::from_der(&der).unwrap();
    assert_eq!(info.version, Version::V1);
    // v1 is the default, so the re-encoded form leaves the field out again
    assert_eq!(info.to_der().unwrap(), der);
}

#[test]
fn explicit_v1_decodes_as_v1_and_reencodes_without_it() {
    let info = AnchorInfo::from_der(&anchor(Some(1))).unwrap();
    assert_eq!(info.version, Version::V1);
    // A present value equal to the default still encodes as the default:
    // omitted, per DER
    assert_eq!(info.to_der().unwrap(), anchor(None));
}

#[test]
fn written_zero_is_not_v1() {
    // 0 is not a value TrustAnchorInfoVersion defines; before this it
    // decoded as V1 and the re-encoded form silently dropped it
    if let Ok(info) = AnchorInfo::from_der(&anchor(Some(0))) {
        panic!("INTEGER 0 is not v1(1), but decoded as {:?}", info.version);
    }
}

#[test]
fn written_two_is_rejected() {
    assert!(AnchorInfo::from_der(&anchor(Some(2))).is_err());
}
