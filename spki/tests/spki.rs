//! SubjectPublicKeyInfo tests
use core::convert::TryFrom;
use hex_literal::hex;
use spki::SubjectPublicKeyInfo;

#[cfg(feature = "fingerprint")]
// Taken from pkcs8/tests/public_key.rs
/// Ed25519 `SubjectPublicKeyInfo` encoded as ASN.1 DER
const ED25519_DER_EXAMPLE: &[u8] = include_bytes!("examples/ed25519-pub.der");

/// The SPKI fingerprint for `ED25519_SPKI_FINGERPRINT`
///
/// Generated using `cat ed25519-pub.der | openssl dgst -binary -sha256 | base64`
#[cfg(feature = "fingerprint")]
const ED25519_SPKI_FINGERPRINT: &str = "Vd1MdLDkhTTi9OFzzs61DfjyenrCqomRzHrpFOAwvO0=";

#[cfg(feature = "fingerprint")]
#[test]
fn decode_and_fingerprint_spki() {
    // Repeat the decode test from the pkcs8 crate
    let spki = SubjectPublicKeyInfo::try_from(ED25519_DER_EXAMPLE).unwrap();

    assert_eq!(spki.algorithm.oid, "1.3.101.112".parse().unwrap());
    assert_eq!(spki.algorithm.parameters, None);
    assert_eq!(
        spki.subject_public_key,
        &hex!("4D29167F3F1912A6F7ADFA293A051A15C05EC67B8F17267B1C5550DCE853BD0D")[..]
    );

    // Check the fingerprint
    let mut buf = [0u8; 4096];

    let fingerprint = spki.fingerprint(&mut buf).unwrap();
    assert_eq!(fingerprint, ED25519_SPKI_FINGERPRINT);
}
