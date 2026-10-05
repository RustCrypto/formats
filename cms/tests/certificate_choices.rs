//! `CertificateChoices` tests.

use cms::cert::CertificateChoices;
use der::{Decode, Encode};

/// RFC 5652 10.2.2: `other [3] IMPLICIT OtherCertificateFormat`, so the `[3]` tag replaces the
/// SEQUENCE tag of `OtherCertificateFormat` (as OpenSSL encodes it, `ASN1_IMP` in cms_asn1.c).
#[test]
fn other_certificate_format_is_implicit() {
    // [3] { otherCertFormat 1.2.3, otherCert NULL }
    let der = [0xa3, 0x06, 0x06, 0x02, 0x2a, 0x03, 0x05, 0x00];
    let choice = CertificateChoices::from_der(&der).unwrap();
    match &choice {
        CertificateChoices::Other(other) => {
            assert_eq!(
                other.other_cert_format,
                const_oid::ObjectIdentifier::new_unwrap("1.2.3")
            );
        }
        _ => panic!("expected CertificateChoices::Other"),
    }
    assert_eq!(choice.to_der().unwrap(), der);
}
