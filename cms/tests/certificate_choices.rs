//! `CertificateChoices` tests.

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode, Encode};

/// RFC 5652 10.2.2: `other [3] IMPLICIT OtherCertificateFormat`, so the `[3]` tag replaces the
/// SEQUENCE tag of `OtherCertificateFormat` (as OpenSSL encodes it, `ASN1_IMP` in cms_asn1.c).
#[test]
fn other_certificate_format_is_implicit() {
    // [3] { otherCertFormat 1.2.3, otherCert NULL }
    let der = [0xa3, 0x06, 0x06, 0x02, 0x2a, 0x03, 0x05, 0x00];
    let choice: CertificateChoices = CertificateChoices::from_der(&der).unwrap();
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

/// RFC 7030 A.1 `/cacerts` bundle. Its certificates are not in DER order, so decoding must sort
/// them. DER (X.690 11.6) sorts SET OF elements by their encoded bytes.
#[test]
fn decoded_certificate_set_is_in_der_order() {
    let ci = ContentInfo::from_der(include_bytes!("examples/rfc7030_cacerts.ber")).unwrap();
    let sd: SignedData = ci.content.decode_as().unwrap();
    let encoded: Vec<Vec<u8>> = sd
        .certificates
        .unwrap()
        .0
        .iter()
        .map(|c| c.to_der().unwrap())
        .collect();
    assert_eq!(encoded.len(), 4);
    assert!(encoded.is_sorted());
}
