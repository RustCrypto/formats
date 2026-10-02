use der::{Decode, Encode};
use x509_cert::{
    Version,
    certificate::Rfc5280,
    crl::{CertificateList, TbsCertList},
};

#[test]
fn decode_crl() {
    // vanilla CRL from PKITS
    let der_encoded_cert = include_bytes!("examples/GoodCACRL.crl");
    let crl = CertificateList::<Rfc5280>::from_der(der_encoded_cert).unwrap();
    assert_eq!(2, crl.tbs_cert_list.crl_extensions.unwrap().len());
    assert_eq!(2, crl.tbs_cert_list.revoked_certificates.unwrap().len());

    // CRL with an entry with no entry extensions
    let der_encoded_cert = include_bytes!("examples/tscpbcasha256.crl");
    let crl = CertificateList::<Rfc5280>::from_der(der_encoded_cert).unwrap();
    assert_eq!(2, crl.tbs_cert_list.crl_extensions.unwrap().len());
    assert_eq!(4, crl.tbs_cert_list.revoked_certificates.unwrap().len());
}

/// RFC 5280 Section 5.1: `version Version OPTIONAL -- if present, MUST be v2`. A v1 CRL has no
/// version field; it must decode (as `Version::V1`) and re-encode to the same bytes, while a
/// v2 CRL keeps its explicit `INTEGER 1`.
#[test]
fn decode_v1_crl_without_version() {
    // TBSCertList { sha256WithRSAEncryption, issuer CN=a, thisUpdate 700101000000Z }
    let v1_tbs: &[u8] = &[
        0x30, 0x2c, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
        0x05, 0x00, 0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x01,
        0x61, 0x17, 0x0d, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x5a,
    ];
    let tbs = TbsCertList::<Rfc5280>::from_der(v1_tbs).unwrap();
    assert_eq!(tbs.version, Version::V1);
    assert_eq!(tbs.to_der().unwrap(), v1_tbs);

    // The same list with an explicit v2 version keeps it.
    let mut v2_tbs = vec![0x30, 0x2f, 0x02, 0x01, 0x01];
    v2_tbs.extend_from_slice(&v1_tbs[2..]);
    let tbs = TbsCertList::<Rfc5280>::from_der(&v2_tbs).unwrap();
    assert_eq!(tbs.version, Version::V2);
    assert_eq!(tbs.to_der().unwrap(), v2_tbs);
}
