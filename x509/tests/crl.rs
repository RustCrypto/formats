//! CRL tests
use der::Decodable;
use x509::crl::CertificateList;

#[test]
fn decode_crl() {
    let der_encoded_cert = include_bytes!("examples/GoodCACRL.crl");
    let result = CertificateList::from_der(der_encoded_cert);
    let crl: CertificateList = result.unwrap();
    assert_eq!(2, crl.tbs_cert_list.crl_extensions.unwrap().len());
    assert_eq!(2, crl.tbs_cert_list.revoked_certificates.unwrap().len());
}
