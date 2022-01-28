use pkcs7::cryptographic_message_syntax2004::*;
use x509::der::{Decodable, Encodable};

#[test]
fn signed_data_parse_test1() {
    let der_encoded_sd = include_bytes!("examples/caCertsIssuedTofbcag4.p7c");
    let ci = ContentInfo2004::from_der(der_encoded_sd).unwrap();
    let content = ci.content.unwrap().to_vec().unwrap();
    let _sd = SignedData::from_der(content.as_slice()).unwrap();
    //assert_eq!(1, sd.certificates.unwrap().len());

    let der_encoded_sd = include_bytes!("examples/DODJITCINTEROPERABILITYROOTCA2_IT.p7c");
    let ci = ContentInfo2004::from_der(der_encoded_sd).unwrap();
    let content = ci.content.unwrap().to_vec().unwrap();
    let sd = SignedData::from_der(content.as_slice()).unwrap();
    assert_eq!(1, sd.certificates.unwrap().len());

    let der_encoded_sd = include_bytes!("examples/DODROOTCA3_IB.p7c");
    let ci = ContentInfo2004::from_der(der_encoded_sd).unwrap();
    let content = ci.content.unwrap().to_vec().unwrap();
    let sd = SignedData::from_der(content.as_slice()).unwrap();
    assert_eq!(26, sd.certificates.unwrap().len());
}
