use cmpv2::body::PkiBody;
use cmpv2::header::{PkiHeader, Pvno};
use cmpv2::message::PkiMessage;
use der::{Decode, Encode};

#[test]
fn genm_req_header_test() {
    // read PkiHeader cracked from request object used in genm_req_message_test
    let header_01 = include_bytes!("examples/genm_req_header_01.bin");
    let result = PkiHeader::from_der(header_01);
    assert!(result.is_ok());
    let header = result.unwrap();
    assert_eq!(header.pvno, Pvno::Cmp2000);

    let reencoded_header_01 = header.to_der().unwrap();
    println!("Original : {header_01:02X?}");
    println!("Reencoded: {reencoded_header_01:02X?}");
    assert_eq!(header_01, reencoded_header_01.as_slice());
}

#[test]
fn genm_req_body_test() {
    // read PkiBody cracked from request object used in genm_req_message_test
    let body_01 = include_bytes!("examples/genm_req_body_01.bin");
    println!("Original : {body_01:02X?}");
    let result = PkiBody::from_der(body_01);
    println!("{result:?}");
    assert!(result.is_ok());
    let body = result.unwrap();

    let reencoded_body_01 = body.to_der().unwrap();
    println!("Original : {body_01:02X?}");
    println!("Reencoded: {reencoded_body_01:02X?}");
    assert_eq!(body_01, reencoded_body_01.as_slice());
}

#[test]
fn genm_req_message_test() {
    // read request object created and captured via:
    // server:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-server-key.pem
    //   - openssl req -new -key ec384-server-key.pem -out ec384-server-key.csr
    //   - openssl req -text -in ec384-server-key.csr -noout
    //   - openssl x509 -req -days 365 -in ec384-server-key.csr -signkey ec384-server-key.pem -out ec384-server-key.crt
    //   - openssl cmp -port 8888 -srv_ref ABCD --srv_key ec384-server-key.pem -srv_cert ec384-server-key.crt
    // client:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-key-pair.pem
    //   - openssl cmp -cmd genm -server 127.0.0.1:8080 -path pkix/ -ref 1234 -secret pass:1234-5678-1234-5678 -recipient "/CN=CMPserver" -geninfo 1.2.3.4:int:56789 -infotype signKeyPairTypes -cacertsout capubs.pem -certout cl_cert.pem -srv_cert ec384-server-key.crt -reqout genm_req_01.bin -rspout genm_rsp_01.bin
    let req_01 = include_bytes!("examples/genm_req_01.bin");
    let result = PkiMessage::from_der(req_01);
    println!("{result:?}");
    assert!(result.is_ok());
    let message = result.unwrap();

    let reencoded_req_01 = message.to_der().unwrap();
    println!("Original : {req_01:02X?}");
    println!("Reencoded: {reencoded_req_01:02X?}");
    assert_eq!(req_01, reencoded_req_01.as_slice());
}

#[test]
fn genm_rsp_message_test() {
    // read request object created and captured via:
    // server:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-server-key.pem
    //   - openssl req -new -key ec384-server-key.pem -out ec384-server-key.csr
    //   - openssl req -text -in ec384-server-key.csr -noout
    //   - openssl x509 -req -days 365 -in ec384-server-key.csr -signkey ec384-server-key.pem -out ec384-server-key.crt
    //   - openssl cmp -port 8888 -srv_ref ABCD --srv_key ec384-server-key.pem -srv_cert ec384-server-key.crt
    // client:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-key-pair.pem
    //   - openssl cmp -cmd genm -server 127.0.0.1:8080 -path pkix/ -ref 1234 -secret pass:1234-5678-1234-5678 -recipient "/CN=CMPserver" -geninfo 1.2.3.4:int:56789 -infotype signKeyPairTypes -cacertsout capubs.pem -certout cl_cert.pem -srv_cert ec384-server-key.crt -reqout genm_req_01.bin -rspout genm_rsp_01.bin
    let req_01 = include_bytes!("examples/genm_rsp_01.bin");
    let result = PkiMessage::from_der(req_01);
    println!("{result:?}");
    assert!(result.is_ok());
    let message = result.unwrap();

    let reencoded_req_01 = message.to_der().unwrap();
    println!("Original : {req_01:02X?}");
    println!("Reencoded: {reencoded_req_01:02X?}");
    assert_eq!(req_01, reencoded_req_01.as_slice());
}
