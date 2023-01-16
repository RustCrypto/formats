use crmf::request::{CertReqMessages, CertReqMsg, CertRequest, CertTemplate};
use der::{Decode, Encode};

#[test]
fn certtemplate_test() {
    // read header cracked from request object created and captured via:
    // server:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-server-key.pem
    //   - openssl req -new -key ec384-server-key.pem -out ec384-server-key.csr
    //   - openssl req -text -in ec384-server-key.csr -noout
    //   - openssl x509 -req -days 365 -in ec384-server-key.csr -signkey ec384-server-key.pem -out ec384-server-key.crt
    //   - openssl cmp -port 8888 -srv_ref ABCD --srv_key ec384-server-key.pem -srv_cert ec384-server-key.crt
    // client:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-key-pair.pem
    //   - openssl cmp -cmd ir -server 127.0.0.1:8888 -path pkix/ -ref 1234 -secret pass:1234-5678-1234-5678 -recipient "/CN=CMPserver" -newkey ec384-key-pair.pem -subject "/CN=MyName" -cacertsout capubs.pem -certout cl_cert.pem -srv_cert ec384-server-key.crt -reqout req.bin -rspout rsp.bin
    let header_01 = include_bytes!("examples/certtemplate.bin");
    let result = CertTemplate::from_der(header_01);
    println!("{:?}", result);
    assert!(result.is_ok());
    let cert_template = result.unwrap();

    assert!(cert_template.version.is_none());
    assert!(cert_template.serial_number.is_none());
    assert!(cert_template.signature.is_none());
    assert!(cert_template.issuer.is_none());
    assert!(cert_template.validity.is_none());
    assert!(cert_template.subject.is_some());
    assert!(cert_template.subject_public_key_info.is_some());
    assert!(cert_template.issuer_unique_id.is_none());
    assert!(cert_template.subject_unique_id.is_none());
    assert!(cert_template.extensions.is_none());

    let reencoded_header_01 = cert_template.to_vec().unwrap();
    println!("Original : {:02X?}", header_01);
    println!("Reencoded: {:02X?}", reencoded_header_01);
    assert_eq!(header_01, reencoded_header_01.as_slice());
}

#[test]
fn certrequest_test() {
    // read header cracked from request object created and captured via:
    // server:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-server-key.pem
    //   - openssl req -new -key ec384-server-key.pem -out ec384-server-key.csr
    //   - openssl req -text -in ec384-server-key.csr -noout
    //   - openssl x509 -req -days 365 -in ec384-server-key.csr -signkey ec384-server-key.pem -out ec384-server-key.crt
    //   - openssl cmp -port 8888 -srv_ref ABCD --srv_key ec384-server-key.pem -srv_cert ec384-server-key.crt
    // client:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-key-pair.pem
    //   - openssl cmp -cmd ir -server 127.0.0.1:8888 -path pkix/ -ref 1234 -secret pass:1234-5678-1234-5678 -recipient "/CN=CMPserver" -newkey ec384-key-pair.pem -subject "/CN=MyName" -cacertsout capubs.pem -certout cl_cert.pem -srv_cert ec384-server-key.crt -reqout req.bin -rspout rsp.bin
    let header_01 = include_bytes!("examples/certrequest.bin");
    let result = CertRequest::from_der(header_01);
    println!("{:?}", result);
    assert!(result.is_ok());
    let header = result.unwrap();

    let reencoded_header_01 = header.to_vec().unwrap();
    println!("Original : {:02X?}", header_01);
    println!("Reencoded: {:02X?}", reencoded_header_01);
    assert_eq!(header_01, reencoded_header_01.as_slice());
}

#[test]
fn certreqmsg_test() {
    // read header cracked from request object created and captured via:
    // server:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-server-key.pem
    //   - openssl req -new -key ec384-server-key.pem -out ec384-server-key.csr
    //   - openssl req -text -in ec384-server-key.csr -noout
    //   - openssl x509 -req -days 365 -in ec384-server-key.csr -signkey ec384-server-key.pem -out ec384-server-key.crt
    //   - openssl cmp -port 8888 -srv_ref ABCD --srv_key ec384-server-key.pem -srv_cert ec384-server-key.crt
    // client:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-key-pair.pem
    //   - openssl cmp -cmd ir -server 127.0.0.1:8888 -path pkix/ -ref 1234 -secret pass:1234-5678-1234-5678 -recipient "/CN=CMPserver" -newkey ec384-key-pair.pem -subject "/CN=MyName" -cacertsout capubs.pem -certout cl_cert.pem -srv_cert ec384-server-key.crt -reqout req.bin -rspout rsp.bin
    let header_01 = include_bytes!("examples/certreqmsg.bin");
    let result = CertReqMsg::from_der(header_01);
    println!("{:?}", result);
    assert!(result.is_ok());
    let header = result.unwrap();

    let reencoded_header_01 = header.to_vec().unwrap();
    println!("Original : {:02X?}", header_01);
    println!("Reencoded: {:02X?}", reencoded_header_01);
    assert_eq!(header_01, reencoded_header_01.as_slice());
}

#[test]
fn certreqmsgs_test() {
    // read header cracked from request object created and captured via:
    // server:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-server-key.pem
    //   - openssl req -new -key ec384-server-key.pem -out ec384-server-key.csr
    //   - openssl req -text -in ec384-server-key.csr -noout
    //   - openssl x509 -req -days 365 -in ec384-server-key.csr -signkey ec384-server-key.pem -out ec384-server-key.crt
    //   - openssl cmp -port 8888 -srv_ref ABCD --srv_key ec384-server-key.pem -srv_cert ec384-server-key.crt
    // client:
    //   - openssl ecparam -genkey -name secp384r1 -noout -out ec384-key-pair.pem
    //   - openssl cmp -cmd ir -server 127.0.0.1:8888 -path pkix/ -ref 1234 -secret pass:1234-5678-1234-5678 -recipient "/CN=CMPserver" -newkey ec384-key-pair.pem -subject "/CN=MyName" -cacertsout capubs.pem -certout cl_cert.pem -srv_cert ec384-server-key.crt -reqout req.bin -rspout rsp.bin
    let header_01 = include_bytes!("examples/certreqmsgs.bin");
    let result = CertReqMessages::from_der(header_01);
    println!("{:?}", result);
    assert!(result.is_ok());
    let header = result.unwrap();

    let reencoded_header_01 = header.to_vec().unwrap();
    println!("Original : {:02X?}", header_01);
    println!("Reencoded: {:02X?}", reencoded_header_01);
    assert_eq!(header_01, reencoded_header_01.as_slice());
}
