//! ocsp request decode tests

use der::{Decode, Encode, asn1::ObjectIdentifier};
use hex_literal::hex;
use x509_cert::{ext::Extension, serial_number::SerialNumber};
use x509_ocsp::{ext::Nonce, *};

const ID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const ID_SHA224: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.4");
const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const ID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const ID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
const ID_PKIX_OCSP_NONCE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.2");
const ID_PKIX_OCSP_SERVICE_LOCATOR: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.7");
const ID_PKIX_OCSP_RESPONSE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.4");
//const ID_PKIX_OCSP_PREF_SIG_ALGS: ObjectIdentifier =
//    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.8");
const SHA_256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

fn assert_ocsp_request(ocsp_req: &OcspRequest, req_len: usize) {
    assert_eq!(ocsp_req.tbs_request.version, Version::V1);
    assert_eq!(ocsp_req.tbs_request.request_list.len(), req_len);
}

fn assert_request(
    req: &Request,
    expected_hash_oid: ObjectIdentifier,
    expected_issuer_name_hash: &[u8],
    expected_issuer_key_hash: &[u8],
    expected_serial: &SerialNumber,
) {
    assert_eq!(req.req_cert.hash_algorithm.oid, expected_hash_oid);
    assert!(req.req_cert.hash_algorithm.parameters.is_some());
    assert_eq!(
        &req.req_cert.issuer_name_hash.as_bytes(),
        &expected_issuer_name_hash
    );
    assert_eq!(
        &req.req_cert.issuer_key_hash.as_bytes(),
        &expected_issuer_key_hash
    );
    assert_eq!(&req.req_cert.serial_number, expected_serial);
}

fn assert_extension(
    ext: &Extension,
    expected_oid: ObjectIdentifier,
    expected_critical: bool,
    data: &[u8],
) {
    assert_eq!(ext.extn_id, expected_oid);
    assert_eq!(ext.critical, expected_critical);
    assert_eq!(&ext.extn_value.as_bytes(), &data);
}

#[test]
fn decode_ocsp_req_sha1_certid() {
    let data = std::fs::read("tests/examples/sha1-certid-ocsp-req.der").unwrap();
    let ocsp_req = OcspRequest::from_der(&data[..]).unwrap();
    let name_hash = hex!("94D418C85D800AF31266F13D3D8CD8CD6AA5BB74");
    let key_hash = hex!("5DD72C171C018B2FFA92C3133913689EBD82115C");
    let serial = SerialNumber::from(0x10001usize);
    assert_ocsp_request(&ocsp_req, 1);
    assert!(ocsp_req.optional_signature.is_none());
    assert_request(
        &ocsp_req.tbs_request.request_list[0],
        ID_SHA1,
        &name_hash[..],
        &key_hash[..],
        &serial,
    );
}

#[test]
fn decode_ocsp_req_sha224_certid() {
    let data = std::fs::read("tests/examples/sha224-certid-ocsp-req.der").unwrap();
    let ocsp_req = OcspRequest::from_der(&data[..]).unwrap();
    let name_hash = hex!("3D1F07D457D6634B0F2501C71ADB1DE5C41C515207F4206A5ACDA560");
    let key_hash = hex!("2962CA2A9DE7A3A75A96EAC2031F50684DF5B50F5E6635DECBD74DA3");
    let serial = SerialNumber::from(0x10001usize);
    assert_ocsp_request(&ocsp_req, 1);
    assert!(ocsp_req.optional_signature.is_none());
    assert_request(
        &ocsp_req.tbs_request.request_list[0],
        ID_SHA224,
        &name_hash[..],
        &key_hash[..],
        &serial,
    );
}

#[test]
fn decode_ocsp_req_sha256_certid() {
    let data = std::fs::read("tests/examples/sha256-certid-ocsp-req.der").unwrap();
    let ocsp_req = OcspRequest::from_der(&data[..]).unwrap();
    let name_hash = hex!("056078AE157D9BB53154B1ABEBD26057D624FDDD9F09AE63814E90A365F444C5");
    let key_hash = hex!("15C37A883122D2FB6DBFA83E3CBD93E9EEF8125E3FD785724BC42D9D6FBA39B7");
    let serial = SerialNumber::from(0x10001usize);
    assert_ocsp_request(&ocsp_req, 1);
    assert!(ocsp_req.optional_signature.is_none());
    assert_request(
        &ocsp_req.tbs_request.request_list[0],
        ID_SHA256,
        &name_hash[..],
        &key_hash[..],
        &serial,
    );
}

#[test]
fn decode_ocsp_req_sha384_certid() {
    let data = std::fs::read("tests/examples/sha384-certid-ocsp-req.der").unwrap();
    let ocsp_req = OcspRequest::from_der(&data[..]).unwrap();
    let name_hash = hex!(
        "97EFAF937F262E72C9C8FFFB55FDBC9FBB7EA353CD837CE01AF6F0D489AB\
         4EC9AE4AD7248410268C23F9C0FF5161BB28"
    );
    let key_hash = hex!(
        "F54E78323C7201B9C799040AF35FE3BC1492DA6B0EFD799C80BA45A611CD\
         C129F6A79067ACF14B83340FE122CF2305FE"
    );
    let serial = SerialNumber::from(0x10001usize);
    assert_ocsp_request(&ocsp_req, 1);
    assert!(ocsp_req.optional_signature.is_none());
    assert_request(
        &ocsp_req.tbs_request.request_list[0],
        ID_SHA384,
        &name_hash[..],
        &key_hash[..],
        &serial,
    );
}

#[test]
fn decode_ocsp_req_sha512_certid() {
    let data = std::fs::read("tests/examples/sha512-certid-ocsp-req.der").unwrap();
    let ocsp_req = OcspRequest::from_der(&data[..]).unwrap();
    let name_hash = hex!(
        "6AE6D566832B216D55BF3F8CCBBBD662E4D798D7E5FC64CEE6CB35DF60EE\
         1181305CB2747626560AFABD29B781A9A4631B0DFA1A05727323B3B81EEB\
         54E57981"
    );
    let key_hash = hex!(
        "FEAC2688D16143E11050AEF3CDFAE4E4E21DF08F40A9FA3F5D80903B8394\
         50EE29620263B12AB92F3E840458A4871119B6757D337CEDB9044B8A5F72\
         39615E06"
    );
    let serial = SerialNumber::from(0x10001usize);
    assert_ocsp_request(&ocsp_req, 1);
    assert!(ocsp_req.optional_signature.is_none());
    assert_request(
        &ocsp_req.tbs_request.request_list[0],
        ID_SHA512,
        &name_hash[..],
        &key_hash[..],
        &serial,
    );
}

#[test]
fn decode_ocsp_req_multiple_extensions() {
    let data = std::fs::read("tests/examples/ocsp-multiple-exts-clean-req.der").unwrap();
    let ocsp_req = OcspRequest::from_der(&data[..]).unwrap();
    let name_hash = hex!("94D418C85D800AF31266F13D3D8CD8CD6AA5BB74");
    let key_hash = hex!("5DD72C171C018B2FFA92C3133913689EBD82115C");
    let serial = SerialNumber::from(0x10001usize);
    let nonce_ext = hex!("0420BB42AE6BEBD2B6E455CA02BC853452635F08863EFFAF25E182905E7FFF1FB40A");
    let nonce = Nonce::new(hex!(
        "BB42AE6BEBD2B6E455CA02BC853452635F08863EFFAF25E182905E7FFF1FB40A"
    ))
    .unwrap();
    let response_ext = hex!("300B06092B0601050507300101");
    let srv_loc_ext = hex!(
        "3051301D311B3019060355040313127273612D323034382D736861323536\
         2D63613030301006082B0601050507300187047F000001301C06082B0601\
         0505073001871000000000000000000000000000000001"
    );

    // Assert OcspRequest and RequestExtensions
    assert_ocsp_request(&ocsp_req, 1);
    assert!(ocsp_req.optional_signature.is_none());
    assert!(ocsp_req.tbs_request.request_extensions.is_some());
    let req_exts = ocsp_req.tbs_request.request_extensions.as_ref().unwrap();
    assert_eq!(req_exts.len(), 2);
    assert_extension(&req_exts[0], ID_PKIX_OCSP_NONCE, false, &nonce_ext[..]);
    assert_eq!(ocsp_req.nonce(), Some(nonce));
    assert_extension(&req_exts[1], ID_PKIX_OCSP_RESPONSE, true, &response_ext[..]);

    // Assert Request and SingleRequestExtensions
    let req = &ocsp_req.tbs_request.request_list[0];
    assert_request(req, ID_SHA1, &name_hash[..], &key_hash[..], &serial);
    assert!(req.single_request_extensions.is_some());
    let single_req_exts = req.single_request_extensions.as_ref().unwrap();
    assert_eq!(single_req_exts.len(), 1);
    assert_extension(
        &single_req_exts[0],
        ID_PKIX_OCSP_SERVICE_LOCATOR,
        false,
        &srv_loc_ext[..],
    );
}

#[test]
fn decode_ocsp_req_multiple_requests() {
    let data = std::fs::read("tests/examples/ocsp-multiple-requests-req.der").unwrap();
    let ocsp_req = OcspRequest::from_der(&data[..]).unwrap();
    let sha1_name_hash = hex!("94D418C85D800AF31266F13D3D8CD8CD6AA5BB74");
    let sha1_key_hash = hex!("5DD72C171C018B2FFA92C3133913689EBD82115C");
    let sha224_name_hash = hex!("3D1F07D457D6634B0F2501C71ADB1DE5C41C515207F4206A5ACDA560");
    let sha224_key_hash = hex!("2962CA2A9DE7A3A75A96EAC2031F50684DF5B50F5E6635DECBD74DA3");
    let sha256_name_hash = hex!("056078AE157D9BB53154B1ABEBD26057D624FDDD9F09AE63814E90A365F444C5");
    let sha256_key_hash = hex!("15C37A883122D2FB6DBFA83E3CBD93E9EEF8125E3FD785724BC42D9D6FBA39B7");
    let sha384_name_hash = hex!(
        "97EFAF937F262E72C9C8FFFB55FDBC9FBB7EA353CD837CE01AF6F0D489AB\
         4EC9AE4AD7248410268C23F9C0FF5161BB28"
    );
    let sha384_key_hash = hex!(
        "F54E78323C7201B9C799040AF35FE3BC1492DA6B0EFD799C80BA45A611CD\
         C129F6A79067ACF14B83340FE122CF2305FE"
    );
    let sha512_name_hash = hex!(
        "6AE6D566832B216D55BF3F8CCBBBD662E4D798D7E5FC64CEE6CB35DF60EE\
         1181305CB2747626560AFABD29B781A9A4631B0DFA1A05727323B3B81EEB\
         54E57981"
    );
    let sha512_key_hash = hex!(
        "FEAC2688D16143E11050AEF3CDFAE4E4E21DF08F40A9FA3F5D80903B8394\
         50EE29620263B12AB92F3E840458A4871119B6757D337CEDB9044B8A5F72\
         39615E06"
    );
    assert_ocsp_request(&ocsp_req, 8);
    assert!(ocsp_req.optional_signature.is_none());
    let req_list = &ocsp_req.tbs_request.request_list;
    assert_request(
        &req_list[0],
        ID_SHA1,
        &sha1_name_hash[..],
        &sha1_key_hash[..],
        &SerialNumber::from(0x10001usize),
    );
    assert_request(
        &req_list[1],
        ID_SHA224,
        &sha224_name_hash[..],
        &sha224_key_hash[..],
        &SerialNumber::from(0x10001usize),
    );
    assert_request(
        &req_list[2],
        ID_SHA256,
        &sha256_name_hash[..],
        &sha256_key_hash[..],
        &SerialNumber::from(0x10001usize),
    );
    assert_request(
        &req_list[3],
        ID_SHA384,
        &sha384_name_hash[..],
        &sha384_key_hash[..],
        &SerialNumber::from(0x10001usize),
    );
    assert_request(
        &req_list[4],
        ID_SHA512,
        &sha512_name_hash[..],
        &sha512_key_hash[..],
        &SerialNumber::from(0x10001usize),
    );
    assert_request(
        &req_list[5],
        ID_SHA1,
        &sha1_name_hash[..],
        &sha1_key_hash[..],
        &SerialNumber::from(0x5usize),
    );
    assert_request(
        &req_list[6],
        ID_SHA1,
        &sha1_name_hash[..],
        &sha1_key_hash[..],
        &SerialNumber::from(0x16usize),
    );
    assert_request(
        &req_list[7],
        ID_SHA1,
        &sha1_name_hash[..],
        &sha1_key_hash[..],
        &SerialNumber::from(0xFFFFFFFFusize),
    );
}

#[test]
fn decode_ocsp_req_multiple_requests_nonce() {
    let data = std::fs::read("tests/examples/ocsp-multiple-requests-nonce-req.der").unwrap();
    let ocsp_req = OcspRequest::from_der(&data[..]).unwrap();
    let sha1_name_hash = hex!("94D418C85D800AF31266F13D3D8CD8CD6AA5BB74");
    let sha1_key_hash = hex!("5DD72C171C018B2FFA92C3133913689EBD82115C");
    let sha224_name_hash = hex!("3D1F07D457D6634B0F2501C71ADB1DE5C41C515207F4206A5ACDA560");
    let sha224_key_hash = hex!("2962CA2A9DE7A3A75A96EAC2031F50684DF5B50F5E6635DECBD74DA3");
    let sha256_name_hash = hex!("056078AE157D9BB53154B1ABEBD26057D624FDDD9F09AE63814E90A365F444C5");
    let sha256_key_hash = hex!("15C37A883122D2FB6DBFA83E3CBD93E9EEF8125E3FD785724BC42D9D6FBA39B7");
    let sha384_name_hash = hex!(
        "97EFAF937F262E72C9C8FFFB55FDBC9FBB7EA353CD837CE01AF6F0D489AB\
         4EC9AE4AD7248410268C23F9C0FF5161BB28"
    );
    let sha384_key_hash = hex!(
        "F54E78323C7201B9C799040AF35FE3BC1492DA6B0EFD799C80BA45A611CD\
         C129F6A79067ACF14B83340FE122CF2305FE"
    );
    let sha512_name_hash = hex!(
        "6AE6D566832B216D55BF3F8CCBBBD662E4D798D7E5FC64CEE6CB35DF60EE\
         1181305CB2747626560AFABD29B781A9A4631B0DFA1A05727323B3B81EEB\
         54E57981"
    );
    let sha512_key_hash = hex!(
        "FEAC2688D16143E11050AEF3CDFAE4E4E21DF08F40A9FA3F5D80903B8394\
         50EE29620263B12AB92F3E840458A4871119B6757D337CEDB9044B8A5F72\
         39615E06"
    );
    let nonce_ext = hex!("042027E51B16C355C29C18B686987041A1D972C4C17AE1F6250FCDEA5FCD7AE81677");
    let nonce = Nonce::new(hex!(
        "27E51B16C355C29C18B686987041A1D972C4C17AE1F6250FCDEA5FCD7AE81677"
    ))
    .unwrap();

    assert_ocsp_request(&ocsp_req, 8);
    assert!(ocsp_req.optional_signature.is_none());
    assert!(ocsp_req.nonce().is_some());
    assert!(ocsp_req.tbs_request.request_extensions.is_some());
    let req_exts = ocsp_req.tbs_request.request_extensions.as_ref().unwrap();
    assert_eq!(req_exts.len(), 1);
    assert_extension(&req_exts[0], ID_PKIX_OCSP_NONCE, false, &nonce_ext[..]);
    assert_eq!(ocsp_req.nonce(), Some(nonce));

    let req_list = &ocsp_req.tbs_request.request_list;
    assert_request(
        &req_list[0],
        ID_SHA1,
        &sha1_name_hash[..],
        &sha1_key_hash[..],
        &SerialNumber::from(0x10001usize),
    );
    assert_request(
        &req_list[1],
        ID_SHA224,
        &sha224_name_hash[..],
        &sha224_key_hash[..],
        &SerialNumber::from(0x10001usize),
    );
    assert_request(
        &req_list[2],
        ID_SHA256,
        &sha256_name_hash[..],
        &sha256_key_hash[..],
        &SerialNumber::from(0x10001usize),
    );
    assert_request(
        &req_list[3],
        ID_SHA384,
        &sha384_name_hash[..],
        &sha384_key_hash[..],
        &SerialNumber::from(0x10001usize),
    );
    assert_request(
        &req_list[4],
        ID_SHA512,
        &sha512_name_hash[..],
        &sha512_key_hash[..],
        &SerialNumber::from(0x10001usize),
    );
    assert_request(
        &req_list[5],
        ID_SHA1,
        &sha1_name_hash[..],
        &sha1_key_hash[..],
        &SerialNumber::from(0x5usize),
    );
    assert_request(
        &req_list[6],
        ID_SHA1,
        &sha1_name_hash[..],
        &sha1_key_hash[..],
        &SerialNumber::from(0x16usize),
    );
    assert_request(
        &req_list[7],
        ID_SHA1,
        &sha1_name_hash[..],
        &sha1_key_hash[..],
        &SerialNumber::from(0xFFFFFFFFusize),
    );
}

#[test]
fn decode_ocsp_req_signed() {
    let data = std::fs::read("tests/examples/ocsp-signed-req.der").unwrap();
    let cert_data = std::fs::read("tests/examples/rsa-2048-sha256-crt.der").unwrap();
    let ocsp_req = OcspRequest::from_der(&data[..]).unwrap();
    let name_hash = hex!("94D418C85D800AF31266F13D3D8CD8CD6AA5BB74");
    let key_hash = hex!("5DD72C171C018B2FFA92C3133913689EBD82115C");
    let serial = SerialNumber::from(0x10001usize);
    let signature = hex!(
        "1e0dfaf5e27978260b302ac79b1a038b328c\
         0bb518b3610af97813f7796660129e71a3aa\
         35703bddd5bdee3876d3a138fe78b514a45d\
         37168b992a6aafb286cc9ec653fd347cd69d\
         f41a065bb258791634991b7d868dfe25a621\
         bd0db54117437f270ed427c9cf00b5cd6211\
         0372ff31aa62831f838da8f3017240e8aaa0\
         08abbde6668974d2161b67f1bc75474590d8\
         f0cd371f694604303b2eb936c4c416ac990e\
         8ca9cfcaa3660c7307d666e71c57ea4e24f6\
         175180572f787bab9a529d8babeae3165cb6\
         fa080d62135c2de081359d7a40715e155f64\
         07649742066ea2142c12d0abb72c8e3e0105\
         582b6282e15c25989410df55912a3cb280c1\
         e48d1ae9"
    );
    assert_ocsp_request(&ocsp_req, 1);
    assert_request(
        &ocsp_req.tbs_request.request_list[0],
        ID_SHA1,
        &name_hash[..],
        &key_hash[..],
        &serial,
    );
    match &ocsp_req.optional_signature {
        Some(sig) => {
            assert_eq!(sig.signature_algorithm.oid, SHA_256_WITH_RSA_ENCRYPTION);
            assert_eq!(sig.signature.as_bytes().unwrap(), signature);
            match &sig.certs {
                Some(certs) => {
                    assert_eq!(certs.len(), 1);
                    assert_eq!(certs[0].to_der().unwrap(), cert_data);
                }
                None => panic!("no signing certificate"),
            }
        }
        None => panic!("no signature"),
    }
}
