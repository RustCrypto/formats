//! ocsp request decode tests

use der::{asn1::ObjectIdentifier, Decode, Encode};
use hex_literal::hex;
use x509_cert::{ext::Extension, serial_number::SerialNumber};
use x509_ocsp::*;

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

// OCSP Request Data:
//     Version: 1 (0x0)
//     Requestor List:
//         Certificate ID:
//           Hash Algorithm: sha1
//           Issuer Name Hash: 94D418C85D800AF31266F13D3D8CD8CD6AA5BB74
//           Issuer Key Hash: 5DD72C171C018B2FFA92C3133913689EBD82115C
//           Serial Number: 010001
#[test]
fn decode_ocsp_req_sha1_certid() {
    let data = hex!(
        "304430423040303e303c300906052b0e03021a0500041494d418c85d800a\
         f31266f13d3d8cd8cd6aa5bb7404145dd72c171c018b2ffa92c313391368\
         9ebd82115c0203010001"
    );
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

// OCSP Request Data:
//     Version: 1 (0x0)
//     Requestor List:
//         Certificate ID:
//           Hash Algorithm: sha224
//           Issuer Name Hash: 3D1F07D457D6634B0F2501C71ADB1DE5C41C515207F4206A5ACDA560
//           Issuer Key Hash: 2962CA2A9DE7A3A75A96EAC2031F50684DF5B50F5E6635DECBD74DA3
//           Serial Number: 01000
#[test]
fn decode_ocsp_req_sha224_certid() {
    let data = hex!(
        "30583056305430523050300d06096086480165030402040500041c3d1f07\
         d457d6634b0f2501c71adb1de5c41c515207f4206a5acda560041c2962ca\
         2a9de7a3a75a96eac2031f50684df5b50f5e6635decbd74da30203010001"
    );
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

// OCSP Request Data:
//     Version: 1 (0x0)
//     Requestor List:
//         Certificate ID:
//           Hash Algorithm: sha256
//           Issuer Name Hash: 056078AE157D9BB53154B1ABEBD26057D624FDDD9F09AE63814E90A365F444C5
//           Issuer Key Hash: 15C37A883122D2FB6DBFA83E3CBD93E9EEF8125E3FD785724BC42D9D6FBA39B7
//           Serial Number: 010001
#[test]
fn decode_ocsp_req_sha256_certid() {
    let data = hex!(
        "3060305e305c305a3058300d060960864801650304020105000420056078\
         ae157d9bb53154b1abebd26057d624fddd9f09ae63814e90a365f444c504\
         2015c37a883122d2fb6dbfa83e3cbd93e9eef8125e3fd785724bc42d9d6f\
         ba39b70203010001"
    );
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

// OCSP Request Data:
//     Version: 1 (0x0)
//     Requestor List:
//         Certificate ID:
//           Hash Algorithm: sha384
//           Issuer Name Hash: 97EFAF937F262E72C9C8FFFB55FDBC9FBB7EA353CD837CE01AF6F0D489AB4EC9AE4AD7\
//                             248410268C23F9C0FF5161BB28
//           Issuer Key Hash: F54E78323C7201B9C799040AF35FE3BC1492DA6B0EFD799C80BA45A611CDC129F6A790\
//                            67ACF14B83340FE122CF2305FE
//           Serial Number: 010001
#[test]
fn decode_ocsp_req_sha384_certid() {
    let data = hex!(
        "308180307e307c307a3078300d06096086480165030402020500043097ef\
         af937f262e72c9c8fffb55fdbc9fbb7ea353cd837ce01af6f0d489ab4ec9\
         ae4ad7248410268c23f9c0ff5161bb280430f54e78323c7201b9c799040a\
         f35fe3bc1492da6b0efd799c80ba45a611cdc129f6a79067acf14b83340f\
         e122cf2305fe0203010001"
    );
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

// OCSP Request Data:
//     Version: 1 (0x0)
//     Requestor List:
//         Certificate ID:
//           Hash Algorithm: sha512
//           Issuer Name Hash: 6AE6D566832B216D55BF3F8CCBBBD662E4D798D7E5FC64CEE6CB35DF60EE1181305CB2\
//                             747626560AFABD29B781A9A4631B0DFA1A05727323B3B81EEB54E57981
//           Issuer Key Hash: FEAC2688D16143E11050AEF3CDFAE4E4E21DF08F40A9FA3F5D80903B839450EE296202\
//                            63B12AB92F3E840458A4871119B6757D337CEDB9044B8A5F7239615E06
//           Serial Number: 010001
#[test]
fn decode_ocsp_req_sha512_certid() {
    let data = hex!(
        "3081a43081a130819e30819b308198300d06096086480165030402030500\
         04406ae6d566832b216d55bf3f8ccbbbd662e4d798d7e5fc64cee6cb35df\
         60ee1181305cb2747626560afabd29b781a9a4631b0dfa1a05727323b3b8\
         1eeb54e579810440feac2688d16143e11050aef3cdfae4e4e21df08f40a9\
         fa3f5d80903b839450ee29620263b12ab92f3e840458a4871119b6757d33\
         7cedb9044b8a5f7239615e060203010001"
    );
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

// OCSP Request Data:
//     Version: 1 (0x0)
//     Requestor List:
//         Certificate ID:
//           Hash Algorithm: sha1
//           Issuer Name Hash: 94D418C85D800AF31266F13D3D8CD8CD6AA5BB74
//           Issuer Key Hash: 5DD72C171C018B2FFA92C3133913689EBD82115C
//           Serial Number: 010001
//         Request Single Extensions:
//             OCSP Service Locator:
//                 Issuer: CN = rsa-2048-sha256-ca
//                                 OCSP - IP Address:127.0.0.1
//                                 OCSP - IP Address:0:0:0:0:0:0:0:1
//     Request Extensions:
//         OCSP Nonce:
//             0420CF8C1680796EC887B7D47C8BFDA825430B21589F2167614AB5B6727A48A55B7D
//         Acceptable OCSP Responses: critical
//             Basic OCSP Response
//
// -- asn1parse
//  ...
//   81:d=7  hl=2 l=   9 prim: OBJECT            :OCSP Service Locator
//   92:d=7  hl=2 l=  83 prim: OCTET STRING      [HEX DUMP]:3051301D311B3019060355040313127273612D323034382D7368613235362D636130\
//                                                          30301006082B0601050507300187047F000001301C06082B06010505073001871000\
//                                                          000000000000000000000000000001
//  ...
//  183:d=5  hl=2 l=   9 prim: OBJECT            :OCSP Nonce
//  194:d=5  hl=2 l=  34 prim: OCTET STRING      [HEX DUMP]:0420CF8C1680796EC887B7D47C8BFDA825430B21589F2167614AB5B6727A48A55B7D
//  ...
//  232:d=5  hl=2 l=   9 prim: OBJECT            :Acceptable OCSP Responses
//  243:d=5  hl=2 l=   1 prim: BOOLEAN           :255
//  246:d=5  hl=2 l=  13 prim: OCTET STRING      [HEX DUMP]:300B06092B0601050507300101
#[test]
fn decode_ocsp_req_multiple_extensions() {
    let data = hex!(
        "308201013081fe3081a73081a4303c300906052b0e03021a0500041494d4\
         18c85d800af31266f13d3d8cd8cd6aa5bb7404145dd72c171c018b2ffa92\
         c3133913689ebd82115c0203010001a0643062306006092b060105050730\
         010704533051301d311b3019060355040313127273612d323034382d7368\
         613235362d63613030301006082b0601050507300187047f000001301c06\
         082b06010505073001871000000000000000000000000000000001a25230\
         50302f06092b060105050730010204220420cf8c1680796ec887b7d47c8b\
         fda825430b21589f2167614ab5b6727a48a55b7d301d06092b0601050507\
         3001040101ff040d300b06092b0601050507300101"
    );
    let ocsp_req = OcspRequest::from_der(&data[..]).unwrap();
    let name_hash = hex!("94D418C85D800AF31266F13D3D8CD8CD6AA5BB74");
    let key_hash = hex!("5DD72C171C018B2FFA92C3133913689EBD82115C");
    let serial = SerialNumber::from(0x10001usize);
    let nonce_ext = hex!(
        "0420CF8C1680796EC887B7D47C8BFDA825430B21589F2167614AB5B6727A\
         48A55B7D"
    );
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

// OCSP Request Data:
//     Version: 1 (0x0)
//     Requestor List:
//         Certificate ID:
//           Hash Algorithm: sha1
//           Issuer Name Hash: 94D418C85D800AF31266F13D3D8CD8CD6AA5BB74
//           Issuer Key Hash: 5DD72C171C018B2FFA92C3133913689EBD82115C
//           Serial Number: 010001
//         Certificate ID:
//           Hash Algorithm: sha224
//           Issuer Name Hash: 3D1F07D457D6634B0F2501C71ADB1DE5C41C515207F4206A5ACDA560
//           Issuer Key Hash: 2962CA2A9DE7A3A75A96EAC2031F50684DF5B50F5E6635DECBD74DA3
//           Serial Number: 010001
//         Certificate ID:
//           Hash Algorithm: sha256
//           Issuer Name Hash: 056078AE157D9BB53154B1ABEBD26057D624FDDD9F09AE63814E90A365F444C5
//           Issuer Key Hash: 15C37A883122D2FB6DBFA83E3CBD93E9EEF8125E3FD785724BC42D9D6FBA39B7
//           Serial Number: 010001
//         Certificate ID:
//           Hash Algorithm: sha384
//           Issuer Name Hash: 97EFAF937F262E72C9C8FFFB55FDBC9FBB7EA353CD837CE01AF6F0D489AB4EC9AE4AD7\
//                             248410268C23F9C0FF5161BB28
//           Issuer Key Hash: F54E78323C7201B9C799040AF35FE3BC1492DA6B0EFD799C80BA45A611CDC129F6A790\
//                            67ACF14B83340FE122CF2305FE
//           Serial Number: 010001
//         Certificate ID:
//           Hash Algorithm: sha512
//           Issuer Name Hash: 6AE6D566832B216D55BF3F8CCBBBD662E4D798D7E5FC64CEE6CB35DF60EE1181305CB2\
//                             747626560AFABD29B781A9A4631B0DFA1A05727323B3B81EEB54E57981
//           Issuer Key Hash: FEAC2688D16143E11050AEF3CDFAE4E4E21DF08F40A9FA3F5D80903B839450EE296202\
//                            63B12AB92F3E840458A4871119B6757D337CEDB9044B8A5F7239615E06
//           Serial Number: 010001
//         Certificate ID:
//           Hash Algorithm: sha1
//           Issuer Name Hash: 94D418C85D800AF31266F13D3D8CD8CD6AA5BB74
//           Issuer Key Hash: 5DD72C171C018B2FFA92C3133913689EBD82115C
//           Serial Number: 05
//         Certificate ID:
//           Hash Algorithm: sha1
//           Issuer Name Hash: 94D418C85D800AF31266F13D3D8CD8CD6AA5BB74
//           Issuer Key Hash: 5DD72C171C018B2FFA92C3133913689EBD82115C
//           Serial Number: 16
//         Certificate ID:
//           Hash Algorithm: sha1
//           Issuer Name Hash: 94D418C85D800AF31266F13D3D8CD8CD6AA5BB74
//           Issuer Key Hash: 5DD72C171C018B2FFA92C3133913689EBD82115C
//           Serial Number: FFFFFFFF
#[test]
fn decode_ocsp_req_multiple_requests() {
    let data = hex!(
        "308202d0308202cc308202c8303e303c300906052b0e03021a0500041494\
         d418c85d800af31266f13d3d8cd8cd6aa5bb7404145dd72c171c018b2ffa\
         92c3133913689ebd82115c020301000130523050300d0609608648016503\
         0402040500041c3d1f07d457d6634b0f2501c71adb1de5c41c515207f420\
         6a5acda560041c2962ca2a9de7a3a75a96eac2031f50684df5b50f5e6635\
         decbd74da30203010001305a3058300d0609608648016503040201050004\
         20056078ae157d9bb53154b1abebd26057d624fddd9f09ae63814e90a365\
         f444c5042015c37a883122d2fb6dbfa83e3cbd93e9eef8125e3fd785724b\
         c42d9d6fba39b70203010001307a3078300d060960864801650304020205\
         00043097efaf937f262e72c9c8fffb55fdbc9fbb7ea353cd837ce01af6f0\
         d489ab4ec9ae4ad7248410268c23f9c0ff5161bb280430f54e78323c7201\
         b9c799040af35fe3bc1492da6b0efd799c80ba45a611cdc129f6a79067ac\
         f14b83340fe122cf2305fe020301000130819b308198300d060960864801\
         6503040203050004406ae6d566832b216d55bf3f8ccbbbd662e4d798d7e5\
         fc64cee6cb35df60ee1181305cb2747626560afabd29b781a9a4631b0dfa\
         1a05727323b3b81eeb54e579810440feac2688d16143e11050aef3cdfae4\
         e4e21df08f40a9fa3f5d80903b839450ee29620263b12ab92f3e840458a4\
         871119b6757d337cedb9044b8a5f7239615e060203010001303c303a3009\
         06052b0e03021a0500041494d418c85d800af31266f13d3d8cd8cd6aa5bb\
         7404145dd72c171c018b2ffa92c3133913689ebd82115c020105303c303a\
         300906052b0e03021a0500041494d418c85d800af31266f13d3d8cd8cd6a\
         a5bb7404145dd72c171c018b2ffa92c3133913689ebd82115c0201163040\
         303e300906052b0e03021a0500041494d418c85d800af31266f13d3d8cd8\
         cd6aa5bb7404145dd72c171c018b2ffa92c3133913689ebd82115c020500\
         ffffffff"
    );
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

// OCSP Request Data:
//     Version: 1 (0x0)
//     Requestor List:
//         Certificate ID:
//           Hash Algorithm: sha1
//           Issuer Name Hash: 94D418C85D800AF31266F13D3D8CD8CD6AA5BB74
//           Issuer Key Hash: 5DD72C171C018B2FFA92C3133913689EBD82115C
//           Serial Number: 010001
//         Certificate ID:
//           Hash Algorithm: sha224
//           Issuer Name Hash: 3D1F07D457D6634B0F2501C71ADB1DE5C41C515207F4206A5ACDA560
//           Issuer Key Hash: 2962CA2A9DE7A3A75A96EAC2031F50684DF5B50F5E6635DECBD74DA3
//           Serial Number: 010001
//         Certificate ID:
//           Hash Algorithm: sha256
//           Issuer Name Hash: 056078AE157D9BB53154B1ABEBD26057D624FDDD9F09AE63814E90A365F444C5
//           Issuer Key Hash: 15C37A883122D2FB6DBFA83E3CBD93E9EEF8125E3FD785724BC42D9D6FBA39B7
//           Serial Number: 010001
//         Certificate ID:
//           Hash Algorithm: sha384
//           Issuer Name Hash: 97EFAF937F262E72C9C8FFFB55FDBC9FBB7EA353CD837CE01AF6F0D489AB4EC9AE4AD7\
//                             248410268C23F9C0FF5161BB28
//           Issuer Key Hash: F54E78323C7201B9C799040AF35FE3BC1492DA6B0EFD799C80BA45A611CDC129F6A790\
//                            67ACF14B83340FE122CF2305FE
//           Serial Number: 010001
//         Certificate ID:
//           Hash Algorithm: sha512
//           Issuer Name Hash: 6AE6D566832B216D55BF3F8CCBBBD662E4D798D7E5FC64CEE6CB35DF60EE1181305CB2\
//                             747626560AFABD29B781A9A4631B0DFA1A05727323B3B81EEB54E57981
//           Issuer Key Hash: FEAC2688D16143E11050AEF3CDFAE4E4E21DF08F40A9FA3F5D80903B839450EE296202\
//                            63B12AB92F3E840458A4871119B6757D337CEDB9044B8A5F7239615E06
//           Serial Number: 010001
//         Certificate ID:
//           Hash Algorithm: sha1
//           Issuer Name Hash: 94D418C85D800AF31266F13D3D8CD8CD6AA5BB74
//           Issuer Key Hash: 5DD72C171C018B2FFA92C3133913689EBD82115C
//           Serial Number: 05
//         Certificate ID:
//           Hash Algorithm: sha1
//           Issuer Name Hash: 94D418C85D800AF31266F13D3D8CD8CD6AA5BB74
//           Issuer Key Hash: 5DD72C171C018B2FFA92C3133913689EBD82115C
//           Serial Number: 16
//         Certificate ID:
//           Hash Algorithm: sha1
//           Issuer Name Hash: 94D418C85D800AF31266F13D3D8CD8CD6AA5BB74
//           Issuer Key Hash: 5DD72C171C018B2FFA92C3133913689EBD82115C
//           Serial Number: FFFFFFFF
//     Request Extensions:
//         OCSP Nonce:
//             0420C683B4342C1DEFBE6BB5839DC41B26BA7C63364C7F5452A1E0E2FB24DC6EE770
#[test]
fn decode_ocsp_req_multiple_requests_nonce() {
    let data = hex!(
        "3082030530820301308202c8303e303c300906052b0e03021a0500041494\
         d418c85d800af31266f13d3d8cd8cd6aa5bb7404145dd72c171c018b2ffa\
         92c3133913689ebd82115c020301000130523050300d0609608648016503\
         0402040500041c3d1f07d457d6634b0f2501c71adb1de5c41c515207f420\
         6a5acda560041c2962ca2a9de7a3a75a96eac2031f50684df5b50f5e6635\
         decbd74da30203010001305a3058300d0609608648016503040201050004\
         20056078ae157d9bb53154b1abebd26057d624fddd9f09ae63814e90a365\
         f444c5042015c37a883122d2fb6dbfa83e3cbd93e9eef8125e3fd785724b\
         c42d9d6fba39b70203010001307a3078300d060960864801650304020205\
         00043097efaf937f262e72c9c8fffb55fdbc9fbb7ea353cd837ce01af6f0\
         d489ab4ec9ae4ad7248410268c23f9c0ff5161bb280430f54e78323c7201\
         b9c799040af35fe3bc1492da6b0efd799c80ba45a611cdc129f6a79067ac\
         f14b83340fe122cf2305fe020301000130819b308198300d060960864801\
         6503040203050004406ae6d566832b216d55bf3f8ccbbbd662e4d798d7e5\
         fc64cee6cb35df60ee1181305cb2747626560afabd29b781a9a4631b0dfa\
         1a05727323b3b81eeb54e579810440feac2688d16143e11050aef3cdfae4\
         e4e21df08f40a9fa3f5d80903b839450ee29620263b12ab92f3e840458a4\
         871119b6757d337cedb9044b8a5f7239615e060203010001303c303a3009\
         06052b0e03021a0500041494d418c85d800af31266f13d3d8cd8cd6aa5bb\
         7404145dd72c171c018b2ffa92c3133913689ebd82115c020105303c303a\
         300906052b0e03021a0500041494d418c85d800af31266f13d3d8cd8cd6a\
         a5bb7404145dd72c171c018b2ffa92c3133913689ebd82115c0201163040\
         303e300906052b0e03021a0500041494d418c85d800af31266f13d3d8cd8\
         cd6aa5bb7404145dd72c171c018b2ffa92c3133913689ebd82115c020500\
         ffffffffa2333031302f06092b060105050730010204220420c683b4342c\
         1defbe6bb5839dc41b26ba7c63364c7f5452a1e0e2fb24dc6ee770"
    );
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
    let nonce_ext = hex!(
        "0420C683B4342C1DEFBE6BB5839DC41B26BA7C63364C7F5452A1E0E2FB24\
         DC6EE770"
    );

    assert_ocsp_request(&ocsp_req, 8);
    assert!(ocsp_req.optional_signature.is_none());
    assert!(ocsp_req.tbs_request.request_extensions.is_some());
    let req_exts = ocsp_req.tbs_request.request_extensions.as_ref().unwrap();
    assert_eq!(req_exts.len(), 1);
    assert_extension(&req_exts[0], ID_PKIX_OCSP_NONCE, false, &nonce_ext[..]);

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

// OCSP Request Data:
//     Version: 1 (0x0)
//     Requestor List:
//         Certificate ID:
//           Hash Algorithm: sha1
//           Issuer Name Hash: 94D418C85D800AF31266F13D3D8CD8CD6AA5BB74
//           Issuer Key Hash: 5DD72C171C018B2FFA92C3133913689EBD82115C
//           Serial Number: 010001
//     Signature Algorithm: sha256WithRSAEncryption
//     Signature Value:
//         1e:0d:fa:f5:e2:79:78:26:0b:30:2a:c7:9b:1a:03:8b:32:8c:
//         0b:b5:18:b3:61:0a:f9:78:13:f7:79:66:60:12:9e:71:a3:aa:
//         35:70:3b:dd:d5:bd:ee:38:76:d3:a1:38:fe:78:b5:14:a4:5d:
//         37:16:8b:99:2a:6a:af:b2:86:cc:9e:c6:53:fd:34:7c:d6:9d:
//         f4:1a:06:5b:b2:58:79:16:34:99:1b:7d:86:8d:fe:25:a6:21:
//         bd:0d:b5:41:17:43:7f:27:0e:d4:27:c9:cf:00:b5:cd:62:11:
//         03:72:ff:31:aa:62:83:1f:83:8d:a8:f3:01:72:40:e8:aa:a0:
//         08:ab:bd:e6:66:89:74:d2:16:1b:67:f1:bc:75:47:45:90:d8:
//         f0:cd:37:1f:69:46:04:30:3b:2e:b9:36:c4:c4:16:ac:99:0e:
//         8c:a9:cf:ca:a3:66:0c:73:07:d6:66:e7:1c:57:ea:4e:24:f6:
//         17:51:80:57:2f:78:7b:ab:9a:52:9d:8b:ab:ea:e3:16:5c:b6:
//         fa:08:0d:62:13:5c:2d:e0:81:35:9d:7a:40:71:5e:15:5f:64:
//         07:64:97:42:06:6e:a2:14:2c:12:d0:ab:b7:2c:8e:3e:01:05:
//         58:2b:62:82:e1:5c:25:98:94:10:df:55:91:2a:3c:b2:80:c1:
//         e4:8d:1a:e9
// Certificate:
//     Data:
//         Version: 1 (0x0)
//         Serial Number: 2 (0x2)
//         Signature Algorithm: sha256WithRSAEncryption
//         Issuer: CN=rsa-2048-sha256-ca
//         Validity
//             Not Before: Nov  5 01:09:45 2023 GMT
//             Not After : Nov  4 01:09:45 2026 GMT
//         Subject: CN=rsa-2048-sha256-crt
//         Subject Public Key Info:
//             Public Key Algorithm: rsaEncryption
//                 Public-Key: (2048 bit)
//                 Modulus:
//                     00:c1:2e:ec:dc:ae:5f:1f:c3:38:fb:a5:3f:19:8e:
//                     7c:65:f4:ef:83:22:dc:b3:ff:21:9a:6b:08:b2:2f:
//                     34:b6:e7:af:75:fd:37:b4:6f:21:fe:bb:ef:17:dd:
//                     7a:54:ce:d2:75:92:29:51:8c:d7:59:ae:c0:fd:c5:
//                     96:27:ca:e5:ed:ae:b2:6c:cb:ee:c5:e5:44:ee:5f:
//                     fe:d8:7d:c2:1c:f0:19:e8:51:ed:d3:18:a4:a3:ca:
//                     28:4c:35:4e:64:7c:0a:20:42:1c:e3:15:54:d1:cf:
//                     b9:38:79:7f:8d:34:fa:30:4f:09:69:7b:ca:b4:71:
//                     0a:2a:b9:e9:eb:cf:56:7c:fa:50:7b:10:ea:8d:35:
//                     4c:5b:da:55:84:c6:a2:be:b2:87:8a:de:28:2a:e1:
//                     6d:5f:82:58:de:39:bf:55:c8:2e:b6:bb:e1:73:a9:
//                     2d:8c:dd:8d:d5:0d:34:da:e0:31:e1:a3:0f:41:4a:
//                     64:bf:5e:66:2a:e9:b7:78:31:ce:8b:c0:c4:57:cc:
//                     d4:07:37:b9:1a:d4:28:e9:19:db:d3:03:21:5a:83:
//                     9d:66:f0:f8:f6:d8:96:cf:99:79:dd:19:58:be:df:
//                     d6:5e:b6:1f:79:86:44:0a:91:88:37:b1:4c:01:af:
//                     fc:80:b7:cf:c3:55:5d:86:73:c3:87:cb:df:77:01:
//                     a9:73
//                 Exponent: 65537 (0x10001)
//     Signature Algorithm: sha256WithRSAEncryption
//     Signature Value:
//         04:80:4e:2f:d4:65:f0:c9:dc:fb:b4:8a:d5:f9:72:cd:ad:db:
//         33:61:7f:1f:fd:27:47:75:ec:6a:46:20:46:d9:ed:f3:b2:cc:
//         3e:25:62:fa:4e:78:4a:ae:f6:f4:ca:a9:95:2b:07:3d:01:3c:
//         71:a4:52:99:2e:7f:d5:da:d6:3c:97:60:b9:9c:4f:0f:6f:a3:
//         de:a9:d9:cb:3e:18:49:42:05:f1:49:66:7e:ac:a1:6a:19:51:
//         2b:bb:e1:3b:9e:b3:e2:da:bc:bc:36:12:45:00:f6:de:33:d1:
//         af:6b:52:c2:99:b8:ab:72:c8:55:9b:a4:8d:b8:18:9c:95:2f:
//         8b:f0:83:b1:80:25:b5:91:d4:e3:28:93:37:b1:cf:7f:c8:48:
//         18:ba:ac:0f:64:d0:b7:ca:c8:88:6a:75:01:14:b6:8c:6a:49:
//         65:d8:01:fe:26:23:77:d9:f0:4d:96:da:c4:90:b0:20:a6:8c:
//         5d:2a:88:3d:1a:32:4c:97:5b:47:5b:88:4e:72:13:86:85:21:
//         90:03:82:67:5f:94:6e:45:d8:50:70:f7:10:5c:bb:38:2c:99:
//         f3:d8:3a:3a:5d:a1:d9:12:83:83:bc:f3:a6:fa:e1:10:2a:6e:
//         5b:72:ec:ea:b1:ad:61:74:6e:cc:03:21:0e:95:75:07:28:22:
//         62:44:a9:7e
//
// -- stripped signature bytes
//
// 1e0dfaf5e27978260b302ac79b1a038b328c
// 0bb518b3610af97813f7796660129e71a3aa
// 35703bddd5bdee3876d3a138fe78b514a45d
// 37168b992a6aafb286cc9ec653fd347cd69d
// f41a065bb258791634991b7d868dfe25a621
// bd0db54117437f270ed427c9cf00b5cd6211
// 0372ff31aa62831f838da8f3017240e8aaa0
// 08abbde6668974d2161b67f1bc75474590d8
// f0cd371f694604303b2eb936c4c416ac990e
// 8ca9cfcaa3660c7307d666e71c57ea4e24f6
// 175180572f787bab9a529d8babeae3165cb6
// fa080d62135c2de081359d7a40715e155f64
// 07649742066ea2142c12d0abb72c8e3e0105
// 582b6282e15c25989410df55912a3cb280c1
// e48d1ae9
#[test]
fn decode_ocsp_req_signed() {
    let ocsp_data = hex!(
        "3082041b30423040303e303c300906052b0e03021a0500041494d418c85d\
         800af31266f13d3d8cd8cd6aa5bb7404145dd72c171c018b2ffa92c31339\
         13689ebd82115c0203010001a08203d3308203cf300d06092a864886f70d\
         01010b050003820101001e0dfaf5e27978260b302ac79b1a038b328c0bb5\
         18b3610af97813f7796660129e71a3aa35703bddd5bdee3876d3a138fe78\
         b514a45d37168b992a6aafb286cc9ec653fd347cd69df41a065bb2587916\
         34991b7d868dfe25a621bd0db54117437f270ed427c9cf00b5cd62110372\
         ff31aa62831f838da8f3017240e8aaa008abbde6668974d2161b67f1bc75\
         474590d8f0cd371f694604303b2eb936c4c416ac990e8ca9cfcaa3660c73\
         07d666e71c57ea4e24f6175180572f787bab9a529d8babeae3165cb6fa08\
         0d62135c2de081359d7a40715e155f6407649742066ea2142c12d0abb72c\
         8e3e0105582b6282e15c25989410df55912a3cb280c1e48d1ae9a08202b7\
         308202b3308202af30820197020102300d06092a864886f70d01010b0500\
         301d311b3019060355040313127273612d323034382d7368613235362d63\
         61301e170d3233313130353031303934355a170d32363131303430313039\
         34355a301e311c301a060355040313137273612d323034382d7368613235\
         362d63727430820122300d06092a864886f70d01010105000382010f0030\
         82010a0282010100c12eecdcae5f1fc338fba53f198e7c65f4ef8322dcb3\
         ff219a6b08b22f34b6e7af75fd37b46f21febbef17dd7a54ced275922951\
         8cd759aec0fdc59627cae5edaeb26ccbeec5e544ee5ffed87dc21cf019e8\
         51edd318a4a3ca284c354e647c0a20421ce31554d1cfb938797f8d34fa30\
         4f09697bcab4710a2ab9e9ebcf567cfa507b10ea8d354c5bda5584c6a2be\
         b2878ade282ae16d5f8258de39bf55c82eb6bbe173a92d8cdd8dd50d34da\
         e031e1a30f414a64bf5e662ae9b77831ce8bc0c457ccd40737b91ad428e9\
         19dbd303215a839d66f0f8f6d896cf9979dd1958bedfd65eb61f7986440a\
         918837b14c01affc80b7cfc3555d8673c387cbdf7701a973020301000130\
         0d06092a864886f70d01010b0500038201010004804e2fd465f0c9dcfbb4\
         8ad5f972cdaddb33617f1ffd274775ec6a462046d9edf3b2cc3e2562fa4e\
         784aaef6f4caa9952b073d013c71a452992e7fd5dad63c9760b99c4f0f6f\
         a3dea9d9cb3e18494205f149667eaca16a19512bbbe13b9eb3e2dabcbc36\
         124500f6de33d1af6b52c299b8ab72c8559ba48db8189c952f8bf083b180\
         25b591d4e3289337b1cf7fc84818baac0f64d0b7cac8886a750114b68c6a\
         4965d801fe262377d9f04d96dac490b020a68c5d2a883d1a324c975b475b\
         884e7213868521900382675f946e45d85070f7105cbb382c99f3d83a3a5d\
         a1d9128383bcf3a6fae1102a6e5b72eceab1ad61746ecc03210e95750728\
         226244a97e"
    );
    let cert_data = hex!(
        "308202af30820197020102300d06092a864886f70d01010b0500301d311b\
         3019060355040313127273612d323034382d7368613235362d6361301e17\
         0d3233313130353031303934355a170d3236313130343031303934355a30\
         1e311c301a060355040313137273612d323034382d7368613235362d6372\
         7430820122300d06092a864886f70d01010105000382010f003082010a02\
         82010100c12eecdcae5f1fc338fba53f198e7c65f4ef8322dcb3ff219a6b\
         08b22f34b6e7af75fd37b46f21febbef17dd7a54ced2759229518cd759ae\
         c0fdc59627cae5edaeb26ccbeec5e544ee5ffed87dc21cf019e851edd318\
         a4a3ca284c354e647c0a20421ce31554d1cfb938797f8d34fa304f09697b\
         cab4710a2ab9e9ebcf567cfa507b10ea8d354c5bda5584c6a2beb2878ade\
         282ae16d5f8258de39bf55c82eb6bbe173a92d8cdd8dd50d34dae031e1a3\
         0f414a64bf5e662ae9b77831ce8bc0c457ccd40737b91ad428e919dbd303\
         215a839d66f0f8f6d896cf9979dd1958bedfd65eb61f7986440a918837b1\
         4c01affc80b7cfc3555d8673c387cbdf7701a9730203010001300d06092a\
         864886f70d01010b0500038201010004804e2fd465f0c9dcfbb48ad5f972\
         cdaddb33617f1ffd274775ec6a462046d9edf3b2cc3e2562fa4e784aaef6\
         f4caa9952b073d013c71a452992e7fd5dad63c9760b99c4f0f6fa3dea9d9\
         cb3e18494205f149667eaca16a19512bbbe13b9eb3e2dabcbc36124500f6\
         de33d1af6b52c299b8ab72c8559ba48db8189c952f8bf083b18025b591d4\
         e3289337b1cf7fc84818baac0f64d0b7cac8886a750114b68c6a4965d801\
         fe262377d9f04d96dac490b020a68c5d2a883d1a324c975b475b884e7213\
         868521900382675f946e45d85070f7105cbb382c99f3d83a3a5da1d91283\
         83bcf3a6fae1102a6e5b72eceab1ad61746ecc03210e95750728226244a9\
         7e"
    );
    let ocsp_req = OcspRequest::from_der(&ocsp_data[..]).unwrap();
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
