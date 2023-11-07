//! ocsp response decode tests

use der::{
    asn1::{GeneralizedTime, Null, ObjectIdentifier, OctetString},
    DateTime, Decode, Encode,
};
use hex_literal::hex;
use lazy_static::lazy_static;
use spki::AlgorithmIdentifierOwned;
use x509_cert::{ext::Extension, name::Name, serial_number::SerialNumber};
use x509_ocsp::*;

const ID_PKIX_OCSP_BASIC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");
const ID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const ID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
const ID_PKIX_OCSP_NONCE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.2");
const ID_PKIX_OCSP_CRL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.3");
const ID_PKIX_OCSP_ARCHIVE_CUTOFF: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.6");
const SHA_256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

lazy_static! {
    // CN = rsa-2048-sha256-ocsp-crt (printable string)
    static ref RESPONDER_ID: ResponderId = ResponderId::ByName(
        Name::from_der(
            &hex!(
                "30233121301f060355040313187273612d323034382d7368613235362d6f\
                 6373702d637274"
                 )[..]
            )
        .unwrap()
        );
    static ref TIME: GeneralizedTime =
        GeneralizedTime::from_date_time(DateTime::new(2020, 1, 1, 0, 0, 0).unwrap());
}

const CA_CERTIFICATE_DATA: &[u8] = &hex!(
    "3082032b30820213a003020102020101300d06092a864886f70d01010b05\
     00301d311b3019060355040313127273612d323034382d7368613235362d\
     6361301e170d3233313130353031303934355a170d333231313032303130\
     3934355a301d311b3019060355040313127273612d323034382d73686132\
     35362d636130820122300d06092a864886f70d01010105000382010f0030\
     82010a0282010100be984263d2834964fb0ca6668c72bd2162934811dd51\
     2efc9bd0b02d8d6a18cb54256348e40fb6fc86c7d75b26c84b863034e034\
     e8928077ae22bafbd5b89828eadf300fe69d9c6b800f7ec86323379cfffe\
     dd6c921b07354fbe3020dd3ef56e77df0420b2a43854dd711120b3d945e2\
     a619e70963d71bed0ff8955a6bed95966572c0087f7b45db31b873cb75bd\
     42c21e83d47f29ba2d4fb213b91d8554504e4d75768c547a5a49559e6ae4\
     57deed051273ea7c8482ec72e4749095ed6ba06ad04407297244472d9118\
     308ce066ba23566ff5faa9301d65b09bafe53c337e776a3a81a8e774b771\
     5b39570c59c4c3316c576466167d6779ff5244362f7541850203010001a3\
     763074300c0603551d13040530030101ff301d0603551d0e041604145dd7\
     2c171c018b2ffa92c3133913689ebd82115c30450603551d23043e303c80\
     145dd72c171c018b2ffa92c3133913689ebd82115ca121a41f301d311b30\
     19060355040313127273612d323034382d7368613235362d636182010130\
     0d06092a864886f70d01010b05000382010100a6c69f0a7d673fad77a1e9\
     78323289916ef85501e276c57a6dd8ca9917ea36b46088ff70f0d04b2c40\
     ae1f242942f5a0c4e4c7c80074ce32ec246c4e921163731d7bb2048f94f7\
     cade1c6e7e8abea615c5829f6cf55a4776cb3f4f18072b314b1b16a87e49\
     614d03a6371425d05099c5a3e4ef3e23cd170ba084ddae9e18ac3dc85c05\
     9462b75497bf1d8f01aa117841012619d4150944cb7b22a5b787edc6d606\
     de4ec6fa3641e8e3672dd4979228e556ec98097cafe035646b210d472dc1\
     9deecf0961901d06279e93239eb1f268804dfb7892dada551c81fc790b3f\
     246cdecafe01ac3108f42eb921e8e3d6d8cc83304fd22076555d3498aa4e\
     38da3584ff"
);

fn assert_ocsp_response(ocsp_res: &OcspResponse) -> BasicOcspResponse {
    assert_eq!(ocsp_res.response_status, OcspResponseStatus::Successful);
    let res = ocsp_res.response_bytes.as_ref().unwrap();
    assert_eq!(res.response_type, ID_PKIX_OCSP_BASIC);
    BasicOcspResponse::from_der(res.response.as_bytes()).unwrap()
}

fn assert_signature(
    res: &BasicOcspResponse,
    expected_alg_oid: ObjectIdentifier,
    expected_sig: &[u8],
    expected_cert: Option<&[u8]>,
) {
    assert_eq!(res.signature_algorithm.oid, expected_alg_oid);
    assert_eq!(res.signature.as_bytes().unwrap(), expected_sig);
    match expected_cert {
        Some(c) => {
            let certs = res.certs.as_ref().unwrap();
            assert_eq!(certs[0].to_der().unwrap(), c);
        }
        None => assert!(res.certs.as_ref().is_none()),
    }
}

fn assert_basic_response<'a>(
    res: &'a BasicOcspResponse,
    expected_id: &ResponderId,
    expected_time: &GeneralizedTime,
    expected_certid: &CertId,
) -> &'a SingleResponse {
    let data = &res.tbs_response_data;
    assert_eq!(data.version, Version::V1);
    assert_eq!(&data.responder_id, expected_id);
    assert_eq!(&data.produced_at, expected_time);
    let mut filter = data
        .responses
        .iter()
        .filter(|r| &r.cert_id == expected_certid);
    match filter.next() {
        None => panic!("CertId not found"),
        Some(res) => &res,
    }
}

fn assert_single_response(
    single_res: &SingleResponse,
    expected_status: CertStatus,
    expected_this_update: &GeneralizedTime,
    expected_next_update: Option<&GeneralizedTime>,
) {
    assert_eq!(single_res.cert_status, expected_status);
    assert_eq!(single_res.this_update, *expected_this_update);
    assert_eq!(single_res.next_update, expected_next_update.copied());
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

// Responder Error: malformedrequest (1)
#[test]
fn decode_ocsp_resp_malformed_request() {
    let data = hex!("30030a0101");
    let ocsp_res = OcspResponse::from_der(&data[..]).unwrap();
    assert_eq!(
        ocsp_res.response_status,
        OcspResponseStatus::MalformedRequest
    );
}

// Responder Error: internalerror (2)
#[test]
fn decode_ocsp_resp_internal_error() {
    let data = hex!("30030a0102");
    let ocsp_res = OcspResponse::from_der(&data[..]).unwrap();
    assert_eq!(ocsp_res.response_status, OcspResponseStatus::InternalError);
}

// Responder Error: trylater (3)
#[test]
fn decode_ocsp_resp_try_later() {
    let data = hex!("30030a0103");
    let ocsp_res = OcspResponse::from_der(&data[..]).unwrap();
    assert_eq!(ocsp_res.response_status, OcspResponseStatus::TryLater);
}

// Responder Error: sigrequired (5)
#[test]
fn decode_ocsp_resp_sig_required() {
    let data = hex!("30030a0105");
    let ocsp_res = OcspResponse::from_der(&data[..]).unwrap();
    assert_eq!(ocsp_res.response_status, OcspResponseStatus::SigRequired);
}

// Responder Error: unauthorized (6)
#[test]
fn decode_ocsp_resp_unauthorized() {
    let data = hex!("30030a0106");
    let ocsp_res = OcspResponse::from_der(&data[..]).unwrap();
    assert_eq!(ocsp_res.response_status, OcspResponseStatus::Unauthorized);
}

// OCSP Response Data:
//     OCSP Response Status: successful (0x0)
//     Response Type: Basic OCSP Response
//     Version: 1 (0x0)
//     Responder Id: CN = rsa-2048-sha256-ocsp-crt
//     Produced At: Jan  1 00:00:00 2020 GMT
//     Responses:
//     Certificate ID:
//       Hash Algorithm: sha1
//       Issuer Name Hash: 94D418C85D800AF31266F13D3D8CD8CD6AA5BB74
//       Issuer Key Hash: 5DD72C171C018B2FFA92C3133913689EBD82115C
//       Serial Number: 010001
//     Cert Status: good
//     This Update: Jan  1 00:00:00 2020 GMT
//     Next Update: Jan  1 00:00:00 2020 GMT
//
//     Signature Algorithm: sha256WithRSAEncryption
//     Signature Value:
//         22:80:f3:fd:0b:26:43:b4:e2:7f:86:b5:99:fd:29:74:5d:51:
//         4d:ce:a2:39:64:6a:c1:d0:52:20:75:30:9f:ec:4e:14:8a:51:
//         49:f1:9c:01:8c:88:6e:70:7e:c9:f1:51:61:39:6a:d0:69:2e:
//         56:8e:5c:3a:e6:78:43:3b:03:c8:9b:54:9c:1b:22:a8:d8:d9:
//         c3:48:89:1b:07:d4:6c:06:82:17:d2:2e:53:c6:1f:56:71:b2:
//         2d:65:7b:84:7f:c2:bc:15:1d:d8:c8:16:eb:7d:a3:0d:bf:c6:
//         fb:3f:17:d3:da:81:e6:51:cb:08:0c:f6:27:34:6a:8e:db:06:
//         7f:36:ea:f2:d6:77:e8:d4:04:a2:2d:88:92:20:07:22:89:fe:
//         f3:25:df:92:5c:d1:1b:7f:0f:e4:1a:09:b9:27:62:69:4c:87:
//         dd:73:3e:15:4d:54:51:13:ac:c2:83:53:2e:c0:18:1d:10:07:
//         31:3a:97:00:b1:e0:93:be:77:4a:c1:cb:6f:0c:5a:a9:70:65:
//         fd:ff:5b:68:2d:79:0f:10:ed:fa:a8:e8:2d:26:a9:13:e1:de:
//         26:8d:5a:6f:28:a3:b2:33:a0:e0:bd:51:11:5e:db:fa:c6:f2:
//         c4:c8:d9:29:8f:21:ec:42:24:ec:49:d4:47:98:4b:5f:e9:94:
//         46:1b:f3:b3
//
// -- stripped signature bytes
//
// 2280f3fd0b2643b4e27f86b599fd29745d51
// 4dcea239646ac1d0522075309fec4e148a51
// 49f19c018c886e707ec9f15161396ad0692e
// 568e5c3ae678433b03c89b549c1b22a8d8d9
// c348891b07d46c068217d22e53c61f5671b2
// 2d657b847fc2bc151dd8c816eb7da30dbfc6
// fb3f17d3da81e651cb080cf627346a8edb06
// 7f36eaf2d677e8d404a22d889220072289fe
// f325df925cd11b7f0fe41a09b92762694c87
// dd733e154d545113acc283532ec0181d1007
// 313a9700b1e093be774ac1cb6f0c5aa97065
// fdff5b682d790f10edfaa8e82d26a913e1de
// 268d5a6f28a3b233a0e0bd51115edbfac6f2
// c4c8d9298f21ec4224ec49d447984b5fe994
// 461bf3b3
#[test]
fn decode_ocsp_resp_sha1_certid() {
    let data = hex!(
        "3082050c0a0100a08205053082050106092b0601050507300101048204f2\
         308204ee3081a0a12530233121301f060355040313187273612d32303438\
         2d7368613235362d6f6373702d637274180f323032303031303130303030\
         30305a30663064303c300906052b0e03021a0500041494d418c85d800af3\
         1266f13d3d8cd8cd6aa5bb7404145dd72c171c018b2ffa92c3133913689e\
         bd82115c02030100018000180f32303230303130313030303030305aa011\
         180f32303230303130313030303030305a300d06092a864886f70d01010b\
         050003820101002280f3fd0b2643b4e27f86b599fd29745d514dcea23964\
         6ac1d0522075309fec4e148a5149f19c018c886e707ec9f15161396ad069\
         2e568e5c3ae678433b03c89b549c1b22a8d8d9c348891b07d46c068217d2\
         2e53c61f5671b22d657b847fc2bc151dd8c816eb7da30dbfc6fb3f17d3da\
         81e651cb080cf627346a8edb067f36eaf2d677e8d404a22d889220072289\
         fef325df925cd11b7f0fe41a09b92762694c87dd733e154d545113acc283\
         532ec0181d1007313a9700b1e093be774ac1cb6f0c5aa97065fdff5b682d\
         790f10edfaa8e82d26a913e1de268d5a6f28a3b233a0e0bd51115edbfac6\
         f2c4c8d9298f21ec4224ec49d447984b5fe994461bf3b3a0820333308203\
         2f3082032b30820213a003020102020101300d06092a864886f70d01010b\
         0500301d311b3019060355040313127273612d323034382d736861323536\
         2d6361301e170d3233313130353031303934355a170d3332313130323031\
         303934355a301d311b3019060355040313127273612d323034382d736861\
         3235362d636130820122300d06092a864886f70d01010105000382010f00\
         3082010a0282010100be984263d2834964fb0ca6668c72bd2162934811dd\
         512efc9bd0b02d8d6a18cb54256348e40fb6fc86c7d75b26c84b863034e0\
         34e8928077ae22bafbd5b89828eadf300fe69d9c6b800f7ec86323379cff\
         fedd6c921b07354fbe3020dd3ef56e77df0420b2a43854dd711120b3d945\
         e2a619e70963d71bed0ff8955a6bed95966572c0087f7b45db31b873cb75\
         bd42c21e83d47f29ba2d4fb213b91d8554504e4d75768c547a5a49559e6a\
         e457deed051273ea7c8482ec72e4749095ed6ba06ad04407297244472d91\
         18308ce066ba23566ff5faa9301d65b09bafe53c337e776a3a81a8e774b7\
         715b39570c59c4c3316c576466167d6779ff5244362f7541850203010001\
         a3763074300c0603551d13040530030101ff301d0603551d0e041604145d\
         d72c171c018b2ffa92c3133913689ebd82115c30450603551d23043e303c\
         80145dd72c171c018b2ffa92c3133913689ebd82115ca121a41f301d311b\
         3019060355040313127273612d323034382d7368613235362d6361820101\
         300d06092a864886f70d01010b05000382010100a6c69f0a7d673fad77a1\
         e978323289916ef85501e276c57a6dd8ca9917ea36b46088ff70f0d04b2c\
         40ae1f242942f5a0c4e4c7c80074ce32ec246c4e921163731d7bb2048f94\
         f7cade1c6e7e8abea615c5829f6cf55a4776cb3f4f18072b314b1b16a87e\
         49614d03a6371425d05099c5a3e4ef3e23cd170ba084ddae9e18ac3dc85c\
         059462b75497bf1d8f01aa117841012619d4150944cb7b22a5b787edc6d6\
         06de4ec6fa3641e8e3672dd4979228e556ec98097cafe035646b210d472d\
         c19deecf0961901d06279e93239eb1f268804dfb7892dada551c81fc790b\
         3f246cdecafe01ac3108f42eb921e8e3d6d8cc83304fd22076555d3498aa\
         4e38da3584ff"
    );
    let signature = hex!(
        "2280f3fd0b2643b4e27f86b599fd29745d51\
        4dcea239646ac1d0522075309fec4e148a51\
        49f19c018c886e707ec9f15161396ad0692e\
        568e5c3ae678433b03c89b549c1b22a8d8d9\
        c348891b07d46c068217d22e53c61f5671b2\
        2d657b847fc2bc151dd8c816eb7da30dbfc6\
        fb3f17d3da81e651cb080cf627346a8edb06\
        7f36eaf2d677e8d404a22d889220072289fe\
        f325df925cd11b7f0fe41a09b92762694c87\
        dd733e154d545113acc283532ec0181d1007\
        313a9700b1e093be774ac1cb6f0c5aa97065\
        fdff5b682d790f10edfaa8e82d26a913e1de\
        268d5a6f28a3b233a0e0bd51115edbfac6f2\
        c4c8d9298f21ec4224ec49d447984b5fe994\
        461bf3b3"
    );
    let res = OcspResponse::from_der(&data[..]).unwrap();
    let res = assert_ocsp_response(&res);
    assert_signature(
        &res,
        SHA_256_WITH_RSA_ENCRYPTION,
        &signature[..],
        Some(CA_CERTIFICATE_DATA),
    );
    let certid = CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: ID_SHA1,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(&hex!("94D418C85D800AF31266F13D3D8CD8CD6AA5BB74")[..])
            .unwrap(),
        issuer_key_hash: OctetString::new(&hex!("5DD72C171C018B2FFA92C3133913689EBD82115C")[..])
            .unwrap(),
        serial_number: SerialNumber::from(0x10001usize),
    };
    let single = assert_basic_response(&res, &RESPONDER_ID, &TIME, &certid);
    assert_single_response(&single, CertStatus::Good(Null), &TIME, Some(&TIME));
}

// OCSP Response Data:
//     OCSP Response Status: successful (0x0)
//     Response Type: Basic OCSP Response
//     Version: 1 (0x0)
//     Responder Id: CN = rsa-2048-sha256-ocsp-crt
//     Produced At: Jan  1 00:00:00 2020 GMT
//     Responses:
//     Certificate ID:
//       Hash Algorithm: sha256
//       Issuer Name Hash: 056078AE157D9BB53154B1ABEBD26057D624FDDD9F09AE63814E90A365F444C5
//       Issuer Key Hash: 15C37A883122D2FB6DBFA83E3CBD93E9EEF8125E3FD785724BC42D9D6FBA39B7
//       Serial Number: 010001
//     Cert Status: good
//     This Update: Jan  1 00:00:00 2020 GMT
//     Next Update: Jan  1 00:00:00 2020 GMT
//
//     Signature Algorithm: sha256WithRSAEncryption
//     Signature Value:
//         7a:19:ff:54:0d:48:41:49:27:11:b8:b0:62:0c:f5:b7:c8:eb:
//         10:61:18:4d:8e:e0:90:6b:33:14:ef:d2:4a:eb:e6:7e:49:ae:
//         9e:46:1e:c9:b7:6d:83:73:47:71:47:af:3b:f6:e8:c8:5d:e5:
//         37:f8:eb:58:2d:9f:2d:8c:55:05:73:1b:9e:83:cc:ed:df:30:
//         9d:14:db:97:e7:a0:a5:83:db:72:66:9e:30:ec:ad:b3:d4:63:
//         3f:56:30:97:aa:e3:c1:20:ca:51:b2:8d:61:10:79:83:f1:72:
//         c9:85:ac:1f:0c:e9:54:28:c0:6b:07:64:42:6c:e0:87:fd:ce:
//         be:e7:39:e2:54:a9:0a:9e:10:5f:07:37:72:c0:38:84:61:92:
//         d4:50:8e:4c:f2:bc:2e:5f:0a:51:1b:8c:76:34:5a:c1:34:93:
//         04:32:57:7f:62:9d:8a:a5:21:71:89:1e:1f:26:6a:a1:ef:40:
//         cd:58:1e:ad:c1:93:ca:fd:d9:cc:90:16:96:02:aa:c1:70:b8:
//         31:8c:78:1b:ec:ba:05:9c:7e:f5:44:50:a5:7c:cd:d3:c6:e1:
//         ce:a1:3e:13:d5:8d:be:a3:e4:a1:aa:80:9a:4d:bf:e0:fd:08:
//         32:90:5e:25:6b:a5:37:19:8c:37:68:f3:4f:ff:29:16:3d:64:
//         34:be:02:c2
//
// -- stripped signature bytes
//
// 7a19ff540d4841492711b8b0620cf5b7c8eb
// 1061184d8ee0906b3314efd24aebe67e49ae
// 9e461ec9b76d8373477147af3bf6e8c85de5
// 37f8eb582d9f2d8c5505731b9e83cceddf30
// 9d14db97e7a0a583db72669e30ecadb3d463
// 3f563097aae3c120ca51b28d61107983f172
// c985ac1f0ce95428c06b0764426ce087fdce
// bee739e254a90a9e105f073772c038846192
// d4508e4cf2bc2e5f0a511b8c76345ac13493
// 0432577f629d8aa52171891e1f266aa1ef40
// cd581eadc193cafdd9cc90169602aac170b8
// 318c781becba059c7ef54450a57ccdd3c6e1
// cea13e13d58dbea3e4a1aa809a4dbfe0fd08
// 32905e256ba537198c3768f34fff29163d64
// 34be02c2
#[test]
fn decode_ocsp_resp_sha256_certid() {
    let data = hex!(
        "3082052a0a0100a08205233082051f06092b060105050730010104820510\
         3082050c3081bea12530233121301f060355040313187273612d32303438\
         2d7368613235362d6f6373702d637274180f323032303031303130303030\
         30305a3081833081803058300d0609608648016503040201050004200560\
         78ae157d9bb53154b1abebd26057d624fddd9f09ae63814e90a365f444c5\
         042015c37a883122d2fb6dbfa83e3cbd93e9eef8125e3fd785724bc42d9d\
         6fba39b702030100018000180f32303230303130313030303030305aa011\
         180f32303230303130313030303030305a300d06092a864886f70d01010b\
         050003820101007a19ff540d4841492711b8b0620cf5b7c8eb1061184d8e\
         e0906b3314efd24aebe67e49ae9e461ec9b76d8373477147af3bf6e8c85d\
         e537f8eb582d9f2d8c5505731b9e83cceddf309d14db97e7a0a583db7266\
         9e30ecadb3d4633f563097aae3c120ca51b28d61107983f172c985ac1f0c\
         e95428c06b0764426ce087fdcebee739e254a90a9e105f073772c0388461\
         92d4508e4cf2bc2e5f0a511b8c76345ac134930432577f629d8aa5217189\
         1e1f266aa1ef40cd581eadc193cafdd9cc90169602aac170b8318c781bec\
         ba059c7ef54450a57ccdd3c6e1cea13e13d58dbea3e4a1aa809a4dbfe0fd\
         0832905e256ba537198c3768f34fff29163d6434be02c2a0820333308203\
         2f3082032b30820213a003020102020101300d06092a864886f70d01010b\
         0500301d311b3019060355040313127273612d323034382d736861323536\
         2d6361301e170d3233313130353031303934355a170d3332313130323031\
         303934355a301d311b3019060355040313127273612d323034382d736861\
         3235362d636130820122300d06092a864886f70d01010105000382010f00\
         3082010a0282010100be984263d2834964fb0ca6668c72bd2162934811dd\
         512efc9bd0b02d8d6a18cb54256348e40fb6fc86c7d75b26c84b863034e0\
         34e8928077ae22bafbd5b89828eadf300fe69d9c6b800f7ec86323379cff\
         fedd6c921b07354fbe3020dd3ef56e77df0420b2a43854dd711120b3d945\
         e2a619e70963d71bed0ff8955a6bed95966572c0087f7b45db31b873cb75\
         bd42c21e83d47f29ba2d4fb213b91d8554504e4d75768c547a5a49559e6a\
         e457deed051273ea7c8482ec72e4749095ed6ba06ad04407297244472d91\
         18308ce066ba23566ff5faa9301d65b09bafe53c337e776a3a81a8e774b7\
         715b39570c59c4c3316c576466167d6779ff5244362f7541850203010001\
         a3763074300c0603551d13040530030101ff301d0603551d0e041604145d\
         d72c171c018b2ffa92c3133913689ebd82115c30450603551d23043e303c\
         80145dd72c171c018b2ffa92c3133913689ebd82115ca121a41f301d311b\
         3019060355040313127273612d323034382d7368613235362d6361820101\
         300d06092a864886f70d01010b05000382010100a6c69f0a7d673fad77a1\
         e978323289916ef85501e276c57a6dd8ca9917ea36b46088ff70f0d04b2c\
         40ae1f242942f5a0c4e4c7c80074ce32ec246c4e921163731d7bb2048f94\
         f7cade1c6e7e8abea615c5829f6cf55a4776cb3f4f18072b314b1b16a87e\
         49614d03a6371425d05099c5a3e4ef3e23cd170ba084ddae9e18ac3dc85c\
         059462b75497bf1d8f01aa117841012619d4150944cb7b22a5b787edc6d6\
         06de4ec6fa3641e8e3672dd4979228e556ec98097cafe035646b210d472d\
         c19deecf0961901d06279e93239eb1f268804dfb7892dada551c81fc790b\
         3f246cdecafe01ac3108f42eb921e8e3d6d8cc83304fd22076555d3498aa\
         4e38da3584ff"
    );
    let signature = hex!(
        "7a19ff540d4841492711b8b0620cf5b7c8eb\
         1061184d8ee0906b3314efd24aebe67e49ae\
         9e461ec9b76d8373477147af3bf6e8c85de5\
         37f8eb582d9f2d8c5505731b9e83cceddf30\
         9d14db97e7a0a583db72669e30ecadb3d463\
         3f563097aae3c120ca51b28d61107983f172\
         c985ac1f0ce95428c06b0764426ce087fdce\
         bee739e254a90a9e105f073772c038846192\
         d4508e4cf2bc2e5f0a511b8c76345ac13493\
         0432577f629d8aa52171891e1f266aa1ef40\
         cd581eadc193cafdd9cc90169602aac170b8\
         318c781becba059c7ef54450a57ccdd3c6e1\
         cea13e13d58dbea3e4a1aa809a4dbfe0fd08\
         32905e256ba537198c3768f34fff29163d64\
         34be02c2"
    );
    let res = OcspResponse::from_der(&data[..]).unwrap();
    let res = assert_ocsp_response(&res);
    assert_signature(
        &res,
        SHA_256_WITH_RSA_ENCRYPTION,
        &signature[..],
        Some(CA_CERTIFICATE_DATA),
    );
    let certid = CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: ID_SHA256,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(
            &hex!("056078AE157D9BB53154B1ABEBD26057D624FDDD9F09AE63814E90A365F444C5")[..],
        )
        .unwrap(),
        issuer_key_hash: OctetString::new(
            &hex!("15C37A883122D2FB6DBFA83E3CBD93E9EEF8125E3FD785724BC42D9D6FBA39B7")[..],
        )
        .unwrap(),
        serial_number: SerialNumber::from(0x10001usize),
    };
    let single = assert_basic_response(&res, &RESPONDER_ID, &TIME, &certid);
    assert_single_response(&single, CertStatus::Good(Null), &TIME, Some(&TIME));
}

// OCSP Response Data:
//     OCSP Response Status: successful (0x0)
//     Response Type: Basic OCSP Response
//     Version: 1 (0x0)
//     Responder Id: CN = rsa-2048-sha256-ocsp-crt
//     Produced At: Jan  1 00:00:00 2020 GMT
//     Responses:
//     Certificate ID:
//       Hash Algorithm: sha512
//       Issuer Name Hash: 6AE6D566832B216D55BF3F8CCBBBD662E4D798D7E5FC64CEE6CB35DF60EE1181305CB2\
// 747626560AFABD29B781A9A4631B0DFA1A05727323B3B81EEB54E57981
//       Issuer Key Hash: FEAC2688D16143E11050AEF3CDFAE4E4E21DF08F40A9FA3F5D80903B839450EE296202\
// 63B12AB92F3E840458A4871119B6757D337CEDB9044B8A5F7239615E06
//       Serial Number: 010001
//     Cert Status: good
//     This Update: Jan  1 00:00:00 2020 GMT
//     Next Update: Jan  1 00:00:00 2020 GMT
//
//     Signature Algorithm: sha256WithRSAEncryption
//     Signature Value:
//         20:f1:48:4b:2b:42:e0:7c:8d:29:8e:85:b6:f5:ba:4d:7e:7b:
//         1e:04:e2:00:4c:db:ef:e3:ff:73:fa:36:d8:2b:66:d2:e0:78:
//         e6:bd:6f:e4:cd:02:9b:69:95:5f:4f:41:e9:e3:7a:f7:01:76:
//         01:26:d5:47:5a:d5:d7:83:ff:6a:a9:1c:8f:e5:2d:1c:04:45:
//         08:38:9d:88:1c:b0:f7:88:8c:3f:7b:eb:d8:6a:0a:93:f3:ad:
//         ec:7b:e0:ab:35:1f:95:ec:17:b3:65:3a:42:5d:d4:e8:3c:29:
//         4d:62:5c:1d:c7:ae:cd:30:14:e9:14:9e:42:1a:80:0a:e5:d2:
//         bb:03:33:eb:6f:8d:c0:9e:4f:49:5e:e4:69:da:96:4d:f5:6a:
//         91:9e:6f:ee:b7:c4:fa:cd:d6:6f:a7:97:f4:19:2b:85:bc:bf:
//         3b:cd:09:1d:ba:45:02:08:98:a9:5f:b7:26:22:d5:3c:c2:df:
//         c1:95:ec:53:62:b9:c6:d5:00:65:41:c2:55:9e:31:e4:71:96:
//         82:c1:30:81:c2:46:03:ff:2c:11:2e:fe:44:1f:30:2b:61:b0:
//         04:7f:e3:e7:74:6f:b7:81:ab:46:56:2d:f5:35:53:ab:9f:d2:
//         4b:0e:67:a4:27:90:68:15:c1:5c:45:92:e3:2d:63:1d:3d:5d:
//         90:a5:1e:d4
//
// -- stripped signature bytes
//
// 20f1484b2b42e07c8d298e85b6f5ba4d7e7b
// 1e04e2004cdbefe3ff73fa36d82b66d2e078
// e6bd6fe4cd029b69955f4f41e9e37af70176
// 0126d5475ad5d783ff6aa91c8fe52d1c0445
// 08389d881cb0f7888c3f7bebd86a0a93f3ad
// ec7be0ab351f95ec17b3653a425dd4e83c29
// 4d625c1dc7aecd3014e9149e421a800ae5d2
// bb0333eb6f8dc09e4f495ee469da964df56a
// 919e6feeb7c4facdd66fa797f4192b85bcbf
// 3bcd091dba45020898a95fb72622d53cc2df
// c195ec5362b9c6d5006541c2559e31e47196
// 82c13081c24603ff2c112efe441f302b61b0
// 047fe3e7746fb781ab46562df53553ab9fd2
// 4b0e67a427906815c15c4592e32d631d3d5d
// 90a51ed4
#[test]
fn decode_ocsp_resp_sha512_certid() {
    let data = hex!(
        "3082056b0a0100a08205643082056006092b060105050730010104820551\
         3082054d3081ffa12530233121301f060355040313187273612d32303438\
         2d7368613235362d6f6373702d637274180f323032303031303130303030\
         30305a3081c43081c1308198300d0609608648016503040203050004406a\
         e6d566832b216d55bf3f8ccbbbd662e4d798d7e5fc64cee6cb35df60ee11\
         81305cb2747626560afabd29b781a9a4631b0dfa1a05727323b3b81eeb54\
         e579810440feac2688d16143e11050aef3cdfae4e4e21df08f40a9fa3f5d\
         80903b839450ee29620263b12ab92f3e840458a4871119b6757d337cedb9\
         044b8a5f7239615e0602030100018000180f323032303031303130303030\
         30305aa011180f32303230303130313030303030305a300d06092a864886\
         f70d01010b0500038201010020f1484b2b42e07c8d298e85b6f5ba4d7e7b\
         1e04e2004cdbefe3ff73fa36d82b66d2e078e6bd6fe4cd029b69955f4f41\
         e9e37af701760126d5475ad5d783ff6aa91c8fe52d1c044508389d881cb0\
         f7888c3f7bebd86a0a93f3adec7be0ab351f95ec17b3653a425dd4e83c29\
         4d625c1dc7aecd3014e9149e421a800ae5d2bb0333eb6f8dc09e4f495ee4\
         69da964df56a919e6feeb7c4facdd66fa797f4192b85bcbf3bcd091dba45\
         020898a95fb72622d53cc2dfc195ec5362b9c6d5006541c2559e31e47196\
         82c13081c24603ff2c112efe441f302b61b0047fe3e7746fb781ab46562d\
         f53553ab9fd24b0e67a427906815c15c4592e32d631d3d5d90a51ed4a082\
         03333082032f3082032b30820213a003020102020101300d06092a864886\
         f70d01010b0500301d311b3019060355040313127273612d323034382d73\
         68613235362d6361301e170d3233313130353031303934355a170d333231\
         3130323031303934355a301d311b3019060355040313127273612d323034\
         382d7368613235362d636130820122300d06092a864886f70d0101010500\
         0382010f003082010a0282010100be984263d2834964fb0ca6668c72bd21\
         62934811dd512efc9bd0b02d8d6a18cb54256348e40fb6fc86c7d75b26c8\
         4b863034e034e8928077ae22bafbd5b89828eadf300fe69d9c6b800f7ec8\
         6323379cfffedd6c921b07354fbe3020dd3ef56e77df0420b2a43854dd71\
         1120b3d945e2a619e70963d71bed0ff8955a6bed95966572c0087f7b45db\
         31b873cb75bd42c21e83d47f29ba2d4fb213b91d8554504e4d75768c547a\
         5a49559e6ae457deed051273ea7c8482ec72e4749095ed6ba06ad0440729\
         7244472d9118308ce066ba23566ff5faa9301d65b09bafe53c337e776a3a\
         81a8e774b7715b39570c59c4c3316c576466167d6779ff5244362f754185\
         0203010001a3763074300c0603551d13040530030101ff301d0603551d0e\
         041604145dd72c171c018b2ffa92c3133913689ebd82115c30450603551d\
         23043e303c80145dd72c171c018b2ffa92c3133913689ebd82115ca121a4\
         1f301d311b3019060355040313127273612d323034382d7368613235362d\
         6361820101300d06092a864886f70d01010b05000382010100a6c69f0a7d\
         673fad77a1e978323289916ef85501e276c57a6dd8ca9917ea36b46088ff\
         70f0d04b2c40ae1f242942f5a0c4e4c7c80074ce32ec246c4e921163731d\
         7bb2048f94f7cade1c6e7e8abea615c5829f6cf55a4776cb3f4f18072b31\
         4b1b16a87e49614d03a6371425d05099c5a3e4ef3e23cd170ba084ddae9e\
         18ac3dc85c059462b75497bf1d8f01aa117841012619d4150944cb7b22a5\
         b787edc6d606de4ec6fa3641e8e3672dd4979228e556ec98097cafe03564\
         6b210d472dc19deecf0961901d06279e93239eb1f268804dfb7892dada55\
         1c81fc790b3f246cdecafe01ac3108f42eb921e8e3d6d8cc83304fd22076\
         555d3498aa4e38da3584ff"
    );
    let signature = hex!(
        "20f1484b2b42e07c8d298e85b6f5ba4d7e7b\
         1e04e2004cdbefe3ff73fa36d82b66d2e078\
         e6bd6fe4cd029b69955f4f41e9e37af70176\
         0126d5475ad5d783ff6aa91c8fe52d1c0445\
         08389d881cb0f7888c3f7bebd86a0a93f3ad\
         ec7be0ab351f95ec17b3653a425dd4e83c29\
         4d625c1dc7aecd3014e9149e421a800ae5d2\
         bb0333eb6f8dc09e4f495ee469da964df56a\
         919e6feeb7c4facdd66fa797f4192b85bcbf\
         3bcd091dba45020898a95fb72622d53cc2df\
         c195ec5362b9c6d5006541c2559e31e47196\
         82c13081c24603ff2c112efe441f302b61b0\
         047fe3e7746fb781ab46562df53553ab9fd2\
         4b0e67a427906815c15c4592e32d631d3d5d\
         90a51ed4"
    );
    let res = OcspResponse::from_der(&data[..]).unwrap();
    let res = assert_ocsp_response(&res);
    assert_signature(
        &res,
        SHA_256_WITH_RSA_ENCRYPTION,
        &signature[..],
        Some(CA_CERTIFICATE_DATA),
    );
    let certid = CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: ID_SHA512,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(
            &hex!(
                "6AE6D566832B216D55BF3F8CCBBBD662E4D798D7E5FC64CEE6CB35DF60EE1181305CB2\
                 747626560AFABD29B781A9A4631B0DFA1A05727323B3B81EEB54E57981"
            )[..],
        )
        .unwrap(),
        issuer_key_hash: OctetString::new(
            &hex!(
                "FEAC2688D16143E11050AEF3CDFAE4E4E21DF08F40A9FA3F5D80903B839450EE296202\
                 63B12AB92F3E840458A4871119B6757D337CEDB9044B8A5F7239615E06"
            )[..],
        )
        .unwrap(),
        serial_number: SerialNumber::from(0x10001usize),
    };
    let single = assert_basic_response(&res, &RESPONDER_ID, &TIME, &certid);
    assert_single_response(&single, CertStatus::Good(Null), &TIME, Some(&TIME));
}

// OCSP Response Data:
//     OCSP Response Status: successful (0x0)
//     Response Type: Basic OCSP Response
//     Version: 1 (0x0)
//     Responder Id: CN = rsa-2048-sha256-ocsp-crt
//     Produced At: Jan  1 00:00:00 2020 GMT
//     Responses:
//     Certificate ID:
//       Hash Algorithm: sha1
//       Issuer Name Hash: 94D418C85D800AF31266F13D3D8CD8CD6AA5BB74
//       Issuer Key Hash: 5DD72C171C018B2FFA92C3133913689EBD82115C
//       Serial Number: 010001
//     Cert Status: good
//     This Update: Jan  1 00:00:00 2020 GMT
//     Next Update: Jan  1 00:00:00 2020 GMT
//         Response Single Extensions:
//             OCSP Archive Cutoff:
//                 Jan  1 00:00:00 2020 GMT
//             OCSP CRL ID:
//                 crlUrl: http://127.0.0.1/crl
//                 crlNum: 01
//                 crlTime: Jan  1 00:00:00 2020 GMT
//
//
//     Response Extensions:
//         OCSP Nonce:
//             04201F27F8C9CD8D154DAAEF021D5AAD6EAD7FE0637D044198E3F39291204924CEF8
//     Signature Algorithm: sha256WithRSAEncryption
//     Signature Value:
//         73:1e:e6:70:3f:4b:c7:79:f5:dc:f7:c8:78:11:fd:56:0c:bf:
//         e9:a0:11:f7:18:31:6b:d5:fe:76:93:fa:d1:c7:ac:b3:e3:58:
//         12:fb:fd:a6:71:2b:7a:4f:18:01:78:d2:de:bf:6b:7b:6f:6e:
//         0f:00:20:e1:e7:7a:89:ca:30:15:04:79:0b:88:59:7d:00:cd:
//         4c:bf:ab:fa:69:d7:02:3f:bb:5c:4f:a0:05:0d:58:bd:49:bd:
//         75:81:d1:c9:21:ed:0e:1b:7d:23:85:46:33:96:df:5c:aa:63:
//         13:4f:7b:a9:c1:20:48:68:52:cf:18:4d:03:60:5a:a5:a1:24:
//         a9:7e:dd:21:28:21:4c:f7:68:b9:6b:24:78:a2:ec:bf:e3:a2:
//         3d:37:58:17:6a:54:bd:1e:e7:3b:bc:17:d5:22:95:3b:21:98:
//         5a:d4:bd:1a:40:e6:45:9f:20:2f:5e:df:44:72:26:2f:6b:a5:
//         62:96:98:56:63:fa:3c:0a:5f:e1:23:a1:3d:30:e1:5d:78:03:
//         a8:3c:61:9a:bf:75:d9:73:28:20:92:dc:a2:4a:16:43:51:69:
//         c6:67:08:99:14:ab:3b:b2:26:0e:22:78:12:8e:e8:95:2f:ad:
//         c5:da:0c:f5:e0:b5:83:51:c3:9b:3d:53:c2:60:dc:0a:38:4b:
//         be:e7:de:b3
//
// -- stripped signature bytes
//
// 731ee6703f4bc779f5dcf7c87811fd560cbf
// e9a011f718316bd5fe7693fad1c7acb3e358
// 12fbfda6712b7a4f180178d2debf6b7b6f6e
// 0f0020e1e77a89ca301504790b88597d00cd
// 4cbfabfa69d7023fbb5c4fa0050d58bd49bd
// 7581d1c921ed0e1b7d2385463396df5caa63
// 134f7ba9c120486852cf184d03605aa5a124
// a97edd2128214cf768b96b2478a2ecbfe3a2
// 3d3758176a54bd1ee73bbc17d522953b2198
// 5ad4bd1a40e6459f202f5edf4472262f6ba5
// 6296985663fa3c0a5fe123a13d30e15d7803
// a83c619abf75d973282092dca24a16435169
// c667089914ab3bb2260e2278128ee8952fad
// c5da0cf5e0b58351c39b3d53c260dc0a384b
// bee7deb3
//
// -- asn1parse
//
// ...
// 176:d=7  hl=2 l=   9 prim: OBJECT            :OCSP Archive Cutoff
// 187:d=7  hl=2 l=  17 prim: OCTET STRING      [HEX DUMP]:180F32303230303130313030303030305A
// ...
// 208:d=7  hl=2 l=   9 prim: OBJECT            :OCSP CRL ID
// 219:d=7  hl=2 l=  50 prim: OCTET STRING      [HEX DUMP]:3030A0161614687474703A2F2F3132372E302E302E312F63726CA103020101A211180F32303230303130313030303030305A
// ...
// 277:d=5  hl=2 l=   9 prim: OBJECT            :OCSP Nonce
// 288:d=5  hl=2 l=  34 prim: OCTET STRING      [HEX DUMP]:04201F27F8C9CD8D154DAAEF021D5AAD6EAD7FE0637D044198E3F39291204924CEF8
// ...
#[test]
fn decode_ocsp_resp_multiple_extensions() {
    let data = hex!(
        "308205a90a0100a08205a23082059e06092b06010505073001010482058f\
         3082058b3082013ca12530233121301f060355040313187273612d323034\
         382d7368613235362d6f6373702d637274180f3230323030313031303030\
         3030305a3081cc3081c9303c300906052b0e03021a0500041494d418c85d\
         800af31266f13d3d8cd8cd6aa5bb7404145dd72c171c018b2ffa92c31339\
         13689ebd82115c02030100018000180f3230323030313031303030303030\
         5aa011180f32303230303130313030303030305aa1633061301e06092b06\
         010505073001060411180f32303230303130313030303030305a303f0609\
         2b060105050730010304323030a0161614687474703a2f2f3132372e302e\
         302e312f63726ca103020101a211180f3230323030313031303030303030\
         5aa1333031302f06092b0601050507300102042204201f27f8c9cd8d154d\
         aaef021d5aad6ead7fe0637d044198e3f39291204924cef8300d06092a86\
         4886f70d01010b05000382010100731ee6703f4bc779f5dcf7c87811fd56\
         0cbfe9a011f718316bd5fe7693fad1c7acb3e35812fbfda6712b7a4f1801\
         78d2debf6b7b6f6e0f0020e1e77a89ca301504790b88597d00cd4cbfabfa\
         69d7023fbb5c4fa0050d58bd49bd7581d1c921ed0e1b7d2385463396df5c\
         aa63134f7ba9c120486852cf184d03605aa5a124a97edd2128214cf768b9\
         6b2478a2ecbfe3a23d3758176a54bd1ee73bbc17d522953b21985ad4bd1a\
         40e6459f202f5edf4472262f6ba56296985663fa3c0a5fe123a13d30e15d\
         7803a83c619abf75d973282092dca24a16435169c667089914ab3bb2260e\
         2278128ee8952fadc5da0cf5e0b58351c39b3d53c260dc0a384bbee7deb3\
         a08203333082032f3082032b30820213a003020102020101300d06092a86\
         4886f70d01010b0500301d311b3019060355040313127273612d32303438\
         2d7368613235362d6361301e170d3233313130353031303934355a170d33\
         32313130323031303934355a301d311b3019060355040313127273612d32\
         3034382d7368613235362d636130820122300d06092a864886f70d010101\
         05000382010f003082010a0282010100be984263d2834964fb0ca6668c72\
         bd2162934811dd512efc9bd0b02d8d6a18cb54256348e40fb6fc86c7d75b\
         26c84b863034e034e8928077ae22bafbd5b89828eadf300fe69d9c6b800f\
         7ec86323379cfffedd6c921b07354fbe3020dd3ef56e77df0420b2a43854\
         dd711120b3d945e2a619e70963d71bed0ff8955a6bed95966572c0087f7b\
         45db31b873cb75bd42c21e83d47f29ba2d4fb213b91d8554504e4d75768c\
         547a5a49559e6ae457deed051273ea7c8482ec72e4749095ed6ba06ad044\
         07297244472d9118308ce066ba23566ff5faa9301d65b09bafe53c337e77\
         6a3a81a8e774b7715b39570c59c4c3316c576466167d6779ff5244362f75\
         41850203010001a3763074300c0603551d13040530030101ff301d060355\
         1d0e041604145dd72c171c018b2ffa92c3133913689ebd82115c30450603\
         551d23043e303c80145dd72c171c018b2ffa92c3133913689ebd82115ca1\
         21a41f301d311b3019060355040313127273612d323034382d7368613235\
         362d6361820101300d06092a864886f70d01010b05000382010100a6c69f\
         0a7d673fad77a1e978323289916ef85501e276c57a6dd8ca9917ea36b460\
         88ff70f0d04b2c40ae1f242942f5a0c4e4c7c80074ce32ec246c4e921163\
         731d7bb2048f94f7cade1c6e7e8abea615c5829f6cf55a4776cb3f4f1807\
         2b314b1b16a87e49614d03a6371425d05099c5a3e4ef3e23cd170ba084dd\
         ae9e18ac3dc85c059462b75497bf1d8f01aa117841012619d4150944cb7b\
         22a5b787edc6d606de4ec6fa3641e8e3672dd4979228e556ec98097cafe0\
         35646b210d472dc19deecf0961901d06279e93239eb1f268804dfb7892da\
         da551c81fc790b3f246cdecafe01ac3108f42eb921e8e3d6d8cc83304fd2\
         2076555d3498aa4e38da3584ff"
    );
    let signature = hex!(
        "731ee6703f4bc779f5dcf7c87811fd560cbf\
         e9a011f718316bd5fe7693fad1c7acb3e358\
         12fbfda6712b7a4f180178d2debf6b7b6f6e\
         0f0020e1e77a89ca301504790b88597d00cd\
         4cbfabfa69d7023fbb5c4fa0050d58bd49bd\
         7581d1c921ed0e1b7d2385463396df5caa63\
         134f7ba9c120486852cf184d03605aa5a124\
         a97edd2128214cf768b96b2478a2ecbfe3a2\
         3d3758176a54bd1ee73bbc17d522953b2198\
         5ad4bd1a40e6459f202f5edf4472262f6ba5\
         6296985663fa3c0a5fe123a13d30e15d7803\
         a83c619abf75d973282092dca24a16435169\
         c667089914ab3bb2260e2278128ee8952fad\
         c5da0cf5e0b58351c39b3d53c260dc0a384b\
         bee7deb3"
    );
    let nonce_ext = hex!("04201F27F8C9CD8D154DAAEF021D5AAD6EAD7FE0637D044198E3F39291204924CEF8");
    let archive_cutoff_ext = hex!("180F32303230303130313030303030305A");
    let crl_refs_ext = hex!(
        "3030A0161614687474703A2F2F3132372E302E302E312F63726CA103020101A2\
         11180F32303230303130313030303030305A"
    );
    let res = OcspResponse::from_der(&data[..]).unwrap();
    let res = assert_ocsp_response(&res);
    assert_signature(
        &res,
        SHA_256_WITH_RSA_ENCRYPTION,
        &signature[..],
        Some(CA_CERTIFICATE_DATA),
    );
    assert!(res.tbs_response_data.response_extensions.as_ref().is_some());
    assert_extension(
        &res.tbs_response_data.response_extensions.as_ref().unwrap()[0],
        ID_PKIX_OCSP_NONCE,
        false,
        &nonce_ext[..],
    );
    let certid = CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: ID_SHA1,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(&hex!("94D418C85D800AF31266F13D3D8CD8CD6AA5BB74")[..])
            .unwrap(),
        issuer_key_hash: OctetString::new(&hex!("5DD72C171C018B2FFA92C3133913689EBD82115C")[..])
            .unwrap(),
        serial_number: SerialNumber::from(0x10001usize),
    };
    let single = assert_basic_response(&res, &RESPONDER_ID, &TIME, &certid);
    assert_single_response(&single, CertStatus::Good(Null), &TIME, Some(&TIME));
    assert!(single.single_extensions.as_ref().is_some());
    assert_extension(
        &single.single_extensions.as_ref().unwrap()[0],
        ID_PKIX_OCSP_ARCHIVE_CUTOFF,
        false,
        &archive_cutoff_ext[..],
    );
    assert_extension(
        &single.single_extensions.as_ref().unwrap()[1],
        ID_PKIX_OCSP_CRL,
        false,
        &crl_refs_ext[..],
    );
}

// OCSP Response Data:
//     OCSP Response Status: successful (0x0)
//     Response Type: Basic OCSP Response
//     Version: 1 (0x0)
//     Responder Id: CN = rsa-2048-sha256-ocsp-crt
//     Produced At: Jan  1 00:00:00 2020 GMT
//     Responses:
//     Certificate ID:
//       Hash Algorithm: sha1
//       Issuer Name Hash: 94D418C85D800AF31266F13D3D8CD8CD6AA5BB74
//       Issuer Key Hash: 5DD72C171C018B2FFA92C3133913689EBD82115C
//       Serial Number: 010001
//     Cert Status: good
//     This Update: Jan  1 00:00:00 2020 GMT
//     Next Update: Jan  1 00:00:00 2020 GMT
//
//     Response Extensions:
//         OCSP Nonce:
//             04201F27F8C9CD8D154DAAEF021D5AAD6EAD7FE0637D044198E3F39291204924CEF8
//     Signature Algorithm: sha256WithRSAEncryption
//     Signature Value:
//         4e:af:b9:23:58:0b:11:0a:a9:ae:67:19:fb:e7:01:cd:be:d3:
//         5a:03:af:e8:5b:b2:43:46:df:33:4f:22:c5:49:f8:e7:bf:e6:
//         ce:bf:69:0c:98:35:42:06:d0:0a:d2:bf:ac:0a:2c:b2:19:7c:
//         04:09:89:19:d3:2e:2d:b9:bb:1c:6e:4f:2a:6a:5a:42:82:28:
//         4f:86:e4:8f:2e:b9:8b:dc:8f:4d:76:9b:fc:e2:ff:1c:d2:5b:
//         c3:85:00:9b:07:6a:43:d5:8b:1e:5f:52:be:ee:76:67:f8:9c:
//         fa:d6:ce:05:4e:cc:fa:ea:a7:58:73:91:c1:58:bf:e8:54:82:
//         ca:42:f4:cc:18:87:99:90:e1:31:a2:35:2b:dd:d6:22:d0:cc:
//         49:07:44:60:79:a5:bf:f4:79:bf:6d:95:01:a0:d3:55:e4:94:
//         9e:83:9d:1d:bc:fa:4e:b5:38:fc:d0:5e:b9:d6:53:73:10:79:
//         37:6a:e1:c2:4c:79:2c:25:45:e3:e8:f2:e0:ca:09:6e:1a:1a:
//         d2:9f:4c:53:b2:a8:5a:2f:1e:0c:df:40:c3:60:f8:df:6b:5f:
//         d5:4b:96:8e:ff:d6:b7:73:07:74:02:c0:d6:d8:bb:4a:35:d7:
//         a9:12:57:d1:fa:d2:c0:3f:d1:6b:41:cc:e8:3c:a4:03:eb:55:
//         c8:aa:2f:99
//
// -- stripped signature bytes
//
// 4eafb923580b110aa9ae6719fbe701cdbed3
// 5a03afe85bb24346df334f22c549f8e7bfe6
// cebf690c98354206d00ad2bfac0a2cb2197c
// 04098919d32e2db9bb1c6e4f2a6a5a428228
// 4f86e48f2eb98bdc8f4d769bfce2ff1cd25b
// c385009b076a43d58b1e5f52beee7667f89c
// fad6ce054eccfaeaa7587391c158bfe85482
// ca42f4cc18879990e131a2352bddd622d0cc
// 4907446079a5bff479bf6d9501a0d355e494
// 9e839d1dbcfa4eb538fcd05eb9d653731079
// 376ae1c24c792c2545e3e8f2e0ca096e1a1a
// d29f4c53b2a85a2f1e0cdf40c360f8df6b5f
// d54b968effd6b773077402c0d6d8bb4a35d7
// a91257d1fad2c03fd16b41cce83ca403eb55
// c8aa2f99
#[test]
fn decode_ocsp_resp_dtm_no_chain() {
    let data = hex!(
        "3082020a0a0100a0820203308201ff06092b0601050507300101048201f0\
         308201ec3081d5a12530233121301f060355040313187273612d32303438\
         2d7368613235362d6f6373702d637274180f323032303031303130303030\
         30305a30663064303c300906052b0e03021a0500041494d418c85d800af3\
         1266f13d3d8cd8cd6aa5bb7404145dd72c171c018b2ffa92c3133913689e\
         bd82115c02030100018000180f32303230303130313030303030305aa011\
         180f32303230303130313030303030305aa1333031302f06092b06010505\
         07300102042204201f27f8c9cd8d154daaef021d5aad6ead7fe0637d0441\
         98e3f39291204924cef8300d06092a864886f70d01010b05000382010100\
         4eafb923580b110aa9ae6719fbe701cdbed35a03afe85bb24346df334f22\
         c549f8e7bfe6cebf690c98354206d00ad2bfac0a2cb2197c04098919d32e\
         2db9bb1c6e4f2a6a5a4282284f86e48f2eb98bdc8f4d769bfce2ff1cd25b\
         c385009b076a43d58b1e5f52beee7667f89cfad6ce054eccfaeaa7587391\
         c158bfe85482ca42f4cc18879990e131a2352bddd622d0cc4907446079a5\
         bff479bf6d9501a0d355e4949e839d1dbcfa4eb538fcd05eb9d653731079\
         376ae1c24c792c2545e3e8f2e0ca096e1a1ad29f4c53b2a85a2f1e0cdf40\
         c360f8df6b5fd54b968effd6b773077402c0d6d8bb4a35d7a91257d1fad2\
         c03fd16b41cce83ca403eb55c8aa2f99"
    );
    let signature = hex!(
        "4eafb923580b110aa9ae6719fbe701cdbed3\
         5a03afe85bb24346df334f22c549f8e7bfe6\
         cebf690c98354206d00ad2bfac0a2cb2197c\
         04098919d32e2db9bb1c6e4f2a6a5a428228\
         4f86e48f2eb98bdc8f4d769bfce2ff1cd25b\
         c385009b076a43d58b1e5f52beee7667f89c\
         fad6ce054eccfaeaa7587391c158bfe85482\
         ca42f4cc18879990e131a2352bddd622d0cc\
         4907446079a5bff479bf6d9501a0d355e494\
         9e839d1dbcfa4eb538fcd05eb9d653731079\
         376ae1c24c792c2545e3e8f2e0ca096e1a1a\
         d29f4c53b2a85a2f1e0cdf40c360f8df6b5f\
         d54b968effd6b773077402c0d6d8bb4a35d7\
         a91257d1fad2c03fd16b41cce83ca403eb55\
         c8aa2f99"
    );
    let nonce_ext = hex!("04201F27F8C9CD8D154DAAEF021D5AAD6EAD7FE0637D044198E3F39291204924CEF8");
    let res = OcspResponse::from_der(&data[..]).unwrap();
    let res = assert_ocsp_response(&res);
    assert_signature(&res, SHA_256_WITH_RSA_ENCRYPTION, &signature[..], None);
    assert!(res.tbs_response_data.response_extensions.as_ref().is_some());
    assert_extension(
        &res.tbs_response_data.response_extensions.as_ref().unwrap()[0],
        ID_PKIX_OCSP_NONCE,
        false,
        &nonce_ext[..],
    );
    let certid = CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: ID_SHA1,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(&hex!("94D418C85D800AF31266F13D3D8CD8CD6AA5BB74")[..])
            .unwrap(),
        issuer_key_hash: OctetString::new(&hex!("5DD72C171C018B2FFA92C3133913689EBD82115C")[..])
            .unwrap(),
        serial_number: SerialNumber::from(0x10001usize),
    };
    let single = assert_basic_response(&res, &RESPONDER_ID, &TIME, &certid);
    assert_single_response(&single, CertStatus::Good(Null), &TIME, Some(&TIME));
}

// OCSP Response Data:
//     OCSP Response Status: successful (0x0)
//     Response Type: Basic OCSP Response
//     Version: 1 (0x0)
//     Responder Id: F4A810E6EA0984AF7636128A40284379986A4735
//     Produced At: Jan  1 00:00:00 2020 GMT
//     Responses:
//     Certificate ID:
//       Hash Algorithm: sha1
//       Issuer Name Hash: 94D418C85D800AF31266F13D3D8CD8CD6AA5BB74
//       Issuer Key Hash: 5DD72C171C018B2FFA92C3133913689EBD82115C
//       Serial Number: 010001
//     Cert Status: good
//     This Update: Jan  1 00:00:00 2020 GMT
//     Next Update: Jan  1 00:00:00 2020 GMT
//
//     Response Extensions:
//         OCSP Nonce:
//             04201F27F8C9CD8D154DAAEF021D5AAD6EAD7FE0637D044198E3F39291204924CEF8
//     Signature Algorithm: sha256WithRSAEncryption
//     Signature Value:
//         7d:5e:ff:1e:86:9e:1a:52:b0:87:ea:e0:0b:c8:ac:5d:10:91:
//         f5:b5:a9:7e:0c:44:99:03:bb:86:03:7f:d5:2d:30:48:07:95:
//         3f:4e:9a:d0:21:e1:51:37:8b:63:33:f8:b9:55:96:b8:be:2a:
//         fb:f8:c0:4d:f7:09:8b:02:5a:c4:5d:73:58:f9:f4:aa:18:e7:
//         aa:d2:41:ce:54:da:eb:c5:e6:f2:59:f5:0f:77:da:37:9a:e4:
//         90:db:04:09:31:cc:80:cd:4c:c0:11:ca:57:a6:2b:05:88:35:
//         52:bb:ec:10:e2:e4:48:6f:39:79:72:f4:e5:58:d2:24:6b:57:
//         2e:e3:42:ad:fe:db:d2:f5:69:71:70:11:03:e7:7a:54:63:dd:
//         d6:9c:69:a7:62:fc:3c:fe:70:2a:d0:8f:01:c2:1c:9f:c9:7b:
//         4f:68:fb:e0:17:6e:65:16:bb:74:b7:d4:74:67:5d:1f:52:9e:
//         23:26:ec:2a:7f:b5:07:d1:29:c1:8e:1e:8b:64:f5:a2:85:27:
//         35:92:53:d4:76:4b:d8:00:e1:f1:94:b6:60:61:34:28:6d:8a:
//         b2:c8:1a:da:98:67:04:51:d0:de:df:2d:31:47:2d:8e:8a:8c:
//         db:80:b0:fd:88:9a:b5:75:a0:fb:12:3d:eb:d7:ee:dd:cb:b2:
//         ab:d4:5a:5e
//
// -- stripped signature bytes
//
// 7d5eff1e869e1a52b087eae00bc8ac5d1091
// f5b5a97e0c449903bb86037fd52d30480795
// 3f4e9ad021e151378b6333f8b95596b8be2a
// fbf8c04df7098b025ac45d7358f9f4aa18e7
// aad241ce54daebc5e6f259f50f77da379ae4
// 90db040931cc80cd4cc011ca57a62b058835
// 52bbec10e2e4486f397972f4e558d2246b57
// 2ee342adfedbd2f56971701103e77a5463dd
// d69c69a762fc3cfe702ad08f01c21c9fc97b
// 4f68fbe0176e6516bb74b7d474675d1f529e
// 2326ec2a7fb507d129c18e1e8b64f5a28527
// 359253d4764bd800e1f194b6606134286d8a
// b2c81ada98670451d0dedf2d31472d8e8a8c
// db80b0fd889ab575a0fb123debd7eeddcbb2
// abd45a5e
#[test]
fn decode_ocsp_resp_dtm_by_key() {
    let data = hex!(
        "308201fb0a0100a08201f4308201f006092b0601050507300101048201e1\
         308201dd3081c6a2160414f4a810e6ea0984af7636128a40284379986a47\
         35180f32303230303130313030303030305a30663064303c300906052b0e\
         03021a0500041494d418c85d800af31266f13d3d8cd8cd6aa5bb7404145d\
         d72c171c018b2ffa92c3133913689ebd82115c02030100018000180f3230\
         3230303130313030303030305aa011180f32303230303130313030303030\
         305aa1333031302f06092b0601050507300102042204201f27f8c9cd8d15\
         4daaef021d5aad6ead7fe0637d044198e3f39291204924cef8300d06092a\
         864886f70d01010b050003820101007d5eff1e869e1a52b087eae00bc8ac\
         5d1091f5b5a97e0c449903bb86037fd52d304807953f4e9ad021e151378b\
         6333f8b95596b8be2afbf8c04df7098b025ac45d7358f9f4aa18e7aad241\
         ce54daebc5e6f259f50f77da379ae490db040931cc80cd4cc011ca57a62b\
         05883552bbec10e2e4486f397972f4e558d2246b572ee342adfedbd2f569\
         71701103e77a5463ddd69c69a762fc3cfe702ad08f01c21c9fc97b4f68fb\
         e0176e6516bb74b7d474675d1f529e2326ec2a7fb507d129c18e1e8b64f5\
         a28527359253d4764bd800e1f194b6606134286d8ab2c81ada98670451d0\
         dedf2d31472d8e8a8cdb80b0fd889ab575a0fb123debd7eeddcbb2abd45a\
         5e"
    );
    let signature = hex!(
        "7d5eff1e869e1a52b087eae00bc8ac5d1091\
         f5b5a97e0c449903bb86037fd52d30480795\
         3f4e9ad021e151378b6333f8b95596b8be2a\
         fbf8c04df7098b025ac45d7358f9f4aa18e7\
         aad241ce54daebc5e6f259f50f77da379ae4\
         90db040931cc80cd4cc011ca57a62b058835\
         52bbec10e2e4486f397972f4e558d2246b57\
         2ee342adfedbd2f56971701103e77a5463dd\
         d69c69a762fc3cfe702ad08f01c21c9fc97b\
         4f68fbe0176e6516bb74b7d474675d1f529e\
         2326ec2a7fb507d129c18e1e8b64f5a28527\
         359253d4764bd800e1f194b6606134286d8a\
         b2c81ada98670451d0dedf2d31472d8e8a8c\
         db80b0fd889ab575a0fb123debd7eeddcbb2\
         abd45a5e"
    );
    let responder_id = ResponderId::ByKey(
        OctetString::new(&hex!("F4A810E6EA0984AF7636128A40284379986A4735")[..]).unwrap(),
    );
    let nonce_ext = hex!("04201F27F8C9CD8D154DAAEF021D5AAD6EAD7FE0637D044198E3F39291204924CEF8");
    let res = OcspResponse::from_der(&data[..]).unwrap();
    let res = assert_ocsp_response(&res);
    assert_signature(&res, SHA_256_WITH_RSA_ENCRYPTION, &signature[..], None);
    assert!(res.tbs_response_data.response_extensions.as_ref().is_some());
    assert_extension(
        &res.tbs_response_data.response_extensions.as_ref().unwrap()[0],
        ID_PKIX_OCSP_NONCE,
        false,
        &nonce_ext[..],
    );
    let certid = CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: ID_SHA1,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(&hex!("94D418C85D800AF31266F13D3D8CD8CD6AA5BB74")[..])
            .unwrap(),
        issuer_key_hash: OctetString::new(&hex!("5DD72C171C018B2FFA92C3133913689EBD82115C")[..])
            .unwrap(),
        serial_number: SerialNumber::from(0x10001usize),
    };
    let single = assert_basic_response(&res, &responder_id, &TIME, &certid);
    assert_single_response(&single, CertStatus::Good(Null), &TIME, Some(&TIME));
}

// OCSP Response Data:
//     OCSP Response Status: successful (0x0)
//     Response Type: Basic OCSP Response
//     Version: 1 (0x0)
//     Responder Id: CN = rsa-2048-sha256-ocsp-crt
//     Produced At: Jan  1 00:00:00 2020 GMT
//     Responses:
//     Certificate ID:
//       Hash Algorithm: sha1
//       Issuer Name Hash: 94D418C85D800AF31266F13D3D8CD8CD6AA5BB74
//       Issuer Key Hash: 5DD72C171C018B2FFA92C3133913689EBD82115C
//       Serial Number: 010001
//     Cert Status: good
//     This Update: Jan  1 00:00:00 2020 GMT
//     Next Update: Jan  1 00:00:00 2020 GMT
//
//     Certificate ID:
//       Hash Algorithm: sha224
//       Issuer Name Hash: 3D1F07D457D6634B0F2501C71ADB1DE5C41C515207F4206A5ACDA560
//       Issuer Key Hash: 2962CA2A9DE7A3A75A96EAC2031F50684DF5B50F5E6635DECBD74DA3
//       Serial Number: 010001
//     Cert Status: good
//     This Update: Jan  1 00:00:00 2020 GMT
//     Next Update: Jan  1 00:00:00 2020 GMT
//
//     Certificate ID:
//       Hash Algorithm: sha256
//       Issuer Name Hash: 056078AE157D9BB53154B1ABEBD26057D624FDDD9F09AE63814E90A365F444C5
//       Issuer Key Hash: 15C37A883122D2FB6DBFA83E3CBD93E9EEF8125E3FD785724BC42D9D6FBA39B7
//       Serial Number: 010001
//     Cert Status: good
//     This Update: Jan  1 00:00:00 2020 GMT
//     Next Update: Jan  1 00:00:00 2020 GMT
//
//     Certificate ID:
//       Hash Algorithm: sha384
//       Issuer Name Hash: 97EFAF937F262E72C9C8FFFB55FDBC9FBB7EA353CD837CE01AF6F0D489AB4EC9AE4AD7\
// 248410268C23F9C0FF5161BB28
//       Issuer Key Hash: F54E78323C7201B9C799040AF35FE3BC1492DA6B0EFD799C80BA45A611CDC129F6A790\
// 67ACF14B83340FE122CF2305FE
//       Serial Number: 010001
//     Cert Status: good
//     This Update: Jan  1 00:00:00 2020 GMT
//     Next Update: Jan  1 00:00:00 2020 GMT
//
//     Certificate ID:
//       Hash Algorithm: sha512
//       Issuer Name Hash: 6AE6D566832B216D55BF3F8CCBBBD662E4D798D7E5FC64CEE6CB35DF60EE1181305CB2\
// 747626560AFABD29B781A9A4631B0DFA1A05727323B3B81EEB54E57981
//       Issuer Key Hash: FEAC2688D16143E11050AEF3CDFAE4E4E21DF08F40A9FA3F5D80903B839450EE296202\
// 63B12AB92F3E840458A4871119B6757D337CEDB9044B8A5F7239615E06
//       Serial Number: 010001
//     Cert Status: good
//     This Update: Jan  1 00:00:00 2020 GMT
//     Next Update: Jan  1 00:00:00 2020 GMT
//
//     Certificate ID:
//       Hash Algorithm: sha1
//       Issuer Name Hash: 94D418C85D800AF31266F13D3D8CD8CD6AA5BB74
//       Issuer Key Hash: 5DD72C171C018B2FFA92C3133913689EBD82115C
//       Serial Number: 05
//     Cert Status: good
//     This Update: Jan  1 00:00:00 2020 GMT
//     Next Update: Jan  1 00:00:00 2020 GMT
//
//     Certificate ID:
//       Hash Algorithm: sha1
//       Issuer Name Hash: 94D418C85D800AF31266F13D3D8CD8CD6AA5BB74
//       Issuer Key Hash: 5DD72C171C018B2FFA92C3133913689EBD82115C
//       Serial Number: 16
//     Cert Status: good
//     This Update: Jan  1 00:00:00 2020 GMT
//     Next Update: Jan  1 00:00:00 2020 GMT
//
//     Certificate ID:
//       Hash Algorithm: sha1
//       Issuer Name Hash: 94D418C85D800AF31266F13D3D8CD8CD6AA5BB74
//       Issuer Key Hash: 5DD72C171C018B2FFA92C3133913689EBD82115C
//       Serial Number: FFFFFFFF
//     Cert Status: good
//     This Update: Jan  1 00:00:00 2020 GMT
//     Next Update: Jan  1 00:00:00 2020 GMT
//
//     Signature Algorithm: sha256WithRSAEncryption
//     Signature Value:
//         ac:c2:a7:bf:35:5d:d8:16:29:c2:27:a2:c1:f0:7f:2b:5d:34:
//         1d:9a:5d:b7:82:a9:ab:5c:b3:fe:65:4a:05:ba:47:d2:5c:43:
//         8c:c0:b7:d4:f4:30:46:07:88:57:4e:cb:3b:a4:00:f5:86:79:
//         82:9d:91:5b:d5:15:e6:3c:98:f6:3b:82:13:e0:73:db:d1:10:
//         20:53:ef:21:f6:5b:b4:fa:02:49:56:14:2d:f9:d0:f9:d5:f5:
//         73:72:a9:45:07:49:9a:52:70:2d:ea:f6:dc:22:5d:28:25:f7:
//         33:86:f5:ee:c4:70:3d:b1:0c:61:d6:64:7b:91:e8:86:36:b4:
//         1e:8e:57:45:4d:50:a9:f9:86:61:a8:ea:ee:9b:13:35:2b:51:
//         22:6e:4c:1e:b6:52:1c:eb:85:25:ea:a5:c8:a0:22:6a:55:d4:
//         3c:be:59:5d:c0:9a:a9:05:62:59:73:d3:43:c9:22:03:7e:e5:
//         54:3d:3f:e7:49:bc:8f:58:13:89:fc:2b:c3:75:23:3b:75:25:
//         91:9b:3a:68:5c:ff:45:d6:2d:bb:ca:3e:a9:ab:df:02:6d:39:
//         77:5c:0d:4e:97:7d:c4:fd:43:fe:a5:7f:0c:15:ef:13:08:8a:
//         07:6b:a6:64:5b:68:37:11:3c:c2:a8:41:2c:a4:c8:5e:4a:20:
//         b2:1f:5f:64
//
// -- stripped signature data
//
// acc2a7bf355dd81629c227a2c1f07f2b5d34
// 1d9a5db782a9ab5cb3fe654a05ba47d25c43
// 8cc0b7d4f430460788574ecb3ba400f58679
// 829d915bd515e63c98f63b8213e073dbd110
// 2053ef21f65bb4fa024956142df9d0f9d5f5
// 7372a94507499a52702deaf6dc225d2825f7
// 3386f5eec4703db10c61d6647b91e88636b4
// 1e8e57454d50a9f98661a8eaee9b13352b51
// 226e4c1eb6521ceb8525eaa5c8a0226a55d4
// 3cbe595dc09aa905625973d343c922037ee5
// 543d3fe749bc8f581389fc2bc375233b7525
// 919b3a685cff45d62dbbca3ea9abdf026d39
// 775c0d4e977dc4fd43fea57f0c15ef13088a
// 076ba6645b6837113cc2a8412ca4c85e4a20
// b21f5f64
#[test]
fn decode_ocsp_resp_multiple_responses() {
    let data = hex!(
        "308208a30a0100a082089c3082089806092b060105050730010104820889\
         3082088530820436a12530233121301f060355040313187273612d323034\
         382d7368613235362d6f6373702d637274180f3230323030313031303030\
         3030305a308203fa3064303c300906052b0e03021a0500041494d418c85d\
         800af31266f13d3d8cd8cd6aa5bb7404145dd72c171c018b2ffa92c31339\
         13689ebd82115c02030100018000180f3230323030313031303030303030\
         5aa011180f32303230303130313030303030305a30783050300d06096086\
         480165030402040500041c3d1f07d457d6634b0f2501c71adb1de5c41c51\
         5207f4206a5acda560041c2962ca2a9de7a3a75a96eac2031f50684df5b5\
         0f5e6635decbd74da302030100018000180f323032303031303130303030\
         30305aa011180f32303230303130313030303030305a3081803058300d06\
         0960864801650304020105000420056078ae157d9bb53154b1abebd26057\
         d624fddd9f09ae63814e90a365f444c5042015c37a883122d2fb6dbfa83e\
         3cbd93e9eef8125e3fd785724bc42d9d6fba39b702030100018000180f32\
         303230303130313030303030305aa011180f323032303031303130303030\
         30305a3081a03078300d06096086480165030402020500043097efaf937f\
         262e72c9c8fffb55fdbc9fbb7ea353cd837ce01af6f0d489ab4ec9ae4ad7\
         248410268c23f9c0ff5161bb280430f54e78323c7201b9c799040af35fe3\
         bc1492da6b0efd799c80ba45a611cdc129f6a79067acf14b83340fe122cf\
         2305fe02030100018000180f32303230303130313030303030305aa01118\
         0f32303230303130313030303030305a3081c1308198300d060960864801\
         6503040203050004406ae6d566832b216d55bf3f8ccbbbd662e4d798d7e5\
         fc64cee6cb35df60ee1181305cb2747626560afabd29b781a9a4631b0dfa\
         1a05727323b3b81eeb54e579810440feac2688d16143e11050aef3cdfae4\
         e4e21df08f40a9fa3f5d80903b839450ee29620263b12ab92f3e840458a4\
         871119b6757d337cedb9044b8a5f7239615e0602030100018000180f3230\
         3230303130313030303030305aa011180f32303230303130313030303030\
         305a3062303a300906052b0e03021a0500041494d418c85d800af31266f1\
         3d3d8cd8cd6aa5bb7404145dd72c171c018b2ffa92c3133913689ebd8211\
         5c0201058000180f32303230303130313030303030305aa011180f323032\
         30303130313030303030305a3062303a300906052b0e03021a0500041494\
         d418c85d800af31266f13d3d8cd8cd6aa5bb7404145dd72c171c018b2ffa\
         92c3133913689ebd82115c0201168000180f323032303031303130303030\
         30305aa011180f32303230303130313030303030305a3066303e30090605\
         2b0e03021a0500041494d418c85d800af31266f13d3d8cd8cd6aa5bb7404\
         145dd72c171c018b2ffa92c3133913689ebd82115c020500ffffffff8000\
         180f32303230303130313030303030305aa011180f323032303031303130\
         30303030305a300d06092a864886f70d01010b05000382010100acc2a7bf\
         355dd81629c227a2c1f07f2b5d341d9a5db782a9ab5cb3fe654a05ba47d2\
         5c438cc0b7d4f430460788574ecb3ba400f58679829d915bd515e63c98f6\
         3b8213e073dbd1102053ef21f65bb4fa024956142df9d0f9d5f57372a945\
         07499a52702deaf6dc225d2825f73386f5eec4703db10c61d6647b91e886\
         36b41e8e57454d50a9f98661a8eaee9b13352b51226e4c1eb6521ceb8525\
         eaa5c8a0226a55d43cbe595dc09aa905625973d343c922037ee5543d3fe7\
         49bc8f581389fc2bc375233b7525919b3a685cff45d62dbbca3ea9abdf02\
         6d39775c0d4e977dc4fd43fea57f0c15ef13088a076ba6645b6837113cc2\
         a8412ca4c85e4a20b21f5f64a08203333082032f3082032b30820213a003\
         020102020101300d06092a864886f70d01010b0500301d311b3019060355\
         040313127273612d323034382d7368613235362d6361301e170d32333131\
         30353031303934355a170d3332313130323031303934355a301d311b3019\
         060355040313127273612d323034382d7368613235362d63613082012230\
         0d06092a864886f70d01010105000382010f003082010a0282010100be98\
         4263d2834964fb0ca6668c72bd2162934811dd512efc9bd0b02d8d6a18cb\
         54256348e40fb6fc86c7d75b26c84b863034e034e8928077ae22bafbd5b8\
         9828eadf300fe69d9c6b800f7ec86323379cfffedd6c921b07354fbe3020\
         dd3ef56e77df0420b2a43854dd711120b3d945e2a619e70963d71bed0ff8\
         955a6bed95966572c0087f7b45db31b873cb75bd42c21e83d47f29ba2d4f\
         b213b91d8554504e4d75768c547a5a49559e6ae457deed051273ea7c8482\
         ec72e4749095ed6ba06ad04407297244472d9118308ce066ba23566ff5fa\
         a9301d65b09bafe53c337e776a3a81a8e774b7715b39570c59c4c3316c57\
         6466167d6779ff5244362f7541850203010001a3763074300c0603551d13\
         040530030101ff301d0603551d0e041604145dd72c171c018b2ffa92c313\
         3913689ebd82115c30450603551d23043e303c80145dd72c171c018b2ffa\
         92c3133913689ebd82115ca121a41f301d311b3019060355040313127273\
         612d323034382d7368613235362d6361820101300d06092a864886f70d01\
         010b05000382010100a6c69f0a7d673fad77a1e978323289916ef85501e2\
         76c57a6dd8ca9917ea36b46088ff70f0d04b2c40ae1f242942f5a0c4e4c7\
         c80074ce32ec246c4e921163731d7bb2048f94f7cade1c6e7e8abea615c5\
         829f6cf55a4776cb3f4f18072b314b1b16a87e49614d03a6371425d05099\
         c5a3e4ef3e23cd170ba084ddae9e18ac3dc85c059462b75497bf1d8f01aa\
         117841012619d4150944cb7b22a5b787edc6d606de4ec6fa3641e8e3672d\
         d4979228e556ec98097cafe035646b210d472dc19deecf0961901d06279e\
         93239eb1f268804dfb7892dada551c81fc790b3f246cdecafe01ac3108f4\
         2eb921e8e3d6d8cc83304fd22076555d3498aa4e38da3584ff"
    );
    let signature = hex!(
        "acc2a7bf355dd81629c227a2c1f07f2b5d34\
         1d9a5db782a9ab5cb3fe654a05ba47d25c43\
         8cc0b7d4f430460788574ecb3ba400f58679\
         829d915bd515e63c98f63b8213e073dbd110\
         2053ef21f65bb4fa024956142df9d0f9d5f5\
         7372a94507499a52702deaf6dc225d2825f7\
         3386f5eec4703db10c61d6647b91e88636b4\
         1e8e57454d50a9f98661a8eaee9b13352b51\
         226e4c1eb6521ceb8525eaa5c8a0226a55d4\
         3cbe595dc09aa905625973d343c922037ee5\
         543d3fe749bc8f581389fc2bc375233b7525\
         919b3a685cff45d62dbbca3ea9abdf026d39\
         775c0d4e977dc4fd43fea57f0c15ef13088a\
         076ba6645b6837113cc2a8412ca4c85e4a20\
         b21f5f64"
    );
    let res = OcspResponse::from_der(&data[..]).unwrap();
    let res = assert_ocsp_response(&res);
    assert_signature(
        &res,
        SHA_256_WITH_RSA_ENCRYPTION,
        &signature[..],
        Some(CA_CERTIFICATE_DATA),
    );
    let sha1_certid = CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: ID_SHA1,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(&hex!("94D418C85D800AF31266F13D3D8CD8CD6AA5BB74")[..])
            .unwrap(),
        issuer_key_hash: OctetString::new(&hex!("5DD72C171C018B2FFA92C3133913689EBD82115C")[..])
            .unwrap(),
        serial_number: SerialNumber::from(0x10001usize),
    };
    let sha256_certid = CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: ID_SHA256,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(
            &hex!("056078AE157D9BB53154B1ABEBD26057D624FDDD9F09AE63814E90A365F444C5")[..],
        )
        .unwrap(),
        issuer_key_hash: OctetString::new(
            &hex!("15C37A883122D2FB6DBFA83E3CBD93E9EEF8125E3FD785724BC42D9D6FBA39B7")[..],
        )
        .unwrap(),
        serial_number: SerialNumber::from(0x10001usize),
    };
    let sha512_certid = CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: ID_SHA512,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(
            &hex!(
                "6AE6D566832B216D55BF3F8CCBBBD662E4D798D7E5FC64CEE6CB35DF60EE1181305CB2\
                 747626560AFABD29B781A9A4631B0DFA1A05727323B3B81EEB54E57981"
            )[..],
        )
        .unwrap(),
        issuer_key_hash: OctetString::new(
            &hex!(
                "FEAC2688D16143E11050AEF3CDFAE4E4E21DF08F40A9FA3F5D80903B839450EE296202\
                 63B12AB92F3E840458A4871119B6757D337CEDB9044B8A5F7239615E06"
            )[..],
        )
        .unwrap(),
        serial_number: SerialNumber::from(0x10001usize),
    };
    let single = assert_basic_response(&res, &RESPONDER_ID, &TIME, &sha1_certid);
    assert_single_response(&single, CertStatus::Good(Null), &TIME, Some(&TIME));
    let single = assert_basic_response(&res, &RESPONDER_ID, &TIME, &sha256_certid);
    assert_single_response(&single, CertStatus::Good(Null), &TIME, Some(&TIME));
    let single = assert_basic_response(&res, &RESPONDER_ID, &TIME, &sha512_certid);
    assert_single_response(&single, CertStatus::Good(Null), &TIME, Some(&TIME));
}
