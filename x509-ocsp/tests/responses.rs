//! ocsp response decode tests

use der::{
    DateTime, Decode, Encode,
    asn1::{Null, ObjectIdentifier, OctetString},
};
use hex_literal::hex;
use lazy_static::lazy_static;
use spki::AlgorithmIdentifierOwned;
use x509_cert::{
    ext::{Extension, pkix::CrlReason},
    name::Name,
    serial_number::SerialNumber,
};
use x509_ocsp::{ext::Nonce, *};

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
    // PrintableString: CN = rsa-2048-sha256-ocsp-crt
    static ref RESPONDER_ID: ResponderId = ResponderId::ByName(
        Name::from_der(
            &hex!("30233121301f060355040313187273612d323034382d7368613235362d6f6373702d637274")[..]
        )
        .unwrap()
    );

    // Time used almost everywhere in these tests
    static ref TIME: OcspGeneralizedTime = OcspGeneralizedTime::from(
        DateTime::new(2020, 1, 1, 0, 0, 0).unwrap()
    );
}

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
    expected_time: &OcspGeneralizedTime,
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
        Some(res) => res,
    }
}

fn assert_single_response(
    single_res: &SingleResponse,
    expected_status: CertStatus,
    expected_this_update: &OcspGeneralizedTime,
    expected_next_update: Option<&OcspGeneralizedTime>,
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

#[test]
fn decode_ocsp_resp_malformed_request() {
    let data = std::fs::read("tests/examples/ocsp-malformed.der").unwrap();
    let ocsp_res = OcspResponse::from_der(&data[..]).unwrap();
    assert_eq!(
        ocsp_res.response_status,
        OcspResponseStatus::MalformedRequest
    );
}

#[test]
fn decode_ocsp_resp_internal_error() {
    let data = std::fs::read("tests/examples/ocsp-internal-error.der").unwrap();
    let ocsp_res = OcspResponse::from_der(&data[..]).unwrap();
    assert_eq!(ocsp_res.response_status, OcspResponseStatus::InternalError);
}

#[test]
fn decode_ocsp_resp_try_later() {
    let data = std::fs::read("tests/examples/ocsp-try-later.der").unwrap();
    let ocsp_res = OcspResponse::from_der(&data[..]).unwrap();
    assert_eq!(ocsp_res.response_status, OcspResponseStatus::TryLater);
}

#[test]
fn decode_ocsp_resp_sig_required() {
    let data = std::fs::read("tests/examples/ocsp-sig-required.der").unwrap();
    let ocsp_res = OcspResponse::from_der(&data[..]).unwrap();
    assert_eq!(ocsp_res.response_status, OcspResponseStatus::SigRequired);
}

#[test]
fn decode_ocsp_resp_unauthorized() {
    let data = std::fs::read("tests/examples/ocsp-unauthorized.der").unwrap();
    let ocsp_res = OcspResponse::from_der(&data[..]).unwrap();
    assert_eq!(ocsp_res.response_status, OcspResponseStatus::Unauthorized);
}

#[test]
fn decode_ocsp_resp_sha1_certid() {
    let ca = std::fs::read("tests/examples/rsa-2048-sha256-ca.der").unwrap();
    let data = std::fs::read("tests/examples/sha1-certid-ocsp-res.der").unwrap();
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
    assert_signature(&res, SHA_256_WITH_RSA_ENCRYPTION, &signature[..], Some(&ca));
    assert!(res.nonce().is_none());
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
    assert_single_response(single, CertStatus::Good(Null), &TIME, Some(&TIME));
}

#[test]
fn decode_ocsp_resp_sha256_certid() {
    let ca = std::fs::read("tests/examples/rsa-2048-sha256-ca.der").unwrap();
    let data = std::fs::read("tests/examples/sha256-certid-ocsp-res.der").unwrap();
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
    assert!(res.nonce().is_none());
    assert_signature(&res, SHA_256_WITH_RSA_ENCRYPTION, &signature[..], Some(&ca));
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
    assert_single_response(single, CertStatus::Good(Null), &TIME, Some(&TIME));
}

#[test]
fn decode_ocsp_resp_sha512_certid() {
    let ca = std::fs::read("tests/examples/rsa-2048-sha256-ca.der").unwrap();
    let data = std::fs::read("tests/examples/sha512-certid-ocsp-res.der").unwrap();
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
    assert!(res.nonce().is_none());
    assert_signature(&res, SHA_256_WITH_RSA_ENCRYPTION, &signature[..], Some(&ca));
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
    assert_single_response(single, CertStatus::Good(Null), &TIME, Some(&TIME));
}

#[test]
fn decode_ocsp_resp_multiple_extensions() {
    let ca = std::fs::read("tests/examples/rsa-2048-sha256-ca.der").unwrap();
    let data = std::fs::read("tests/examples/ocsp-multiple-exts-res.der").unwrap();
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
    let nonce = Nonce::new(hex!(
        "1F27F8C9CD8D154DAAEF021D5AAD6EAD7FE0637D044198E3F39291204924CEF8"
    ))
    .unwrap();
    let archive_cutoff_ext = hex!("180F32303230303130313030303030305A");
    let crl_refs_ext = hex!(
        "3030A0161614687474703A2F2F3132372E302E302E312F63726CA103020101A2\
         11180F32303230303130313030303030305A"
    );
    let res = OcspResponse::from_der(&data[..]).unwrap();
    let res = assert_ocsp_response(&res);
    assert_signature(&res, SHA_256_WITH_RSA_ENCRYPTION, &signature[..], Some(&ca));
    assert!(res.tbs_response_data.response_extensions.as_ref().is_some());
    assert_extension(
        &res.tbs_response_data.response_extensions.as_ref().unwrap()[0],
        ID_PKIX_OCSP_NONCE,
        false,
        &nonce_ext[..],
    );
    assert_eq!(res.nonce(), Some(nonce));
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
    assert_single_response(single, CertStatus::Good(Null), &TIME, Some(&TIME));
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

#[test]
fn decode_ocsp_resp_dtm_no_chain() {
    let data = std::fs::read("tests/examples/ocsp-dtm-no-chain-res.der").unwrap();
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
    let nonce = Nonce::new(hex!(
        "1F27F8C9CD8D154DAAEF021D5AAD6EAD7FE0637D044198E3F39291204924CEF8"
    ))
    .unwrap();
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
    assert_eq!(res.nonce(), Some(nonce));
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
    assert_single_response(single, CertStatus::Good(Null), &TIME, Some(&TIME));
}

#[test]
fn decode_ocsp_resp_dtm_by_key() {
    let data = std::fs::read("tests/examples/ocsp-by-key-res.der").unwrap();
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
    let nonce = Nonce::new(hex!(
        "1F27F8C9CD8D154DAAEF021D5AAD6EAD7FE0637D044198E3F39291204924CEF8"
    ))
    .unwrap();
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
    assert_eq!(res.nonce(), Some(nonce));
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
    assert_single_response(single, CertStatus::Good(Null), &TIME, Some(&TIME));
}

#[test]
fn decode_ocsp_resp_multiple_responses() {
    let ca = std::fs::read("tests/examples/rsa-2048-sha256-ca.der").unwrap();
    let data = std::fs::read("tests/examples/ocsp-multiple-responses-res.der").unwrap();
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
    assert!(res.nonce().is_none());
    assert_signature(&res, SHA_256_WITH_RSA_ENCRYPTION, &signature[..], Some(&ca));
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
    assert_single_response(single, CertStatus::Good(Null), &TIME, Some(&TIME));
    let single = assert_basic_response(&res, &RESPONDER_ID, &TIME, &sha256_certid);
    assert_single_response(single, CertStatus::Good(Null), &TIME, Some(&TIME));
    let single = assert_basic_response(&res, &RESPONDER_ID, &TIME, &sha512_certid);
    assert_single_response(single, CertStatus::Good(Null), &TIME, Some(&TIME));
}

#[test]
fn decode_ocsp_resp_revoked_response() {
    let data = std::fs::read("tests/examples/DODEMAILCA_63-resp.der").unwrap();
    let res = OcspResponse::from_der(&data[..]).unwrap();
    let res = assert_ocsp_response(&res);
    assert!(res.nonce().is_none());
    let certid = CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: ID_SHA1,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(&hex!("190A0E6D0DB33F82244A595BFA8AC04C163AAD28")[..])
            .unwrap(),
        issuer_key_hash: OctetString::new(&hex!("4D31AD51D64E577E67693325037EC629A5DDBAF3")[..])
            .unwrap(),
        serial_number: SerialNumber::from(0x7ab92usize),
    };
    let mut filter = res
        .tbs_response_data
        .responses
        .iter()
        .filter(|r| r.cert_id == certid);
    match filter.next() {
        None => panic!("CertId not found"),
        Some(res) => match &res.cert_status {
            CertStatus::Revoked(info) => {
                assert!(info.revocation_reason.as_ref().is_some());
                assert_eq!(info.revocation_reason.unwrap(), CrlReason::Superseded);
            }
            _ => panic!("should be revoked"),
        },
    }
}
