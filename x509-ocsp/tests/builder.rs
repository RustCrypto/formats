#![cfg(feature = "builder")]
//! ocsp builder tests

use der::{DateTime, Decode, Encode};
use hex_literal::hex;
use lazy_static::lazy_static;
use rsa::{RsaPrivateKey, pkcs1v15::SigningKey, pkcs8::DecodePrivateKey};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use x509_cert::{Certificate, name::Name, serial_number::SerialNumber};
use x509_ocsp::builder::*;
use x509_ocsp::{ext::*, *};

lazy_static! {
    static ref ISSUER: Certificate = Certificate::from_der(
        &std::fs::read("tests/examples/rsa-2048-sha256-ca.der").unwrap()
    )
    .unwrap();

    static ref ISSUER_KEY: RsaPrivateKey = RsaPrivateKey::from_pkcs8_der(
        &std::fs::read("tests/examples/rsa-2048-sha256-ca-key.der").unwrap()
    )
    .unwrap();

    static ref CERT: Certificate = Certificate::from_der(
        &std::fs::read("tests/examples/rsa-2048-sha256-crt.der").unwrap()
    )
    .unwrap();

    static ref CERT_KEY: RsaPrivateKey = RsaPrivateKey::from_pkcs8_der(
        &std::fs::read("tests/examples/rsa-2048-sha256-crt-key.der").unwrap()
    )
    .unwrap();

    static ref OCSP: Certificate = Certificate::from_der(
        &std::fs::read("tests/examples/rsa-2048-sha256-ocsp-crt.der").unwrap()
    )
    .unwrap();

    static ref OCSP_KEY: RsaPrivateKey = RsaPrivateKey::from_pkcs8_der(
        &std::fs::read("tests/examples/rsa-2048-sha256-ocsp-crt-key.der").unwrap()
    )
    .unwrap();

    // PrintableString: CN = rsa-2048-sha256-ocsp-crt
    static ref RESPONDER_ID: ResponderId = ResponderId::ByName(
        Name::from_der(
            &hex!("30233121301f060355040313187273612d323034382d7368613235362d6f6373702d637274")[..]
        )
        .unwrap()
    );
}

#[test]
fn encode_ocsp_req_sha1_certid() {
    let req_der = std::fs::read("tests/examples/sha1-certid-ocsp-req.der").unwrap();
    let req = OcspRequestBuilder::default()
        .with_request(
            Request::from_issuer::<Sha1>(&ISSUER, SerialNumber::from(0x10001usize)).unwrap(),
        )
        .build();
    assert_eq!(&req.to_der().unwrap(), &req_der);
}

#[test]
fn encode_ocsp_req_sha224_certid() {
    let req_der = std::fs::read("tests/examples/sha224-certid-ocsp-req.der").unwrap();
    let req = OcspRequestBuilder::default()
        .with_request(
            Request::from_issuer::<Sha224>(&ISSUER, SerialNumber::from(0x10001usize)).unwrap(),
        )
        .build();
    assert_eq!(&req.to_der().unwrap(), &req_der);
}

#[test]
fn encode_ocsp_req_sha256_certid() {
    let req_der = std::fs::read("tests/examples/sha256-certid-ocsp-req.der").unwrap();
    let req = OcspRequestBuilder::default()
        .with_request(
            Request::from_issuer::<Sha256>(&ISSUER, SerialNumber::from(0x10001usize)).unwrap(),
        )
        .build();
    assert_eq!(&req.to_der().unwrap(), &req_der);
}

#[test]
fn encode_ocsp_req_sha384_certid() {
    let req_der = std::fs::read("tests/examples/sha384-certid-ocsp-req.der").unwrap();
    let req = OcspRequestBuilder::default()
        .with_request(
            Request::from_issuer::<Sha384>(&ISSUER, SerialNumber::from(0x10001usize)).unwrap(),
        )
        .build();
    assert_eq!(&req.to_der().unwrap(), &req_der);
}

#[test]
fn encode_ocsp_req_sha512_certid() {
    let req_der = std::fs::read("tests/examples/sha512-certid-ocsp-req.der").unwrap();
    let req = OcspRequestBuilder::default()
        .with_request(
            Request::from_issuer::<Sha512>(&ISSUER, SerialNumber::from(0x10001usize)).unwrap(),
        )
        .build();
    assert_eq!(&req.to_der().unwrap(), &req_der);
}

#[test]
fn encode_ocsp_req_multiple_extensions() {
    let req_der = std::fs::read("tests/examples/ocsp-multiple-exts-clean-req.der").unwrap();
    let single_ext1 = ServiceLocator::from_der(
        &hex!(
            "3051301D311B3019060355040313127273612D323034382D736861323536\
             2D63613030301006082B0601050507300187047F000001301C06082B0601\
             0505073001871000000000000000000000000000000001"
        )[..],
    )
    .unwrap();
    let ext1 = Nonce::from_der(
        &hex!("0420BB42AE6BEBD2B6E455CA02BC853452635F08863EFFAF25E182905E7FFF1FB40A")[..],
    )
    .unwrap();
    let ext2 = AcceptableResponses::from_der(&hex!("300B06092B0601050507300101")[..]).unwrap();
    let req = OcspRequestBuilder::default()
        .with_request(
            Request::from_issuer::<Sha1>(&ISSUER, SerialNumber::from(0x10001usize))
                .unwrap()
                .with_extension(&single_ext1)
                .unwrap(),
        )
        .with_extension(&ext1)
        .unwrap()
        .with_extension(&ext2)
        .unwrap()
        .build();
    assert_eq!(&req.to_der().unwrap(), &req_der);
}

#[test]
fn encode_ocsp_req_multiple_requests() {
    let req_der = std::fs::read("tests/examples/ocsp-multiple-requests-req.der").unwrap();
    let req = OcspRequestBuilder::default()
        .with_request(
            Request::from_issuer::<Sha1>(&ISSUER, SerialNumber::from(0x10001usize)).unwrap(),
        )
        .with_request(
            Request::from_issuer::<Sha224>(&ISSUER, SerialNumber::from(0x10001usize)).unwrap(),
        )
        .with_request(
            Request::from_issuer::<Sha256>(&ISSUER, SerialNumber::from(0x10001usize)).unwrap(),
        )
        .with_request(
            Request::from_issuer::<Sha384>(&ISSUER, SerialNumber::from(0x10001usize)).unwrap(),
        )
        .with_request(
            Request::from_issuer::<Sha512>(&ISSUER, SerialNumber::from(0x10001usize)).unwrap(),
        )
        .with_request(Request::from_issuer::<Sha1>(&ISSUER, SerialNumber::from(0x5usize)).unwrap())
        .with_request(Request::from_issuer::<Sha1>(&ISSUER, SerialNumber::from(0x16usize)).unwrap())
        .with_request(
            Request::from_issuer::<Sha1>(&ISSUER, SerialNumber::from(0xFFFFFFFFusize)).unwrap(),
        )
        .build();
    assert_eq!(&req.to_der().unwrap(), &req_der);
}

#[test]
fn encode_ocsp_req_signed() {
    let req_der = std::fs::read("tests/examples/ocsp-signed-req.der").unwrap();
    let mut signer = SigningKey::<Sha256>::new(CERT_KEY.clone());
    let req = OcspRequestBuilder::default()
        .with_request(
            Request::from_issuer::<Sha1>(&ISSUER, SerialNumber::from(0x10001usize)).unwrap(),
        )
        .sign(&mut signer, Some(vec![CERT.clone()]))
        .unwrap();
    assert_eq!(&req.to_der().unwrap(), &req_der);
}

#[test]
fn encode_ocsp_resp_errors() {
    let req_der = std::fs::read("tests/examples/ocsp-malformed.der").unwrap();
    let resp = OcspResponse::malformed_request();
    assert_eq!(&resp.to_der().unwrap(), &req_der);
    let req_der = std::fs::read("tests/examples/ocsp-internal-error.der").unwrap();
    let resp = OcspResponse::internal_error();
    assert_eq!(&resp.to_der().unwrap(), &req_der);
    let req_der = std::fs::read("tests/examples/ocsp-try-later.der").unwrap();
    let resp = OcspResponse::try_later();
    assert_eq!(&resp.to_der().unwrap(), &req_der);
    let req_der = std::fs::read("tests/examples/ocsp-sig-required.der").unwrap();
    let resp = OcspResponse::sig_required();
    assert_eq!(&resp.to_der().unwrap(), &req_der);
    let req_der = std::fs::read("tests/examples/ocsp-unauthorized.der").unwrap();
    let resp = OcspResponse::unauthorized();
    assert_eq!(&resp.to_der().unwrap(), &req_der);
}

#[test]
fn encode_ocsp_resp_sha1_certid() {
    let resp_der = std::fs::read("tests/examples/sha1-certid-ocsp-res.der").unwrap();
    let mut signer = SigningKey::<Sha256>::new(ISSUER_KEY.clone());
    let resp = OcspResponseBuilder::new(RESPONDER_ID.clone())
        .with_single_response(
            SingleResponse::new(
                CertId::from_issuer::<Sha1>(&ISSUER, SerialNumber::from(0x10001usize)).unwrap(),
                CertStatus::good(),
                OcspGeneralizedTime::from(DateTime::new(2020, 1, 1, 0, 0, 0).unwrap()),
            )
            .with_next_update(OcspGeneralizedTime::from(
                DateTime::new(2020, 1, 1, 0, 0, 0).unwrap(),
            )),
        )
        .sign(
            &mut signer,
            Some(vec![ISSUER.clone()]),
            OcspGeneralizedTime::from(DateTime::new(2020, 1, 1, 0, 0, 0).unwrap()),
        )
        .unwrap();
    assert_eq!(&resp.to_der().unwrap(), &resp_der);
}

#[test]
fn encode_ocsp_resp_sha256_certid() {
    let resp_der = std::fs::read("tests/examples/sha256-certid-ocsp-res.der").unwrap();
    let mut signer = SigningKey::<Sha256>::new(ISSUER_KEY.clone());
    let resp = OcspResponseBuilder::new(RESPONDER_ID.clone())
        .with_single_response(
            SingleResponse::new(
                CertId::from_issuer::<Sha256>(&ISSUER, SerialNumber::from(0x10001usize)).unwrap(),
                CertStatus::good(),
                OcspGeneralizedTime::from(DateTime::new(2020, 1, 1, 0, 0, 0).unwrap()),
            )
            .with_next_update(OcspGeneralizedTime::from(
                DateTime::new(2020, 1, 1, 0, 0, 0).unwrap(),
            )),
        )
        .sign(
            &mut signer,
            Some(vec![ISSUER.clone()]),
            OcspGeneralizedTime::from(DateTime::new(2020, 1, 1, 0, 0, 0).unwrap()),
        )
        .unwrap();
    assert_eq!(&resp.to_der().unwrap(), &resp_der);
}

#[test]
fn encode_ocsp_resp_sha512_certid() {
    let resp_der = std::fs::read("tests/examples/sha512-certid-ocsp-res.der").unwrap();
    let mut signer = SigningKey::<Sha256>::new(ISSUER_KEY.clone());
    let resp = OcspResponseBuilder::new(RESPONDER_ID.clone())
        .with_single_response(
            SingleResponse::new(
                CertId::from_issuer::<Sha512>(&ISSUER, SerialNumber::from(0x10001usize)).unwrap(),
                CertStatus::good(),
                OcspGeneralizedTime::from(DateTime::new(2020, 1, 1, 0, 0, 0).unwrap()),
            )
            .with_next_update(OcspGeneralizedTime::from(
                DateTime::new(2020, 1, 1, 0, 0, 0).unwrap(),
            )),
        )
        .sign(
            &mut signer,
            Some(vec![ISSUER.clone()]),
            OcspGeneralizedTime::from(DateTime::new(2020, 1, 1, 0, 0, 0).unwrap()),
        )
        .unwrap();
    assert_eq!(&resp.to_der().unwrap(), &resp_der);
}

#[test]
fn encode_ocsp_resp_multiple_extensions() {
    let resp_der = std::fs::read("tests/examples/ocsp-multiple-exts-res.der").unwrap();
    let ext1 = Nonce::from_der(
        &hex!("04201F27F8C9CD8D154DAAEF021D5AAD6EAD7FE0637D044198E3F39291204924CEF8")[..],
    )
    .unwrap();
    let single_ext1 =
        ArchiveCutoff::from_der(&hex!("180F32303230303130313030303030305A")[..]).unwrap();
    let single_ext2 = CrlReferences::from_der(
        &hex!(
            "3030A0161614687474703A2F2F3132372E302E302E312F63726CA103020101A2\
             11180F32303230303130313030303030305A"
        )[..],
    )
    .unwrap();
    let mut signer = SigningKey::<Sha256>::new(ISSUER_KEY.clone());
    let resp = OcspResponseBuilder::new(RESPONDER_ID.clone())
        .with_single_response(
            SingleResponse::new(
                CertId::from_issuer::<Sha1>(&ISSUER, SerialNumber::from(0x10001usize)).unwrap(),
                CertStatus::good(),
                OcspGeneralizedTime::from(DateTime::new(2020, 1, 1, 0, 0, 0).unwrap()),
            )
            .with_next_update(OcspGeneralizedTime::from(
                DateTime::new(2020, 1, 1, 0, 0, 0).unwrap(),
            ))
            .with_extension(&single_ext1)
            .unwrap()
            .with_extension(&single_ext2)
            .unwrap(),
        )
        .with_extension(&ext1)
        .unwrap()
        .sign(
            &mut signer,
            Some(vec![ISSUER.clone()]),
            OcspGeneralizedTime::from(DateTime::new(2020, 1, 1, 0, 0, 0).unwrap()),
        )
        .unwrap();
    assert_eq!(&resp.to_der().unwrap(), &resp_der);
}

#[test]
fn encode_ocsp_resp_multiple_responses() {
    let resp_der = std::fs::read("tests/examples/ocsp-multiple-responses-res.der").unwrap();
    let mut signer = SigningKey::<Sha256>::new(ISSUER_KEY.clone());
    let resp = OcspResponseBuilder::new(RESPONDER_ID.clone())
        .with_single_response(
            SingleResponse::new(
                CertId::from_issuer::<Sha1>(&ISSUER, SerialNumber::from(0x10001usize)).unwrap(),
                CertStatus::good(),
                OcspGeneralizedTime::from(DateTime::new(2020, 1, 1, 0, 0, 0).unwrap()),
            )
            .with_next_update(OcspGeneralizedTime::from(
                DateTime::new(2020, 1, 1, 0, 0, 0).unwrap(),
            )),
        )
        .with_single_response(
            SingleResponse::new(
                CertId::from_issuer::<Sha224>(&ISSUER, SerialNumber::from(0x10001usize)).unwrap(),
                CertStatus::good(),
                OcspGeneralizedTime::from(DateTime::new(2020, 1, 1, 0, 0, 0).unwrap()),
            )
            .with_next_update(OcspGeneralizedTime::from(
                DateTime::new(2020, 1, 1, 0, 0, 0).unwrap(),
            )),
        )
        .with_single_response(
            SingleResponse::new(
                CertId::from_issuer::<Sha256>(&ISSUER, SerialNumber::from(0x10001usize)).unwrap(),
                CertStatus::good(),
                OcspGeneralizedTime::from(DateTime::new(2020, 1, 1, 0, 0, 0).unwrap()),
            )
            .with_next_update(OcspGeneralizedTime::from(
                DateTime::new(2020, 1, 1, 0, 0, 0).unwrap(),
            )),
        )
        .with_single_response(
            SingleResponse::new(
                CertId::from_issuer::<Sha384>(&ISSUER, SerialNumber::from(0x10001usize)).unwrap(),
                CertStatus::good(),
                OcspGeneralizedTime::from(DateTime::new(2020, 1, 1, 0, 0, 0).unwrap()),
            )
            .with_next_update(OcspGeneralizedTime::from(
                DateTime::new(2020, 1, 1, 0, 0, 0).unwrap(),
            )),
        )
        .with_single_response(
            SingleResponse::new(
                CertId::from_issuer::<Sha512>(&ISSUER, SerialNumber::from(0x10001usize)).unwrap(),
                CertStatus::good(),
                OcspGeneralizedTime::from(DateTime::new(2020, 1, 1, 0, 0, 0).unwrap()),
            )
            .with_next_update(OcspGeneralizedTime::from(
                DateTime::new(2020, 1, 1, 0, 0, 0).unwrap(),
            )),
        )
        .with_single_response(
            SingleResponse::new(
                CertId::from_issuer::<Sha1>(&ISSUER, SerialNumber::from(0x5usize)).unwrap(),
                CertStatus::good(),
                OcspGeneralizedTime::from(DateTime::new(2020, 1, 1, 0, 0, 0).unwrap()),
            )
            .with_next_update(OcspGeneralizedTime::from(
                DateTime::new(2020, 1, 1, 0, 0, 0).unwrap(),
            )),
        )
        .with_single_response(
            SingleResponse::new(
                CertId::from_issuer::<Sha1>(&ISSUER, SerialNumber::from(0x16usize)).unwrap(),
                CertStatus::good(),
                OcspGeneralizedTime::from(DateTime::new(2020, 1, 1, 0, 0, 0).unwrap()),
            )
            .with_next_update(OcspGeneralizedTime::from(
                DateTime::new(2020, 1, 1, 0, 0, 0).unwrap(),
            )),
        )
        .with_single_response(
            SingleResponse::new(
                CertId::from_issuer::<Sha1>(&ISSUER, SerialNumber::from(0xFFFFFFFFusize)).unwrap(),
                CertStatus::good(),
                OcspGeneralizedTime::from(DateTime::new(2020, 1, 1, 0, 0, 0).unwrap()),
            )
            .with_next_update(OcspGeneralizedTime::from(
                DateTime::new(2020, 1, 1, 0, 0, 0).unwrap(),
            )),
        )
        .sign(
            &mut signer,
            Some(vec![ISSUER.clone()]),
            OcspGeneralizedTime::from(DateTime::new(2020, 1, 1, 0, 0, 0).unwrap()),
        )
        .unwrap();
    assert_eq!(&resp.to_der().unwrap(), &resp_der);
}

#[test]
fn encode_ocsp_resp_revoked_delegated() {
    let resp_der = std::fs::read("tests/examples/rsa-2048-sha256-revoked-ocsp-res.der").unwrap();
    let mut signer = SigningKey::<Sha256>::new(OCSP_KEY.clone());
    let resp = OcspResponseBuilder::new(RESPONDER_ID.clone())
        .with_single_response(
            SingleResponse::new(
                CertId::from_issuer::<Sha1>(&ISSUER, SerialNumber::from(3usize)).unwrap(),
                CertStatus::revoked(RevokedInfo {
                    revocation_time: OcspGeneralizedTime::from(
                        DateTime::new(2023, 11, 5, 1, 9, 45).unwrap(),
                    ),
                    revocation_reason: None,
                }),
                OcspGeneralizedTime::from(DateTime::new(2023, 11, 5, 1, 9, 46).unwrap()),
            )
            .with_next_update(OcspGeneralizedTime::from(
                DateTime::new(2024, 11, 4, 1, 9, 46).unwrap(),
            )),
        )
        .sign(
            &mut signer,
            Some(vec![OCSP.clone()]),
            OcspGeneralizedTime::from(DateTime::new(2023, 11, 5, 1, 9, 46).unwrap()),
        )
        .unwrap();
    assert_eq!(&resp.to_der().unwrap(), &resp_der);
}
