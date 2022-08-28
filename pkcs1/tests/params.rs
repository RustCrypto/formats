//! PKCS#1 algorithm params tests

use const_oid::db;
use der::{asn1::ObjectIdentifier, Decode, Encode};
use hex_literal::hex;
use pkcs1::RsaPssParams;
use pkcs1::TrailerField;

/// Default PSS parameters using all default values (SHA1, MGF1)
const RSA_PSS_PARAMETERS_DEFAULTS: &[u8] = &hex!("3000");
/// Example PSS parameters using SHA256 instead of SHA1
const RSA_PSS_PARAMETERS_SHA2_256: &[u8] = &hex!("3030a00d300b0609608648016503040201a11a301806092a864886f70d010108300b0609608648016503040201a203020120");

#[test]
fn decode_pss_param() {
    let param = RsaPssParams::try_from(RSA_PSS_PARAMETERS_SHA2_256).unwrap();

    assert!(param
        .hash
        .assert_algorithm_oid(db::rfc5912::ID_SHA_256)
        .is_ok());
    assert_eq!(param.hash.parameters, None);
    assert!(param
        .mask_gen
        .assert_algorithm_oid(db::rfc5912::ID_MGF_1)
        .is_ok());
    assert_eq!(
        param
            .mask_gen
            .parameters_any()
            .unwrap()
            .sequence(|reader| Ok(ObjectIdentifier::decode(reader)?))
            .unwrap(),
        db::rfc5912::ID_SHA_256
    );
    assert_eq!(param.salt_len, 32);
    assert_eq!(param.trailer_field, TrailerField::BC);
}

#[test]
fn encode_pss_param() {
    let mut buf = [0_u8; 256];
    let param = RsaPssParams::try_from(RSA_PSS_PARAMETERS_SHA2_256).unwrap();
    assert_eq!(
        param.encode_to_slice(&mut buf).unwrap(),
        RSA_PSS_PARAMETERS_SHA2_256
    );
}

#[test]
fn decode_pss_param_default() {
    let param = RsaPssParams::try_from(RSA_PSS_PARAMETERS_DEFAULTS).unwrap();

    assert!(param
        .hash
        .assert_algorithm_oid(db::rfc5912::ID_SHA_1)
        .is_ok());
    assert_eq!(param.hash.parameters, None);
    assert!(param
        .mask_gen
        .assert_algorithm_oid(db::rfc5912::ID_MGF_1)
        .is_ok());
    assert_eq!(
        param
            .mask_gen
            .parameters_any()
            .unwrap()
            .sequence(|reader| Ok(ObjectIdentifier::decode(reader)?))
            .unwrap(),
        db::rfc5912::ID_SHA_1
    );
    assert_eq!(param.salt_len, 20);
    assert_eq!(param.trailer_field, TrailerField::BC);
    assert_eq!(param, Default::default())
}

#[test]
fn encode_pss_param_default() {
    let mut buf = [0_u8; 256];
    assert_eq!(
        RsaPssParams::default().encode_to_slice(&mut buf).unwrap(),
        RSA_PSS_PARAMETERS_DEFAULTS
    );
}
