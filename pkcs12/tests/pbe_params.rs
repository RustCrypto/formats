//! `pbe_params` tests.

use der::{Decode, Encode};
use pkcs12::pbe_params::Pbkdf2Params;

/// RFC 8018: `prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT algid-hmacWithSHA1`. DER omits
/// the default, so HMAC-SHA1 PBKDF2-params have no `prf`. These are the PBKDF2-params of a key
/// encrypted with `openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA1`.
#[test]
fn pbkdf2_params_default_prf() {
    let der = [
        0x30, 0x16, 0x04, 0x10, 0x27, 0xf1, 0x44, 0x97, 0x0f, 0x23, 0xba, 0x4f, 0x98, 0x07, 0xdc,
        0x9d, 0xb5, 0x2f, 0x00, 0xf1, 0x02, 0x02, 0x08, 0x00,
    ];
    let params = Pbkdf2Params::from_der(&der).unwrap();
    assert_eq!(params.iteration_count, 2048);
    assert_eq!(params.key_length, None);
    assert_eq!(params.prf.oid, pkcs5::pbes2::HMAC_WITH_SHA1_OID);
    assert_eq!(params.to_der().unwrap(), der);
}
