use pkcs5::{
    pbes2,
    pbes2::{AES_256_CBC_OID, PBES2_OID, PBKDF2_OID, Pbkdf2Params, Pbkdf2Prf},
};
use pkcs8::{
    EncryptedPrivateKeyInfo,
    spki::{AlgorithmIdentifier, AlgorithmIdentifierOwned},
};

use cms::encrypted_data::EncryptedData;
use const_oid::db::rfc5911::{ID_DATA, ID_ENCRYPTED_DATA};
use der::{
    Any, AnyRef, Decode, Encode,
    asn1::{ContextSpecific, OctetString, SetOfVec},
};
use pkcs5::pbes2::Salt;
use pkcs12::{PKCS_12_PKCS8_KEY_BAG_OID, pfx::Pfx};
use rand_core::Rng;
use x509_cert::Certificate;

use pkcs12::builder::{
    EncryptionAlgorithm, MacAlgorithm, MacDataBuilder, Pkcs12Builder, add_friendly_name_attr,
    add_key_id_attr,
    asn1_utils::{get_auth_safes, get_cert, get_key, get_safe_bags},
    parse_pkcs12,
};

#[cfg(test)]
fn check_key_and_cert(
    der_p12: &[u8],
    password: &str,
    key: &[u8],
    cert: &[u8],
    cert_id: &Option<Vec<u8>>,
    key_id: &Option<Vec<u8>>,
) {
    let pfx = Pfx::from_der(der_p12).unwrap();
    let auth_safes = get_auth_safes(&pfx.auth_safe.content).unwrap();
    for auth_safe in auth_safes {
        if ID_ENCRYPTED_DATA == auth_safe.content_type {
            // certificate
            let recovered_cert = get_cert(&auth_safe.content, password).unwrap();
            assert_eq!(recovered_cert.cert.der, cert);
            assert_eq!(&recovered_cert.cert.local_key_id, cert_id);
        } else if ID_DATA == auth_safe.content_type {
            // key
            let recovered_key = get_key(&auth_safe.content, password).unwrap();
            assert_eq!(*recovered_key.0, key);
            assert_eq!(&recovered_key.1.local_key_id, key_id);
        }
    }

    let contents = parse_pkcs12(der_p12, password).unwrap();
    assert_eq!(contents.certificate.der, cert);
    assert_eq!(*contents.key_der, key);
    if key_id.is_some() {
        assert_eq!(&contents.key_id, key_id);
    } else {
        assert_eq!(&contents.key_id, cert_id);
    }

    assert!(parse_pkcs12(der_p12, &format!("{password}X")).is_err());
}
#[cfg(test)]
fn check_algs(
    mac: &MacAlgorithm,
    enc: &EncryptionAlgorithm,
    kdf: &Pbkdf2Prf,
    der_p12: &[u8],
    p12_iterations: u32,
    mac_iterations: u32,
) {
    let pfx = Pfx::from_der(der_p12).unwrap();
    let auth_safes = get_auth_safes(&pfx.auth_safe.content).unwrap();

    for auth_safe in auth_safes {
        if ID_ENCRYPTED_DATA == auth_safe.content_type {
            // certificate
            let enc_data = EncryptedData::from_der(&auth_safe.content.to_der().unwrap()).unwrap();
            assert_eq!(PBES2_OID, enc_data.enc_content_info.content_enc_alg.oid);

            let enc_params = enc_data
                .enc_content_info
                .content_enc_alg
                .parameters
                .as_ref()
                .unwrap()
                .to_der()
                .unwrap();
            let params = pbes2::Parameters::from_der(&enc_params).unwrap();
            assert_eq!(PBKDF2_OID, params.kdf.oid());
            assert_eq!(kdf.oid(), params.kdf.pbkdf2().unwrap().prf.oid());
            assert_eq!(enc.oid(), params.encryption.oid());
            assert_eq!(p12_iterations, params.kdf.pbkdf2().unwrap().iteration_count);
        } else if ID_DATA == auth_safe.content_type {
            // key
            let safe_bags = get_safe_bags(&auth_safe.content).unwrap();
            for safe_bag in safe_bags {
                match safe_bag.bag_id {
                    PKCS_12_PKCS8_KEY_BAG_OID => {
                        let cs: ContextSpecific<EncryptedPrivateKeyInfo<OctetString>> =
                            ContextSpecific::from_der(&safe_bag.bag_value).unwrap();
                        assert_eq!(PBES2_OID, cs.value.encryption_algorithm.oid());
                        assert_eq!(
                            p12_iterations,
                            cs.value
                                .encryption_algorithm
                                .pbes2()
                                .unwrap()
                                .kdf
                                .pbkdf2()
                                .unwrap()
                                .iteration_count
                        );

                        assert_eq!(
                            kdf.oid(),
                            cs.value
                                .encryption_algorithm
                                .pbes2()
                                .unwrap()
                                .kdf
                                .pbkdf2()
                                .unwrap()
                                .prf
                                .oid()
                        );
                        assert_eq!(
                            enc.oid(),
                            cs.value
                                .encryption_algorithm
                                .pbes2()
                                .unwrap()
                                .encryption
                                .oid()
                        );
                    }
                    _ => {
                        panic!("Unexpected bag type");
                    }
                }
            }
        } else {
            panic!("Unexpected bag type");
        }
    }

    match pfx.mac_data {
        Some(mac_data) => {
            assert_eq!(mac_iterations as i32, mac_data.iterations);
            assert_eq!(mac.oid(), mac_data.mac.algorithm.oid);
        }
        None => {
            panic!("Missing MAC");
        }
    }
}

#[cfg(test)]
fn check_with_openssl(password: &str, der_p12: &[u8], key: &[u8], cert: &[u8]) {
    use openssl::pkcs12::Pkcs12;
    openssl::init();
    let pkcs12 = Pkcs12::from_der(der_p12).unwrap();
    let p12 = pkcs12.as_ref().parse2(password).unwrap();
    let ossl_cert = p12.cert.unwrap();
    let recovered_cert = ossl_cert.to_der().unwrap();
    let ossl_pkey = p12.pkey.unwrap();
    let recovered_key = ossl_pkey.private_key_to_pkcs8().unwrap();
    assert_eq!(recovered_cert, cert);
    assert_eq!(recovered_key, key);
}

#[allow(clippy::unwrap_used)]
#[test]
fn p12_simple() {
    let key = include_bytes!("examples/key.der");
    let cert_bytes = include_bytes!("examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();

    // read this from SubjectAltName
    let key_id = hex_literal::hex!("EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15 D0 7B 00 6D");

    let mut cert_attrs = SetOfVec::new();
    add_key_id_attr(&mut cert_attrs, &key_id).unwrap();

    let mut key_attrs = SetOfVec::new();
    add_key_id_attr(&mut key_attrs, &key_id).unwrap();
    let der_pfx = Pkcs12Builder::new()
        .iterations(Some(2048))
        .unwrap()
        .key_attributes(Some(key_attrs.clone()))
        .cert_attributes(Some(cert_attrs.clone()))
        .build_with_rng(&cert.clone(), key, "password", &mut rand::rng())
        .unwrap();
    let contents = parse_pkcs12(&der_pfx, "password").unwrap();
    assert_eq!(*contents.key_der, key);
    assert_eq!(contents.certificate.der, cert_bytes);
    assert_eq!(contents.key_id, Some(key_id.to_vec()));
}

#[test]
fn p12_builder_combinations() {
    let mac_algs = [
        MacAlgorithm::HmacSha256,
        MacAlgorithm::HmacSha384,
        MacAlgorithm::HmacSha512,
    ];
    let enc_algs = [
        EncryptionAlgorithm::Aes128Cbc,
        EncryptionAlgorithm::Aes192Cbc,
        EncryptionAlgorithm::Aes256Cbc,
    ];
    let kdf_algs = [
        Pbkdf2Prf::HmacWithSha256,
        Pbkdf2Prf::HmacWithSha384,
        Pbkdf2Prf::HmacWithSha512,
    ];

    let key_id = hex_literal::hex!("EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15 D0 7B 00 6D");

    let mut cert_attrs = SetOfVec::new();
    add_key_id_attr(&mut cert_attrs, &key_id).unwrap();

    let mut key_attrs = SetOfVec::new();
    add_key_id_attr(&mut key_attrs, &key_id).unwrap();

    let key = include_bytes!("examples/key.der");
    let cert_bytes = include_bytes!("examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();
    let password = "password";
    let rng = &mut rand::rng();

    // Spin over various combinations of algorithms...
    for mac in &mac_algs {
        for enc in &enc_algs {
            for kdf in &kdf_algs {
                let mut salt = vec![0_u8; 16];
                rng.fill_bytes(salt.as_mut_slice());

                let mut md = MacDataBuilder::new_with_salt(mac.clone(), salt);
                md.iterations(Some(2048)).unwrap();
                let der_pfx = Pkcs12Builder::new()
                    .iterations(Some(2048))
                    .unwrap()
                    .cert_enc_algorithm(Some(enc.clone()))
                    .key_enc_algorithm(Some(enc.clone()))
                    .cert_kdf_algorithm(Some(*kdf))
                    .key_kdf_algorithm(Some(*kdf))
                    .mac_data_builder(Some(md))
                    .key_attributes(Some(key_attrs.clone()))
                    .cert_attributes(Some(cert_attrs.clone()))
                    .build_with_rng(&cert.clone(), key, password, &mut rand::rng())
                    .unwrap();
                println!("{mac:?}-{enc:?}-{kdf:?}: {}", buffer_to_hex(&der_pfx));

                // Parse with pkcs12 crate and make sure algorithms match expectations
                check_algs(mac, enc, kdf, &der_pfx, 2048, 2048);

                // Make sure openssl can parse the results
                check_with_openssl(password, &der_pfx, key, cert_bytes);

                check_key_and_cert(
                    &der_pfx,
                    password,
                    key,
                    cert_bytes,
                    &Some(key_id.to_vec()),
                    &Some(key_id.to_vec()),
                );
            }
        }
    }
}

#[cfg(test)]
pub fn buffer_to_hex(buffer: &[u8]) -> String {
    std::str::from_utf8(&subtle_encoding::hex::encode_upper(buffer))
        .unwrap_or_default()
        .to_string()
}

#[test]
fn p12_builder_with_defaults_test() {
    let mut p12_builder = Pkcs12Builder::new();
    // This test intentionally uses defaults (600k iterations) to verify default behavior.
    let key_id = hex_literal::hex!("EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15 D0 7B 00 6D");

    let mut cert_attrs = SetOfVec::new();
    add_key_id_attr(&mut cert_attrs, &key_id).unwrap();

    let mut key_attrs = SetOfVec::new();
    add_key_id_attr(&mut key_attrs, &key_id).unwrap();

    let key = include_bytes!("examples/key.der");
    let cert_bytes = include_bytes!("examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();

    p12_builder.key_attributes(Some(key_attrs));
    p12_builder.cert_attributes(Some(cert_attrs));

    let der_pfx = p12_builder
        .build_with_rng(&cert, key, "", &mut rand::rng())
        .unwrap();
    check_key_and_cert(
        &der_pfx,
        "",
        key,
        cert_bytes,
        &Some(key_id.to_vec()),
        &Some(key_id.to_vec()),
    );
    check_algs(
        &MacAlgorithm::HmacSha256,
        &EncryptionAlgorithm::Aes256Cbc,
        &Pbkdf2Prf::HmacWithSha256,
        &der_pfx,
        600000,
        600000,
    );
}

#[test]
fn p12_builder_test() {
    use hex_literal::hex;

    let mut p12_builder = Pkcs12Builder::new();
    let key_id = hex!("EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15 D0 7B 00 6D");

    // Cert bag
    let mut cert_attrs = SetOfVec::new();
    add_key_id_attr(&mut cert_attrs, &key_id).unwrap();
    p12_builder.cert_attributes(Some(cert_attrs));

    let cert_kdf_params = Pbkdf2Params {
        salt: Salt::new(hex!("9A A2 77 B5 F0 51 B4 50")).unwrap(),
        iteration_count: 2048,
        key_length: None,
        prf: Pbkdf2Prf::HmacWithSha256,
    };
    let enc_cert_kdf_params = cert_kdf_params.to_der().unwrap();
    let enc_cert_kdf_params_ref = AnyRef::try_from(enc_cert_kdf_params.as_slice()).unwrap();
    let cert_kdf_alg = AlgorithmIdentifierOwned {
        oid: PBKDF2_OID,
        parameters: Some(Any::from(enc_cert_kdf_params_ref)),
    };
    p12_builder.cert_kdf_algorithm_identifier(Some(cert_kdf_alg));

    let cert_iv = OctetString::new(hex!("2E 23 6C 8C 7A 44 0C 3E 0F 4E 0D 32 C9 90 E9 97"))
        .unwrap()
        .to_der()
        .unwrap();
    let cert_iv_ref = AnyRef::try_from(cert_iv.as_slice()).unwrap();
    p12_builder.cert_enc_algorithm_identifier(Some(AlgorithmIdentifier {
        oid: AES_256_CBC_OID,
        parameters: Some(Any::from(cert_iv_ref)),
    }));

    // Key bag
    let mut key_attrs = SetOfVec::new();
    add_key_id_attr(&mut key_attrs, &key_id).unwrap();
    p12_builder.key_attributes(Some(key_attrs));

    let key_kdf_params = Pbkdf2Params {
        salt: Salt::new(hex!("10 AF 41 1E 77 84 BA CD")).unwrap(),
        iteration_count: 2048,
        key_length: None,
        prf: Pbkdf2Prf::HmacWithSha256,
    };
    let enc_key_kdf_params = key_kdf_params.to_der().unwrap();
    let enc_key_kdf_params_ref = AnyRef::try_from(enc_key_kdf_params.as_slice()).unwrap();
    let key_kdf_alg = AlgorithmIdentifierOwned {
        oid: PBKDF2_OID,
        parameters: Some(Any::from(enc_key_kdf_params_ref)),
    };
    p12_builder.key_kdf_algorithm_identifier(Some(key_kdf_alg));

    let key_iv = OctetString::new(hex!("46 21 13 61 4C 99 4D 1F DA 70 B4 71 16 5A AE 4A"))
        .unwrap()
        .to_der()
        .unwrap();
    let key_iv_ref = AnyRef::try_from(key_iv.as_slice()).unwrap();
    p12_builder.key_enc_algorithm_identifier(Some(AlgorithmIdentifier {
        oid: AES_256_CBC_OID,
        parameters: Some(Any::from(key_iv_ref)),
    }));

    // Mac
    let mut md_builder = MacDataBuilder::new(MacAlgorithm::HmacSha256);
    md_builder.iterations(Some(2048)).unwrap();
    md_builder.salt(Some(hex!("FF 08 ED 21 81 C8 A8 E3").to_vec()));
    p12_builder.mac_data_builder(Some(md_builder));

    let orig_p12 = include_bytes!("examples/example.pfx");
    let key = include_bytes!("examples/key.der");
    let cert_bytes = include_bytes!("examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();

    let der_pfx = p12_builder.build(&cert, key, "").unwrap();
    assert_eq!(der_pfx, orig_p12);

    let contents = parse_pkcs12(&der_pfx, "").unwrap();
    assert_eq!(contents.certificate.der, cert_bytes);
    assert_eq!(*contents.key_der, key);
    assert_eq!(contents.key_id, Some(key_id.to_vec()));
}

#[test]
fn invalid_iterations() {
    let mut p12_builder = Pkcs12Builder::new();
    let oversized: u32 = i32::MAX as u32 + 1;
    assert!(p12_builder.iterations(Some(oversized)).is_err());

    let mut mac_builder = MacDataBuilder::new(MacAlgorithm::HmacSha256);
    assert!(mac_builder.iterations(Some(oversized)).is_err());
}

#[test]
fn no_mac_data_and_no_key_identifier() {
    let mut p12_builder = Pkcs12Builder::new();
    p12_builder.omit_mac();
    let key = include_bytes!("examples/key.der");
    let cert_bytes = include_bytes!("examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();

    let der_pfx = p12_builder
        .build_with_rng(&cert, key, "", &mut rand::rng())
        .unwrap();
    check_key_and_cert(&der_pfx, "", key, cert_bytes, &None, &None);
    let pfx = Pfx::from_der(&der_pfx).unwrap();
    assert!(pfx.mac_data.is_none());
}

#[test]
fn p12_builder_iterations_test() {
    let mut p12_builder = Pkcs12Builder::new();
    let key_id = hex_literal::hex!("EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15 D0 7B 00 6D");

    let mut cert_attrs = SetOfVec::new();
    add_key_id_attr(&mut cert_attrs, &key_id).unwrap();

    let mut key_attrs = SetOfVec::new();
    add_key_id_attr(&mut key_attrs, &key_id).unwrap();

    let key = include_bytes!("examples/key.der");
    let cert_bytes = include_bytes!("examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();

    p12_builder.key_attributes(Some(key_attrs));
    p12_builder.cert_attributes(Some(cert_attrs));
    p12_builder.iterations(Some(2048)).unwrap();

    let der_pfx = p12_builder
        .build_with_rng(&cert, key, "", &mut rand::rng())
        .unwrap();
    check_key_and_cert(
        &der_pfx,
        "",
        key,
        cert_bytes,
        &Some(key_id.to_vec()),
        &Some(key_id.to_vec()),
    );
    check_algs(
        &MacAlgorithm::HmacSha256,
        &EncryptionAlgorithm::Aes256Cbc,
        &Pbkdf2Prf::HmacWithSha256,
        &der_pfx,
        2048,
        2048,
    );
}

#[test]
fn different_iterations_test() {
    let mut p12_builder = Pkcs12Builder::new();
    let key_id = hex_literal::hex!("EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15 D0 7B 00 6D");

    let mut cert_attrs = SetOfVec::new();
    add_key_id_attr(&mut cert_attrs, &key_id).unwrap();

    let mut key_attrs = SetOfVec::new();
    add_key_id_attr(&mut key_attrs, &key_id).unwrap();

    let key = include_bytes!("examples/key.der");
    let cert_bytes = include_bytes!("examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();

    p12_builder.key_attributes(Some(key_attrs));
    p12_builder.cert_attributes(Some(cert_attrs));
    p12_builder.iterations(Some(2048)).unwrap();

    let rng = &mut rand::rng();
    let mut salt = vec![0_u8; 16];
    rng.fill_bytes(salt.as_mut_slice());

    let mut md = MacDataBuilder::new_with_salt(MacAlgorithm::HmacSha256, salt);
    md.iterations(Some(2049)).unwrap();
    p12_builder.mac_data_builder(Some(md));

    let der_pfx = p12_builder
        .build_with_rng(&cert, key, "", &mut rand::rng())
        .unwrap();
    check_key_and_cert(
        &der_pfx,
        "",
        key,
        cert_bytes,
        &Some(key_id.to_vec()),
        &Some(key_id.to_vec()),
    );
    check_algs(
        &MacAlgorithm::HmacSha256,
        &EncryptionAlgorithm::Aes256Cbc,
        &Pbkdf2Prf::HmacWithSha256,
        &der_pfx,
        2048,
        2049,
    );
}

#[test]
fn different_key_and_cert_ids_test() {
    let mut p12_builder = Pkcs12Builder::new();
    let cert_id = hex_literal::hex!("EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15 D0 7B 00 6D");
    let key_id = hex_literal::hex!("AA BB CC DD 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF");

    let mut cert_attrs = SetOfVec::new();
    add_key_id_attr(&mut cert_attrs, &cert_id).unwrap();

    let mut key_attrs = SetOfVec::new();
    add_key_id_attr(&mut key_attrs, &key_id).unwrap();

    let key = include_bytes!("examples/key.der");
    let cert_bytes = include_bytes!("examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();

    p12_builder.key_attributes(Some(key_attrs));
    p12_builder.cert_attributes(Some(cert_attrs));
    p12_builder.iterations(Some(2048)).unwrap();

    let der_pfx = p12_builder
        .build_with_rng(&cert, key, "", &mut rand::rng())
        .unwrap();
    check_key_and_cert(
        &der_pfx,
        "",
        key,
        cert_bytes,
        &Some(cert_id.to_vec()),
        &Some(key_id.to_vec()),
    );
    check_algs(
        &MacAlgorithm::HmacSha256,
        &EncryptionAlgorithm::Aes256Cbc,
        &Pbkdf2Prf::HmacWithSha256,
        &der_pfx,
        2048,
        2048,
    );
}

#[test]
fn cert_id_only_test() {
    let mut p12_builder = Pkcs12Builder::new();
    let cert_id = hex_literal::hex!("EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15 D0 7B 00 6D");

    let mut cert_attrs = SetOfVec::new();
    add_key_id_attr(&mut cert_attrs, &cert_id).unwrap();

    let key = include_bytes!("examples/key.der");
    let cert_bytes = include_bytes!("examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();

    p12_builder.cert_attributes(Some(cert_attrs));
    p12_builder.iterations(Some(2048)).unwrap();

    let rng = &mut rand::rng();
    let mut salt = vec![0_u8; 16];
    rng.fill_bytes(salt.as_mut_slice());

    let der_pfx = p12_builder
        .build_with_rng(&cert, key, "", &mut rand::rng())
        .unwrap();
    check_key_and_cert(
        &der_pfx,
        "",
        key,
        cert_bytes,
        &Some(cert_id.to_vec()),
        &None,
    );
    check_algs(
        &MacAlgorithm::HmacSha256,
        &EncryptionAlgorithm::Aes256Cbc,
        &Pbkdf2Prf::HmacWithSha256,
        &der_pfx,
        2048,
        2048,
    );
}

/// Verify that parsing a P12 with legacy PBE encryption produces a clear error
/// when the `legacy` feature is not enabled. Tests the `get_cert` path directly
/// to bypass the MAC check (the test P12 uses SHA-1 MAC which is also gated).
#[cfg(not(feature = "legacy"))]
#[test]
fn legacy_pbe_cert_rejected_without_feature() {
    // Build a valid PBES2 P12, then replace the cert EncryptedData's algorithm OID
    // with a legacy PBE OID to simulate a legacy-encrypted cert bag.
    let mut p12_builder = Pkcs12Builder::new();
    p12_builder.omit_mac(); // skip MAC so we can tamper freely
    p12_builder.iterations(Some(2048)).unwrap();

    let key = include_bytes!("examples/key.der");
    let cert_bytes = include_bytes!("examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();

    let der_pfx = p12_builder
        .build_with_rng(&cert, key, "test", &mut rand::rng())
        .unwrap();

    let pfx = Pfx::from_der(&der_pfx).unwrap();
    let auth_safes = get_auth_safes(&pfx.auth_safe.content).unwrap();
    for auth_safe in &auth_safes {
        if ID_ENCRYPTED_DATA == auth_safe.content_type {
            let enc_data = EncryptedData::from_der(&auth_safe.content.to_der().unwrap()).unwrap();

            // Replace the PBES2 OID with pbeWithSHAAnd3-KeyTripleDES-CBC
            let legacy_oid = const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.1.3");
            let tampered_enc_data = EncryptedData {
                version: enc_data.version,
                enc_content_info: cms::enveloped_data::EncryptedContentInfo {
                    content_type: enc_data.enc_content_info.content_type,
                    content_enc_alg: AlgorithmIdentifier {
                        oid: legacy_oid,
                        parameters: enc_data.enc_content_info.content_enc_alg.parameters,
                    },
                    encrypted_content: enc_data.enc_content_info.encrypted_content,
                },
                unprotected_attrs: None,
            };
            let der_tampered = tampered_enc_data.to_der().unwrap();
            let any_tampered = Any::from_der(&der_tampered).unwrap();

            let err = match get_cert(&any_tampered, "test") {
                Err(e) => e,
                Ok(_) => panic!("Expected error for legacy PBE cert without feature"),
            };
            let msg = format!("{err}");
            assert!(
                msg.contains("legacy") && msg.contains("feature"),
                "Expected error mentioning legacy feature, got: {msg}"
            );
            return;
        }
    }
    panic!("Did not find ID_ENCRYPTED_DATA in auth_safes");
}

/// Verify that parsing a P12 with legacy PBE key encryption produces a clear error
/// when the `legacy` feature is not enabled. Tests the `get_key` path directly.
#[cfg(not(feature = "legacy"))]
#[test]
fn legacy_pbe_key_rejected_without_feature() {
    use pkcs12::builder::asn1_utils::get_key;

    // Build a valid PBES2 P12, extract the key auth_safe content, then tamper the
    // key encryption OID to a legacy PBE OID.
    let mut p12_builder = Pkcs12Builder::new();
    p12_builder.omit_mac();
    p12_builder.iterations(Some(2048)).unwrap();

    let key = include_bytes!("examples/key.der");
    let cert_bytes = include_bytes!("examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();

    let der_pfx = p12_builder
        .build_with_rng(&cert, key, "test", &mut rand::rng())
        .unwrap();

    let pfx = Pfx::from_der(&der_pfx).unwrap();
    let auth_safes = get_auth_safes(&pfx.auth_safe.content).unwrap();
    for auth_safe in &auth_safes {
        if ID_DATA == auth_safe.content_type {
            let safe_bags = get_safe_bags(&auth_safe.content).unwrap();
            for safe_bag in safe_bags {
                if safe_bag.bag_id == PKCS_12_PKCS8_KEY_BAG_OID {
                    // Parse the encrypted key and replace the algorithm OID
                    let cs: ContextSpecific<pkcs12::pbe_params::EncryptedPrivateKeyInfo> =
                        ContextSpecific::from_der(&safe_bag.bag_value).unwrap();
                    let legacy_oid =
                        const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.1.3");
                    let tampered_epki = pkcs12::pbe_params::EncryptedPrivateKeyInfo {
                        encryption_algorithm: AlgorithmIdentifierOwned {
                            oid: legacy_oid,
                            parameters: cs.value.encryption_algorithm.parameters,
                        },
                        encrypted_data: cs.value.encrypted_data,
                    };
                    // Re-encode as a SafeBag
                    let tampered_bag_value = tampered_epki.to_der().unwrap();
                    let tampered_safe_bag = pkcs12::safe_bag::SafeBag {
                        bag_id: PKCS_12_PKCS8_KEY_BAG_OID,
                        bag_value: tampered_bag_value,
                        bag_attributes: safe_bag.bag_attributes,
                    };
                    let tampered_bags = vec![tampered_safe_bag];
                    let tampered_bags_der = tampered_bags.to_der().unwrap();
                    let tampered_os = OctetString::new(tampered_bags_der)
                        .unwrap()
                        .to_der()
                        .unwrap();
                    let tampered_any = Any::from_der(&tampered_os).unwrap();

                    let err = match get_key(&tampered_any, "test") {
                        Err(e) => e,
                        Ok(_) => panic!("Expected error for legacy PBE key without feature"),
                    };
                    let msg = format!("{err}");
                    assert!(
                        msg.contains("legacy") && msg.contains("feature"),
                        "Expected error mentioning legacy feature, got: {msg}"
                    );
                    return;
                }
            }
        }
    }
    panic!("Did not find key SafeBag in auth_safes");
}

/// Verify that a P12 with an excessively high MAC iteration count is rejected during parsing.
#[test]
fn excessive_mac_iterations_rejected() {
    let mut p12_builder = Pkcs12Builder::new();
    p12_builder.iterations(Some(2048)).unwrap();

    let key = include_bytes!("examples/key.der");
    let cert_bytes = include_bytes!("examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();

    let der_pfx = p12_builder
        .build_with_rng(&cert, key, "test", &mut rand::rng())
        .unwrap();

    // Parse the valid P12 and re-encode with an excessive MAC iteration count.
    let mut pfx = Pfx::from_der(&der_pfx).unwrap();
    let mac_data = pfx.mac_data.as_mut().unwrap();
    mac_data.iterations = 100_000_001;
    let tampered = pfx.to_der().unwrap();

    let err = match parse_pkcs12(&tampered, "test") {
        Err(e) => e,
        Ok(_) => panic!("Expected error for excessive iterations"),
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("iterations"),
        "Expected error about iterations limit, got: {msg}"
    );
}

/// Helper to build a PKCS #12 with Oracle TrustedKeyUsage attributes on both key and cert bags.
#[allow(clippy::unwrap_used)]
fn build_p12_with_oracle_tku() -> Vec<u8> {
    use const_oid::ObjectIdentifier;
    use const_oid::db::rfc5280::ANY_EXTENDED_KEY_USAGE;
    use x509_cert::attr::Attribute;

    let key = include_bytes!("examples/key.der");
    let cert_bytes = include_bytes!("examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();

    let key_id = hex_literal::hex!("EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15 D0 7B 00 6D");

    // Oracle TrustedKeyUsage attribute: OID value = anyExtendedKeyUsage
    let oracle_trusted_key_usage = ObjectIdentifier::new_unwrap("2.16.840.1.113894.746875.1.1");
    let eku_bytes = ANY_EXTENDED_KEY_USAGE.to_der().unwrap();
    let eku_ref = AnyRef::try_from(eku_bytes.as_slice()).unwrap();
    let mut tku_values = SetOfVec::new();
    tku_values.insert(Any::from(eku_ref)).unwrap();
    let tku_attr = Attribute {
        oid: oracle_trusted_key_usage,
        values: tku_values,
    };

    // Key bag: localKeyID + friendlyName + TrustedKeyUsage
    let mut key_attrs = SetOfVec::new();
    add_key_id_attr(&mut key_attrs, &key_id).unwrap();
    add_friendly_name_attr(&mut key_attrs, "my-key").unwrap();
    key_attrs.insert(tku_attr.clone()).unwrap();

    // Cert bag: localKeyID + friendlyName + TrustedKeyUsage
    let mut cert_attrs = SetOfVec::new();
    add_key_id_attr(&mut cert_attrs, &key_id).unwrap();
    add_friendly_name_attr(&mut cert_attrs, "my-cert").unwrap();
    cert_attrs.insert(tku_attr.clone()).unwrap();

    Pkcs12Builder::new()
        .iterations(Some(2048))
        .unwrap()
        .key_attributes(Some(key_attrs))
        .cert_attributes(Some(cert_attrs))
        .build_with_rng(&cert, key, "password", &mut rand::rng())
        .unwrap()
}

/// Build a PKCS #12 with an ORACLE_TrustedKeyUsage attribute on both the key and cert bags,
/// alongside the well-known localKeyID and friendlyName, and verify they all round-trip.
#[allow(clippy::unwrap_used)]
#[test]
fn other_attributes_roundtrip() {
    use const_oid::ObjectIdentifier;

    let key = include_bytes!("examples/key.der");
    let cert_bytes = include_bytes!("examples/cert.der");
    let key_id = hex_literal::hex!("EF 09 61 31 5F 51 9D 61 F2 69 7D 9E 75 E5 52 15 D0 7B 00 6D");
    let oracle_trusted_key_usage = ObjectIdentifier::new_unwrap("2.16.840.1.113894.746875.1.1");

    let der_pfx = build_p12_with_oracle_tku();

    let contents = parse_pkcs12(&der_pfx, "password").unwrap();

    // Key bag attributes
    assert_eq!(*contents.key_der, key);
    assert_eq!(contents.key_id, Some(key_id.to_vec()));
    assert_eq!(contents.friendly_name.as_deref(), Some("my-key"));
    let key_other = contents
        .other_key_attributes
        .expect("expected other key attributes");
    assert_eq!(key_other.len(), 1);
    assert_eq!(key_other[0].oid, oracle_trusted_key_usage);

    // Cert bag attributes
    assert_eq!(contents.certificate.der, cert_bytes);
    assert_eq!(contents.certificate.local_key_id, Some(key_id.to_vec()));
    assert_eq!(
        contents.certificate.friendly_name.as_deref(),
        Some("my-cert")
    );
    let cert_other = contents
        .certificate
        .other_attributes
        .expect("expected other cert attributes");
    assert_eq!(cert_other.len(), 1);
    assert_eq!(cert_other[0].oid, oracle_trusted_key_usage);
}
