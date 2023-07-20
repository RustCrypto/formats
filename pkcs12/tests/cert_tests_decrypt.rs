#[cfg(feature = "decrypt")]
use der::Encode;

#[cfg(feature = "decrypt")]
use pkcs12::decrypt::decrypt_pfx;

#[cfg(all(feature = "decrypt", feature = "insecure", feature = "kdf"))]
use const_oid::ObjectIdentifier;

#[cfg(all(feature = "decrypt", not(feature = "insecure")))]
use pkcs12::decrypt::Error;

#[cfg(all(feature = "decrypt", not(feature = "insecure")))]
use pkcs12::PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC;

#[cfg(all(feature = "decrypt", feature = "insecure"))]
use pkcs12::decrypt::Error;

#[cfg(all(feature = "decrypt", feature = "insecure"))]
use pkcs12::PKCS_12_PBEWITH_SHAAND40_BIT_RC2_CBC;

#[cfg(feature = "decrypt")]
#[test]
fn decode_sample_pfx_with_decrypt() {
    let bytes = include_bytes!("examples/example.pfx");
    let (key, cert) = decrypt_pfx(bytes, "".as_bytes()).unwrap();
    let enc_key = key.unwrap().to_der().unwrap();
    assert_eq!(include_bytes!("examples/key.der"), enc_key.as_slice());
    let enc_cert = cert.get(0).expect("Missing certificate").to_der().unwrap();
    assert_eq!(include_bytes!("examples/cert.der"), enc_cert.as_slice());
}

#[cfg(feature = "decrypt")]
#[test]
fn decode_sample_pfx2_with_decrypt() {
    let bytes = include_bytes!("examples/example2.pfx");
    let (key, cert) = decrypt_pfx(bytes, "1234".as_bytes()).unwrap();
    let enc_key = key.unwrap().to_der().unwrap();
    assert_eq!(include_bytes!("examples/key.der"), enc_key.as_slice());
    let enc_cert = cert.get(0).expect("Missing certificate").to_der().unwrap();
    assert_eq!(include_bytes!("examples/cert.der"), enc_cert.as_slice());
}

#[cfg(feature = "decrypt")]
#[test]
fn decode_sample_pfx3_with_decrypt() {
    // openssl pkcs12 -export -out example3.pfx -inkey key.pem -in cert.pem -passout pass:1234 -certpbe NONE -keypbe aes-128-cbc
    let bytes = include_bytes!("examples/example3.pfx");
    let (key, cert) = decrypt_pfx(bytes, "1234".as_bytes()).unwrap();
    let enc_key = key.unwrap().to_der().unwrap();
    assert_eq!(include_bytes!("examples/key.der"), enc_key.as_slice());
    let enc_cert = cert.get(0).expect("Missing certificate").to_der().unwrap();
    assert_eq!(include_bytes!("examples/cert.der"), enc_cert.as_slice());
}

#[cfg(all(feature = "insecure", feature = "decrypt"))]
#[test]
fn decode_sample_pfx4_with_decrypt() {
    // openssl pkcs12 -export -out example4.pfx -inkey key.pem -in cert.pem -passout pass:1234 -certpbe aes-192-cbc -keypbe aes-256-cbc
    let bytes = include_bytes!("examples/example4.pfx");
    let (key, cert) = decrypt_pfx(bytes, "1234".as_bytes()).unwrap();
    let enc_key = key.unwrap().to_der().unwrap();
    assert_eq!(include_bytes!("examples/key.der"), enc_key.as_slice());
    let enc_cert = cert.get(0).expect("Missing certificate").to_der().unwrap();
    assert_eq!(include_bytes!("examples/cert.der"), enc_cert.as_slice());
}

#[cfg(all(feature = "insecure", feature = "decrypt"))]
#[test]
fn decode_sample_pfx5_with_decrypt() {
    // openssl pkcs12 -export -out example5.pfx -inkey key.pem -in cert.pem -passout pass:1234 -certpbe aes-192-cbc -keypbe aes-256-cbc -nomac
    let bytes = include_bytes!("examples/example5.pfx");
    let (key, cert) = decrypt_pfx(bytes, "1234".as_bytes()).unwrap();
    let enc_key = key.unwrap().to_der().unwrap();
    assert_eq!(include_bytes!("examples/key.der"), enc_key.as_slice());
    let enc_cert = cert.get(0).expect("Missing certificate").to_der().unwrap();
    assert_eq!(include_bytes!("examples/cert.der"), enc_cert.as_slice());
}

#[cfg(feature = "decrypt")]
#[test]
fn decode_sample_pfx6_with_decrypt() {
    // openssl pkcs12 -export -out example6.pfx -inkey key.pem -in cert.pem -passout pass:1234 -iter 1
    let bytes = include_bytes!("examples/example6.pfx");
    let (key, cert) = decrypt_pfx(bytes, "1234".as_bytes()).unwrap();
    let enc_key = key.unwrap().to_der().unwrap();
    assert_eq!(include_bytes!("examples/key.der"), enc_key.as_slice());
    let enc_cert = cert.get(0).expect("Missing certificate").to_der().unwrap();
    assert_eq!(include_bytes!("examples/cert.der"), enc_cert.as_slice());
}

#[cfg(feature = "decrypt")]
#[test]
fn decode_sample_pfx7_with_decrypt() {
    // openssl pkcs12 -export -out example6.pfx -inkey key.pem -in cert.pem -passout pass:1234 -iter 1
    let bytes = include_bytes!("examples/example7.pfx");
    let (key, cert) = decrypt_pfx(bytes, "1234".as_bytes()).unwrap();
    let enc_key = key.unwrap().to_der().unwrap();
    assert_eq!(
        include_bytes!("examples/ValidCertificatePathTest1EE.key"),
        enc_key.as_slice()
    );
    let enc_cert = cert.get(0).expect("Missing certificate").to_der().unwrap();
    assert_eq!(
        include_bytes!("examples/ValidCertificatePathTest1EE.crt"),
        enc_cert.as_slice()
    );
    let enc_ca_cert = cert.get(1).expect("Missing certificate").to_der().unwrap();
    assert_eq!(
        include_bytes!("examples/GoodCACert.der"),
        enc_ca_cert.as_slice()
    );
}

#[cfg(all(feature = "decrypt", feature = "kdf", feature = "insecure"))]
#[test]
fn decode_sample_pfx8_with_decrypt() {
    // openssl pkcs12 -export -out example8.pfx -inkey key.pem -in cert.pem -passout pass:1234 -macalg SHA384 -certpbe aes-192-cbc -keypbe aes-256-cbc
    let bytes = include_bytes!("examples/example8.pfx");
    let (key, cert) = decrypt_pfx(bytes, "1234".as_bytes()).unwrap();
    let enc_key = key.unwrap().to_der().unwrap();
    assert_eq!(include_bytes!("examples/key.der"), enc_key.as_slice());
    let enc_cert = cert.get(0).expect("Missing certificate").to_der().unwrap();
    assert_eq!(include_bytes!("examples/cert.der"), enc_cert.as_slice());
}

#[cfg(all(feature = "decrypt", feature = "kdf", feature = "insecure"))]
#[test]
fn decode_sample_pfx9_with_decrypt() {
    // openssl pkcs12 -export -out example9.pfx -inkey key.pem -in cert.pem -passout pass:1234 -macalg SHA512
    let bytes = include_bytes!("examples/example9.pfx");
    let (key, cert) = decrypt_pfx(bytes, "1234".as_bytes()).unwrap();
    let enc_key = key.unwrap().to_der().unwrap();
    assert_eq!(include_bytes!("examples/key.der"), enc_key.as_slice());
    let enc_cert = cert.get(0).expect("Missing certificate").to_der().unwrap();
    assert_eq!(include_bytes!("examples/cert.der"), enc_cert.as_slice());
}

#[cfg(all(feature = "decrypt", feature = "kdf", feature = "insecure"))]
#[test]
fn decode_sample_pfx10_with_decrypt() {
    // openssl pkcs12 -export -out example10.pfx -inkey key.pem -in cert.pem -passout pass:1234 -macalg SHA256 -certpbe aes-192-cbc -keypbe aes-256-cbc -iter 600000
    let bytes = include_bytes!("examples/example10.pfx");
    let (key, cert) = decrypt_pfx(bytes, "1234".as_bytes()).unwrap();
    let enc_key = key.unwrap().to_der().unwrap();
    assert_eq!(include_bytes!("examples/key.der"), enc_key.as_slice());
    let enc_cert = cert.get(0).expect("Missing certificate").to_der().unwrap();
    assert_eq!(include_bytes!("examples/cert.der"), enc_cert.as_slice());
}

#[cfg(all(feature = "decrypt", feature = "kdf", feature = "insecure"))]
#[test]
fn decode_sample_pfx11_with_decrypt() {
    // openssl pkcs12 -export -out example11.pfx -inkey key.pem -in cert.pem -passout pass:1234 -macalg BLAKE2b512 -certpbe aes-192-cbc -keypbe aes-256-cbc
    let bytes = include_bytes!("examples/example11.pfx");
    let r = decrypt_pfx(bytes, "1234".as_bytes());
    assert!(r.is_err());
    const BLAKE2B512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.1722.12.2.1.16");

    assert_eq!(r.err(), Some(Error::UnexpectedAlgorithm(BLAKE2B512)))
}

#[cfg(all(feature = "decrypt", feature = "kdf", feature = "insecure"))]
#[test]
fn decode_sample_pfx12_with_decrypt() {
    // openssl pkcs12 -export -out example12.pfx -inkey key.pem -in cert.pem -passout pass:1234 -macalg SHA256 -certpbe aes-192-cbc -keypbe aes-256-cbc -noiter
    let bytes = include_bytes!("examples/example12.pfx");
    let (key, cert) = decrypt_pfx(bytes, "1234".as_bytes()).unwrap();
    let enc_key = key.unwrap().to_der().unwrap();
    assert_eq!(include_bytes!("examples/key.der"), enc_key.as_slice());
    let enc_cert = cert.get(0).expect("Missing certificate").to_der().unwrap();
    assert_eq!(include_bytes!("examples/cert.der"), enc_cert.as_slice());
}

#[cfg(all(feature = "decrypt", feature = "kdf", feature = "insecure"))]
#[test]
fn decode_sample_pfx13_with_decrypt() {
    // openssl pkcs12 -export -out example13.pfx -inkey key.pem -in cert.pem -passout pass:1234 -macalg SHA256 -certpbe aes-192-cbc -keypbe aes-256-cbc -nomaciter
    let bytes = include_bytes!("examples/example13.pfx");
    let (key, cert) = decrypt_pfx(bytes, "1234".as_bytes()).unwrap();
    let enc_key = key.unwrap().to_der().unwrap();
    assert_eq!(include_bytes!("examples/key.der"), enc_key.as_slice());
    let enc_cert = cert.get(0).expect("Missing certificate").to_der().unwrap();
    assert_eq!(include_bytes!("examples/cert.der"), enc_cert.as_slice());
}

#[cfg(all(feature = "decrypt", feature = "kdf", feature = "insecure"))]
#[test]
fn decode_sample_pfx14_with_decrypt() {
    // openssl pkcs12 -export -out example14.pfx -inkey key.pem -in cert.pem -passout pass:1234 -certpbe aes-192-cbc -keypbe aes-256-cbc -descert
    let bytes = include_bytes!("examples/example14.pfx");
    let (key, cert) = decrypt_pfx(bytes, "1234".as_bytes()).unwrap();
    let enc_key = key.unwrap().to_der().unwrap();
    assert_eq!(include_bytes!("examples/key.der"), enc_key.as_slice());
    let enc_cert = cert.get(0).expect("Missing certificate").to_der().unwrap();
    assert_eq!(include_bytes!("examples/cert.der"), enc_cert.as_slice());
}

#[cfg(all(feature = "decrypt", feature = "kdf", feature = "insecure"))]
#[test]
fn decode_sample_pfx15_with_decrypt() {
    // openssl pkcs12 -export -out example15.pfx -inkey key.pem -in cert.pem -passout pass:1234 -certpbe aes-192-cbc -keypbe aes-256-cbc -nokeys
    let bytes = include_bytes!("examples/example15.pfx");
    let (key, cert) = decrypt_pfx(bytes, "1234".as_bytes()).unwrap();
    assert!(key.is_none());
    let enc_cert = cert.get(0).expect("Missing certificate").to_der().unwrap();
    assert_eq!(include_bytes!("examples/cert.der"), enc_cert.as_slice());
}

#[cfg(all(feature = "decrypt", feature = "kdf", feature = "insecure"))]
#[test]
fn decode_sample_pfx16_with_decrypt() {
    // openssl pkcs12 -export -out example15.pfx -inkey key.pem -in cert.pem -passout pass:1234 -certpbe aes-192-cbc -keypbe aes-256-cbc -nocerts
    let bytes = include_bytes!("examples/example16.pfx");
    let (key, cert) = decrypt_pfx(bytes, "1234".as_bytes()).unwrap();
    let enc_key = key.unwrap().to_der().unwrap();
    assert_eq!(include_bytes!("examples/key.der"), enc_key.as_slice());
    assert!(cert.is_empty());
}

#[cfg(all(feature = "decrypt", feature = "kdf"))]
#[test]
fn decode_sample_pfx17_with_decrypt() {
    // this was generated on linux (the rest were on macos). For this command on macos, getting the non-default Mac algorithm resulted in default (SHA1) in the KDF
    // openssl pkcs12 -export -out example17.pfx -inkey key.pem -in cert.pem -passout pass:1234 -certpbe aes-192-cbc -keypbe aes-256-cbc -macalg SHA256
    let bytes = include_bytes!("examples/example17.pfx");
    let (key, cert) = decrypt_pfx(bytes, "1234".as_bytes()).unwrap();
    let enc_key = key.unwrap().to_der().unwrap();
    assert_eq!(include_bytes!("examples/key.der"), enc_key.as_slice());
    let enc_cert = cert.get(0).expect("Missing certificate").to_der().unwrap();
    assert_eq!(include_bytes!("examples/cert.der"), enc_cert.as_slice());
}

#[cfg(all(feature = "decrypt", not(feature = "insecure")))]
#[test]
fn decode_sample_pkits_with_decrypt_fail() {
    let bytes = include_bytes!("examples/ValidCertificatePathTest1EE.p12");
    let r = decrypt_pfx(bytes, "password".as_bytes());
    assert!(r.is_err());
    assert_eq!(
        r.err(),
        Some(Error::UnexpectedAlgorithm(
            PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC
        ))
    )
}

#[cfg(all(feature = "insecure", feature = "decrypt", feature = "kdf"))]
#[test]
fn decode_sample_pkits_with_decrypt() {
    let bytes = include_bytes!("examples/ValidCertificatePathTest1EE.p12");
    let (key, cert) = decrypt_pfx(bytes, "password".as_bytes()).unwrap();
    let enc_key = key.unwrap().to_der().unwrap();
    assert_eq!(
        include_bytes!("examples/ValidCertificatePathTest1EE.key"),
        enc_key.as_slice()
    );
    let enc_cert = cert.get(0).expect("Missing certificate").to_der().unwrap();
    assert_eq!(
        include_bytes!("examples/ValidCertificatePathTest1EE.crt"),
        enc_cert.as_slice()
    );
}

#[cfg(all(feature = "insecure", feature = "decrypt", feature = "kdf"))]
#[test]
fn decode_sample_pkits_macos_with_decrypt() {
    let bytes = include_bytes!("examples/ValidCertificatePathTest1EE_macos.p12");
    let r = decrypt_pfx(bytes, "password".as_bytes());
    assert!(r.is_err());
    assert_eq!(
        r.err(),
        Some(Error::UnexpectedAlgorithm(
            PKCS_12_PBEWITH_SHAAND40_BIT_RC2_CBC
        ))
    )
}

#[cfg(all(feature = "insecure", feature = "decrypt", feature = "kdf"))]
#[test]
fn decode_sample_pkits_windows_tdes_with_decrypt() {
    let bytes = include_bytes!("examples/ValidCertificatePathTest1EE_windows_tdes.p12.pfx");
    let (_key, cert) = decrypt_pfx(bytes, "password".as_bytes()).unwrap();
    // key includes key usage values, hence no comparison here
    let enc_cert = cert.get(0).expect("Missing certificate").to_der().unwrap();
    assert_eq!(
        include_bytes!("examples/ValidCertificatePathTest1EE.crt"),
        enc_cert.as_slice()
    );
}

#[cfg(feature = "decrypt")]
#[test]
fn decode_sample_pkits_windows_aes_with_decrypt() {
    let bytes = include_bytes!("examples/ValidCertificatePathTest1EE_windows_aes.p12.pfx");
    let (_key, cert) = decrypt_pfx(bytes, "password".as_bytes()).unwrap();
    // key includes key usage values, hence no comparison here
    let enc_cert = cert.get(0).expect("Missing certificate").to_der().unwrap();
    assert_eq!(
        include_bytes!("examples/ValidCertificatePathTest1EE.crt"),
        enc_cert.as_slice()
    );
}

// PKCS #12 objects exported from Firefox are BER encoded (so not testing those here)
