use subtle_encoding::hex;

pub fn buffer_to_hex(buffer: &[u8]) -> String {
    let hex = hex::encode_upper(buffer);
    let r = std::str::from_utf8(hex.as_slice());
    if let Ok(s) = r {
        s.to_string()
    } else {
        "".to_string()
    }
}

#[cfg(all(feature = "builder", feature = "decrypt"))]
#[test]
fn build_no_pbe() {
    use der::{Decode, Encode};
    #[cfg(feature = "builder")]
    use pkcs12::builder::Pkcs12Builder;
    #[cfg(feature = "decrypt")]
    use pkcs12::decrypt::decrypt_pfx;
    use pkcs12::safe_bag::PrivateKeyInfo;
    use pkcs8::rand_core::OsRng;
    use x509_cert::Certificate;

    let key_bytes = include_bytes!("examples/ValidCertificatePathTest1EE.key");
    let priv_key_info = PrivateKeyInfo::from_der(key_bytes).unwrap();
    let cert_bytes = include_bytes!("examples/ValidCertificatePathTest1EE.crt");
    let cert = Certificate::from_der(cert_bytes).unwrap();
    let ca_cert_bytes = include_bytes!("examples/GoodCACert.der");
    let ca_cert = Certificate::from_der(ca_cert_bytes).unwrap();
    let mut builder = Pkcs12Builder::new(priv_key_info, cert, &mut OsRng).unwrap();
    builder.add_certificate(ca_cert).unwrap();
    builder.mac_alg(None).unwrap();
    let pfx = builder.build(None, &mut OsRng).unwrap();
    let der_pfx = pfx.to_der().unwrap();
    let (dkey, dcert) = decrypt_pfx(&der_pfx, "".as_bytes()).unwrap();
    let dkey_bytes = dkey.unwrap().to_der().unwrap();
    let dcert_bytes = dcert.get(0).unwrap().to_der().unwrap();
    assert_eq!(key_bytes, dkey_bytes.as_slice());
    assert_eq!(cert_bytes, dcert_bytes.as_slice());
}

#[cfg(all(feature = "builder", feature = "decrypt"))]
#[test]
fn build_key_pbe() {
    use der::{Decode, Encode};
    #[cfg(feature = "builder")]
    use pkcs12::builder::Pkcs12Builder;
    #[cfg(feature = "decrypt")]
    use pkcs12::decrypt::decrypt_pfx;
    use pkcs12::safe_bag::PrivateKeyInfo;
    use pkcs8::rand_core::OsRng;
    use x509_cert::Certificate;

    let key_bytes = include_bytes!("examples/ValidCertificatePathTest1EE.key");
    let priv_key_info = PrivateKeyInfo::from_der(key_bytes).unwrap();
    let cert_bytes = include_bytes!("examples/ValidCertificatePathTest1EE.crt");
    let cert = Certificate::from_der(cert_bytes).unwrap();
    let ca_cert_bytes = include_bytes!("examples/GoodCACert.der");
    let ca_cert = Certificate::from_der(ca_cert_bytes).unwrap();
    let mut builder = Pkcs12Builder::new(priv_key_info, cert, &mut OsRng).unwrap();
    builder.add_certificate(ca_cert).unwrap();
    builder.mac_alg(None).unwrap();
    let pfx = builder.build(Some(b"1234"), &mut OsRng).unwrap();
    let der_pfx = pfx.to_der().unwrap();
    println!("{}", buffer_to_hex(&der_pfx));
    let (dkey, dcert) = decrypt_pfx(&der_pfx, "1234".as_bytes()).unwrap();
    let dkey_bytes = dkey.unwrap().to_der().unwrap();
    let dcert_bytes = dcert.get(0).unwrap().to_der().unwrap();
    assert_eq!(key_bytes, dkey_bytes.as_slice());
    assert_eq!(cert_bytes, dcert_bytes.as_slice());
}

#[cfg(all(feature = "builder", feature = "decrypt"))]
#[test]
fn build_key_and_cert_pbe() {
    use der::{Decode, Encode};
    #[cfg(feature = "builder")]
    use pkcs12::builder::Pkcs12Builder;
    #[cfg(feature = "decrypt")]
    use pkcs12::decrypt::decrypt_pfx;
    use pkcs12::safe_bag::PrivateKeyInfo;
    use pkcs8::rand_core::OsRng;
    use x509_cert::Certificate;

    let key_bytes = include_bytes!("examples/ValidCertificatePathTest1EE.key");
    let priv_key_info = PrivateKeyInfo::from_der(key_bytes).unwrap();
    let cert_bytes = include_bytes!("examples/ValidCertificatePathTest1EE.crt");
    let cert = Certificate::from_der(cert_bytes).unwrap();
    let ca_cert_bytes = include_bytes!("examples/GoodCACert.der");
    let ca_cert = Certificate::from_der(ca_cert_bytes).unwrap();
    let mut builder = Pkcs12Builder::new(priv_key_info, cert, &mut OsRng).unwrap();
    builder.add_certificate(ca_cert).unwrap();
    let pfx = builder.build(Some(b"1234"), &mut OsRng).unwrap();
    let der_pfx = pfx.to_der().unwrap();
    println!("{}", buffer_to_hex(&der_pfx));
    let (dkey, dcert) = decrypt_pfx(&der_pfx, "1234".as_bytes()).unwrap();
    let dkey_bytes = dkey.unwrap().to_der().unwrap();
    let dcert_bytes = dcert.get(0).unwrap().to_der().unwrap();
    assert_eq!(key_bytes, dkey_bytes.as_slice());
    assert_eq!(cert_bytes, dcert_bytes.as_slice());
}