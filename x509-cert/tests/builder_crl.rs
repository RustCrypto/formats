#![cfg(all(feature = "builder", feature = "pem"))]

use std::{str::FromStr, time::Duration};

use der::{EncodePem, pem::LineEnding};
use p256::{NistP256, ecdsa::DerSignature, pkcs8::DecodePrivateKey};
use rand::rng;
use x509_cert::{
    SubjectPublicKeyInfo,
    builder::{Builder, CertificateBuilder, CrlBuilder, profile},
    crl::RevokedCert,
    ext::pkix::CrlNumber,
    name::Name,
    serial_number::SerialNumber,
    time::{Time, Validity},
};
use x509_cert_test_support::openssl;

const PKCS8_PUBLIC_KEY_DER: &[u8] = include_bytes!("examples/p256-pub.der");
const PKCS8_PRIVATE_KEY_DER: &[u8] = include_bytes!("examples/p256-priv.der");

fn ecdsa_signer() -> ecdsa::SigningKey<NistP256> {
    let secret_key = p256::SecretKey::from_pkcs8_der(PKCS8_PRIVATE_KEY_DER).unwrap();
    ecdsa::SigningKey::from(secret_key)
}

#[test]
fn crl_signer() {
    let mut rng = rng();
    let serial_number = SerialNumber::generate(&mut rng);
    let validity = Validity::from_now(Duration::new(5, 0)).unwrap();
    let subject =
        Name::from_str("CN=World domination corporation,O=World domination Inc,C=US").unwrap();
    let profile = profile::cabf::Root::new(false, subject).expect("create root profile");
    let pub_key = SubjectPublicKeyInfo::try_from(PKCS8_PUBLIC_KEY_DER).expect("get ecdsa pub key");

    let signer = ecdsa_signer();
    let builder = CertificateBuilder::new(profile, serial_number, validity, pub_key)
        .expect("Create certificate");

    let ca_certificate = builder.build::<_, DerSignature>(&signer).unwrap();

    let crl_number = CrlNumber::try_from(42u128).unwrap();

    let builder = CrlBuilder::new(&ca_certificate, crl_number)
        .unwrap()
        .with_certificates(
            vec![
                RevokedCert {
                    serial_number: SerialNumber::generate(&mut rng),
                    revocation_date: Time::now().unwrap(),
                    crl_entry_extensions: None,
                },
                RevokedCert {
                    serial_number: SerialNumber::generate(&mut rng),
                    revocation_date: Time::now().unwrap(),
                    crl_entry_extensions: None,
                },
            ]
            .into_iter(),
        );

    let crl = builder.build::<_, DerSignature>(&signer).unwrap();

    let pem = crl.to_pem(LineEnding::LF).expect("generate pem");
    println!("{}", openssl::check_crl(pem.as_bytes()));
}
