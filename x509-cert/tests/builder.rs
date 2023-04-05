#![cfg(all(feature = "builder", feature = "pem"))]

use der::{pem::LineEnding, Decode, Encode, EncodePem};
use p256::{pkcs8::DecodePrivateKey, NistP256};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use sha2::Sha256;
use spki::SubjectPublicKeyInfoOwned;
use std::{str::FromStr, time::Duration};
use x509_cert::{
    builder::{CertificateBuilder, Profile},
    certificate::Version,
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};
use x509_cert_test_support::{openssl, zlint};

const RSA_2048_DER_EXAMPLE: &[u8] = include_bytes!("examples/rsa2048-pub.der");

#[test]
fn root_ca_certificate() {
    let serial_number = SerialNumber::from(42u32);
    let validity = Validity::from_now(Duration::new(5, 0)).unwrap();
    let profile = Profile::Root;
    let subject = Name::from_str("CN=World domination corporation,O=World domination Inc,C=US")
        .unwrap()
        .to_der()
        .unwrap();
    let subject = Name::from_der(&subject).unwrap();
    let pub_key =
        SubjectPublicKeyInfoOwned::try_from(RSA_2048_DER_EXAMPLE).expect("get rsa pub key");

    let mut signer = rsa_signer();
    let mut builder = CertificateBuilder::new(
        profile,
        Version::V3,
        serial_number,
        validity,
        subject,
        pub_key,
        &mut signer,
    )
    .expect("Create certificate");

    let certificate = builder.build().unwrap();

    let pem = certificate.to_pem(LineEnding::LF).expect("generate pem");
    println!("{}", openssl::check_certificate(pem.as_bytes()));

    let ignored = &[];
    zlint::check_certificate(pem.as_bytes(), ignored);
}

#[test]
fn sub_ca_certificate() {
    let serial_number = SerialNumber::from(42u32);
    let validity = Validity::from_now(Duration::new(5, 0)).unwrap();

    let issuer = Name::from_str("CN=World domination corporation,O=World domination Inc,C=US")
        .unwrap()
        .to_der()
        .unwrap();
    let issuer = Name::from_der(&issuer).unwrap();
    let profile = Profile::SubCA {
        issuer,
        path_len_constraint: Some(0),
    };

    let subject = Name::from_str("CN=World domination task force,O=World domination Inc,C=US")
        .unwrap()
        .to_der()
        .unwrap();
    let subject = Name::from_der(&subject).unwrap();
    let pub_key =
        SubjectPublicKeyInfoOwned::try_from(RSA_2048_DER_EXAMPLE).expect("get rsa pub key");

    let mut signer = ecdsa_signer();
    let mut builder = CertificateBuilder::new::<ecdsa::Signature<NistP256>>(
        profile,
        Version::V3,
        serial_number,
        validity,
        subject,
        pub_key,
        &mut signer,
    )
    .expect("Create certificate");

    let certificate = builder.build::<ecdsa::Signature<NistP256>>().unwrap();

    let pem = certificate.to_pem(LineEnding::LF).expect("generate pem");
    println!("{}", openssl::check_certificate(pem.as_bytes()));

    // TODO(baloo): not too sure we should tackle those in this API.
    let ignored = &[
        "w_sub_ca_aia_missing",
        "e_sub_ca_crl_distribution_points_missing",
        "e_sub_ca_certificate_policies_missing",
        "w_sub_ca_aia_does_not_contain_issuing_ca_url",
    ];

    zlint::check_certificate(pem.as_bytes(), ignored);
}

const RSA_2048_PRIV_DER_EXAMPLE: &[u8] = include_bytes!("examples/rsa2048-priv.der");

fn rsa_signer() -> SigningKey<Sha256> {
    let private_key = rsa::RsaPrivateKey::from_pkcs1_der(RSA_2048_PRIV_DER_EXAMPLE).unwrap();
    let signing_key = SigningKey::<Sha256>::new_with_prefix(private_key);
    signing_key
}

const PKCS8_PRIVATE_KEY_DER: &[u8] = include_bytes!("examples/p256-priv.der");

fn ecdsa_signer() -> ecdsa::SigningKey<NistP256> {
    let secret_key = p256::SecretKey::from_pkcs8_der(PKCS8_PRIVATE_KEY_DER).unwrap();
    ecdsa::SigningKey::from(secret_key)
}
