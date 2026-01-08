#![cfg(all(feature = "builder", feature = "pem", feature = "std"))]

use der::{
    EncodePem,
    asn1::{Ia5String, PrintableString},
    pem::LineEnding,
};
use p256::{NistP256, ecdsa::DerSignature, elliptic_curve::Generate, pkcs8::DecodePrivateKey};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use sha2::Sha256;
use spki::SubjectPublicKeyInfo;
use std::{str::FromStr, time::Duration};
use x509_cert::{
    builder::{AsyncBuilder, Builder, CertificateBuilder, RequestBuilder, profile},
    ext::pkix::{
        SubjectAltName,
        name::{DirectoryString, GeneralName},
    },
    name::Name,
    request,
    serial_number::SerialNumber,
    time::Validity,
};
use x509_cert_test_support::{openssl, zlint};

#[cfg(feature = "hazmat")]
use x509_cert::builder::profile::cabf::tls::Tls12Options;

const RSA_2048_DER_EXAMPLE: &[u8] = include_bytes!("examples/rsa2048-pub.der");
const PKCS8_PUBLIC_KEY_DER: &[u8] = include_bytes!("examples/p256-pub.der");

#[test]
fn root_ca_certificate() {
    let serial_number = SerialNumber::from(42u32);
    let validity = Validity::from_now(Duration::new(5, 0)).unwrap();
    let subject =
        Name::from_str("CN=World domination corporation,O=World domination Inc,C=US").unwrap();
    let profile = profile::cabf::Root::new(false, subject).expect("create root profile");

    let pub_key = SubjectPublicKeyInfo::try_from(RSA_2048_DER_EXAMPLE).expect("get rsa pub key");

    let signer = rsa_signer();
    let builder = CertificateBuilder::new(profile, serial_number, validity, pub_key)
        .expect("Create certificate");

    let certificate = builder.build(&signer).unwrap();

    let pem = certificate.to_pem(LineEnding::LF).expect("generate pem");
    println!("{}", openssl::check_certificate(pem.as_bytes()));

    let ignored = &[];
    zlint::check_certificate(pem.as_bytes(), ignored);
}

#[test]
fn root_ca_certificate_ecdsa() {
    let serial_number = SerialNumber::from(42u32);
    let validity = Validity::from_now(Duration::new(5, 0)).unwrap();

    let subject =
        Name::from_str("CN=World domination corporation,O=World domination Inc,C=US").unwrap();
    let profile = profile::cabf::Root::new(false, subject).expect("create root profile");
    let pub_key = SubjectPublicKeyInfo::try_from(PKCS8_PUBLIC_KEY_DER).expect("get ecdsa pub key");

    let signer = ecdsa_signer();
    let builder = CertificateBuilder::new(profile, serial_number, validity, pub_key)
        .expect("Create certificate");

    let certificate = builder.build::<_, DerSignature>(&signer).unwrap();

    let pem = certificate.to_pem(LineEnding::LF).expect("generate pem");
    println!("{}", openssl::check_certificate(pem.as_bytes()));

    let ignored = &[];
    zlint::check_certificate(pem.as_bytes(), ignored);
}

#[test]
fn sub_ca_certificate() {
    let serial_number = SerialNumber::from(42u32);
    let validity = Validity::from_now(Duration::new(5, 0)).unwrap();

    let issuer =
        Name::from_str("CN=World domination corporation,O=World domination Inc,C=US").unwrap();
    let subject =
        Name::from_str("CN=World domination task force,O=World domination Inc,C=US").unwrap();
    let profile = profile::cabf::tls::Subordinate {
        subject,
        issuer,
        path_len_constraint: Some(0),
        client_auth: false,
        emits_ocsp_response: true,
    };

    let pub_key = SubjectPublicKeyInfo::try_from(RSA_2048_DER_EXAMPLE).expect("get rsa pub key");

    let signer = ecdsa_signer();
    let builder = CertificateBuilder::new(profile, serial_number, validity, pub_key)
        .expect("Create certificate");

    let certificate = builder.build::<_, DerSignature>(&signer).unwrap();

    let pem = certificate.to_pem(LineEnding::LF).expect("generate pem");
    println!("{}", openssl::check_certificate(pem.as_bytes()));

    // TODO(baloo): not too sure we should tackle those in this API.
    let ignored = &[
        "w_sub_ca_aia_missing",
        "e_sub_ca_crl_distribution_points_missing",
        "e_sub_ca_certificate_policies_missing",
        "w_sub_ca_aia_does_not_contain_issuing_ca_url",
        "e_invalid_ca_certificate_policies",
    ];

    zlint::check_certificate(pem.as_bytes(), ignored);
}

#[test]
fn leaf_certificate() {
    let serial_number = SerialNumber::from(42u32);
    let validity = Validity::from_now(Duration::new(5, 0)).unwrap();

    let issuer =
        Name::from_str("CN=World domination corporation,O=World domination Inc,C=US").unwrap();
    let subject = Name::from_str("C=US").unwrap();
    let profile = profile::cabf::tls::Subscriber {
        certificate_type: profile::cabf::tls::CertificateType::domain_validated(
            subject.clone(),
            vec![GeneralName::DnsName(
                Ia5String::new(b"example.com").unwrap(),
            )],
        )
        .expect("create DomainValidated profile"),
        issuer: issuer.clone(),
        client_auth: false,

        #[cfg(feature = "hazmat")]
        tls12_options: Tls12Options::default(),
        #[cfg(feature = "hazmat")]
        enable_data_encipherment: false,
    };

    let pub_key = SubjectPublicKeyInfo::try_from(RSA_2048_DER_EXAMPLE).expect("get rsa pub key");

    let signer = ecdsa_signer();
    let builder =
        CertificateBuilder::new(profile, serial_number.clone(), validity, pub_key.clone())
            .expect("Create certificate");

    let certificate = builder.build::<_, DerSignature>(&signer).unwrap();

    let pem = certificate.to_pem(LineEnding::LF).expect("generate pem");
    println!("{}", openssl::check_certificate(pem.as_bytes()));

    // TODO(baloo): not too sure we should tackle those in this API.
    let ignored = vec![
        "e_sub_cert_aia_missing",
        "e_sub_cert_crl_distribution_points_missing",
        "w_sub_cert_aia_does_not_contain_issuing_ca_url",
        // Missing policies
        "e_sub_cert_certificate_policies_missing",
        "e_sub_cert_cert_policy_empty",
        // Needs to be added by the end-user
        "e_sub_cert_aia_does_not_contain_ocsp_url",
        // SAN needs to include DNS name (if used)
        "e_ext_san_missing",
        "e_subject_common_name_not_exactly_from_san",
        // Extended key usage needs to be added by end-user and is use-case dependent
        "e_sub_cert_eku_missing",
        // CABF BRs v2 now marks ski as NOT RECOMMEND. Users of zlint are intended to
        // select either RFC5280 lint or CABF lint. We want the CABF lint here and
        // should ignore the RFC5280 one.
        "w_ext_subject_key_identifier_missing_sub_cert",
    ];

    zlint::check_certificate(pem.as_bytes(), &ignored);
}

#[test]
fn pss_certificate() {
    let serial_number = SerialNumber::from(42u32);
    let validity = Validity::from_now(Duration::new(5, 0)).unwrap();

    let issuer =
        Name::from_str("CN=World domination corporation,O=World domination Inc,C=US").unwrap();

    let subject = Name::from_str("C=US").unwrap();
    let profile = profile::cabf::tls::Subscriber {
        certificate_type: profile::cabf::tls::CertificateType::domain_validated(
            subject.clone(),
            vec![GeneralName::DnsName(
                Ia5String::new(b"example.com").unwrap(),
            )],
        )
        .expect("create DomainValidated profile"),

        issuer,
        client_auth: false,

        #[cfg(feature = "hazmat")]
        tls12_options: Tls12Options::default(),
        #[cfg(feature = "hazmat")]
        enable_data_encipherment: false,
    };

    let pub_key = SubjectPublicKeyInfo::try_from(RSA_2048_DER_EXAMPLE).expect("get rsa pub key");

    let signer = rsa_pss_signer();
    let builder = CertificateBuilder::new(profile, serial_number, validity, pub_key)
        .expect("Create certificate");

    let certificate = builder
        .build_with_rng::<_, rsa::pss::Signature, _>(&signer, &mut rand::rng())
        .unwrap();

    let pem = certificate.to_pem(LineEnding::LF).expect("generate pem");
    println!("{}", openssl::check_certificate(pem.as_bytes()));

    // TODO(baloo): not too sure we should tackle those in this API.
    let ignored = &[
        "e_sub_cert_aia_missing",
        "e_sub_cert_crl_distribution_points_missing",
        "w_sub_cert_aia_does_not_contain_issuing_ca_url",
        // Missing policies
        "e_sub_cert_certificate_policies_missing",
        "e_sub_cert_cert_policy_empty",
        // Needs to be added by the end-user
        "e_sub_cert_aia_does_not_contain_ocsp_url",
        // SAN needs to include DNS name (if used)
        "e_ext_san_missing",
        "e_subject_common_name_not_exactly_from_san",
        // Extended key usage needs to be added by end-user and is use-case dependent
        "e_sub_cert_eku_missing",
        // zlint warns on RSAPSS signature algorithms
        "e_signature_algorithm_not_supported",
        // CABF BRs v2 now marks ski as NOT RECOMMEND. Users of zlint are intended to
        // select either RFC5280 lint or CABF lint. We want the CABF lint here and
        // should ignore the RFC5280 one.
        "w_ext_subject_key_identifier_missing_sub_cert",
    ];

    zlint::check_certificate(pem.as_bytes(), ignored);
}

const RSA_2048_PRIV_DER_EXAMPLE: &[u8] = include_bytes!("examples/rsa2048-priv.der");

fn rsa_signer() -> SigningKey<Sha256> {
    let private_key = rsa::RsaPrivateKey::from_pkcs1_der(RSA_2048_PRIV_DER_EXAMPLE).unwrap();
    SigningKey::<Sha256>::new(private_key)
}

fn rsa_pss_signer() -> rsa::pss::SigningKey<Sha256> {
    let private_key = rsa::RsaPrivateKey::from_pkcs1_der(RSA_2048_PRIV_DER_EXAMPLE).unwrap();
    rsa::pss::SigningKey::<Sha256>::new(private_key)
}

const PKCS8_PRIVATE_KEY_DER: &[u8] = include_bytes!("examples/p256-priv.der");

fn ecdsa_signer() -> ecdsa::SigningKey<NistP256> {
    let secret_key = p256::SecretKey::from_pkcs8_der(PKCS8_PRIVATE_KEY_DER).unwrap();
    ecdsa::SigningKey::from(secret_key)
}

#[test]
fn certificate_request() {
    use std::net::{IpAddr, Ipv4Addr};
    let subject = Name::from_str("CN=service.domination.world").unwrap();

    let signer = ecdsa_signer();
    let mut builder = RequestBuilder::new(subject).expect("Create certificate request");
    builder
        .add_extension(&SubjectAltName(vec![GeneralName::from(IpAddr::V4(
            Ipv4Addr::new(192, 0, 2, 0),
        ))]))
        .unwrap();

    let cert_req = builder.build::<_, DerSignature>(&signer).unwrap();
    let pem = cert_req.to_pem(LineEnding::LF).expect("generate pem");
    use std::fs::File;
    use std::io::Write;
    let mut file = File::create("/tmp/ecdsa.csr").expect("create pem file");
    file.write_all(pem.as_bytes()).expect("Create pem file");
    println!("{}", openssl::check_request(pem.as_bytes()));
}

#[test]
fn certificate_request_attributes() {
    let subject = Name::from_str("CN=service.domination.world").unwrap();

    let signer = ecdsa_signer();
    let mut builder = RequestBuilder::new(subject).expect("Create certificate request");
    builder
        .add_attribute(&request::attributes::ChallengePassword(
            DirectoryString::PrintableString(
                PrintableString::new(b"password1234")
                    .expect("create printable string with password"),
            ),
        ))
        .expect("unable to add attribute");

    let cert_req = builder.build::<_, DerSignature>(&signer).unwrap();
    let pem = cert_req.to_pem(LineEnding::LF).expect("generate pem");
    use std::fs::File;
    use std::io::Write;
    let mut file = File::create("/tmp/ecdsa.csr").expect("create pem file");
    file.write_all(pem.as_bytes()).expect("Create pem file");
    println!("{}", openssl::check_request(pem.as_bytes()));
}

#[test]
fn dynamic_signer() {
    let subject = Name::from_str("CN=Test").expect("parse common name");

    let csr_builder = RequestBuilder::new(subject).expect("construct builder");
    let mut rng = rand::rng();

    let csr = if true {
        let req_signer = p256::ecdsa::SigningKey::generate_from_rng(&mut rng);
        csr_builder
            .build::<_, p256::ecdsa::DerSignature>(&req_signer)
            .expect("Sign request")
    } else {
        let req_signer = rsa_signer();
        csr_builder.build(&req_signer).expect("Sign request")
    };

    let csr_pem = csr.to_pem(LineEnding::LF).expect("format CSR");

    println!("{csr_pem}");
}

#[tokio::test]
async fn async_builder() {
    let serial_number = SerialNumber::from(42u32);
    let validity = Validity::from_now(Duration::new(5, 0)).unwrap();

    let subject =
        Name::from_str("CN=World domination corporation,O=World domination Inc,C=US").unwrap();
    let profile = profile::cabf::Root::new(false, subject).expect("create root profile");

    let pub_key = SubjectPublicKeyInfo::try_from(PKCS8_PUBLIC_KEY_DER).expect("get ecdsa pub key");

    let signer = ecdsa_signer();
    let builder = CertificateBuilder::new(profile, serial_number, validity, pub_key)
        .expect("Create certificate");

    let certificate = builder
        .build_async::<_, DerSignature>(&signer)
        .await
        .unwrap();

    let pem = certificate.to_pem(LineEnding::LF).expect("generate pem");
    println!("{}", openssl::check_certificate(pem.as_bytes()));
}
