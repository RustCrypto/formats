#![cfg(all(feature = "builder", feature = "pem", feature = "std"))]

use std::{
    str::FromStr,
    time::{Duration, SystemTime},
};

use der::{EncodePem, pem::LineEnding};
use p256::{NistP256, ecdsa::DerSignature, pkcs8::DecodePrivateKey};
use rand::rng;
use x509_cert::{
    SubjectPublicKeyInfo,
    builder::{
        Builder, CertificateBuilder, CrlBuilder,
        profile::{self, cabf::tls::CertificateType},
    },
    certificate::Rfc5280,
    crl::RevokedCert,
    ext::{
        ToExtension,
        pkix::{CrlNumber, CrlReason, name::GeneralName},
    },
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

    let builder = CrlBuilder::<Rfc5280>::new(&ca_certificate, crl_number)
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

/// RFC 5280 5.2.1: the CRL's authorityKeyIdentifier identifies the key used to sign the CRL,
/// i.e. the CRL issuer's own key, not the key of whoever issued the CRL issuer's certificate.
#[test]
fn crl_aki_is_issuer_key() {
    use der::{Decode, oid::AssociatedOid};
    use x509_cert::ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier};

    let mut rng = rng();
    let signer = ecdsa_signer();
    let pub_key = SubjectPublicKeyInfo::try_from(PKCS8_PUBLIC_KEY_DER).expect("get ecdsa pub key");

    // An intermediate CA certificate: its own AKI names its issuer's key (a different key).
    let other_key = p256::ecdsa::SigningKey::from(p256::SecretKey::from_slice(&[7u8; 32]).unwrap());
    let root_name = Name::from_str("CN=root,O=World domination Inc,C=US").unwrap();
    let sub_name = Name::from_str("CN=sub,O=World domination Inc,C=US").unwrap();
    let profile = profile::cabf::tls::Subordinate {
        issuer: root_name,
        subject: sub_name,
        path_len_constraint: None,
        emits_ocsp_response: false,
        client_auth: false,
    };
    let validity = Validity::from_now(Duration::new(60, 0)).unwrap();
    let builder = CertificateBuilder::new(
        profile,
        SerialNumber::generate(&mut rng),
        validity,
        pub_key.clone(),
    )
    .expect("Create certificate");
    // signed by the root key; the subordinate's own key is `pub_key`
    let sub_ca = builder.build::<_, DerSignature>(&other_key).unwrap();

    let (_, sub_aki) = sub_ca
        .tbs_certificate()
        .get_extension::<AuthorityKeyIdentifier>()
        .unwrap()
        .unwrap();
    let (_, sub_ski) = sub_ca
        .tbs_certificate()
        .get_extension::<SubjectKeyIdentifier>()
        .unwrap()
        .unwrap();
    assert_ne!(sub_aki.key_identifier, Some(sub_ski.0.clone()));

    // The subordinate CA signs a CRL with its own key.
    let crl = CrlBuilder::<Rfc5280>::new(&sub_ca, CrlNumber::try_from(1u128).unwrap())
        .unwrap()
        .build::<_, DerSignature>(&signer)
        .unwrap();
    let crl_aki = crl
        .tbs_cert_list
        .crl_extensions
        .as_ref()
        .unwrap()
        .iter()
        .find(|e| e.extn_id == AuthorityKeyIdentifier::OID)
        .map(|e| AuthorityKeyIdentifier::from_der(e.extn_value.as_bytes()).unwrap())
        .unwrap();
    assert_eq!(crl_aki.key_identifier, Some(sub_ski.0));
}

/// Use `openssl verify` to run a mock certificate chain against a newly signed CRL.
#[test]
fn crl_verify() {
    let mut rng = rng();
    let signer = ecdsa_signer();

    let serial_number = SerialNumber::generate(&mut rng);
    let validity = Validity::from_now(Duration::new(60, 0)).unwrap();
    let subject = Name::from_str("CN=root,O=World domination Inc,C=US").unwrap();
    let profile = profile::cabf::Root::new(false, subject.clone()).expect("create root profile");
    let pub_key = SubjectPublicKeyInfo::try_from(PKCS8_PUBLIC_KEY_DER).expect("get ecdsa pub key");

    let builder = CertificateBuilder::new(profile, serial_number, validity, pub_key.clone())
        .expect("Create certificate");

    let ca_certificate = builder.build::<_, DerSignature>(&signer).unwrap();

    let serial_number = SerialNumber::generate(&mut rng);
    let delegated = Name::from_str("CN=example.com,O=World domination Inc,C=US").unwrap();
    let profile = profile::cabf::tls::Subscriber {
        certificate_type: CertificateType::domain_validated(
            delegated.clone(),
            vec![GeneralName::DirectoryName(delegated.clone())],
        )
        .expect("create domain validated"),
        issuer: subject,
        client_auth: true,
        #[cfg(feature = "hazmat")]
        tls12_options: Default::default(),
        #[cfg(feature = "hazmat")]
        enable_data_encipherment: false,
    };

    let builder = CertificateBuilder::new(profile, serial_number.clone(), validity, pub_key)
        .expect("Create certificate");

    let leaf_certificate = builder.build::<_, DerSignature>(&signer).unwrap();

    let crl_number = CrlNumber::try_from(43u128).unwrap();

    let revocation_date = SystemTime::now() - Duration::from_secs(5);

    let builder = CrlBuilder::<Rfc5280>::new(&ca_certificate, crl_number)
        .unwrap()
        .with_certificates(
            vec![RevokedCert {
                serial_number,
                revocation_date: revocation_date.try_into().unwrap(),
                crl_entry_extensions: Some(vec![
                    CrlReason::Unspecified
                        .to_extension(&delegated, &[])
                        .unwrap(),
                ]),
            }]
            .into_iter(),
        );

    let crl = builder.build::<_, DerSignature>(&signer).unwrap();

    println!(
        "{}",
        openssl::check_certificate(
            ca_certificate
                .to_pem(LineEnding::LF)
                .expect("ca: generate pem")
                .as_bytes(),
        )
    );
    println!(
        "{}",
        openssl::check_certificate(
            leaf_certificate
                .to_pem(LineEnding::LF)
                .expect("ca: generate pem")
                .as_bytes(),
        )
    );
    println!(
        "{}",
        openssl::check_crl(
            crl.to_pem(LineEnding::LF)
                .expect("crl: generate pem")
                .as_bytes(),
        )
    );

    let (status, verification_output, verification_stderr) = openssl::verify(
        ca_certificate
            .to_pem(LineEnding::LF)
            .expect("ca: generate pem")
            .as_bytes(),
        leaf_certificate
            .to_pem(LineEnding::LF)
            .expect("leaf: generate pem")
            .as_bytes(),
        crl.to_pem(LineEnding::LF)
            .expect("crl: generate pem")
            .as_bytes(),
    );
    assert_eq!(status.code(), Some(2));
    println!("{verification_output}");
    println!("{verification_stderr}");
    assert!(verification_stderr.contains("certificate revoked"));
}
