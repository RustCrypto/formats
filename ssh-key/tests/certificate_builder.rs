//! Certificate builder tests.

#![cfg(all(
    feature = "alloc",
    feature = "fingerprint",
    any(feature = "ed25519", feature = "p256")
))]

use hex_literal::hex;
use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
use ssh_key::{
    certificate::{self, CertType},
    Algorithm, PrivateKey,
};

#[cfg(feature = "p256")]
use ssh_key::EcdsaCurve;

/// Example Unix timestamp when a certificate was issued (2020-09-13 12:26:40 UTC).
const ISSUED_AT: u64 = 1600000000;

/// Example Unix timestamp when a certificate is valid (2022-04-15 05:20:00 UTC).
const VALID_AT: u64 = 1650000000;

/// Example Unix timestamp when a certificate expires (2023-11-14 22:13:20 UTC).
const EXPIRES_AT: u64 = 1700000000;

/// Example serial number.
const SERIAL: u64 = 42;

/// Example key ID.
const KEY_ID: &str = "example";

/// Example principal name.
const PRINCIPAL: &str = "nobody";

/// Critical extension 1.
const CRITICAL_EXTENSION_1: (&str, &str) = ("critical name 1", "critical data 2");

/// Critical extension 1.
const CRITICAL_EXTENSION_2: (&str, &str) = ("critical name 2", "critical data 2");

/// Non critical extension 1.
const EXTENSION_1: (&str, &str) = ("extension name 1", "extension data 1");

/// Non critical extension 2.
const EXTENSION_2: (&str, &str) = ("extension name 2", "extension data 2");

/// Example comment.
const COMMENT: &str = "user@example.com";

/// Seed to use for PRNG.
const PRNG_SEED: [u8; 32] = [42; 32];

#[cfg(feature = "ed25519")]
#[test]
fn ed25519_sign_and_verify() {
    let mut rng = ChaCha8Rng::from_seed(PRNG_SEED);

    let ca_key = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
    let subject_key = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();

    let mut cert_builder = certificate::Builder::new_with_random_nonce(
        &mut rng,
        subject_key.public_key(),
        ISSUED_AT,
        EXPIRES_AT,
    );
    cert_builder.serial(SERIAL).unwrap();
    cert_builder.key_id(KEY_ID).unwrap();
    cert_builder.valid_principal(PRINCIPAL).unwrap();
    cert_builder
        .critical_option(CRITICAL_EXTENSION_1.0, CRITICAL_EXTENSION_1.1)
        .unwrap();
    cert_builder
        .critical_option(CRITICAL_EXTENSION_2.0, CRITICAL_EXTENSION_2.1)
        .unwrap();
    cert_builder
        .extension(EXTENSION_1.0, EXTENSION_1.1)
        .unwrap();
    cert_builder
        .extension(EXTENSION_2.0, EXTENSION_2.1)
        .unwrap();
    cert_builder.comment(COMMENT).unwrap();

    let cert = cert_builder.sign(&ca_key).unwrap();
    assert_eq!(cert.algorithm(), Algorithm::Ed25519);
    assert_eq!(cert.nonce(), &hex!("321fdf7e0a2afe803308f394f54c6abe"));
    assert_eq!(cert.public_key(), subject_key.public_key().key_data());
    assert_eq!(cert.serial(), SERIAL);
    assert_eq!(cert.cert_type(), CertType::User);
    assert_eq!(cert.key_id(), KEY_ID);
    assert_eq!(cert.valid_principals().len(), 1);
    assert_eq!(cert.valid_principals()[0], PRINCIPAL);
    assert_eq!(cert.valid_after(), ISSUED_AT);
    assert_eq!(cert.valid_before(), EXPIRES_AT);
    assert_eq!(cert.critical_options().len(), 2);
    assert_eq!(
        cert.critical_options().get(CRITICAL_EXTENSION_1.0).unwrap(),
        CRITICAL_EXTENSION_1.1
    );
    assert_eq!(cert.extensions().get(EXTENSION_2.0).unwrap(), EXTENSION_2.1);
    assert_eq!(cert.extensions().len(), 2);
    assert_eq!(cert.extensions().get(EXTENSION_1.0).unwrap(), EXTENSION_1.1);
    assert_eq!(cert.extensions().get(EXTENSION_2.0).unwrap(), EXTENSION_2.1);
    assert_eq!(cert.signature_key(), ca_key.public_key().key_data());
    assert_eq!(cert.comment(), COMMENT);

    let ca_fingerprint = ca_key.fingerprint(Default::default());
    assert!(cert.validate_at(VALID_AT, &[ca_fingerprint]).is_ok());
}

#[cfg(feature = "p256")]
#[test]
fn ecdsa_nistp256_sign_and_verify() {
    let mut rng = ChaCha8Rng::from_seed(PRNG_SEED);

    let algorithm = Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    };
    let ca_key = PrivateKey::random(&mut rng, algorithm).unwrap();
    let subject_key = PrivateKey::random(&mut rng, algorithm).unwrap();
    let mut cert_builder = certificate::Builder::new_with_random_nonce(
        &mut rng,
        subject_key.public_key(),
        ISSUED_AT,
        EXPIRES_AT,
    );
    cert_builder.all_principals_valid().unwrap();
    let cert = cert_builder.sign(&ca_key).unwrap();

    assert_eq!(cert.algorithm(), algorithm);
    assert_eq!(cert.nonce(), &hex!("321fdf7e0a2afe803308f394f54c6abe"));
    assert_eq!(cert.public_key(), subject_key.public_key().key_data());
    assert_eq!(cert.signature_key(), ca_key.public_key().key_data());

    let ca_fingerprint = ca_key.fingerprint(Default::default());
    assert!(cert.validate_at(VALID_AT, &[ca_fingerprint]).is_ok());
}

#[cfg(feature = "rsa")]
#[test]
fn rsa_sign_and_verify() {
    let mut rng = ChaCha8Rng::from_seed(PRNG_SEED);

    let algorithm = Algorithm::Rsa { hash: None };
    let ca_key = PrivateKey::random(&mut rng, algorithm).unwrap();
    let subject_key = PrivateKey::random(&mut rng, algorithm).unwrap();
    let mut cert_builder = certificate::Builder::new_with_random_nonce(
        &mut rng,
        subject_key.public_key(),
        ISSUED_AT,
        EXPIRES_AT,
    );
    cert_builder.all_principals_valid().unwrap();
    let cert = cert_builder.sign(&ca_key).unwrap();

    assert_eq!(cert.algorithm(), algorithm);
    assert_eq!(cert.nonce(), &hex!("13e4d4c95eb914e8b1d3c0f3de757594"));
    assert_eq!(cert.public_key(), subject_key.public_key().key_data());
    assert_eq!(cert.signature_key(), ca_key.public_key().key_data());

    let ca_fingerprint = ca_key.fingerprint(Default::default());
    assert!(cert.validate_at(VALID_AT, &[ca_fingerprint]).is_ok());
}
