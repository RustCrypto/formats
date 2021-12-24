//! SSH private key tests.

use hex_literal::hex;
use ssh_key::{Algorithm, PrivateKey};

#[cfg(feature = "ecdsa")]
use ssh_key::EcdsaCurve;

/// Ed25519 OpenSSH-formatted private key
const OSSH_ED25519_EXAMPLE: &str = include_str!("examples/id_ed25519");

/// ECDSA/P-256 OpenSSH-formatted public key
#[cfg(feature = "ecdsa")]
const OSSH_ECDSA_P256_EXAMPLE: &str = include_str!("examples/id_ecdsa_p256");

/// ECDSA/P-384 OpenSSH-formatted public key
#[cfg(feature = "ecdsa")]
const OSSH_ECDSA_P384_EXAMPLE: &str = include_str!("examples/id_ecdsa_p384");

/// ECDSA/P-521 OpenSSH-formatted public key
#[cfg(feature = "ecdsa")]
const OSSH_ECDSA_P521_EXAMPLE: &str = include_str!("examples/id_ecdsa_p521");

#[cfg(feature = "ecdsa")]
#[test]
fn decode_ecdsa_p256_openssh() {
    let ossh_key = PrivateKey::from_openssh(OSSH_ECDSA_P256_EXAMPLE).unwrap();
    assert_eq!(
        Algorithm::Ecdsa(EcdsaCurve::NistP256),
        ossh_key.key_data.algorithm(),
    );

    let ecdsa_keypair = ossh_key.key_data.ecdsa().unwrap();
    assert_eq!(EcdsaCurve::NistP256, ecdsa_keypair.curve());
    assert_eq!(
        &hex!(
            "047c1fd8730ce53457be8d924098ec3648830f92aa8a2363ac656fdd4521fa6313e511f1891b4e9e5aaf8e1
             42d06ad15a66a4257f3f051d84e8a0e2f91ba807047"
        ),
        ecdsa_keypair.public_key_bytes(),
    );
    assert_eq!(
        &hex!("ca78a64774bfae37123224937f0398960189707aca0a8645ceb4359c423ba079"),
        ecdsa_keypair.private_key_bytes(),
    );

    #[cfg(feature = "alloc")]
    assert_eq!("user@example.com", ossh_key.comment);
}

#[cfg(feature = "ecdsa")]
#[test]
fn decode_ecdsa_p384_openssh() {
    let ossh_key = PrivateKey::from_openssh(OSSH_ECDSA_P384_EXAMPLE).unwrap();
    assert_eq!(
        Algorithm::Ecdsa(EcdsaCurve::NistP384),
        ossh_key.key_data.algorithm(),
    );

    let ecdsa_keypair = ossh_key.key_data.ecdsa().unwrap();
    assert_eq!(EcdsaCurve::NistP384, ecdsa_keypair.curve());
    assert_eq!(
        &hex!(
            "042e6e82dc5407f104a11117c7c05b1993c3ceb3db25fae68ba169502a4ff9395d9ad36b543e8014ff15d70
             8e21f09f585aa6dfad575b79b943418b86198d9bcd9b07fff9399b15d43d34efaeb2e56b7b33cff880b242b
             3e0b58af96c75841ec41"
        ),
        ecdsa_keypair.public_key_bytes(),
    );
    assert_eq!(
        &hex!(
            "0377d9e9328b2925196977320a2bfe013801897fa0287848af817bdc7f400e8801fd0f9c057d106914b389c
             b156f600b"
        ),
        ecdsa_keypair.private_key_bytes(),
    );

    #[cfg(feature = "alloc")]
    assert_eq!("user@example.com", ossh_key.comment);
}

#[cfg(feature = "ecdsa")]
#[test]
fn decode_ecdsa_p521_openssh() {
    let ossh_key = PrivateKey::from_openssh(OSSH_ECDSA_P521_EXAMPLE).unwrap();
    assert_eq!(
        Algorithm::Ecdsa(EcdsaCurve::NistP521),
        ossh_key.key_data.algorithm(),
    );

    let ecdsa_keypair = ossh_key.key_data.ecdsa().unwrap();
    assert_eq!(EcdsaCurve::NistP521, ecdsa_keypair.curve());
    assert_eq!(
        &hex!(
            "04016136934f192b23d961fbf44c8184166002cea2c7d18b20ad018d046ef068d3e8250fd4e9f17ca6693a8
             554c3269a6d9f5762a2f9a2cb8797d4b201de421d3dcc580103cb947a858bb7783df863f82951d96f91a792
             5d7e2baad26e47e3f2fa5b07c8272848a4423b750d7ad2b8b692d66ddecaec5385086b1fd1b682ca291c88d
             63762"
        ),
        ecdsa_keypair.public_key_bytes(),
    );
    assert_eq!(
        &hex!(
            "01ec905f2ab7a9169f161f09e567fcab225bbe6276727a5f2724535c2b663d7ad8e32527d7f5998a992240c
             bb90cec3ed67fe902bced588beb972c7716e0927cda82"
        ),
        ecdsa_keypair.private_key_bytes(),
    );

    #[cfg(feature = "alloc")]
    assert_eq!("user@example.com", ossh_key.comment);
}

#[test]
fn decode_ed25519_openssh() {
    let ossh_key = PrivateKey::from_openssh(OSSH_ED25519_EXAMPLE).unwrap();
    assert_eq!(Algorithm::Ed25519, ossh_key.key_data.algorithm());

    let ed25519_keypair = ossh_key.key_data.ed25519().unwrap();
    assert_eq!(
        &hex!("b33eaef37ea2df7caa010defdea34e241f65f1b529a4f43ed14327f5c54aab62"),
        ed25519_keypair.public.as_ref(),
    );
    assert_eq!(
        &hex!("b606c222d10c16dae16c70a4d45173472ec617e05c656920d26e56c08fb591ed"),
        ed25519_keypair.private.as_ref(),
    );

    #[cfg(feature = "alloc")]
    assert_eq!(ossh_key.comment, "user@example.com");
}
