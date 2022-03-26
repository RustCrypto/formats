//! Encrypted SSH private key tests.

#![cfg(feature = "alloc")]

use hex_literal::hex;
use ssh_key::{Algorithm, PrivateKey};

/// Encrypted Ed25519 OpenSSH-formatted private key.
const OSSH_ED25519_ENC_EXAMPLE: &str = include_str!("examples/id_ed25519.enc");

#[test]
fn decode_ed25519_enc_openssh() {
    let ossh_key = PrivateKey::from_openssh(OSSH_ED25519_ENC_EXAMPLE).unwrap();
    assert_eq!(Algorithm::Ed25519, ossh_key.algorithm());
    assert_eq!(
        &hex!("b33eaef37ea2df7caa010defdea34e241f65f1b529a4f43ed14327f5c54aab62"),
        ossh_key.public_key().key_data().ed25519().unwrap().as_ref(),
    );
}
