//! Encrypted SSH private key tests.

#![cfg(feature = "alloc")]

use hex_literal::hex;
use ssh_key::{Algorithm, KdfAlg, KdfOpts, PrivateKey};

/// Encrypted Ed25519 OpenSSH-formatted private key.
const OSSH_ED25519_ENC_EXAMPLE: &str = include_str!("examples/id_ed25519.enc");

#[test]
fn decode_ed25519_enc_openssh() {
    let ossh_key = PrivateKey::from_openssh(OSSH_ED25519_ENC_EXAMPLE).unwrap();
    assert_eq!(Algorithm::Ed25519, ossh_key.algorithm());
    assert_eq!(KdfAlg::Bcrypt, ossh_key.kdf_alg());

    match ossh_key.kdf_opts() {
        KdfOpts::Bcrypt { salt, rounds } => {
            assert_eq!(salt, &hex!("4a1fdeae8d6ba607afd69d334f8d379a"));
            assert_eq!(*rounds, 16);
        }
        other => panic!("unexpected KDF algorithm: {:?}", other),
    }

    assert_eq!(
        &hex!("b33eaef37ea2df7caa010defdea34e241f65f1b529a4f43ed14327f5c54aab62"),
        ossh_key.public_key().key_data().ed25519().unwrap().as_ref(),
    );
}

#[test]
fn encode_ed25519_enc_openssh() {
    let ossh_key = PrivateKey::from_openssh(OSSH_ED25519_ENC_EXAMPLE).unwrap();
    assert_eq!(
        OSSH_ED25519_ENC_EXAMPLE.trim_end(),
        ossh_key.to_openssh(Default::default()).unwrap().trim_end()
    );
}
