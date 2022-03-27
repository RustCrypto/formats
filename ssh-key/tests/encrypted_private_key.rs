//! Encrypted SSH private key tests.

#![cfg(feature = "alloc")]

use hex_literal::hex;
use ssh_key::{Algorithm, Cipher, Kdf, KdfAlg, PrivateKey};

/// Unencrypted Ed25519 OpenSSH-formatted private key.
#[cfg(all(feature = "encryption", feature = "subtle"))]
const OPENSSH_ED25519_EXAMPLE: &str = include_str!("examples/id_ed25519");

/// Encrypted Ed25519 OpenSSH-formatted private key.
///
/// This is the encrypted form of `OPENSSH_ED25519_EXAMPLE`.
const OPENSSH_ED25519_ENC_EXAMPLE: &str = include_str!("examples/id_ed25519.enc");

/// Bad password; don't actually use outside tests!
#[cfg(all(feature = "encryption", feature = "subtle"))]
const PASSWORD: &[u8] = b"hunter42";

#[test]
fn decode_ed25519_enc_openssh() {
    let key = PrivateKey::from_openssh(OPENSSH_ED25519_ENC_EXAMPLE).unwrap();
    assert_eq!(Algorithm::Ed25519, key.algorithm());
    assert_eq!(Cipher::Aes256Ctr, key.cipher().unwrap());
    assert_eq!(KdfAlg::Bcrypt, key.kdf().algorithm());

    match key.kdf() {
        Kdf::Bcrypt { salt, rounds } => {
            assert_eq!(salt, &hex!("4a1fdeae8d6ba607afd69d334f8d379a"));
            assert_eq!(*rounds, 16);
        }
        other => panic!("unexpected KDF algorithm: {:?}", other),
    }

    assert_eq!(
        &hex!("b33eaef37ea2df7caa010defdea34e241f65f1b529a4f43ed14327f5c54aab62"),
        key.public_key().key_data().ed25519().unwrap().as_ref(),
    );
}

#[cfg(all(feature = "encryption", feature = "subtle"))]
#[test]
fn decrypt_ed25519_enc_openssh() {
    let key_enc = PrivateKey::from_openssh(OPENSSH_ED25519_ENC_EXAMPLE).unwrap();
    let key_dec = key_enc.decrypt(PASSWORD).unwrap();
    assert_eq!(
        PrivateKey::from_openssh(OPENSSH_ED25519_EXAMPLE).unwrap(),
        key_dec
    );
}

#[test]
fn encode_ed25519_enc_openssh() {
    let key = PrivateKey::from_openssh(OPENSSH_ED25519_ENC_EXAMPLE).unwrap();
    assert_eq!(
        OPENSSH_ED25519_ENC_EXAMPLE.trim_end(),
        key.to_openssh(Default::default()).unwrap().trim_end()
    );
}
