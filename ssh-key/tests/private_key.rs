//! SSH private key tests.

use hex_literal::hex;
use ssh_key::{Algorithm, PrivateKey};

/// Ed25519 OpenSSH-formatted private key
const OSSH_ED25519_EXAMPLE: &str = include_str!("examples/id_ed25519");

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
