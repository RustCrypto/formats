//! OpenSSH certificate tests.

#![cfg(feature = "alloc")]

use hex_literal::hex;
use ssh_key::{Algorithm, Certificate};
use std::str::FromStr;

#[cfg(feature = "ecdsa")]
use ssh_key::EcdsaCurve;

/// DSA OpenSSH Certificate
#[cfg(feature = "alloc")]
const DSA_CERT_EXAMPLE: &str = include_str!("examples/id_dsa_1024-cert.pub");

/// ECDSA/P-256 OpenSSH Certificate
#[cfg(feature = "ecdsa")]
const ECDSA_P256_CERT_EXAMPLE: &str = include_str!("examples/id_ecdsa_p256-cert.pub");

/// Ed25519 OpenSSH Certificate
const ED25519_CERT_EXAMPLE: &str = include_str!("examples/id_ed25519-cert.pub");

/// RSA (4096-bit) OpenSSH Certificate
const RSA_4096_CERT_EXAMPLE: &str = include_str!("examples/id_rsa_4096-cert.pub");

#[test]
fn decode_dsa_openssh() {
    let key = Certificate::from_str(DSA_CERT_EXAMPLE).unwrap();
    assert_eq!(Algorithm::Dsa, key.public_key().algorithm());

    let dsa_key = key.public_key().dsa().unwrap();
    assert_eq!(
        &hex!(
            "00dc3d89250ed9462114cb2c8d4816e3a511aaff1b06b0e01de17c1cb04e581bcab97176471d89fd7ca1817
             e3c48e2ccbafd2170f69e8e5c8b6ab69b9c5f45d95e1d9293e965227eee5b879b1123371c21b1db60f14b5e
             5c05a4782ceb43a32f449647703063621e7a286bec95b16726c18b5e52383d00b297a6b03489b06068a5"
        ),
        dsa_key.p.as_bytes(),
    );
    assert_eq!(
        &hex!("00891815378597fe42d3fd261fe76df365845bbb87"),
        dsa_key.q.as_bytes(),
    );
    assert_eq!(
        &hex!(
            "4739b3908a8415466dc7b156fb98ecb71552a170ba0b3b7aa81bd81391de0a7ae7a1b45002dfeadc9225fbc
             520a713fe4104a74bed53fd5915da736365afd3f09777bbccfbadf7ac2b087b7f4d95fabe47d72a46e95088
             f9cd2a9fbf236b58a6982647f3c00430ad7352d47a25ebbe9477f0c3127da86ad7448644b76de5875c"
        ),
        dsa_key.g.as_bytes(),
    );
    assert_eq!(
        &hex!(
            "6042a6b3fd861344cb21ccccd8719e25aa0be0980e79cbabf4877f5ef071f6039770352eac3d4c368f29daf
             a57b475c78d44989f16577527e598334be6aae4abd750c36af80489d392697c1f32f3cf3c9a8b99bcddb53d
             7a37e1a28fd53d4934131cf41c437c6734d1e04004adcd925b84b3956c30c3a3904eecb31400b0df48"
        ),
        dsa_key.y.as_bytes(),
    );

    assert_eq!("user@example.com", key.comment());
}

#[cfg(feature = "ecdsa")]
#[test]
fn decode_ecdsa_p256_openssh() {
    let key = Certificate::from_str(ECDSA_P256_CERT_EXAMPLE).unwrap();
    assert_eq!(
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256
        },
        key.public_key().algorithm(),
    );

    let ecdsa_key = key.public_key().ecdsa().unwrap();
    assert_eq!(EcdsaCurve::NistP256, ecdsa_key.curve());
    assert_eq!(
        &hex!(
            "047c1fd8730ce53457be8d924098ec3648830f92aa8a2363ac656fdd4521fa6313e511f1891b4e9e5aaf8e1
             42d06ad15a66a4257f3f051d84e8a0e2f91ba807047"
        ),
        ecdsa_key.as_ref(),
    );

    assert_eq!("user@example.com", key.comment());
}

#[test]
fn decode_ed25519_openssh() {
    let key = Certificate::from_str(ED25519_CERT_EXAMPLE).unwrap();

    assert_eq!(Algorithm::Ed25519, key.public_key().algorithm());
    assert_eq!(
        &hex!("b33eaef37ea2df7caa010defdea34e241f65f1b529a4f43ed14327f5c54aab62"),
        key.public_key().ed25519().unwrap().as_ref(),
    );

    assert_eq!("user@example.com", key.comment());
}

#[test]
fn decode_rsa_4096_openssh() {
    let key = Certificate::from_str(RSA_4096_CERT_EXAMPLE).unwrap();
    assert_eq!(Algorithm::Rsa { hash: None }, key.public_key().algorithm());

    let rsa_key = key.public_key().rsa().unwrap();
    assert_eq!(&hex!("010001"), rsa_key.e.as_bytes());
    assert_eq!(
        &hex!(
            "00b45911edc6ec5e7d2261a48c46ab889b1858306271123e6f02dc914cf3c0352492e8a6b7a7925added527
             e547dcebff6d0c19c0bc9153975199f47f4964ed20f5aceed4e82556b228a0c1fbfaa85e6339ba2ff4094d9
             4e2b09d43a3dd68225d0bbc858293cbf167b18d6374ebe79220a633d400176f1f6b46fd626acb252bf294aa
             db2acd59626a023a8e5ec53ced8685164c72ca3a2ec646812c6e61ffcba740ff15c054f0691e3a8d52c79c4
             4b7c1fc6c9704aed09ee0195bf09c5c5ba1173b7b1179be33fb3711d3b82e98f80521367a84303cb1236ebe
             8fc095683420a4de652c071d592759d42a0c9d2e73313cdfb71a071c936659433481a406308820e173b934f
             be877d873fec24d31a4d3bb9a3645055ca37bf710e214e5fc250d5964c66f18e4f05a3b93f42aa0753bd044
             e45b456c0e62fdcc1fcadef72930dc8a7a96b3e27d8eecea139a00aaf2fe79063ccb78d26d537625bdf0c4c
             8a68a04ed6f965eef7a6b1da5d8e26fc57f1047b97e2c594a9e420410977f22d1751b6d9498e8e457034049
             3c336bf86563ef03a15bc49b0ba6fe73201f64f0413ddb4d0cc5f6cf43389907e1df29e0cc388040e3371d0
             4814140f75cac08079431043222fb91f075d76be55cbe138e3b99a605c561c49dea50e253c8306c4f4f77d9
             96f898db64c5d8a0a15c6efa28b0934bf0b6f2b01950d877230fe4401078420fd6dd3"
        ),
        rsa_key.n.as_bytes(),
    );

    assert_eq!("user@example.com", key.comment());
}

#[test]
fn encode_dsa_openssh() {
    let key = Certificate::from_str(DSA_CERT_EXAMPLE).unwrap();
    assert_eq!(DSA_CERT_EXAMPLE.trim_end(), &key.to_string().unwrap());
}

#[cfg(feature = "ecdsa")]
#[test]
fn encode_ecdsa_p256_openssh() {
    let key = Certificate::from_str(ECDSA_P256_CERT_EXAMPLE).unwrap();
    assert_eq!(
        ECDSA_P256_CERT_EXAMPLE.trim_end(),
        &key.to_string().unwrap()
    );
}

#[test]
fn encode_ed25519_openssh() {
    let key = Certificate::from_str(ED25519_CERT_EXAMPLE).unwrap();
    assert_eq!(ED25519_CERT_EXAMPLE.trim_end(), &key.to_string().unwrap());
}

#[test]
fn encode_rsa_4096_openssh() {
    let key = Certificate::from_str(RSA_4096_CERT_EXAMPLE).unwrap();
    assert_eq!(RSA_4096_CERT_EXAMPLE.trim_end(), &key.to_string().unwrap());
}
