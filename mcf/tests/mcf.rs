//! Modular Crypt Format integration tests.

#![cfg(feature = "alloc")]

use hex_literal::hex;
use mcf::{Base64, McfHash};

#[test]
fn parse_malformed() {
    assert!("Hello, world!".parse::<McfHash>().is_err());
    assert!("$".parse::<McfHash>().is_err());
    assert!("$foo".parse::<McfHash>().is_err());
    assert!("$$".parse::<McfHash>().is_err());
    assert!("$$foo".parse::<McfHash>().is_err());
    assert!("$foo$".parse::<McfHash>().is_err());
    assert!("$-$foo".parse::<McfHash>().is_err());
    assert!("$foo-$bar".parse::<McfHash>().is_err());
    assert!("$-foo$bar".parse::<McfHash>().is_err());
}

#[test]
fn parse_sha512_hash() {
    let s = "$6$rounds=100000$exn6tVc2j/MZD8uG$BI1Xh8qQSK9J4m14uwy7abn.ctj/TIAzlaVCto0MQrOFIeTXsc1iwzH16XEWo/a7c7Y9eVJvufVzYAs4EsPOy0";
    let hash: McfHash = s.parse().unwrap();
    assert_eq!("6", hash.id());

    let mut fields = hash.fields();
    assert_eq!("rounds=100000", fields.next().unwrap().as_str());

    let salt = fields.next().unwrap();
    assert_eq!("exn6tVc2j/MZD8uG", salt.as_str());

    let salt_bytes = salt.decode_base64(Base64::ShaCrypt).unwrap();
    assert_eq!(&hex!("6a3f237988126f80958fa24b"), salt_bytes.as_slice());

    let hash = fields.next().unwrap();
    assert_eq!(
        "BI1Xh8qQSK9J4m14uwy7abn.ctj/TIAzlaVCto0MQrOFIeTXsc1iwzH16XEWo/a7c7Y9eVJvufVzYAs4EsPOy0",
        hash.as_str()
    );

    let hash_bytes = hash.decode_base64(Base64::ShaCrypt).unwrap();
    assert_eq!(
        &hex!(
            "0d358cad62739eb554863c183aef27e6390368fe061fc5fcb1193a392d60dcad4594fa8d383ab8fc3f0dc8088974602668422e6a58edfa1afe24831b10be69be"
        ),
        hash_bytes.as_slice()
    );

    assert_eq!(None, fields.next());
}
