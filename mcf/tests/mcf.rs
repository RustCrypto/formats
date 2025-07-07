//! Modular Crypt Format integration tests.

use mcf::McfHash;

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
    assert_eq!("exn6tVc2j/MZD8uG", fields.next().unwrap().as_str());
    assert_eq!(
        "BI1Xh8qQSK9J4m14uwy7abn.ctj/TIAzlaVCto0MQrOFIeTXsc1iwzH16XEWo/a7c7Y9eVJvufVzYAs4EsPOy0",
        fields.next().unwrap().as_str()
    );
    assert_eq!(None, fields.next());
}
