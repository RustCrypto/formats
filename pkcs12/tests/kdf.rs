#![cfg(feature = "kdf")]
/// Test cases for the key derivation functions.
/// All test cases have been verified against openssl's method `PKCS12_key_gen_utf8`.
/// See https://github.com/xemwebe/test_pkcs12_kdf for a sample program.
///
use hex_literal::hex;
use pkcs12::kdf::{Pkcs12KeyType, derive_key_utf8};

/// rounds=1 is the minimum valid value per RFC 7292 Appendix C (`iterations INTEGER (1..MAX)`).
/// Vectors generated with:
///   openssl kdf -keylen 32 -kdfopt digest:SHA256 \
///     -kdfopt hexpass:00670065004000e4006800650069006d0000 \
///     -kdfopt hexsalt:0102030405060708 -kdfopt iter:1 -kdfopt id:<N> PKCS12KDF
/// where hexpass is "ge@äheim" encoded as UTF-16BE with a 2-byte null terminator.
#[test]
fn pkcs12_key_derive_rounds_one_boundary() {
    const PASS: &str = "ge@äheim";
    const SALT: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(PASS, &SALT, Pkcs12KeyType::Mac, 1, 32).unwrap(),
        hex!("6490c5afd22f24a9346308c25babe8446c632c5937685bebc88feda260bad102")
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(PASS, &SALT, Pkcs12KeyType::EncryptionKey, 1, 32).unwrap(),
        hex!("637bbe1fe81bfc5abb031f335548d5dced0f0051c69cc2b9c28b2c66935085e5")
    );
}

/// rounds <= 0 must return an error; silently producing wrong output (one hash application
/// instead of the requested count) is a correctness failure.
#[test]
fn pkcs12_key_derive_zero_rounds_errors() {
    const PASS: &str = "ge@äheim";
    const SALT: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    assert!(
        derive_key_utf8::<sha2::Sha256>(PASS, &SALT, Pkcs12KeyType::Mac, 0, 32).is_err(),
        "rounds=0 must be rejected"
    );
    assert!(
        derive_key_utf8::<sha2::Sha256>(PASS, &SALT, Pkcs12KeyType::Mac, -1, 32).is_err(),
        "rounds=-1 must be rejected"
    );
    assert!(
        derive_key_utf8::<sha2::Sha256>(PASS, &SALT, Pkcs12KeyType::Mac, i32::MIN, 32).is_err(),
        "rounds=i32::MIN must be rejected"
    );
}

#[test]
fn pkcs12_key_derive_sha256() {
    const PASS_SHORT: &str = "ge@äheim";
    const SALT_INC: [u8; 8] = [0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8];

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(
            PASS_SHORT,
            &SALT_INC,
            Pkcs12KeyType::EncryptionKey,
            100,
            32
        )
        .unwrap(),
        hex!("fae4d4957a3cc781e1180b9d4fb79c1e0c8579b746a3177e5b0768a3118bf863")
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Iv, 100, 32).unwrap(),
        hex!("e5ff813bc6547de5155b14d2fada85b3201a977349db6e26ccc998d9e8f83d6c")
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Mac, 100, 32)
            .unwrap(),
        hex!("136355ed9434516682534f46d63956db5ff06b844702c2c1f3b46321e2524a4d")
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(
            PASS_SHORT,
            &SALT_INC,
            Pkcs12KeyType::EncryptionKey,
            100,
            20
        )
        .unwrap(),
        hex!("fae4d4957a3cc781e1180b9d4fb79c1e0c8579b7")
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Iv, 100, 20).unwrap(),
        hex!("e5ff813bc6547de5155b14d2fada85b3201a9773")
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Mac, 100, 20)
            .unwrap(),
        hex!("136355ed9434516682534f46d63956db5ff06b84")
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(
            PASS_SHORT,
            &SALT_INC,
            Pkcs12KeyType::EncryptionKey,
            100,
            12
        )
        .unwrap(),
        hex!("fae4d4957a3cc781e1180b9d")
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Iv, 100, 12).unwrap(),
        hex!("e5ff813bc6547de5155b14d2")
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Mac, 100, 12)
            .unwrap(),
        hex!("136355ed9434516682534f46")
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(
            PASS_SHORT,
            &SALT_INC,
            Pkcs12KeyType::EncryptionKey,
            1000,
            32
        )
        .unwrap(),
        hex!("2b95a0569b63f641fae1efca32e84db3699ab74540628ba66283b58cf5400527")
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Iv, 1000, 32)
            .unwrap(),
        hex!("6472c0ebad3fab4123e8b5ed7834de21eeb20187b3eff78a7d1cdffa4034851d")
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Mac, 1000, 32)
            .unwrap(),
        hex!("3f9113f05c30a996c4a516409bdac9d065f44296ccd52bb75de3fcfdbe2bf130")
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(
            PASS_SHORT,
            &SALT_INC,
            Pkcs12KeyType::EncryptionKey,
            1000,
            100
        )
        .unwrap(),
        hex!(
            "2b95a0569b63f641fae1efca32e84db3699ab74540628ba66283b58cf5400527d8d0ebe2ccbf768c51c4d8fbd1bb156be06c1c59cbb69e44052ffc37376fdb47b2de7f9e543de9d096d8e5474b220410ff1c5d8bb7e5bc0f61baeaa12fd0da1d7a970172"
        )
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(
            PASS_SHORT,
            &SALT_INC,
            Pkcs12KeyType::EncryptionKey,
            1000,
            200
        )
        .unwrap(),
        hex!(
            "2b95a0569b63f641fae1efca32e84db3699ab74540628ba66283b58cf5400527d8d0ebe2ccbf768c51c4d8fbd1bb156be06c1c59cbb69e44052ffc37376fdb47b2de7f9e543de9d096d8e5474b220410ff1c5d8bb7e5bc0f61baeaa12fd0da1d7a9701729cea6014d7fe62a2ed926dc36b61307f119d64edbceb5a9c58133bbf75ba0bef000a1a5180e4b1de7d89c89528bcb7899a1e46fd4da0d9de8f8e65e8d0d775e33d1247e76d596a34303161b219f39afda448bf518a2835fc5e28f0b55a1b6137a2c70cf7"
        )
    );
}

#[test]
fn pkcs12_key_derive_sha512() {
    const PASS_SHORT: &str = "ge@äheim";
    const SALT_INC: [u8; 8] = [0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8];

    assert_eq!(
        derive_key_utf8::<sha2::Sha512>(
            PASS_SHORT,
            &SALT_INC,
            Pkcs12KeyType::EncryptionKey,
            100,
            32
        )
        .unwrap(),
        hex!("b14a9f01bfd9dce4c9d66d2fe9937e5fd9f1afa59e370a6fa4fc81c1cc8ec8ee")
    );
}

#[test]
fn pkcs12_key_derive_whirlpool() {
    const PASS_SHORT: &str = "ge@äheim";
    const SALT_INC: [u8; 8] = [0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8];

    assert_eq!(
        derive_key_utf8::<whirlpool::Whirlpool>(
            PASS_SHORT,
            &SALT_INC,
            Pkcs12KeyType::EncryptionKey,
            100,
            32
        )
        .unwrap(),
        hex!("3324282adb468bff0734d3b7e399094ec8500cb5b0a3604055da107577aaf766")
    );
}

#[test]
fn pkcs12_key_derive_special_chars() {
    const PASS_SHORT: &str = "🔥";
    const SALT_INC: [u8; 8] = [0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8];

    assert!(
        derive_key_utf8::<sha2::Sha256>(
            PASS_SHORT,
            &SALT_INC,
            Pkcs12KeyType::EncryptionKey,
            100,
            32
        )
        .is_err()
    ); // Emoji is not in the Basic Multilingual Plane
}
