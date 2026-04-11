#![cfg(feature = "kdf")]
/// Test cases for the key derivation functions.
/// All test cases have been verified against openssl's method `PKCS12_key_gen_utf8`.
/// See https://github.com/xemwebe/test_pkcs12_kdf for a sample program.
///
use hex_literal::hex;
use pkcs12::kdf::{Pkcs12KeyType, derive_key_utf8};

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
        .unwrap()
        .as_slice(),
        hex!("fae4d4957a3cc781e1180b9d4fb79c1e0c8579b746a3177e5b0768a3118bf863").as_slice()
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Iv, 100, 32)
            .unwrap()
            .as_slice(),
        hex!("e5ff813bc6547de5155b14d2fada85b3201a977349db6e26ccc998d9e8f83d6c").as_slice()
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Mac, 100, 32)
            .unwrap()
            .as_slice(),
        hex!("136355ed9434516682534f46d63956db5ff06b844702c2c1f3b46321e2524a4d").as_slice()
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(
            PASS_SHORT,
            &SALT_INC,
            Pkcs12KeyType::EncryptionKey,
            100,
            20
        )
        .unwrap()
        .as_slice(),
        hex!("fae4d4957a3cc781e1180b9d4fb79c1e0c8579b7").as_slice()
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Iv, 100, 20)
            .unwrap()
            .as_slice(),
        hex!("e5ff813bc6547de5155b14d2fada85b3201a9773").as_slice()
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Mac, 100, 20)
            .unwrap()
            .as_slice(),
        hex!("136355ed9434516682534f46d63956db5ff06b84").as_slice()
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(
            PASS_SHORT,
            &SALT_INC,
            Pkcs12KeyType::EncryptionKey,
            100,
            12
        )
        .unwrap()
        .as_slice(),
        hex!("fae4d4957a3cc781e1180b9d").as_slice()
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Iv, 100, 12)
            .unwrap()
            .as_slice(),
        hex!("e5ff813bc6547de5155b14d2").as_slice()
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Mac, 100, 12)
            .unwrap()
            .as_slice(),
        hex!("136355ed9434516682534f46").as_slice()
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(
            PASS_SHORT,
            &SALT_INC,
            Pkcs12KeyType::EncryptionKey,
            1000,
            32
        )
        .unwrap()
        .as_slice(),
        hex!("2b95a0569b63f641fae1efca32e84db3699ab74540628ba66283b58cf5400527").as_slice()
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Iv, 1000, 32)
            .unwrap()
            .as_slice(),
        hex!("6472c0ebad3fab4123e8b5ed7834de21eeb20187b3eff78a7d1cdffa4034851d").as_slice()
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(PASS_SHORT, &SALT_INC, Pkcs12KeyType::Mac, 1000, 32)
            .unwrap()
            .as_slice(),
        hex!("3f9113f05c30a996c4a516409bdac9d065f44296ccd52bb75de3fcfdbe2bf130").as_slice()
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(
            PASS_SHORT,
            &SALT_INC,
            Pkcs12KeyType::EncryptionKey,
            1000,
            100
        )
        .unwrap()
        .as_slice(),
        hex!(
            "2b95a0569b63f641fae1efca32e84db3699ab74540628ba66283b58cf5400527d8d0ebe2ccbf768c51c4d8fbd1bb156be06c1c59cbb69e44052ffc37376fdb47b2de7f9e543de9d096d8e5474b220410ff1c5d8bb7e5bc0f61baeaa12fd0da1d7a970172"
        )
        .as_slice()
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(
            PASS_SHORT,
            &SALT_INC,
            Pkcs12KeyType::EncryptionKey,
            1000,
            200
        )
        .unwrap()
        .as_slice(),
        hex!(
            "2b95a0569b63f641fae1efca32e84db3699ab74540628ba66283b58cf5400527d8d0ebe2ccbf768c51c4d8fbd1bb156be06c1c59cbb69e44052ffc37376fdb47b2de7f9e543de9d096d8e5474b220410ff1c5d8bb7e5bc0f61baeaa12fd0da1d7a9701729cea6014d7fe62a2ed926dc36b61307f119d64edbceb5a9c58133bbf75ba0bef000a1a5180e4b1de7d89c89528bcb7899a1e46fd4da0d9de8f8e65e8d0d775e33d1247e76d596a34303161b219f39afda448bf518a2835fc5e28f0b55a1b6137a2c70cf7"
        )
        .as_slice()
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
        .unwrap()
        .as_slice(),
        hex!("b14a9f01bfd9dce4c9d66d2fe9937e5fd9f1afa59e370a6fa4fc81c1cc8ec8ee").as_slice()
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
        .unwrap()
        .as_slice(),
        hex!("3324282adb468bff0734d3b7e399094ec8500cb5b0a3604055da107577aaf766").as_slice()
    );
}

/// Empty password: derive_key_utf8("") → BmpString null-terminates to [0x00, 0x00],
/// so the password contribution to I is one block of that two-byte sequence repeated.
/// Vectors verified with `openssl kdf -kdfopt hexpass:0000 ...`.
#[test]
fn pkcs12_key_derive_empty_password() {
    const SALT_INC: [u8; 8] = [0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8];

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>("", &SALT_INC, Pkcs12KeyType::EncryptionKey, 100, 32)
            .unwrap()
            .as_slice(),
        hex!("4a8bd650518803030f2e71ae5665d0f8c59f498feede48a0ccad0e027ef1b4e1").as_slice()
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>("", &SALT_INC, Pkcs12KeyType::Iv, 100, 32)
            .unwrap()
            .as_slice(),
        hex!("43de84225ec6ee96207e2d3d00d6da341ff8750da1ce792090cc4f7f4be6906b").as_slice()
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>("", &SALT_INC, Pkcs12KeyType::Mac, 100, 32)
            .unwrap()
            .as_slice(),
        hex!("b96a85b509ed9ce0a5d28853c4221291c7c05fe01c4837938893128c4f8c866c").as_slice()
    );

    // Verify key_len=1 is a prefix of key_len=32 (algorithm is a prefix construction).
    assert_eq!(
        derive_key_utf8::<sha2::Sha256>("", &SALT_INC, Pkcs12KeyType::EncryptionKey, 100, 1)
            .unwrap()
            .as_slice(),
        hex!("4a").as_slice()
    );
}

/// Long salt (72 bytes, two SHA-256 blocks of 64): exercises the S-padding loop when
/// the salt overflows a single diversifier block.
/// Vectors verified with `openssl kdf -kdfopt hexsalt:<72 bytes> ...`.
#[test]
fn pkcs12_key_derive_long_salt() {
    const PASS: &str = "ge@\u{00e4}heim";
    // 72-byte salt (0x01..=0x48): spans two 64-byte SHA-256 blocks so slen=128.
    const SALT_LONG: [u8; 72] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
        0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
        0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    ];

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(PASS, &SALT_LONG, Pkcs12KeyType::EncryptionKey, 100, 32)
            .unwrap()
            .as_slice(),
        hex!("dcbd2bae16461c4e784d7fea6d186b8f8044257b354209caace2df99b4f1c5a9").as_slice()
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(PASS, &SALT_LONG, Pkcs12KeyType::Iv, 100, 32)
            .unwrap()
            .as_slice(),
        hex!("8e3d55eb2c664926aacd16312aff0b33ec793a2189468704bd63e470bddedcae").as_slice()
    );

    assert_eq!(
        derive_key_utf8::<sha2::Sha256>(PASS, &SALT_LONG, Pkcs12KeyType::Mac, 100, 32)
            .unwrap()
            .as_slice(),
        hex!("a4f6653f89f2a599dd07e02277fdebdabc1fa22e205a73e23cd406980b6784d4").as_slice()
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
