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

/// SHA-1 KDF vectors for pbeWithSHAAnd3-KeyTripleDES-CBC (OID 1.2.840.113549.1.12.1.3).
/// All expected values generated with OpenSSL 3.0 using hexpass (BMP-encoded password):
///
///   PASSWORD_HEX=$(python3 -c \
///     "s='password'; print(''.join(f'{ord(c):04x}' for c in s) + '0000')")
///   openssl kdf -provider legacy -provider default -digest SHA1 \
///     -kdfopt hexpass:$PASSWORD_HEX -kdfopt hexsalt:<salt> \
///     -kdfopt iter:<iter> -kdfopt id:<id> -keylen <len> PKCS12KDF
///
/// IMPORTANT: use `hexpass:` (BMP/UTF-16BE + null terminator), NOT `pass:`.
/// The `pass:` flag passes raw ASCII bytes, which diverges from the PKCS#12
/// spec (and from `derive_key_utf8`) for all passwords, including pure ASCII.
/// Cross-validated: SHA-256 vectors match upstream kdf.rs test expectations.
#[test]
fn pkcs12_key_derive_sha1_password_2048() {
    // password="password", salt=00 01 02 03 04 05 06 07, iter=2048
    const SALT: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

    // ID=1 (EncryptionKey), 24 bytes — 3DES key length
    assert_eq!(
        derive_key_utf8::<sha1::Sha1>("password", &SALT, Pkcs12KeyType::EncryptionKey, 2048, 24)
            .unwrap(),
        hex!("d0fced80aa6413a0b14c5c21d5869a78e3bbf36d4fd2a7fa")
    );

    // ID=2 (IV), 8 bytes — 3DES IV length
    assert_eq!(
        derive_key_utf8::<sha1::Sha1>("password", &SALT, Pkcs12KeyType::Iv, 2048, 8).unwrap(),
        hex!("ea35854d10fc84f3")
    );

    // ID=3 (MAC), 20 bytes — SHA-1 HMAC key length
    assert_eq!(
        derive_key_utf8::<sha1::Sha1>("password", &SALT, Pkcs12KeyType::Mac, 2048, 20).unwrap(),
        hex!("01a2ae2f9281dea66b1f07f68a0c030d170d7d9b")
    );
}

#[test]
fn pkcs12_key_derive_sha1_hunter2_1024() {
    // password="hunter2", salt=de ad be ef ca fe ba be, iter=1024
    const SALT: [u8; 8] = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe];

    // ID=1 (EncryptionKey), 24 bytes
    assert_eq!(
        derive_key_utf8::<sha1::Sha1>("hunter2", &SALT, Pkcs12KeyType::EncryptionKey, 1024, 24)
            .unwrap(),
        hex!("443402ec5909c0b28f3b919115f945afd5fce925713f8c73")
    );

    // ID=2 (IV), 8 bytes
    assert_eq!(
        derive_key_utf8::<sha1::Sha1>("hunter2", &SALT, Pkcs12KeyType::Iv, 1024, 8).unwrap(),
        hex!("28830f9a1d8052c2")
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

/// A non-positive round count is malformed (RFC 7292 §B.2 requires at least
/// one iteration).  `derive_key_utf8` must return `Err` for `rounds <= 0`
/// rather than silently producing single-hash output.
#[test]
fn pkcs12_key_derive_nonpositive_rounds_fails() {
    const SALT: [u8; 8] = [0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8];

    assert!(
        derive_key_utf8::<sha2::Sha256>("password", &SALT, Pkcs12KeyType::EncryptionKey, 0, 32)
            .is_err(),
        "rounds=0 must return Err"
    );
    assert!(
        derive_key_utf8::<sha2::Sha256>("password", &SALT, Pkcs12KeyType::EncryptionKey, -1, 32)
            .is_err(),
        "rounds=-1 must return Err"
    );
}
