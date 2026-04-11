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

// ──────────────────────────────────────────────────────────────────────────────
// SHA-1 KDF vectors (drh-consultancy, via Bouncy Castle PKCS12Test.java)
//
// These are the canonical interoperability test vectors for the RFC 7292
// Appendix B.2 KDF with SHA-1.  The original source is a page by
// David Hopwood published at drh-consultancy.demon.co.uk (now unreachable),
// but the values are preserved verbatim in:
//
//   - Bouncy Castle: PKCS12Test.java, class PKCS12VectorTest
//   - OpenSSL: test/evppbe_pkcs12.txt
//
// Both sources agree on all 10 vectors.  The values here were independently
// confirmed by running:
//
//   openssl kdf -keylen <N> -kdfopt digest:SHA1 \
//     -kdfopt hexpass:<hexpass> -kdfopt hexsalt:<hexsalt> \
//     -kdfopt iter:<i> -kdfopt id:<id> PKCS12KDF
//
// where hexpass is the password encoded as BMP (UTF-16BE + 2-byte null
// terminator), as required by RFC 7292 §B.1.
//
// Vectors 1–5: password = "smeg"  (hexpass = 0073006d006500670000)
// Vectors 6–10: password = "queeg" (hexpass = 007100750065006500670000)
// Salt for all: 0x0102030405060708090a0b0c0d0e0f10 (16 bytes)
// ──────────────────────────────────────────────────────────────────────────────

/// drh-consultancy / BC PKCS12Test vectors 1–5, password = "smeg".
///
/// Key lengths 24 and 20 mirror the 3DES key (24 bytes) and HMAC-SHA1 MAC key
/// (20 bytes) used in the BC reference tests.  All values confirmed against
/// OpenSSL 3.0.13 `openssl kdf PKCS12KDF`.
#[test]
fn pkcs12_kdf_sha1_drh_smeg() {
    const PASS: &str = "smeg";
    const SALT: [u8; 16] = hex!("0102030405060708090a0b0c0d0e0f10");

    // Vector 1: ID=1 (encryption key), iter=1, keylen=24
    assert_eq!(
        derive_key_utf8::<sha1::Sha1>(PASS, &SALT, Pkcs12KeyType::EncryptionKey, 1, 24).unwrap(),
        hex!("99c05599b3bd11688ea5e61f6d5c34c6c8442f86169a68a5"),
    );

    // Vector 2: ID=2 (IV), iter=1, keylen=8
    assert_eq!(
        derive_key_utf8::<sha1::Sha1>(PASS, &SALT, Pkcs12KeyType::Iv, 1, 8).unwrap(),
        hex!("a72ab19138364bb8"),
    );

    // Vector 3: ID=3 (MAC key), iter=1, keylen=20
    assert_eq!(
        derive_key_utf8::<sha1::Sha1>(PASS, &SALT, Pkcs12KeyType::Mac, 1, 20).unwrap(),
        hex!("b557ad8e9a6ef5822add6e295e059be24c6721d8"),
    );

    // Vector 4: ID=1 (encryption key), iter=2, keylen=24
    assert_eq!(
        derive_key_utf8::<sha1::Sha1>(PASS, &SALT, Pkcs12KeyType::EncryptionKey, 2, 24).unwrap(),
        hex!("b8dda13c333a860b697ebc2fb3f4c7cb60cdfccf34344bf3"),
    );

    // Vector 5: ID=3 (MAC key), iter=2, keylen=20
    assert_eq!(
        derive_key_utf8::<sha1::Sha1>(PASS, &SALT, Pkcs12KeyType::Mac, 2, 20).unwrap(),
        hex!("ca876a9516fd732f1352e4348d289c0a23b00983"),
    );
}

/// drh-consultancy / BC PKCS12Test vectors 6–10, password = "queeg".
///
/// All values confirmed against OpenSSL 3.0.13 `openssl kdf PKCS12KDF`.
#[test]
fn pkcs12_kdf_sha1_drh_queeg() {
    const PASS: &str = "queeg";
    const SALT: [u8; 16] = hex!("0102030405060708090a0b0c0d0e0f10");

    // Vector 6: ID=1 (encryption key), iter=1, keylen=24
    assert_eq!(
        derive_key_utf8::<sha1::Sha1>(PASS, &SALT, Pkcs12KeyType::EncryptionKey, 1, 24).unwrap(),
        hex!("125b270e097b07f098be169ef63384c7a185227c43bfc87e"),
    );

    // Vector 7: ID=2 (IV), iter=1, keylen=8
    assert_eq!(
        derive_key_utf8::<sha1::Sha1>(PASS, &SALT, Pkcs12KeyType::Iv, 1, 8).unwrap(),
        hex!("9595d1e27c653729"),
    );

    // Vector 8: ID=3 (MAC key), iter=1, keylen=20
    assert_eq!(
        derive_key_utf8::<sha1::Sha1>(PASS, &SALT, Pkcs12KeyType::Mac, 1, 20).unwrap(),
        hex!("043399c86c7c73a11fc4a623612bd9100ca30996"),
    );

    // Vector 9: ID=1 (encryption key), iter=2, keylen=24
    assert_eq!(
        derive_key_utf8::<sha1::Sha1>(PASS, &SALT, Pkcs12KeyType::EncryptionKey, 2, 24).unwrap(),
        hex!("753ff384647dd981eb02d25ae82d36e87ba0b4b907a618e1"),
    );

    // Vector 10: ID=3 (MAC key), iter=2, keylen=20
    assert_eq!(
        derive_key_utf8::<sha1::Sha1>(PASS, &SALT, Pkcs12KeyType::Mac, 2, 20).unwrap(),
        hex!("424ef1a8e5431d2bbb3f19734d3dca4d77ada7be"),
    );
}

/// RC2-specific PKCS12KDF key sizes, password = "smeg", iter = 1.
///
/// These vectors cover the exact key lengths used by the two RC2 OIDs in
/// PKCS#12:
///   - `pbeWithSHAAnd128BitRC2-CBC` (OID 1.2.840.113549.1.12.1.5): keylen=16
///   - `pbeWithSHAAnd40BitRC2-CBC`  (OID 1.2.840.113549.1.12.1.6): keylen=5
///   - RC2 CBC IV: keylen=8 (same as 3DES IV; shared with vector 2 above)
///
/// The 16-byte and 5-byte outputs are the leading bytes of the 24-byte
/// vector-1 output (since SHA-1 produces 20 bytes per round and both 16 and 5
/// fit within a single round, the KDF output is a prefix of the longer output).
/// This relationship was verified by running `openssl kdf PKCS12KDF` with
/// keylen=16 and keylen=5 independently, confirming both values.
///
/// Oracle: OpenSSL 3.0.13, command:
/// `openssl kdf -keylen <N> -kdfopt digest:SHA1 \
///   -kdfopt hexpass:0073006d006500670000 \
///   -kdfopt hexsalt:0102030405060708090a0b0c0d0e0f10 \
///   -kdfopt iter:1 -kdfopt id:1 PKCS12KDF`
#[test]
fn pkcs12_kdf_sha1_rc2_key_sizes() {
    const PASS: &str = "smeg";
    const SALT: [u8; 16] = hex!("0102030405060708090a0b0c0d0e0f10");

    // RC2-128 key (16 bytes) — first 16 bytes of the 24-byte vector-1 output
    assert_eq!(
        derive_key_utf8::<sha1::Sha1>(PASS, &SALT, Pkcs12KeyType::EncryptionKey, 1, 16).unwrap(),
        hex!("99c05599b3bd11688ea5e61f6d5c34c6"),
    );

    // RC2-40 key (5 bytes) — first 5 bytes of the 24-byte vector-1 output
    assert_eq!(
        derive_key_utf8::<sha1::Sha1>(PASS, &SALT, Pkcs12KeyType::EncryptionKey, 1, 5).unwrap(),
        hex!("99c05599b3"),
    );

    // RC2 CBC IV (8 bytes) — same as vector-2 above, included here for completeness
    assert_eq!(
        derive_key_utf8::<sha1::Sha1>(PASS, &SALT, Pkcs12KeyType::Iv, 1, 8).unwrap(),
        hex!("a72ab19138364bb8"),
    );
}
