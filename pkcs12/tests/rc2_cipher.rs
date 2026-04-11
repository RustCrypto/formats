#![cfg(feature = "encryption")]
//! RC2 cipher-layer correctness tests.
//!
//! These tests verify that the `rc2` and `cbc` crates behave as required by
//! the pkcs12 RC2 decryption implementation **before** any pkcs12-level code
//! is exercised.  Every expected value is taken from an external oracle:
//!
//! - **ECB KATs 1–8**: RFC 2268 §5 test vectors (the normative RC2 spec).
//! - **CBC vectors**: OpenSSL 3.0.13 legacy provider (`openssl enc -rc2-cbc`
//!   / `-rc2-40-cbc`).
//!
//! The EKB sensitivity test (same 16-byte key, EKB 64 vs EKB 128) confirms
//! that the effective-key-bits parameter meaningfully changes the cipher
//! output; this is the property that distinguishes the two RC2 OIDs in
//! PKCS#12.
//!
//! # How these vectors were generated
//!
//! ```text
//! # ECB: verified against RFC 2268 §5, confirmed by running rc2 0.9.0 tests
//!
//! # CBC RC2-128 (key 16 bytes, EKB=128):
//! printf 'hello world' | openssl enc -rc2-cbc -nosalt \
//!   -K 88bca90e90875a7f0f79c384627bafb2 \
//!   -iv a72ab19138364bb8 \
//!   -provider legacy -provider default | xxd -p
//! # → b3468f91360fb65caa67d26844214355
//!
//! # CBC RC2-40 (key 5 bytes, EKB=40):
//! printf 'hello world' | openssl enc -rc2-40-cbc -nosalt \
//!   -K 99c05599b3 \
//!   -iv a72ab19138364bb8 \
//!   -provider legacy -provider default | xxd -p
//! # → 47bba99d52b3ac4b4f796cec88798b6f
//! ```

use cipher::{
    Block, BlockCipherEncrypt, BlockModeDecrypt, KeyInit, KeyIvInit, block_padding::Pkcs7,
};
use hex_literal::hex;
use rc2::Rc2;

type Rc2CbcDec = cbc::Decryptor<Rc2>;

/// Encrypt one RC2 block with an explicit effective key length.
fn ecb_ekb(key: &[u8], ekb: usize, pt: [u8; 8]) -> [u8; 8] {
    let cipher = Rc2::new_with_eff_key_len(key, ekb);
    let mut block: Block<Rc2> = pt.into();
    cipher.encrypt_block(&mut block);
    block.into()
}

/// Encrypt one RC2 block with `new_from_slice` (EKB = key_len × 8).
fn ecb(key: &[u8], pt: [u8; 8]) -> [u8; 8] {
    let cipher = Rc2::new_from_slice(key).unwrap();
    let mut block: Block<Rc2> = pt.into();
    cipher.encrypt_block(&mut block);
    block.into()
}

// ──────────────────────────────────────────────────────────────────────────────
// RFC 2268 §5 ECB known-answer tests
//
// Oracle: RFC 2268 "A Description of the RC2(r) Encryption Algorithm"
//         Section 5 "Test Vectors".
//
// Vectors 1–3 use `new_with_eff_key_len` with the explicit EKB from the RFC.
// Vectors 4–6 use `new_with_eff_key_len(key, 64)`.
// Vector 7 uses `new_from_slice` on the same 16-byte key as vector 6
//   (EKB = 16×8 = 128) — the ciphertext differs, proving EKB sensitivity.
// Vector 8 uses `new_with_eff_key_len(key, 129)` on a 33-byte key.
// ──────────────────────────────────────────────────────────────────────────────

/// RFC 2268 §5 vector 1: 8-byte all-zero key, EKB = 63.
#[test]
fn rfc2268_ecb_kat_1() {
    assert_eq!(ecb_ekb(&[0u8; 8], 63, [0u8; 8]), hex!("ebb773f993278eff"),);
}

/// RFC 2268 §5 vector 2: 8-byte all-0xFF key, EKB = 64, all-0xFF plaintext.
#[test]
fn rfc2268_ecb_kat_2() {
    assert_eq!(ecb_ekb(&[0xff; 8], 64, [0xff; 8]), hex!("278b27e42e2f0d49"),);
}

/// RFC 2268 §5 vector 3: 8-byte key beginning with 0x30, EKB = 64.
#[test]
fn rfc2268_ecb_kat_3() {
    assert_eq!(
        ecb_ekb(&hex!("3000000000000000"), 64, hex!("1000000000000001")),
        hex!("30649edf9be7d2c2"),
    );
}

/// RFC 2268 §5 vector 4: 1-byte key, EKB = 64.
#[test]
fn rfc2268_ecb_kat_4() {
    assert_eq!(ecb_ekb(&[0x88], 64, [0u8; 8]), hex!("61a8a244adacccf0"),);
}

/// RFC 2268 §5 vector 5: 7-byte key, EKB = 64.
#[test]
fn rfc2268_ecb_kat_5() {
    assert_eq!(
        ecb_ekb(&hex!("88bca90e90875a"), 64, [0u8; 8]),
        hex!("6ccf4308974c267f"),
    );
}

/// RFC 2268 §5 vector 6: 16-byte key, EKB = 64.
#[test]
fn rfc2268_ecb_kat_6() {
    assert_eq!(
        ecb_ekb(&hex!("88bca90e90875a7f0f79c384627bafb2"), 64, [0u8; 8]),
        hex!("1a807d272bbe5db1"),
    );
}

/// RFC 2268 §5 vector 7: same 16-byte key as vector 6, EKB = 128 (new_from_slice).
///
/// The ciphertext differs from vector 6, demonstrating that EKB is not just a
/// clamp but changes the key schedule in a way that alters the cipher output.
/// This is the property that distinguishes `pbeWithSHAAnd128BitRC2-CBC` (EKB=128)
/// from any hypothetical 16-byte RC2-64 scheme.
#[test]
fn rfc2268_ecb_kat_7() {
    assert_eq!(
        ecb(&hex!("88bca90e90875a7f0f79c384627bafb2"), [0u8; 8]),
        hex!("2269552ab0f85ca6"),
    );
}

/// RFC 2268 §5 vector 8: 33-byte key, EKB = 129.
#[test]
fn rfc2268_ecb_kat_8() {
    assert_eq!(
        ecb_ekb(
            &hex!("88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e"),
            129,
            [0u8; 8],
        ),
        hex!("5b78d3a43dfff1f1"),
    );
}

/// EKB sensitivity proof: vectors 6 and 7 use the identical 16-byte key but
/// different effective key lengths (64 vs 128); the ciphertexts must differ.
///
/// This confirms that passing the wrong EKB to RC2 produces wrong output, so
/// any implementation that ignores EKB would fail both this assertion and the
/// RFC KATs above.
#[test]
fn rfc2268_ekb_sensitivity() {
    let key = hex!("88bca90e90875a7f0f79c384627bafb2");
    let ct_ekb64 = ecb_ekb(&key, 64, [0u8; 8]);
    let ct_ekb128 = ecb(&key, [0u8; 8]);
    assert_ne!(
        ct_ekb64, ct_ekb128,
        "RC2 with EKB=64 and EKB=128 must produce different ciphertext for the same key"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// CBC decryption vectors
//
// Oracle: OpenSSL 3.0.13 legacy provider.
// Both vectors use PKCS#7 padding and IV = a72ab19138364bb8 (derived from the
// drh-consultancy "smeg" salt via PKCS12KDF ID=2, iter=1).
// ──────────────────────────────────────────────────────────────────────────────

const IV: [u8; 8] = hex!("a72ab19138364bb8");

/// RC2-128-CBC: 16-byte key (EKB=128), decrypt "hello world".
///
/// Oracle: OpenSSL 3.0.13
/// `printf 'hello world' | openssl enc -rc2-cbc -nosalt \
///   -K 88bca90e90875a7f0f79c384627bafb2 -iv a72ab19138364bb8 \
///   -provider legacy -provider default | xxd -p`
/// Output: b3468f91360fb65caa67d26844214355
#[test]
fn rc2_128_cbc_decrypt_openssl() {
    let key = hex!("88bca90e90875a7f0f79c384627bafb2");
    let mut ct = hex!("b3468f91360fb65caa67d26844214355").to_vec();
    let pt = Rc2CbcDec::new_from_slices(&key, &IV)
        .unwrap()
        .decrypt_padded::<Pkcs7>(&mut ct)
        .unwrap();
    assert_eq!(pt, b"hello world");
}

/// RC2-40-CBC: 5-byte key (EKB=40), decrypt "hello world".
///
/// Key is the first 5 bytes of the drh-consultancy "smeg" PKCS12KDF output
/// (ID=1, iter=1, keylen=5), also independently confirmed by OpenSSL PKCS12KDF.
///
/// Oracle: OpenSSL 3.0.13
/// `printf 'hello world' | openssl enc -rc2-40-cbc -nosalt \
///   -K 99c05599b3 -iv a72ab19138364bb8 \
///   -provider legacy -provider default | xxd -p`
/// Output: 47bba99d52b3ac4b4f796cec88798b6f
#[test]
fn rc2_40_cbc_decrypt_openssl() {
    let key = hex!("99c05599b3");
    let mut ct = hex!("47bba99d52b3ac4b4f796cec88798b6f").to_vec();
    let pt = Rc2CbcDec::new_from_slices(&key, &IV)
        .unwrap()
        .decrypt_padded::<Pkcs7>(&mut ct)
        .unwrap();
    assert_eq!(pt, b"hello world");
}
