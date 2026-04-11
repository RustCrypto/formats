//! Integration tests for RC2-CBC PKCS#12 shrouded key bag decryption.
//!
//! Covers both OIDs:
//! - `pbeWithSHAAnd128BitRC2-CBC` (OID 1.2.840.113549.1.12.1.5)
//! - `pbeWithSHAAnd40BitRC2-CBC`  (OID 1.2.840.113549.1.12.1.6)
//!
//! Test fixtures are in `tests/data/`; see `tests/data/README.md` for
//! generation commands and oracle fingerprints.
#![cfg(feature = "encryption")]

use der::{
    Decode, Encode,
    asn1::{Any, ContextSpecific, OctetString},
};
use hex_literal::hex;
use pkcs8::PrivateKeyInfoOwned;
use pkcs12::{
    AuthenticatedSafe, PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC,
    PKCS_12_PBE_WITH_SHAAND40_BIT_RC2_CBC, PKCS_12_PBE_WITH_SHAAND128_BIT_RC2_CBC,
    PKCS_12_PKCS8_KEY_BAG_OID,
    pbe_params::{EncryptedPrivateKeyInfo, Pkcs12PbeParams},
    pfx::Pfx,
    safe_bag::SafeContents,
};
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;

/// SHA-256 of the PrivateKeyInfo DER blob for all `hunter2` RSA fixtures
/// (iter=1, iter=2048, iter=100000 — all encrypt the same RSA-2048 key).
///
/// Oracle: independently confirmed by
///   - `openssl pkcs12 -legacy ... -nodes | openssl pkcs8 -nocrypt -topk8 -outform DER | sha256sum`
///   - pyca/cryptography `pkcs12.load_key_and_certificates` + `private_bytes(DER, PKCS8, NoEncryption)`
const RSA_KEY_DER_SHA256: [u8; 32] =
    hex!("ccdf40f8d0881c5aa3cb9c563399f5fb590f7615ef7da4d057031bc809c9190d");

// OIDs used in assertions.
const ID_DATA: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const RSA_ENCRYPTION: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

// ── helpers ───────────────────────────────────────────────────────────────────

/// Walk a PFX and return the first `pkcs8ShroudedKeyBag` found inside any
/// plaintext (`data`) `ContentInfo`.  Panics if none is found.
fn find_shrouded_key(pfx_bytes: &[u8]) -> EncryptedPrivateKeyInfo {
    let pfx = Pfx::from_der(pfx_bytes).expect("parse Pfx");
    let pfx_content_der = pfx.auth_safe.content.to_der().unwrap();
    let auth_safes_os = OctetString::from_der(&pfx_content_der).unwrap();
    let auth_safes: AuthenticatedSafe<'_> =
        AuthenticatedSafe::from_der(auth_safes_os.as_bytes()).unwrap();

    for ci in auth_safes {
        if ci.content_type != ID_DATA {
            continue;
        }
        let ci_der = ci.content.to_der().unwrap();
        let safe_os = OctetString::from_der(&ci_der).unwrap();
        let bags = SafeContents::from_der(safe_os.as_bytes()).unwrap();
        for bag in bags {
            if bag.bag_id != PKCS_12_PKCS8_KEY_BAG_OID {
                continue;
            }
            // SafeBag.bagValue is `[0] EXPLICIT ANY` (RFC 7292 §4.2), so
            // bag.bag_value carries the raw DER including the context-specific
            // [0] tag.  ContextSpecific<T> strips that outer tag before
            // decoding T; using EncryptedPrivateKeyInfo::from_der directly
            // would fail because the leading byte is 0xa0, not a SEQUENCE tag.
            let cs: ContextSpecific<EncryptedPrivateKeyInfo> =
                ContextSpecific::from_der(&bag.bag_value).unwrap();
            return cs.value;
        }
    }
    panic!("no pkcs8ShroudedKeyBag found in PFX");
}

/// Decrypt a RC2-128-CBC shrouded key bag from `pfx_bytes` and return the
/// raw PKCS#8 `PrivateKeyInfo` DER.  Panics on any error.
fn decrypt_rc2_128(pfx_bytes: &[u8], password: &str) -> Vec<u8> {
    find_shrouded_key(pfx_bytes)
        .decrypt_rc2_128_cbc(password)
        .expect("decrypt_rc2_128_cbc failed")
        .to_vec()
}

/// Decrypt a RC2-40-CBC shrouded key bag from `pfx_bytes` and return the
/// raw PKCS#8 `PrivateKeyInfo` DER.  Panics on any error.
fn decrypt_rc2_40(pfx_bytes: &[u8], password: &str) -> Vec<u8> {
    find_shrouded_key(pfx_bytes)
        .decrypt_rc2_40_cbc(password)
        .expect("decrypt_rc2_40_cbc failed")
        .to_vec()
}

// ── RC2-128 happy-path tests ───────────────────────────────────────────────────

/// Decrypt with 1 KDF iteration.
#[test]
fn decrypt_rc2_128_iter1() {
    let pki_der = decrypt_rc2_128(include_bytes!("data/test-rc2-128-iter1.p12"), "hunter2");
    let pki = PrivateKeyInfoOwned::from_der(&pki_der).expect("parse PrivateKeyInfo");
    assert_eq!(pki.algorithm.oid, RSA_ENCRYPTION);
    assert!(!pki.private_key.as_bytes().is_empty());
}

/// Decrypt with 2048 KDF iterations (standard OpenSSL default).
#[test]
fn decrypt_rc2_128_iter2048() {
    let pki_der = decrypt_rc2_128(include_bytes!("data/test-rc2-128-iter2048.p12"), "hunter2");
    let pki = PrivateKeyInfoOwned::from_der(&pki_der).expect("parse PrivateKeyInfo");
    assert_eq!(pki.algorithm.oid, RSA_ENCRYPTION);
    assert!(!pki.private_key.as_bytes().is_empty());
}

/// Decrypt with 100 000 KDF iterations.
#[test]
fn decrypt_rc2_128_iter100000() {
    let pki_der = decrypt_rc2_128(
        include_bytes!("data/test-rc2-128-iter100000.p12"),
        "hunter2",
    );
    let pki = PrivateKeyInfoOwned::from_der(&pki_der).expect("parse PrivateKeyInfo");
    assert_eq!(pki.algorithm.oid, RSA_ENCRYPTION);
    assert!(!pki.private_key.as_bytes().is_empty());
}

/// **Key consistency**: all three RC2-128 fixtures encrypt the same key.
/// If the KDF or decryption differs by iteration count, outputs diverge.
#[test]
fn decrypt_rc2_128_all_iter_variants_agree() {
    let k1 = decrypt_rc2_128(include_bytes!("data/test-rc2-128-iter1.p12"), "hunter2");
    let k2048 = decrypt_rc2_128(include_bytes!("data/test-rc2-128-iter2048.p12"), "hunter2");
    let k100k = decrypt_rc2_128(
        include_bytes!("data/test-rc2-128-iter100000.p12"),
        "hunter2",
    );
    assert_eq!(
        k1, k2048,
        "iter=1 and iter=2048 must decrypt to the same key"
    );
    assert_eq!(
        k1, k100k,
        "iter=1 and iter=100000 must decrypt to the same key"
    );
}

// ── RC2-128 error-path tests ───────────────────────────────────────────────────

/// Wrong password must produce `Err`.
#[test]
fn decrypt_rc2_128_wrong_password() {
    let epki = find_shrouded_key(include_bytes!("data/test-rc2-128-iter2048.p12"));
    assert!(
        epki.decrypt_rc2_128_cbc("wrong-password").is_err(),
        "RC2-128 decryption with wrong password must return Err"
    );
}

// ── RC2-40 happy-path tests ────────────────────────────────────────────────────

/// Decrypt RC2-40 fixture with 2048 iterations.
#[test]
fn decrypt_rc2_40_iter2048() {
    let pki_der = decrypt_rc2_40(include_bytes!("data/test-rc2-40-iter2048.p12"), "hunter2");
    let pki = PrivateKeyInfoOwned::from_der(&pki_der).expect("parse PrivateKeyInfo");
    assert_eq!(pki.algorithm.oid, RSA_ENCRYPTION);
    assert!(!pki.private_key.as_bytes().is_empty());
}

// ── RC2-40 error-path tests ────────────────────────────────────────────────────

/// Wrong password for RC2-40.
#[test]
fn decrypt_rc2_40_wrong_password() {
    let epki = find_shrouded_key(include_bytes!("data/test-rc2-40-iter2048.p12"));
    assert!(
        epki.decrypt_rc2_40_cbc("wrong-password").is_err(),
        "RC2-40 decryption with wrong password must return Err"
    );
}

// ── external oracle fingerprint checks ────────────────────────────────────────

/// **Fingerprint oracle**: the SHA-256 of the decrypted PrivateKeyInfo DER
/// must match the value independently produced by OpenSSL and pyca/cryptography.
///
/// Oracle documented in `tests/data/README.md`.
#[test]
fn fingerprint_oracle_rc2_128() {
    for (path, label) in [
        (
            include_bytes!("data/test-rc2-128-iter1.p12").as_slice(),
            "iter=1",
        ),
        (
            include_bytes!("data/test-rc2-128-iter2048.p12").as_slice(),
            "iter=2048",
        ),
        (
            include_bytes!("data/test-rc2-128-iter100000.p12").as_slice(),
            "iter=100000",
        ),
    ] {
        let pki_der = decrypt_rc2_128(path, "hunter2");
        let hash = Sha256::digest(&pki_der);
        assert_eq!(
            hash.as_slice(),
            RSA_KEY_DER_SHA256,
            "RC2-128 {label}: PrivateKeyInfo DER sha256 does not match oracle"
        );
    }
}

/// Same oracle, RC2-40 variant.
#[test]
fn fingerprint_oracle_rc2_40() {
    let pki_der = decrypt_rc2_40(include_bytes!("data/test-rc2-40-iter2048.p12"), "hunter2");
    let hash = Sha256::digest(&pki_der);
    assert_eq!(
        hash.as_slice(),
        RSA_KEY_DER_SHA256,
        "RC2-40 iter=2048: PrivateKeyInfo DER sha256 does not match oracle"
    );
}

// ── OID mismatch / key-size binding tests ─────────────────────────────────────

/// Passing a RC2-128-encrypted `EncryptedPrivateKeyInfo` to `decrypt_rc2_40_cbc`
/// must return `Err` (OID mismatch detected before any key material is used).
#[test]
fn oid_swap_rc2_128_into_decrypt_rc2_40_returns_err() {
    let epki = find_shrouded_key(include_bytes!("data/test-rc2-128-iter2048.p12"));
    assert_eq!(
        epki.encryption_algorithm.oid, PKCS_12_PBE_WITH_SHAAND128_BIT_RC2_CBC,
        "precondition: fixture must have RC2-128 OID"
    );
    assert!(
        epki.decrypt_rc2_40_cbc("hunter2").is_err(),
        "decrypt_rc2_40_cbc must reject a RC2-128-OID bag"
    );
}

/// Passing a RC2-40-encrypted `EncryptedPrivateKeyInfo` to `decrypt_rc2_128_cbc`
/// must return `Err` (OID mismatch).
#[test]
fn oid_swap_rc2_40_into_decrypt_rc2_128_returns_err() {
    let epki = find_shrouded_key(include_bytes!("data/test-rc2-40-iter2048.p12"));
    assert_eq!(
        epki.encryption_algorithm.oid, PKCS_12_PBE_WITH_SHAAND40_BIT_RC2_CBC,
        "precondition: fixture must have RC2-40 OID"
    );
    assert!(
        epki.decrypt_rc2_128_cbc("hunter2").is_err(),
        "decrypt_rc2_128_cbc must reject a RC2-40-OID bag"
    );
}

// ── cipher-layer isolation tests ──────────────────────────────────────────────

/// RC2-128-CBC cipher-layer isolation vector.
///
/// This test bypasses PFX parsing and exercises only the KDF + RC2-128-CBC
/// decrypt path.  The `EncryptedPrivateKeyInfo` is constructed in memory from
/// oracle values; no `.p12` file is involved.
///
/// ## Oracle sources
///
/// **KDF** (key and IV) — OpenSSL 3.0.13 `openssl kdf PKCS12KDF`:
/// ```text
/// # password "smeg" as BMP UTF-16BE + null = 0073006d006500670000
/// # salt = 0102030405060708090a0b0c0d0e0f10, iter=1
///
/// # key (ID=1, keylen=16):
/// openssl kdf -keylen 16 -kdfopt digest:SHA1 \
///   -kdfopt hexpass:0073006d006500670000 \
///   -kdfopt hexsalt:0102030405060708090a0b0c0d0e0f10 \
///   -kdfopt iter:1 -kdfopt id:1 PKCS12KDF
/// → 99c05599b3bd11688ea5e61f6d5c34c6
///
/// # IV (ID=2, keylen=8):
/// openssl kdf ... -kdfopt id:2 -keylen 8 PKCS12KDF
/// → a72ab19138364bb8
/// ```
///
/// **Ciphertext** — OpenSSL 3.0.13 `openssl enc -rc2-cbc`:
/// ```text
/// printf 'hello world' | openssl enc -rc2-cbc -nosalt \
///   -K 99c05599b3bd11688ea5e61f6d5c34c6 \
///   -iv a72ab19138364bb8 \
///   -provider legacy -provider default | xxd -p
/// → 3b39ac25104a763e3b3cb663e8a66b0f
/// ```
/// (Cross-checked: decrypting the ciphertext with OpenSSL returns `hello world`.)
#[test]
fn cipher_layer_isolation_rc2_128() {
    let salt = OctetString::new(hex!("0102030405060708090a0b0c0d0e0f10").to_vec()).expect("salt");
    let pbe_params = Pkcs12PbeParams {
        salt,
        iterations: 1,
    };
    let params_der = pbe_params.to_der().expect("encode Pkcs12PbeParams");
    let params_any = Any::from_der(&params_der).expect("Any from params DER");

    let ciphertext =
        OctetString::new(hex!("3b39ac25104a763e3b3cb663e8a66b0f").to_vec()).expect("ciphertext");

    let epki = EncryptedPrivateKeyInfo {
        encryption_algorithm: AlgorithmIdentifierOwned {
            oid: PKCS_12_PBE_WITH_SHAAND128_BIT_RC2_CBC,
            parameters: Some(params_any),
        },
        encrypted_data: ciphertext,
    };

    let plaintext = epki
        .decrypt_rc2_128_cbc("smeg")
        .expect("decrypt_rc2_128_cbc failed on cipher-layer vector");

    assert_eq!(
        &*plaintext, b"hello world",
        "RC2-128 cipher-layer vector: wrong plaintext"
    );
}

/// RC2-40-CBC cipher-layer isolation vector.
///
/// ## Oracle sources
///
/// **KDF** — same salt/iter/password as the RC2-128 test above, keylen=5:
/// ```text
/// openssl kdf -keylen 5 -kdfopt digest:SHA1 \
///   -kdfopt hexpass:0073006d006500670000 \
///   -kdfopt hexsalt:0102030405060708090a0b0c0d0e0f10 \
///   -kdfopt iter:1 -kdfopt id:1 PKCS12KDF
/// → 99c05599b3
/// ```
///
/// **Ciphertext** — OpenSSL 3.0.13 `openssl enc -rc2-40-cbc`:
/// ```text
/// printf 'hello world' | openssl enc -rc2-40-cbc -nosalt \
///   -K 99c05599b3 \
///   -iv a72ab19138364bb8 \
///   -provider legacy -provider default | xxd -p
/// → 47bba99d52b3ac4b4f796cec88798b6f
/// ```
#[test]
fn cipher_layer_isolation_rc2_40() {
    let salt = OctetString::new(hex!("0102030405060708090a0b0c0d0e0f10").to_vec()).expect("salt");
    let pbe_params = Pkcs12PbeParams {
        salt,
        iterations: 1,
    };
    let params_der = pbe_params.to_der().expect("encode Pkcs12PbeParams");
    let params_any = Any::from_der(&params_der).expect("Any from params DER");

    let ciphertext =
        OctetString::new(hex!("47bba99d52b3ac4b4f796cec88798b6f").to_vec()).expect("ciphertext");

    let epki = EncryptedPrivateKeyInfo {
        encryption_algorithm: AlgorithmIdentifierOwned {
            oid: PKCS_12_PBE_WITH_SHAAND40_BIT_RC2_CBC,
            parameters: Some(params_any),
        },
        encrypted_data: ciphertext,
    };

    let plaintext = epki
        .decrypt_rc2_40_cbc("smeg")
        .expect("decrypt_rc2_40_cbc failed on cipher-layer vector");

    assert_eq!(
        &*plaintext, b"hello world",
        "RC2-40 cipher-layer vector: wrong plaintext"
    );
}

// ── cross-vendor interoperability (pyca/cryptography fixture) ─────────────────

/// **pyca cross-vendor parse + OID rejection test.**
///
/// This fixture was generated by pyca/cryptography and contains a mixed-cipher
/// PFX: the cert bag uses `pbeWithSHAAnd40BitRC2-CBC` and the EC private key
/// bag uses `pbeWithSHAAnd3-KeyTripleDES-CBC`.
///
/// What this test covers:
/// 1. The PFX round-trips through our DER parser without error (cross-vendor
///    format compatibility).
/// 2. `find_shrouded_key` locates the `pkcs8ShroudedKeyBag` (the 3DES EC
///    key bag) — confirming our PFX-walking helper handles non-RC2 bags.
/// 3. Both RC2 decrypt methods reject the 3DES bag at the OID check (before
///    any KDF work is done).
///
/// The cert bag is encrypted with RC2-40 but cert bags are not
/// `pkcs8ShroudedKeyBag` items and cannot be reached through our decrypt API.
/// Full decryption of this fixture (key + cert) will be covered by a future
/// test once 3DES decryption is implemented.
///
/// SHA-256 oracle for the EC PrivateKeyInfo DER (reserved for 3DES PR):
/// `c5eacb73dd8324007d050afcc807fccd09c1f752634eeafaffc0872b35da4383`
/// (confirmed: `pyca private_bytes(DER, PKCS8, NoEncryption)`)
///
/// Password: "cryptography".  Source: pyca/cryptography test vectors.
#[test]
fn pyca_fixture_parses_and_key_bag_has_3des_oid() {
    // find_shrouded_key parses the PFX and locates the pkcs8ShroudedKeyBag;
    // a panic here would mean our DER parser rejects a pyca-generated PFX.
    let epki = find_shrouded_key(include_bytes!("data/pyca-cert-rc2-key-3des.p12"));

    // The key bag must have the 3DES OID — not one of the two RC2 OIDs.
    assert_eq!(
        epki.encryption_algorithm.oid, PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC,
        "pyca fixture key bag must use pbeWithSHAAnd3-KeyTripleDES-CBC OID"
    );

    // Both RC2 methods must bail out at the OID check, not crash or silently
    // produce garbage.
    assert!(
        epki.decrypt_rc2_40_cbc("cryptography").is_err(),
        "decrypt_rc2_40_cbc must reject a 3DES-OID bag"
    );
    assert!(
        epki.decrypt_rc2_128_cbc("cryptography").is_err(),
        "decrypt_rc2_128_cbc must reject a 3DES-OID bag"
    );
}
