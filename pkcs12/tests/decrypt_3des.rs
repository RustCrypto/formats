//! Integration tests for `pbeWithSHAAnd3-KeyTripleDES-CBC` decryption
//! (OID 1.2.840.113549.1.12.1.3, RFC 7292 §B.2 + Appendix C).
//!
//! Test fixtures are in `tests/data/`; see `tests/data/README.md` for
//! generation commands and oracle fingerprints.
#![cfg(feature = "encryption")]

use der::{
    Decode, Encode,
    asn1::{Any, ContextSpecific, OctetString},
};
use hex_literal::hex;
use pkcs12::{
    AuthenticatedSafe, PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC, PKCS_12_PKCS8_KEY_BAG_OID,
    pbe_params::{EncryptedPrivateKeyInfo, Pkcs12PbeParams},
    pfx::Pfx,
    safe_bag::SafeContents,
};
// Use the canonical pkcs8 type rather than a local duplicate.
// pkcs8::PrivateKeyInfoOwned implements PartialEq/Eq via constant-time
// comparison (subtle feature) on the key material — safer than a naive derive.
use pkcs8::PrivateKeyInfoOwned;
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;

/// SHA-256 of the PrivateKeyInfo DER blob inside all three `hunter2` RSA
/// fixtures (iter=1, iter=2048, iter=100000 — all encrypt the same key).
///
/// Oracle source: independently verified with:
///   - pyca/cryptography `pkcs12.load_key_and_certificates` + `private_bytes(DER, PKCS8, NoEncryption)`
///   - `openssl pkcs12 -legacy ... -nodes | openssl pkcs8 -nocrypt -topk8 -outform DER | sha256sum`
///
/// Both external tools agree on this value.  Any change to this constant
/// indicates a regression in the KDF or decryption path.
const RSA_KEY_DER_SHA256: [u8; 32] =
    hex!("ccdf40f8d0881c5aa3cb9c563399f5fb590f7615ef7da4d057031bc809c9190d");

/// SHA-256 of the PrivateKeyInfo DER blob inside the pyca EC fixture.
///
/// Oracle source: pyca/cryptography (independent EC implementation, password
/// `"cryptography"`, 2048 iterations, `pbeWithSHA1And3-KeyTripleDES-CBC`).
const PYCA_EC_KEY_DER_SHA256: [u8; 32] =
    hex!("956890dd43249260db8b4a7edf87541070086c186f6a5e39e2eba2eec28f634c");

// OIDs used in assertions.
const ID_DATA: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const RSA_ENCRYPTION: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EC_PUBLIC_KEY: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

// ── helpers ──────────────────────────────────────────────────────────────────

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
            // bag_value is the raw TLV of [0] EXPLICIT EncryptedPrivateKeyInfo.
            let cs: ContextSpecific<EncryptedPrivateKeyInfo> =
                ContextSpecific::from_der(&bag.bag_value).unwrap();
            return cs.value;
        }
    }
    panic!("no pkcs8ShroudedKeyBag found in PFX");
}

/// Decrypt the first `pkcs8ShroudedKeyBag` in `pfx_bytes` and return the
/// raw PKCS#8 `PrivateKeyInfo` DER.  Panics on any parsing or decryption error.
fn decrypt_key(pfx_bytes: &[u8], password: &str) -> Vec<u8> {
    let epki = find_shrouded_key(pfx_bytes);
    epki.decrypt_3des_cbc(password)
        .expect("decrypt_3des_cbc failed")
        .to_vec()
}

// ── happy-path tests ──────────────────────────────────────────────────────────

/// Decrypt with 1 KDF iteration.  Smoke-tests the low-iteration path.
#[test]
fn decrypt_3des_hunter2_iter1() {
    let pki_der = decrypt_key(include_bytes!("data/test-3des-iter1.p12"), "hunter2");
    let pki = PrivateKeyInfoOwned::from_der(&pki_der).expect("parse PrivateKeyInfo");
    assert_eq!(pki.algorithm.oid, RSA_ENCRYPTION);
    assert!(!pki.private_key.as_bytes().is_empty());
}

/// Decrypt with 2048 KDF iterations (standard OpenSSL default).
#[test]
fn decrypt_3des_hunter2_iter2048() {
    let pki_der = decrypt_key(include_bytes!("data/test-3des-iter2048.p12"), "hunter2");
    let pki = PrivateKeyInfoOwned::from_der(&pki_der).expect("parse PrivateKeyInfo");
    assert_eq!(pki.algorithm.oid, RSA_ENCRYPTION);
    assert!(!pki.private_key.as_bytes().is_empty());
}

/// Decrypt with 100 000 KDF iterations.
#[test]
fn decrypt_3des_hunter2_iter100000() {
    let pki_der = decrypt_key(include_bytes!("data/test-3des-iter100000.p12"), "hunter2");
    let pki = PrivateKeyInfoOwned::from_der(&pki_der).expect("parse PrivateKeyInfo");
    assert_eq!(pki.algorithm.oid, RSA_ENCRYPTION);
    assert!(!pki.private_key.as_bytes().is_empty());
}

/// **Key consistency oracle**: all three files contain the same RSA-2048 key
/// encrypted with different iteration counts.  If our KDF or decryption is
/// wrong, at least two of the three outputs will differ.
#[test]
fn decrypt_3des_all_iter_variants_agree() {
    let k1 = decrypt_key(include_bytes!("data/test-3des-iter1.p12"), "hunter2");
    let k2048 = decrypt_key(include_bytes!("data/test-3des-iter2048.p12"), "hunter2");
    let k100k = decrypt_key(include_bytes!("data/test-3des-iter100000.p12"), "hunter2");
    assert_eq!(
        k1, k2048,
        "iter=1 and iter=2048 must decrypt to the same key"
    );
    assert_eq!(
        k1, k100k,
        "iter=1 and iter=100000 must decrypt to the same key"
    );
}

// ── error-path tests ──────────────────────────────────────────────────────────

/// Wrong password must produce `Err` (PKCS#7 unpadding detects the bad key).
#[test]
fn decrypt_3des_wrong_password_fails() {
    let epki = find_shrouded_key(include_bytes!("data/test-3des-iter2048.p12"));
    assert!(
        epki.decrypt_3des_cbc("wrong-password").is_err(),
        "decryption with wrong password must return Err"
    );
}

// ── cross-vendor interoperability ─────────────────────────────────────────────

/// pyca/cryptography test vector: private key encrypted with
/// `pbeWithSHA1And3-KeyTripleDES-CBC`, 2048 iterations, password `cryptography`.
/// Certificate uses RC2-CBC (not tested here).  The private key is an EC key
/// (`id-ecPublicKey`, OID 1.2.840.10045.2.1).  The fixture is from an
/// independent implementation; successful decryption proves interoperability.
#[test]
fn decrypt_3des_pyca_fixture() {
    let pki_der = decrypt_key(
        include_bytes!("data/pyca-cert-rc2-key-3des.p12"),
        "cryptography",
    );
    let pki = PrivateKeyInfoOwned::from_der(&pki_der).expect("parse PrivateKeyInfo");
    assert_eq!(pki.algorithm.oid, EC_PUBLIC_KEY);
    assert!(!pki.private_key.as_bytes().is_empty());
}

// ── external oracle fingerprint checks ───────────────────────────────────────

/// Verify that the decrypted `PrivateKeyInfo` DER bytes match the SHA-256
/// fingerprint computed by two independent external implementations
/// (pyca/cryptography and OpenSSL).  This is the strongest oracle available
/// without re-implementing RSA key parsing: a regression in the KDF or
/// cipher layer will change these bytes and fail this test.
///
/// Expected values documented in `tests/data/README.md` and hardcoded in
/// `RSA_KEY_DER_SHA256` and `PYCA_EC_KEY_DER_SHA256` at the top of this file.
#[test]
fn decrypt_3des_fingerprint_oracle() {
    // All three RSA fixtures contain the same key at different iteration counts.
    // Each decrypted DER blob must hash to RSA_KEY_DER_SHA256.
    for (path, label) in [
        (
            include_bytes!("data/test-3des-iter1.p12").as_slice(),
            "iter=1",
        ),
        (
            include_bytes!("data/test-3des-iter2048.p12").as_slice(),
            "iter=2048",
        ),
        (
            include_bytes!("data/test-3des-iter100000.p12").as_slice(),
            "iter=100000",
        ),
    ] {
        let pki_der = decrypt_key(path, "hunter2");
        let hash = Sha256::digest(&pki_der);
        assert_eq!(
            hash.as_slice(),
            RSA_KEY_DER_SHA256,
            "{label}: PrivateKeyInfo DER sha256 does not match oracle"
        );
    }

    // pyca EC fixture: independent implementation, different algorithm.
    let pyca_der = decrypt_key(
        include_bytes!("data/pyca-cert-rc2-key-3des.p12"),
        "cryptography",
    );
    let pyca_hash = Sha256::digest(&pyca_der);
    assert_eq!(
        pyca_hash.as_slice(),
        PYCA_EC_KEY_DER_SHA256,
        "pyca fixture: PrivateKeyInfo DER sha256 does not match oracle"
    );
}

// ── cipher-layer isolation test ───────────────────────────────────────────────

/// Bouncy Castle PBETest.java cipher-layer isolation vector.
///
/// This test bypasses PFX parsing and exercises only the KDF + 3DES-CBC
/// decrypt path.  All values are derived from two independent external
/// oracles; the test constructs a minimal `EncryptedPrivateKeyInfo` in
/// memory rather than reading a `.p12` file.
///
/// ## Oracle sources
///
/// **KDF** (key and IV) — OpenSSL 3.x `PKCS12KDF` provider:
/// ```text
/// PASSWORD_HEX=007000610073007300770... (BMP UTF-16BE "password" + 0000)
/// openssl kdf -provider legacy -provider default -digest SHA1 \
///   -kdfopt hexpass:$PASSWORD_HEX \
///   -kdfopt hexsalt:7d60435f02e9e0ae \
///   -kdfopt iter:2048 -kdfopt id:1 -keylen 24 PKCS12KDF
///   → 732f2d33c801732b7206756cbd44f9c1c103ddd97c7cbe8e (key)
/// openssl kdf ... -kdfopt id:2 -keylen 8 PKCS12KDF
///   → b07bf522c8d608b8 (IV)
/// ```
///
/// **Ciphertext** — OpenSSL `enc -des-ede3-cbc` applied to the PKCS#7-padded
/// known plaintext with the KDF-derived key and IV:
/// ```text
/// echo -n "1234567890abcdef..." | xxd -r -p \
///   | openssl enc -des-ede3-cbc -K <key> -iv <IV> -nosalt
///   → 9594495aa2cfc9a5bb210823454146a39cc584dab504ae1a
/// ```
/// Round-trip verified: decrypting the ciphertext with OpenSSL returns the
/// original plaintext byte-for-byte.
///
/// **Test parameters** from Bouncy Castle `PBETest.java`
/// (`bcgit/bc-java`, `prov/src/test/java/org/bouncycastle/jce/provider/test/`):
/// - password: `"password"`, salt: `7d60435f02e9e0ae`, iterations: 2048
/// - algorithm: `PBEWithSHAAnd3-KeyTripleDES-CBC`
#[test]
fn decrypt_3des_bouncy_castle_cipher_layer() {
    // Build a minimal EncryptedPrivateKeyInfo in memory — no .p12 file involved.
    let salt = OctetString::new(hex!("7d60435f02e9e0ae").to_vec()).expect("salt OctetString");
    let pbe_params = Pkcs12PbeParams {
        salt,
        iterations: 2048,
    };
    // Encode Pkcs12PbeParams to DER, then wrap as der::Any for the
    // AlgorithmIdentifier parameters field.
    let params_der = pbe_params.to_der().expect("encode Pkcs12PbeParams");
    let params_any = Any::from_der(&params_der).expect("Any from Pkcs12PbeParams DER");

    let ciphertext =
        OctetString::new(hex!("9594495aa2cfc9a5bb210823454146a39cc584dab504ae1a").to_vec())
            .expect("ciphertext OctetString");

    let epki = EncryptedPrivateKeyInfo {
        encryption_algorithm: AlgorithmIdentifierOwned {
            oid: PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC,
            parameters: Some(params_any),
        },
        encrypted_data: ciphertext,
    };

    let plaintext = epki
        .decrypt_3des_cbc("password")
        .expect("decrypt_3des_cbc failed on Bouncy Castle vector");

    // Known plaintext from Bouncy Castle PBETest.java (23 bytes).
    assert_eq!(
        &*plaintext,
        &hex!("1234567890abcdefabcdef1234567890fedbca098765"),
        "Bouncy Castle cipher-layer vector: decrypted plaintext does not match"
    );
}
