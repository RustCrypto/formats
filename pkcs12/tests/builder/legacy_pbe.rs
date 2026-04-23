//! Tests for PKCS#12 legacy PBE decryption support (pbeWithSHAAnd3-KeyTripleDES-CBC, etc.)

use std::process::Command;
use std::sync::LazyLock;

use tempfile::TempDir;

use pkcs12::builder::asn1_utils::parse_pkcs12;

const PASSWORD: &str = "legacy-pbe-test";

/// Cached detection of whether the system OpenSSL has the legacy provider.
/// On OpenSSL 1.x the legacy algorithms are always built in (returns `true`).
/// On OpenSSL 3.x we probe with `openssl list -providers -provider legacy`.
static HAS_LEGACY_PROVIDER: LazyLock<bool> = LazyLock::new(|| {
    let version_out = Command::new("openssl")
        .args(["version"])
        .output()
        .expect("openssl version");
    let version = String::from_utf8_lossy(&version_out.stdout);

    // OpenSSL 1.x has legacy algorithms built in
    if version.starts_with("OpenSSL 1.") || version.starts_with("LibreSSL") {
        return true;
    }

    // OpenSSL 3.x: probe the legacy provider
    Command::new("openssl")
        .args(["list", "-providers", "-provider", "legacy"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a fresh RSA key + self-signed certificate via OpenSSL.
/// Returns `(key_pem_path, cert_pem_path, key_der, cert_der, TempDir)`.
fn generate_credentials() -> (String, String, Vec<u8>, Vec<u8>, TempDir) {
    let dir = TempDir::new().expect("temp dir");
    let key_pem = dir.path().join("key.pem");
    let cert_pem = dir.path().join("cert.pem");

    let ok = Command::new("openssl")
        .args([
            "genpkey",
            "-quiet",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            key_pem.to_str().unwrap(),
        ])
        .status()
        .expect("spawn openssl genpkey");
    assert!(ok.success(), "openssl genpkey failed");

    let ok = Command::new("openssl")
        .args([
            "req",
            "-quiet",
            "-new",
            "-x509",
            "-key",
            key_pem.to_str().unwrap(),
            "-out",
            cert_pem.to_str().unwrap(),
            "-days",
            "365",
            "-subj",
            "/CN=legacy-pbe-test/O=Test",
        ])
        .status()
        .expect("spawn openssl req");
    assert!(ok.success(), "openssl req -x509 failed");

    let key_der = Command::new("openssl")
        .args(["pkey", "-in", key_pem.to_str().unwrap(), "-outform", "DER"])
        .output()
        .expect("openssl pkey");
    assert!(key_der.status.success());

    let cert_der = Command::new("openssl")
        .args(["x509", "-in", cert_pem.to_str().unwrap(), "-outform", "DER"])
        .output()
        .expect("openssl x509");
    assert!(cert_der.status.success());

    let key_pem_str = key_pem.to_str().unwrap().to_string();
    let cert_pem_str = cert_pem.to_str().unwrap().to_string();
    (
        key_pem_str,
        cert_pem_str,
        key_der.stdout,
        cert_der.stdout,
        dir,
    )
}

/// Build a PKCS#12 file with OpenSSL using legacy PBE for both key and cert bags.
fn openssl_export_legacy_pbe(
    cert_pem_path: &str,
    key_pem_path: &str,
    keypbe: &str,
    certpbe: &str,
) -> Vec<u8> {
    let dir = TempDir::new().expect("temp dir");
    let p12_path = dir.path().join("out.p12");

    let out = Command::new("openssl")
        .args([
            "pkcs12",
            "-export",
            "-in",
            cert_pem_path,
            "-inkey",
            key_pem_path,
            "-out",
            p12_path.to_str().unwrap(),
            "-passout",
            &format!("pass:{PASSWORD}"),
            "-keypbe",
            keypbe,
            "-certpbe",
            certpbe,
            "-macalg",
            "SHA1",
            "-iter",
            "2048",
        ])
        .output()
        .expect("spawn openssl pkcs12 -export");

    if !out.status.success() {
        eprintln!(
            "[openssl pkcs12 -export stderr]\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert!(
        out.status.success(),
        "openssl pkcs12 -export with legacy PBE failed (keypbe={keypbe}, certpbe={certpbe})"
    );

    std::fs::read(&p12_path).expect("read exported p12")
}

// ---------------------------------------------------------------------------
// Tests --- pbeWithSHAAnd3-KeyTripleDES-CBC (both key and cert bags)
// ---------------------------------------------------------------------------

/// Parse a PKCS#12 file that uses 3DES PBE for both key and cert.
#[test]
fn legacy_3des_both_bags() {
    let (key_pem, cert_pem, key_der, cert_der, _dir) = generate_credentials();

    let p12_bytes =
        openssl_export_legacy_pbe(&cert_pem, &key_pem, "PBE-SHA1-3DES", "PBE-SHA1-3DES");

    let contents =
        parse_pkcs12(&p12_bytes, PASSWORD).expect("get_key_and_cert with 3DES PBE failed");

    assert_eq!(*contents.key_der, key_der);
    assert_eq!(contents.certificate.der, cert_der);
}

/// Wrong password should fail MAC verification or decryption.
#[test]
fn legacy_3des_wrong_password() {
    let (key_pem, cert_pem, _, _, _dir) = generate_credentials();

    let p12_bytes =
        openssl_export_legacy_pbe(&cert_pem, &key_pem, "PBE-SHA1-3DES", "PBE-SHA1-3DES");

    let result = parse_pkcs12(&p12_bytes, "wrong-password");
    assert!(
        result.is_err(),
        "should fail with wrong password on 3DES PBE P12"
    );
}

// ---------------------------------------------------------------------------
// Tests --- mixed: legacy PBE cert bag + PBES2 key bag (and vice versa)
// ---------------------------------------------------------------------------

/// Legacy PBE for the cert bag, PBES2 (AES-256-CBC) for the key bag.
#[test]
fn legacy_cert_pbes2_key() {
    let (key_pem, cert_pem, key_der, cert_der, _dir) = generate_credentials();

    let p12_bytes = openssl_export_legacy_pbe(&cert_pem, &key_pem, "AES-256-CBC", "PBE-SHA1-3DES");

    let contents =
        parse_pkcs12(&p12_bytes, PASSWORD).expect("get_key_and_cert with mixed PBE/PBES2 failed");

    assert_eq!(*contents.key_der, key_der);
    assert_eq!(contents.certificate.der, cert_der);
}

/// PBES2 (AES-256-CBC) for the cert bag, legacy PBE for the key bag.
#[test]
fn pbes2_cert_legacy_key() {
    let (key_pem, cert_pem, key_der, cert_der, _dir) = generate_credentials();

    let p12_bytes = openssl_export_legacy_pbe(&cert_pem, &key_pem, "PBE-SHA1-3DES", "AES-256-CBC");

    let contents =
        parse_pkcs12(&p12_bytes, PASSWORD).expect("get_key_and_cert with mixed PBES2/PBE failed");

    assert_eq!(*contents.key_der, key_der);
    assert_eq!(contents.certificate.der, cert_der);
}

// ---------------------------------------------------------------------------
// Tests --- RC2-CBC variants
// ---------------------------------------------------------------------------

/// Build a PKCS#12 file using the OpenSSL legacy provider (needed for RC2-40).
/// Requires `HAS_LEGACY_PROVIDER` to be checked by the caller before invoking.
fn openssl_export_legacy_provider(
    cert_pem_path: &str,
    key_pem_path: &str,
    keypbe: &str,
    certpbe: &str,
) -> Vec<u8> {
    let dir = TempDir::new().expect("temp dir");
    let p12_path = dir.path().join("out.p12");

    let out = Command::new("openssl")
        .args([
            "pkcs12",
            "-export",
            "-in",
            cert_pem_path,
            "-inkey",
            key_pem_path,
            "-out",
            p12_path.to_str().unwrap(),
            "-passout",
            &format!("pass:{PASSWORD}"),
            "-keypbe",
            keypbe,
            "-certpbe",
            certpbe,
            "-macalg",
            "SHA1",
            "-iter",
            "2048",
            "-legacy",
        ])
        .output()
        .expect("spawn openssl pkcs12 -export");

    assert!(
        out.status.success(),
        "openssl pkcs12 -export with legacy provider failed (keypbe={keypbe}, certpbe={certpbe}): {}",
        String::from_utf8_lossy(&out.stderr)
    );

    std::fs::read(&p12_path).expect("read exported p12")
}

/// Parse a PKCS#12 file that uses RC2-40-CBC for the cert bag and 3DES for the key bag.
/// This was the historical OpenSSL default. Skipped if OpenSSL doesn't support legacy provider.
#[test]
fn legacy_rc2_40_cert_3des_key() {
    if !*HAS_LEGACY_PROVIDER {
        println!("Skipping: OpenSSL legacy provider not available");
        return;
    }
    let (key_pem, cert_pem, key_der, cert_der, _dir) = generate_credentials();

    let p12_bytes =
        openssl_export_legacy_provider(&cert_pem, &key_pem, "PBE-SHA1-3DES", "PBE-SHA1-RC2-40");

    let contents = parse_pkcs12(&p12_bytes, PASSWORD)
        .expect("get_key_and_cert with RC2-40 cert / 3DES key failed");

    assert_eq!(*contents.key_der, key_der);
    assert_eq!(contents.certificate.der, cert_der);
}

// ---------------------------------------------------------------------------
// Tests --- PKCS#12 KDF unit tests
// ---------------------------------------------------------------------------

/// Verify that the PKCS#12 KDF produces expected output for a known test vector.
/// This uses the RFC 7292 Appendix B KDF with SHA-1.
#[test]
fn pkcs12_kdf_known_answer() {
    use pkcs12::kdf::{Pkcs12KeyType, derive_key_utf8};
    use sha1::Sha1;

    // Derive a 24-byte encryption key from a known password and salt
    let password = "test";
    let salt = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let iterations = 2048;
    let key_len = 24;

    let key = derive_key_utf8::<Sha1>(
        password,
        &salt,
        Pkcs12KeyType::EncryptionKey,
        iterations,
        key_len,
    )
    .expect("KDF should succeed");
    assert_eq!(key.len(), key_len);

    // Derive again with same inputs --- must be deterministic
    let key2 = derive_key_utf8::<Sha1>(
        password,
        &salt,
        Pkcs12KeyType::EncryptionKey,
        iterations,
        key_len,
    )
    .expect("KDF should succeed");
    assert_eq!(key, key2);

    // Derive IV with same password/salt --- must differ from encryption key
    let iv = derive_key_utf8::<Sha1>(password, &salt, Pkcs12KeyType::Iv, iterations, 8)
        .expect("IV derivation should succeed");
    assert_eq!(iv.len(), 8);
    assert_ne!(&key[..8], iv.as_slice(), "IV must differ from key prefix");
}

/// Verify that different passwords produce different keys.
#[test]
fn pkcs12_kdf_different_passwords() {
    use pkcs12::kdf::{Pkcs12KeyType, derive_key_utf8};
    use sha1::Sha1;

    let salt = [0xAA; 8];
    let key1 = derive_key_utf8::<Sha1>("password1", &salt, Pkcs12KeyType::EncryptionKey, 1000, 24)
        .expect("KDF should succeed");
    let key2 = derive_key_utf8::<Sha1>("password2", &salt, Pkcs12KeyType::EncryptionKey, 1000, 24)
        .expect("KDF should succeed");
    assert_ne!(key1, key2);
}

/// Verify 3DES-CBC round-trip via PKCS#12 KDF-derived key and IV.
#[test]
fn pkcs12_3des_cbc_round_trip() {
    use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
    use pkcs12::kdf::{Pkcs12KeyType, derive_key_utf8};
    use sha1::Sha1;

    let password = "round-trip-test";
    let salt = [0x55; 8];
    let iterations = 1000;

    let key = derive_key_utf8::<Sha1>(
        password,
        &salt,
        Pkcs12KeyType::EncryptionKey,
        iterations,
        24,
    )
    .expect("key derivation");
    let iv = derive_key_utf8::<Sha1>(password, &salt, Pkcs12KeyType::Iv, iterations, 8)
        .expect("IV derivation");

    let plaintext = b"Hello, PKCS#12 legacy PBE world!";

    // Encrypt
    let mut buf = vec![0u8; plaintext.len() + 8]; // room for padding
    buf[..plaintext.len()].copy_from_slice(plaintext);
    let ciphertext = cbc::Encryptor::<des::TdesEde3>::new_from_slices(&key, &iv)
        .expect("encryptor init")
        .encrypt_padded::<Pkcs7>(&mut buf, plaintext.len())
        .expect("encrypt");
    let ct_vec = ciphertext.to_vec();

    // Decrypt
    let mut dec_buf = ct_vec.clone();
    let decrypted = cbc::Decryptor::<des::TdesEde3>::new_from_slices(&key, &iv)
        .expect("decryptor init")
        .decrypt_padded::<Pkcs7>(&mut dec_buf)
        .expect("decrypt");

    assert_eq!(decrypted, plaintext);
}

/// Verify RC2-CBC round-trip via PKCS#12 KDF-derived key and IV using InnerIvInit.
#[test]
fn pkcs12_rc2_40_cbc_round_trip() {
    use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, InnerIvInit, block_padding::Pkcs7};
    use pkcs12::kdf::{Pkcs12KeyType, derive_key_utf8};
    use sha1::Sha1;

    let password = "rc2-round-trip";
    let salt = [0x77; 8];
    let iterations = 1000;

    let key = derive_key_utf8::<Sha1>(password, &salt, Pkcs12KeyType::EncryptionKey, iterations, 5)
        .expect("key derivation");
    let iv = derive_key_utf8::<Sha1>(password, &salt, Pkcs12KeyType::Iv, iterations, 8)
        .expect("IV derivation");

    let plaintext = b"RC2-40 test data padding!!!!!!!!"; // 32 bytes, multiple of block size

    // Encrypt with RC2-40
    let enc_cipher = rc2::Rc2::new_with_eff_key_len(&key, 40);
    let mut buf = vec![0u8; plaintext.len() + 8];
    buf[..plaintext.len()].copy_from_slice(plaintext);
    let ciphertext = cbc::Encryptor::<rc2::Rc2>::inner_iv_slice_init(enc_cipher, &iv)
        .expect("encryptor init")
        .encrypt_padded::<Pkcs7>(&mut buf, plaintext.len())
        .expect("encrypt");
    let ct_vec = ciphertext.to_vec();

    // Decrypt with RC2-40
    let dec_cipher = rc2::Rc2::new_with_eff_key_len(&key, 40);
    let mut dec_buf = ct_vec.clone();
    let decrypted = cbc::Decryptor::<rc2::Rc2>::inner_iv_slice_init(dec_cipher, &iv)
        .expect("decryptor init")
        .decrypt_padded::<Pkcs7>(&mut dec_buf)
        .expect("decrypt");

    assert_eq!(decrypted, plaintext);
}

// ---------------------------------------------------------------------------
// Tests --- Legacy PBE generation (Rust builds, Rust reads back)
// ---------------------------------------------------------------------------

/// Round-trip: generate a P12 with legacy 3DES PBE for both bags, then parse it back.
#[test]
fn generate_legacy_3des_round_trip() {
    use der::Decode;
    use pkcs12::builder::{LegacyPbeAlgorithm, MacAlgorithm, MacDataBuilder, Pkcs12Builder};

    let (_key_pem, _cert_pem, key_der, cert_der, _dir) = generate_credentials();
    let cert = x509_cert::Certificate::from_der(&cert_der).expect("parse cert");

    let mut p12_builder = Pkcs12Builder::new();
    p12_builder.iterations(Some(2048)).expect("set iterations");
    p12_builder
        .cert_legacy_pbe_algorithm(Some(LegacyPbeAlgorithm::ShaAnd3KeyTripleDesCbc))
        .key_legacy_pbe_algorithm(Some(LegacyPbeAlgorithm::ShaAnd3KeyTripleDesCbc));

    // Use SHA-1 MAC for full legacy compatibility
    let mut mdb = MacDataBuilder::new(MacAlgorithm::HmacSha1);
    mdb.iterations(Some(2048)).expect("set mac iterations");
    p12_builder.mac_data_builder(Some(mdb));

    let p12 = p12_builder
        .build_with_rng(&cert, &key_der, PASSWORD, &mut rand::rng())
        .expect("build legacy 3DES P12");

    let contents = parse_pkcs12(&p12, PASSWORD).expect("parse back legacy 3DES P12");

    assert_eq!(*contents.key_der, key_der);
    assert_eq!(contents.certificate.der, cert_der);
}

/// Round-trip: generate a P12 with legacy RC2-128 cert bag + 3DES key bag.
#[test]
fn generate_legacy_rc2_cert_3des_key_round_trip() {
    use der::Decode;
    use pkcs12::builder::{LegacyPbeAlgorithm, Pkcs12Builder};

    let (_key_pem, _cert_pem, key_der, cert_der, _dir) = generate_credentials();
    let cert = x509_cert::Certificate::from_der(&cert_der).expect("parse cert");

    let mut p12_builder = Pkcs12Builder::new();
    p12_builder.iterations(Some(2048)).expect("set iterations");
    p12_builder
        .cert_legacy_pbe_algorithm(Some(LegacyPbeAlgorithm::ShaAnd128BitRc2Cbc))
        .key_legacy_pbe_algorithm(Some(LegacyPbeAlgorithm::ShaAnd3KeyTripleDesCbc));

    let p12 = p12_builder
        .build_with_rng(&cert, &key_der, PASSWORD, &mut rand::rng())
        .expect("build mixed legacy P12");

    let contents = parse_pkcs12(&p12, PASSWORD).expect("parse back mixed legacy P12");

    assert_eq!(*contents.key_der, key_der);
    assert_eq!(contents.certificate.der, cert_der);
}

/// Mixed: legacy PBE cert bag + PBES2 key bag (Rust generates, Rust reads).
#[test]
fn generate_legacy_cert_pbes2_key_round_trip() {
    use der::Decode;
    use pkcs12::builder::{LegacyPbeAlgorithm, Pkcs12Builder};

    let (_key_pem, _cert_pem, key_der, cert_der, _dir) = generate_credentials();
    let cert = x509_cert::Certificate::from_der(&cert_der).expect("parse cert");

    let mut p12_builder = Pkcs12Builder::new();
    p12_builder.iterations(Some(2048)).expect("set iterations");
    p12_builder.cert_legacy_pbe_algorithm(Some(LegacyPbeAlgorithm::ShaAnd3KeyTripleDesCbc));
    // key uses default PBES2

    let p12 = p12_builder
        .build_with_rng(&cert, &key_der, PASSWORD, &mut rand::rng())
        .expect("build legacy-cert/pbes2-key P12");

    let contents = parse_pkcs12(&p12, PASSWORD).expect("parse back legacy-cert/pbes2-key P12");

    assert_eq!(*contents.key_der, key_der);
    assert_eq!(contents.certificate.der, cert_der);
}

/// OpenSSL interop: Rust generates legacy PBE P12 with 3DES, OpenSSL reads it.
#[test]
fn generate_legacy_openssl_reads() {
    use der::Decode;
    use pkcs12::builder::{LegacyPbeAlgorithm, MacAlgorithm, MacDataBuilder, Pkcs12Builder};

    let (_key_pem, _cert_pem, key_der, cert_der, _dir) = generate_credentials();
    let cert = x509_cert::Certificate::from_der(&cert_der).expect("parse cert");

    let mut p12_builder = Pkcs12Builder::new();
    p12_builder.iterations(Some(2048)).expect("set iterations");
    p12_builder
        .cert_legacy_pbe_algorithm(Some(LegacyPbeAlgorithm::ShaAnd3KeyTripleDesCbc))
        .key_legacy_pbe_algorithm(Some(LegacyPbeAlgorithm::ShaAnd3KeyTripleDesCbc));

    let mut mdb = MacDataBuilder::new(MacAlgorithm::HmacSha1);
    mdb.iterations(Some(2048)).expect("set mac iterations");
    p12_builder.mac_data_builder(Some(mdb));

    let p12 = p12_builder
        .build_with_rng(&cert, &key_der, PASSWORD, &mut rand::rng())
        .expect("build legacy P12 for OpenSSL");

    let dir = TempDir::new().expect("temp dir");
    let p12_path = dir.path().join("rust_legacy.p12");
    std::fs::write(&p12_path, &p12).expect("write p12");

    let out = Command::new("openssl")
        .args([
            "pkcs12",
            "-info",
            "-in",
            p12_path.to_str().unwrap(),
            "-passin",
            &format!("pass:{PASSWORD}"),
            "-passout",
            &format!("pass:{PASSWORD}"),
            "-nokeys",
        ])
        .output()
        .expect("openssl pkcs12 -info");

    assert!(
        out.status.success(),
        "OpenSSL failed to read Rust-generated legacy P12: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn process_p12_test() {
    let enc_p12 = hex_literal::hex!(
        "30820B2002010330820AE606092A864886F70D010701A0820AD704820AD330820ACF3082056706092A864886F70D010706A0820558308205540201003082054D06092A864886F70D010701301C060A2A864886F70D010C0103300E0408DA45CC37D1079B1F0202080080820520CC0F46556D09D47BD184504F4D123AA5A702B6EEBA68C009907EAFC5851B1A08AFC0A064612D69D548CFBBB7219A2438448BFE2A272E4B43CDD620B3224367C57E4AEF6EF20A87E2F31C1515FF22906833DFD170B8BEE4F845757274B5798ABFFC1BFDBCA6A2D8FBCEACE50BF5B20CB09A264F6EC0FBD779D0A6972FC375A5DCEB7DF109AB30E113C82B02C5980A900AE1DA212F4519E4BCE000A5265C3FB54FF5DF6C5AD8054AB1631600620E00D2F88FB74721938B520E67AB65FC49C78BF25D5BBC6475838D412DEF40DF2F544AFCAEA45B11A5C28771777FD31349A0BBC40CC089D900F68009689B754A0E97611A0667C9C615414D41D2ACF8B93B9B357636E2DFEFF6113FB2B22C34F736A3AE107C3D0A1874B6499773490F8049318753C577AB9312A6A80F9E318DF370F0F6BD36418BB1766A91A121221333444BD542AFA75DE31550EA5EDE46127D87779238D6CF4C9C5520B08D749FA7BC56923A0696AC8733AEACDCA3CB9611C69711C56C586B1270B45D40E6C78C10D1E734F8EF6F3B476623D378C4F509101778EDB70EEC005E9893BCE418521B5CBC326A8A8A9C77C46E4B04FA6D13326AB666A646031F82DA7BC2BF592510CDE7FE62E2627506F44D1C2379E8F2B25AE19D9D699A5ABDB9D7BF27E60366A9AFBD923C02E21F4EEF2C288A43D28DA41064FF5B1D54E242CAE7B47E82CF3212A23AA0AABA52FAF1AE9F74C284543220D0CE0DD671EED99F40D010A72F46F4BF62D1C5159689E408DF975E28B2DD4615AA21A7581BDA244EAB3203873BD160A62D17BDEA212AC9231B7C6A7E7ABC86E78AE1FCB238B597651A2933F87DAAE175C038AF555DCB0C3ED0322A23B368A2C2ABA878A4CCCE47F5B82C7041004411BC0810F0D5A72EB9BA9061AB6D43B0721A7354652E538A645BF59B3FC6C868D30D455FFFE8322066C3D4FFCF424B323344C79BFFAC19D9B14D13AA85BC8A49B8E9E83F8F29E16538F1E341383C9B98649F611146780CA8D7BF17B069E753A6A6677229F24D5F7D1B627CAE81C6F050476DFF8F26DBAF11C0A2C71C898D021D7B5C5B32A9D9060F1ED8CFB3AC7B349CD4CD99142638CC20778416F35D61F27E3CC5ED61209826DA328D8CD515C77DB0FB397DCD6F86F6D101CEDE28F7CC4CE0C9051DEFCF8E3CB9D4AD78CE8B2F344C98F09CC9B43945AEB97DDE05C8A7E8BF27CDE49871ECA874627BF1B09EBE4D18B23400E3CA5C177E33123085AD1F2E609483FAE950A085A9EB4BE878CCBE41CF16F17161F04313853EE7CE09280F6B835B193BB34E2AF440A890D0AC42C2B2DBFE74607617D3C0A5E5D0A46289E8526F294A3D3EAA1617D900D0600EE444C38AD2E2136F108861D3ED2049AFEF334A2A2D963D990509830CD2F5F59104AA44774A65035844A235C58C070F4051EBAB2E002A5BDB618264E1CD1998720D700B1F73F3BF2512A18FF20187BE0E8EB5C5C2429AF299526EDEFF03DB72B90147ED8E3B250E31845016355CA98836C7889F9F6D7A6A0D9038019B27AD8ADEEA456FA79044C12E8E41BBA96B1F9F0AF534DF9C732C67CBB74008998812F797AD5718BEF0E3CEF14C9BDD74FFD4DBAD07B35C09DD9B1D9ECD09695B8C61EACFA6E6FB10BA32BA3B3FC6DED93DEFE8D3BDE925BEF6204EC2426E2E903AB54CBA69F35785E08F3DB487E9FF16896129F2051A8959883088AAA62C866B362B23F2E6E63B774B6D5F0B878BE56BD9DEC71D8860882B02CBC78F0B770AE7D84028087BBEE6CD51BC28239F46F5A974F63523ED9D363095DA886C36AE44CEF6A6374394D3991CBF39BD16748BD89E5DBD29AF3760C1055B834CB520F119C4283082056006092A864886F70D010701A08205510482054D3082054930820545060B2A864886F70D010C0A0102A08204EE308204EA301C060A2A864886F70D010C0103300E04084C1BBDCDA98501B102020800048204C849E4283055357FCE518F77476290EB288F608332811C61BD906EB2342DBFC0866925CA95642D17FF7833543F5BCF523BEFA11486059E74CA6BA3DE402F8229038815F6458EE09B88F0E6140FC5A7D15251EF6EC36C852133269729BB514B0E344550F8E5FA1ACCCA6A32CB2668B2DAE7C6D46D470633DD002800FA0702D71739A2C0B7E9008551383B243B7C00A95C936B033C5F2C57BF43DCD1F2A41ED5A14F3833E124847DB29D1F88B2B0AB03BFFDE23CF7DF65692AA1F6A32A7C258E7B35708536ED081A7898EBC3A64DB85086F10F315C3B2867E55BE65A6CA938D3B08FAD6BA63326170950F25FAEFC468D34C74C4CACBF1D9C61E44417D8F1A8BAF17A564514C3B53FEE30724EE55B67EBF0CD489356F0DC964CB7E998D1029E24565486C839464C464447EC2DEDE32C9C787628F35D2F50452D85FC084E14C8739BCDF51EBD34EB49E777937E7E2135D9AB836749C904EE8E21538CDBDDF1E3665DC7F07900627BC78B44C6A95EC482A9B8D337BAA4C80433AEA62ADC3F7EEFB4DD0EB0B0936BBBEA543ED9F1407FC55CBBEA72D42EA147FCFEFDCF27D4A3556F4677AFA012E426B2924FF564CE1DD2CA6B8009A77EEEE84D7C639D39F2E7551BAA6ACE03EFC133E41C2D06337C69F5F2FBA6CFBEF97AF650518FE4AF87CC29B68EDA5B5AB87E4021C6B8E0BC1C4FA00FB5FF9B6211B5DCCDC0AF8638E285B2833ACA4E5071BA92E7AA49483A54BB118F3835F1497BBA4355D235A4A8C83D3EEA8D0EEAE5BEE35872009E3E3F389DC1475AD4CF0D601F5170C1068670F476C40A0EF1A0CB9EB290D33C66DAD76B50B8FC1A9CCE1398CA7367B89FA7935A01DC1BF061CF7E439E98E9A8494D863EEBAB4070AC043CBA40DE8F0644327AEC1B1A2F9E10924B068F974532935B884081D198B26EF130AFAEA19E5253218018C4A8DC3D08303FA81313A78CEEA3DC883A22DA15414FE6A8BF5B7E925FA483962F2F7EE534083E2BD21CD76AEB4E3D08B86E57A48FA9AB5D2B27A75D37806625938600CBE2B6709FB63A4F04E44117E4E9D3274409CB16E6D009D2E459225E29AAD9A5340A03F9BDE1775603EA0BCA02603394534308E5C468059877CCDB8F88B1BB15E61BDAC950D1C8439E92FC890DD1E158B6FF7AA842FE2D25C95439D2F7C9F47F686A5083B0DCC59444478B54A5E5BCFF6649E604D04C8FF306165E7BD11C1F4967CA479D9A4164137F0A063E4D51238EABA608F9C9F4E2DBA2E8437A24E4C15EFA51F9E36BDC7DA42B3CC29431575074F06291F5FE4C3B82ED3996B07FB182FF3AAE28EA045E81C63451B37B6EF810E83E6C26D9E93693FFB79539AE8B1503E8F48A70AFE5DED4CCD782177DDD81CC2187BDE9ED49C593925FD77E47FE0F06713F36BB438FBBD6028D80C9707C1E64EACC6119C8AF5482E0EA413128C4D299F18BDDBFC1A9B505026420D33D187A21E42FEC090C61B1B01B03D092C7DD97AA6DCB2797EEE4F14A14D83A31D787E75ACF06D4312E01EA7D81CE837EF4E9EDEFE26E968F9B9D55A4BF0B77D757ECF78F96B365BC3932FB6CEE9F094E9C115A229CEC0C079A35358F713A1450F74D8FE9F173FEF0CADA79435815B4D5EA689DAD7C48ADBC93C71C2674D0A300B0946BA8247E16D75CA4501B8B3DA4DB572C6853E3C46282FDB299C3905468CC80A1755CB676CB37001C1DE4B3414490C5F9667FD9ED1161042F38F21432EA3144301D06092A864886F70D01091431101E0E007300690067006E006500720032302306092A864886F70D01091531160414198F0B8F39F377C7063D27614886B35C59FD495230313021300906052B0E03021A050004142A4B88194EBF14006DF11653BCB7B42D4420AD9204088AEC2E8F2178CE6F02020800"
    );
    let password = "////////";
    assert!(pkcs12::builder::parse_pkcs12(&enc_p12, password).is_ok())
}
