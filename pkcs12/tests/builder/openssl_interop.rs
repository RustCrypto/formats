//! Integration tests verifying PKCS #12 interoperability with OpenSSL.
//!
//! Two directions are tested:
//!   1. Rust builds a PFX  -> OpenSSL parses it (`openssl pkcs12 -noout`)
//!   2. OpenSSL builds a PFX -> Rust parses it (`parse_pkcs12`)

use std::process::Command;
use std::sync::OnceLock;

use der::{Decode, Encode};
use pkcs5::pbes2::Pbkdf2Prf;
use tempfile::TempDir;
use x509_cert::Certificate;

use pkcs12::builder::{
    Pkcs12Builder,
    asn1_utils::parse_pkcs12,
    mac_data_builder::MacDataBuilder,
    supported_algs::{EncryptionAlgorithm, MacAlgorithm},
};

const PASSWORD: &str = "test-p@ss!123";

// ---------------------------------------------------------------------------
// Shared test credentials (generated once per test run)
// ---------------------------------------------------------------------------

/// Returns `(key_der, cert_der)` created once and reused across all tests.
fn creds() -> &'static (Vec<u8>, Vec<u8>) {
    static CREDS: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    CREDS.get_or_init(generate_credentials)
}

/// Generate a 2048-bit RSA key and a self-signed certificate via OpenSSL.
/// Returns `(key_der, cert_der)`.
fn generate_credentials() -> (Vec<u8>, Vec<u8>) {
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
            "/CN=pkcs12-builder-test/O=Test",
        ])
        .status()
        .expect("spawn openssl req");
    assert!(ok.success(), "openssl req -x509 failed");

    // Convert key to PKCS #8 DER
    let key_out = Command::new("openssl")
        .args(["pkey", "-in", key_pem.to_str().unwrap(), "-outform", "DER"])
        .output()
        .expect("spawn openssl pkey");
    assert!(key_out.status.success(), "openssl pkey -outform DER failed");

    // Convert cert to DER
    let cert_out = Command::new("openssl")
        .args(["x509", "-in", cert_pem.to_str().unwrap(), "-outform", "DER"])
        .output()
        .expect("spawn openssl x509");
    assert!(
        cert_out.status.success(),
        "openssl x509 -outform DER failed"
    );

    (key_out.stdout, cert_out.stdout)
}

fn cert_from_der(der: &[u8]) -> Certificate {
    Certificate::from_der(der).expect("parse Certificate from DER")
}

// ---------------------------------------------------------------------------
// Direction 1 helpers: Rust builds PFX, OpenSSL verifies it
// ---------------------------------------------------------------------------

/// Ask OpenSSL to parse `p12_bytes` with the given password.
/// Returns `true` if OpenSSL exits successfully.
fn openssl_verify(p12_bytes: &[u8], password: &str) -> bool {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("test.p12");
    std::fs::write(&path, p12_bytes).expect("write p12");

    let out = Command::new("openssl")
        .args([
            "pkcs12",
            "-in",
            path.to_str().unwrap(),
            "-noout",
            "-passin",
            &format!("pass:{password}"),
        ])
        .output()
        .expect("spawn openssl pkcs12");

    if !out.status.success() {
        eprintln!(
            "[openssl pkcs12 stderr]\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    out.status.success()
}

/// Build a PFX with the given algorithm choices.
fn build_rust_pfx(
    cert: &Certificate,
    key_der: &[u8],
    enc: EncryptionAlgorithm,
    kdf: Pbkdf2Prf,
    mac: MacAlgorithm,
) -> Vec<u8> {
    let mut mac_builder = MacDataBuilder::new(mac);
    mac_builder.iterations(Some(2048)).unwrap();

    let mut builder = Pkcs12Builder::new();
    builder
        .iterations(Some(2048))
        .unwrap()
        .cert_kdf_algorithm(Some(kdf))
        .cert_enc_algorithm(Some(enc.clone()))
        .key_kdf_algorithm(Some(kdf))
        .key_enc_algorithm(Some(enc))
        .mac_data_builder(Some(mac_builder));

    let mut rng = rand::rng();
    builder
        .build_with_rng(cert, key_der, PASSWORD, &mut rng)
        .expect("Pkcs12Builder::build_with_rng")
}

// ---------------------------------------------------------------------------
// Direction 1 tests: Rust builds -> OpenSSL reads
// ---------------------------------------------------------------------------

#[test]
fn rust_default_openssl_reads() {
    let (key_der, cert_der) = creds();
    let cert = cert_from_der(cert_der);
    let p12 = build_rust_pfx(
        &cert,
        key_der,
        EncryptionAlgorithm::Aes256Cbc,
        Pbkdf2Prf::HmacWithSha256,
        MacAlgorithm::HmacSha256,
    );
    assert!(openssl_verify(&p12, PASSWORD));
}

#[test]
fn rust_aes128_cbc_openssl_reads() {
    let (key_der, cert_der) = creds();
    let cert = cert_from_der(cert_der);
    let p12 = build_rust_pfx(
        &cert,
        key_der,
        EncryptionAlgorithm::Aes128Cbc,
        Pbkdf2Prf::HmacWithSha256,
        MacAlgorithm::HmacSha256,
    );
    assert!(openssl_verify(&p12, PASSWORD));
}

#[test]
fn rust_aes192_cbc_openssl_reads() {
    let (key_der, cert_der) = creds();
    let cert = cert_from_der(cert_der);
    let p12 = build_rust_pfx(
        &cert,
        key_der,
        EncryptionAlgorithm::Aes192Cbc,
        Pbkdf2Prf::HmacWithSha256,
        MacAlgorithm::HmacSha256,
    );
    assert!(openssl_verify(&p12, PASSWORD));
}

#[test]
fn rust_pbkdf2_sha384_openssl_reads() {
    let (key_der, cert_der) = creds();
    let cert = cert_from_der(cert_der);
    let p12 = build_rust_pfx(
        &cert,
        key_der,
        EncryptionAlgorithm::Aes256Cbc,
        Pbkdf2Prf::HmacWithSha384,
        MacAlgorithm::HmacSha256,
    );
    assert!(openssl_verify(&p12, PASSWORD));
}

#[test]
fn rust_pbkdf2_sha512_openssl_reads() {
    let (key_der, cert_der) = creds();
    let cert = cert_from_der(cert_der);
    let p12 = build_rust_pfx(
        &cert,
        key_der,
        EncryptionAlgorithm::Aes256Cbc,
        Pbkdf2Prf::HmacWithSha512,
        MacAlgorithm::HmacSha256,
    );
    assert!(openssl_verify(&p12, PASSWORD));
}

#[test]
fn rust_hmac_sha384_mac_openssl_reads() {
    let (key_der, cert_der) = creds();
    let cert = cert_from_der(cert_der);
    let p12 = build_rust_pfx(
        &cert,
        key_der,
        EncryptionAlgorithm::Aes256Cbc,
        Pbkdf2Prf::HmacWithSha256,
        MacAlgorithm::HmacSha384,
    );
    assert!(openssl_verify(&p12, PASSWORD));
}

#[test]
fn rust_hmac_sha512_mac_openssl_reads() {
    let (key_der, cert_der) = creds();
    let cert = cert_from_der(cert_der);
    let p12 = build_rust_pfx(
        &cert,
        key_der,
        EncryptionAlgorithm::Aes256Cbc,
        Pbkdf2Prf::HmacWithSha256,
        MacAlgorithm::HmacSha512,
    );
    assert!(openssl_verify(&p12, PASSWORD));
}

// ---------------------------------------------------------------------------
// Direction 1b: Rust builds PFX with certificate chain -> OpenSSL reads
// ---------------------------------------------------------------------------

#[test]
fn rust_chain_openssl_reads() {
    let dir = TempDir::new().expect("temp dir");
    let ca_key_pem = dir.path().join("ca-key.pem");
    let ca_cert_pem = dir.path().join("ca-cert.pem");
    let ee_key_pem = dir.path().join("ee-key.pem");
    let ee_csr_pem = dir.path().join("ee.csr");
    let ee_cert_pem = dir.path().join("ee-cert.pem");

    // Generate CA key and self-signed CA cert
    let ok = Command::new("openssl")
        .args([
            "genpkey",
            "-quiet",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            ca_key_pem.to_str().unwrap(),
        ])
        .status()
        .expect("spawn openssl genpkey (CA)");
    assert!(ok.success(), "openssl genpkey (CA) failed");

    let ok = Command::new("openssl")
        .args([
            "req",
            "-quiet",
            "-new",
            "-x509",
            "-key",
            ca_key_pem.to_str().unwrap(),
            "-out",
            ca_cert_pem.to_str().unwrap(),
            "-days",
            "365",
            "-subj",
            "/CN=Test CA/O=pkcs12-builder-test",
        ])
        .status()
        .expect("spawn openssl req (CA)");
    assert!(ok.success(), "openssl req -x509 (CA) failed");

    // Generate EE key and CSR
    let ok = Command::new("openssl")
        .args([
            "genpkey",
            "-quiet",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            ee_key_pem.to_str().unwrap(),
        ])
        .status()
        .expect("spawn openssl genpkey (EE)");
    assert!(ok.success(), "openssl genpkey (EE) failed");

    let ok = Command::new("openssl")
        .args([
            "req",
            "-quiet",
            "-new",
            "-key",
            ee_key_pem.to_str().unwrap(),
            "-out",
            ee_csr_pem.to_str().unwrap(),
            "-subj",
            "/CN=Test EE/O=pkcs12-builder-test",
        ])
        .status()
        .expect("spawn openssl req (EE CSR)");
    assert!(ok.success(), "openssl req (EE CSR) failed");

    // Sign EE cert with CA
    let ok = Command::new("openssl")
        .args([
            "x509",
            "-req",
            "-in",
            ee_csr_pem.to_str().unwrap(),
            "-CA",
            ca_cert_pem.to_str().unwrap(),
            "-CAkey",
            ca_key_pem.to_str().unwrap(),
            "-CAcreateserial",
            "-out",
            ee_cert_pem.to_str().unwrap(),
            "-days",
            "365",
        ])
        .output()
        .expect("spawn openssl x509 -req");
    assert!(ok.status.success(), "openssl x509 -req (sign EE) failed");

    // Convert EE key to PKCS #8 DER
    let key_out = Command::new("openssl")
        .args([
            "pkey",
            "-in",
            ee_key_pem.to_str().unwrap(),
            "-outform",
            "DER",
        ])
        .output()
        .expect("spawn openssl pkey (EE)");
    assert!(key_out.status.success());

    // Convert EE cert to DER
    let ee_cert_out = Command::new("openssl")
        .args([
            "x509",
            "-in",
            ee_cert_pem.to_str().unwrap(),
            "-outform",
            "DER",
        ])
        .output()
        .expect("spawn openssl x509 (EE)");
    assert!(ee_cert_out.status.success());

    // Convert CA cert to DER
    let ca_cert_out = Command::new("openssl")
        .args([
            "x509",
            "-in",
            ca_cert_pem.to_str().unwrap(),
            "-outform",
            "DER",
        ])
        .output()
        .expect("spawn openssl x509 (CA)");
    assert!(ca_cert_out.status.success());

    let ee_cert = cert_from_der(&ee_cert_out.stdout);
    let ca_cert = cert_from_der(&ca_cert_out.stdout);

    let mut mac_builder = MacDataBuilder::new(MacAlgorithm::HmacSha256);
    mac_builder.iterations(Some(2048)).unwrap();

    let mut builder = Pkcs12Builder::new();
    builder
        .iterations(Some(2048))
        .unwrap()
        .cert_kdf_algorithm(Some(Pbkdf2Prf::HmacWithSha256))
        .cert_enc_algorithm(Some(EncryptionAlgorithm::Aes256Cbc))
        .key_kdf_algorithm(Some(Pbkdf2Prf::HmacWithSha256))
        .key_enc_algorithm(Some(EncryptionAlgorithm::Aes256Cbc))
        .mac_data_builder(Some(mac_builder))
        .additional_cert(ca_cert.clone());

    let mut rng = rand::rng();
    let p12 = builder
        .build_with_rng(&ee_cert, &key_out.stdout, PASSWORD, &mut rng)
        .expect("build_with_rng with chain");

    assert!(
        openssl_verify(&p12, PASSWORD),
        "OpenSSL failed to read PFX with certificate chain"
    );

    // Verify the Rust parser recovers the additional certificate
    let contents = parse_pkcs12(&p12, PASSWORD).expect("get_key_and_cert with chain");
    assert_eq!(
        contents.additional_certificates.len(),
        1,
        "expected one additional certificate"
    );
    assert_eq!(
        contents.additional_certificates[0].der,
        ca_cert.to_der().unwrap(),
        "additional certificate should match the CA cert"
    );
}

// ---------------------------------------------------------------------------
// Direction 2: OpenSSL builds PFX -> Rust parses it
// ---------------------------------------------------------------------------

/// Export a PKCS #12 file via `openssl pkcs12 -export` using PBES2 algorithms
/// and return the raw DER bytes.
fn openssl_export(cert_pem: &str, key_pem: &str) -> Vec<u8> {
    let dir = TempDir::new().expect("temp dir");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    let p12_path = dir.path().join("out.p12");

    std::fs::write(&cert_path, cert_pem).expect("write cert pem");
    std::fs::write(&key_path, key_pem).expect("write key pem");

    let ok = Command::new("openssl")
        .args([
            "pkcs12",
            "-export",
            "-in",
            cert_path.to_str().unwrap(),
            "-inkey",
            key_path.to_str().unwrap(),
            "-out",
            p12_path.to_str().unwrap(),
            "-passout",
            &format!("pass:{PASSWORD}"),
            // Use PBES2 (AES-256-CBC + PBKDF2) so our library can decrypt
            "-keypbe",
            "AES-256-CBC",
            "-certpbe",
            "AES-256-CBC",
            "-macalg",
            "SHA256",
            "-iter",
            "2048",
        ])
        .output()
        .expect("spawn openssl pkcs12 -export");

    if !ok.status.success() {
        eprintln!(
            "[openssl pkcs12 -export stderr]\n{}",
            String::from_utf8_lossy(&ok.stderr)
        );
    }
    assert!(ok.status.success(), "openssl pkcs12 -export failed");

    std::fs::read(&p12_path).expect("read exported p12")
}

/// OpenSSL generates a PFX using AES-256-CBC / PBKDF2-SHA256; Rust must be
/// able to decrypt and recover the original key and certificate.
#[test]
fn openssl_builds_rust_reads() {
    let dir = TempDir::new().expect("temp dir");
    let key_pem_path = dir.path().join("key.pem");
    let cert_pem_path = dir.path().join("cert.pem");

    // Generate fresh PEM files (we need the PEM text for the export command)
    let ok = Command::new("openssl")
        .args([
            "genpkey",
            "-quiet",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            key_pem_path.to_str().unwrap(),
        ])
        .status()
        .expect("spawn openssl genpkey");
    assert!(ok.success(), "openssl genpkey failed");

    let ok = Command::new("openssl")
        .args([
            "req",
            "-new",
            "-x509",
            "-key",
            key_pem_path.to_str().unwrap(),
            "-out",
            cert_pem_path.to_str().unwrap(),
            "-days",
            "365",
            "-subj",
            "/CN=openssl-builds-rust-reads/O=Test",
        ])
        .status()
        .expect("spawn openssl req");
    assert!(ok.success(), "openssl req -x509 failed");

    let cert_pem = std::fs::read_to_string(&cert_pem_path).expect("read cert pem");
    let key_pem = std::fs::read_to_string(&key_pem_path).expect("read key pem");

    let p12_bytes = openssl_export(&cert_pem, &key_pem);

    let contents = parse_pkcs12(&p12_bytes, PASSWORD).expect("get_key_and_cert failed");

    assert!(
        !contents.key_der.is_empty(),
        "recovered key must not be empty"
    );

    // The subject should contain the CN we encoded above
    let recovered_cert = x509_cert::Certificate::from_der(&contents.certificate.der).unwrap();
    let subject = recovered_cert.tbs_certificate().subject().to_string();
    assert!(
        subject.contains("openssl-builds-rust-reads"),
        "unexpected subject: {subject}"
    );
}
