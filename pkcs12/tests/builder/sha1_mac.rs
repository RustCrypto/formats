//! Tests for the `legacy` feature: HMAC-SHA-1 MAC verification support.

use std::process::Command;

use der::Decode;
use tempfile::TempDir;
use x509_cert::Certificate;

use pkcs12::builder::{MacAlgorithm, MacDataBuilder, Pkcs12Builder, asn1_utils::parse_pkcs12};

const PASSWORD: &str = "sha1-test-pass";

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
            "/CN=sha1-mac-test/O=Test",
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

/// Build a PKCS #12 file with OpenSSL using SHA-1 MAC and PBES2 encryption.
fn openssl_export_sha1_mac(cert_pem_path: &str, key_pem_path: &str) -> Vec<u8> {
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
            "AES-256-CBC",
            "-certpbe",
            "AES-256-CBC",
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
        "openssl pkcs12 -export with SHA1 MAC failed"
    );

    std::fs::read(&p12_path).expect("read exported p12")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Verify that a PKCS #12 file built by OpenSSL with `-macalg SHA1` can be
/// parsed and its MAC verified by our library.
#[test]
fn openssl_sha1_mac_rust_reads() {
    let (key_pem, cert_pem, key_der, cert_der, _dir) = generate_credentials();

    let p12_bytes = openssl_export_sha1_mac(&cert_pem, &key_pem);

    let contents =
        parse_pkcs12(&p12_bytes, PASSWORD).expect("get_key_and_cert with SHA1 MAC failed");

    assert_eq!(*contents.key_der, key_der);
    assert_eq!(contents.certificate.der, cert_der);
}

/// Verify that MAC verification fails with the wrong password on a SHA-1 MAC file.
#[test]
fn openssl_sha1_mac_wrong_password_fails() {
    let (key_pem, cert_pem, _, _, _dir) = generate_credentials();

    let p12_bytes = openssl_export_sha1_mac(&cert_pem, &key_pem);

    let result = parse_pkcs12(&p12_bytes, "wrong-password");
    assert!(
        result.is_err(),
        "SHA1 MAC verification should fail with wrong password"
    );
}

/// Verify that `MacDataBuilder` accepts `HmacSha1` for MAC generation (needed for legacy P12 interop).
#[test]
fn mac_data_builder_accepts_sha1() {
    let key = include_bytes!("examples/key.der");
    let cert_bytes = include_bytes!("examples/cert.der");
    let cert = Certificate::from_der(cert_bytes).unwrap();

    let mut md = MacDataBuilder::new(MacAlgorithm::HmacSha1);
    md.iterations(Some(2048)).unwrap();
    md.salt(Some(vec![0u8; 16]));

    let mut builder = Pkcs12Builder::new();
    builder.mac_data_builder(Some(md));

    let result = builder.build_with_rng(&cert, key, "password", &mut rand::rng());
    assert!(result.is_ok(), "building with HmacSha1 should succeed");

    // Verify the generated P12 can be parsed back with MAC verification
    let p12_bytes = result.unwrap();
    let contents = pkcs12::builder::parse_pkcs12(&p12_bytes, "password");
    assert!(
        contents.is_ok(),
        "should be able to parse back P12 with SHA-1 MAC"
    );
}

/// Verify OID round-trip for `MacAlgorithm::HmacSha1`.
#[test]
fn hmac_sha1_oid_round_trip() {
    let alg = MacAlgorithm::HmacSha1;
    let oid = alg.oid();
    let recovered = MacAlgorithm::try_from(oid).unwrap();
    assert_eq!(alg, recovered);
}

/// Verify `HmacSha1` output size is 20 bytes.
#[test]
fn hmac_sha1_output_size() {
    assert_eq!(MacAlgorithm::HmacSha1.output_size(), 20);
}
