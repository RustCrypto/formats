//! Certificate document tests
use crate::certificate_document::CertificateDocument;
use der::Document;

#[cfg(all(feature = "pem", any(feature = "alloc", feature = "std")))]
use der::Encodable;

use x509_cert::*;

#[cfg(feature = "std")]
use std::path::Path;

#[cfg(feature = "pem")]
use der::pem::LineEnding;

/// `Certificate` encoded as ASN.1 DER
const CERT_DER_EXAMPLE: &[u8] = include_bytes!("examples/amazon.der");

/// `Certificate` encoded as PEM
#[cfg(all(feature = "pem"))]
const CERT_PEM_EXAMPLE: &str = include_str!("examples/amazon.pem");

#[test]
#[cfg(all(feature = "pem", feature = "std"))]
fn decode_cert_pem_file() {
    let doc: CertificateDocument =
        CertificateDocument::read_pem_file(Path::new("tests/examples/amazon.pem")).unwrap();
    assert_eq!(doc.as_ref(), CERT_DER_EXAMPLE);
}

#[test]
#[cfg(all(feature = "std", feature = "alloc"))]
fn decode_cert_der_file() {
    use crate::certificate_document::CertificateDocument;
    let doc: CertificateDocument =
        CertificateDocument::read_der_file(Path::new("tests/examples/amazon.der")).unwrap();
    assert_eq!(doc.as_ref(), CERT_DER_EXAMPLE);
}

#[test]
#[cfg(all(feature = "pem", any(feature = "alloc", feature = "std")))]
fn decode_cert_pem() {
    let doc: CertificateDocument = CERT_PEM_EXAMPLE.parse().unwrap();
    assert_eq!(doc.as_ref(), CERT_DER_EXAMPLE);

    // Ensure `CertificateDocument` parses successfully
    let cert = Certificate::try_from(CERT_DER_EXAMPLE).unwrap();
    assert_eq!(doc.decode(), cert);
    assert_eq!(doc.to_pem(LineEnding::default()).unwrap(), CERT_PEM_EXAMPLE);

    let doc: CertificateDocument = CertificateDocument::from_pem(CERT_PEM_EXAMPLE).unwrap();
    assert_eq!(doc.as_ref(), CERT_DER_EXAMPLE);

    // Ensure `CertificateDocument` parses successfully
    let cert = Certificate::try_from(CERT_DER_EXAMPLE).unwrap();
    assert_eq!(doc.decode(), cert);
    assert_eq!(doc.to_pem(LineEnding::default()).unwrap(), CERT_PEM_EXAMPLE);
}

#[test]
fn decode_cert_der() {
    let doc: CertificateDocument = CertificateDocument::from_der(CERT_DER_EXAMPLE).unwrap();
    assert_eq!(doc.as_ref(), CERT_DER_EXAMPLE);

    // Ensure `CertificateDocument` parses successfully
    let cert = Certificate::try_from(CERT_DER_EXAMPLE).unwrap();
    assert_eq!(doc.decode(), cert);
}

#[test]
#[cfg(all(feature = "pem", any(feature = "alloc", feature = "std")))]
fn encode_cert_der() {
    let pk = Certificate::try_from(CERT_DER_EXAMPLE).unwrap();
    let pk_encoded = pk.to_vec().unwrap();
    assert_eq!(CERT_DER_EXAMPLE, pk_encoded.as_slice());
}

#[test]
#[cfg(feature = "std")]
fn write_cert_der() {
    let doc: CertificateDocument = CertificateDocument::from_der(CERT_DER_EXAMPLE).unwrap();
    assert_eq!(doc.as_ref(), CERT_DER_EXAMPLE);
    assert_eq!(doc.to_der().as_ref(), CERT_DER_EXAMPLE);

    let r = doc.write_der_file(Path::new("tests/examples/amazon.der.regen"));
    if r.is_err() {
        panic!("Failed to write file")
    }

    let doc: CertificateDocument =
        CertificateDocument::read_der_file(Path::new("tests/examples/amazon.der.regen")).unwrap();
    assert_eq!(doc.as_ref(), CERT_DER_EXAMPLE);
    assert_eq!(doc.to_der().as_ref(), CERT_DER_EXAMPLE);
    let r = std::fs::remove_file("tests/examples/amazon.der.regen");
    if r.is_err() {}
}

#[test]
#[cfg(all(feature = "pem", any(feature = "alloc", feature = "std")))]
fn encode_cert_pem() {
    let pk = Certificate::try_from(CERT_DER_EXAMPLE).unwrap();
    let pk_encoded = CertificateDocument::try_from(pk)
        .unwrap()
        .to_pem(Default::default())
        .unwrap();

    assert_eq!(CERT_PEM_EXAMPLE, pk_encoded);
}

#[test]
#[cfg(all(feature = "std", feature = "pem"))]
fn write_cert_pem() {
    let doc: CertificateDocument = CertificateDocument::from_der(CERT_DER_EXAMPLE).unwrap();
    assert_eq!(doc.as_ref(), CERT_DER_EXAMPLE);
    assert_eq!(doc.to_der().as_ref(), CERT_DER_EXAMPLE);

    let r = doc.write_pem_file(
        Path::new("tests/examples/amazon.pem.regen"),
        LineEnding::default(),
    );
    if r.is_err() {
        panic!("Failed to write file")
    }

    let doc: CertificateDocument =
        CertificateDocument::read_pem_file(Path::new("tests/examples/amazon.pem.regen")).unwrap();
    assert_eq!(doc.as_ref(), CERT_DER_EXAMPLE);
    assert_eq!(doc.to_der().as_ref(), CERT_DER_EXAMPLE);
    let r = std::fs::remove_file("tests/examples/amazon.pem.regen");
    if r.is_err() {}
}
