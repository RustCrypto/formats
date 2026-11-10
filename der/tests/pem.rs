//! PEM decoding and encoding tests.

#![cfg(all(feature = "derive", feature = "oid", feature = "pem"))]
#![allow(missing_docs)]

use der::{
    Any, Decode, DecodePem, EncodePem, ErrorKind, Sequence,
    asn1::{BitString, ObjectIdentifier},
    pem::{LineEnding, PemLabel},
};

/// Example SPKI document encoded as DER.
const SPKI_DER: &[u8] = include_bytes!("examples/spki.der");

/// Example SPKI document encoded as PEM.
const SPKI_PEM: &str = include_str!("examples/spki.pem");

/// X.509 `AlgorithmIdentifier`
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct AlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
    pub parameters: Option<Any>,
}

/// X.509 `SubjectPublicKeyInfo` (SPKI) in borrowed form
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpkiBorrowed<'a> {
    pub algorithm: AlgorithmIdentifier,
    #[asn1(type = "BIT STRING")]
    pub subject_public_key: &'a [u8],
}

impl PemLabel for SpkiBorrowed<'_> {
    const PEM_LABEL: &'static str = "PUBLIC KEY";
}

/// X.509 `SubjectPublicKeyInfo` (SPKI) in owned form
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpkiOwned {
    pub algorithm: AlgorithmIdentifier,
    pub subject_public_key: BitString,
}

impl PemLabel for SpkiOwned {
    const PEM_LABEL: &'static str = "PUBLIC KEY";
}

#[test]
fn from_pem() {
    // Decode PEM to owned form.
    let pem_spki = SpkiOwned::from_pem(SPKI_PEM).unwrap();

    // Decode DER to borrowed form.
    let der_spki = SpkiBorrowed::from_der(SPKI_DER).unwrap();

    assert_eq!(pem_spki.algorithm, der_spki.algorithm);
    assert_eq!(
        pem_spki.subject_public_key.raw_bytes(),
        der_spki.subject_public_key
    );
}

#[test]
fn from_pem_trailing_data() {
    // Append a complete NULL, an incomplete tag, or a second SPKI document.
    for trailing in [b"\x05\x00".as_slice(), b"\xff".as_slice(), SPKI_DER] {
        let mut der = SPKI_DER.to_vec();
        der.extend_from_slice(trailing);
        let pem = der::pem::encode_string(SpkiOwned::PEM_LABEL, LineEnding::LF, &der).unwrap();

        let err = SpkiOwned::from_der(&der).unwrap_err();
        assert_eq!(
            err.kind(),
            ErrorKind::TrailingData {
                decoded: SPKI_DER.len().try_into().unwrap(),
                remaining: trailing.len().try_into().unwrap(),
            }
        );
        assert_eq!(SpkiOwned::from_pem(&pem).unwrap_err(), err);
    }
}

#[test]
fn to_pem() {
    let spki = SpkiBorrowed::from_der(SPKI_DER).unwrap();
    let pem = spki.to_pem(LineEnding::default()).unwrap();
    assert_eq!(&pem, SPKI_PEM);
}

#[test]
fn read_zero_slices_from_pem() {
    let spki = SpkiOwned {
        algorithm: AlgorithmIdentifier {
            algorithm: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
            parameters: Some(Any::null()),
        },
        subject_public_key: BitString::new(0, []).unwrap(),
    };

    let pem = spki.to_pem(LineEnding::LF).unwrap();
    SpkiOwned::from_pem(pem).unwrap();
}
