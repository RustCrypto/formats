//! PEM decoding and encoding tests.
#![cfg(all(feature = "derive", feature = "oid", feature = "alloc"))]

use const_oid::ObjectIdentifier;
use der::{Any, Decode, Sequence, asn1::BitString};

/// X.509 `AlgorithmIdentifier`
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct AlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
    pub parameters: Option<Any>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SpkiOwned {
    pub algorithm: AlgorithmIdentifier,
    pub subject_public_key: BitString,
}

#[test]
fn from_ber() {
    let _any1 = Any::from_ber(BER_CERT).expect("from_ber 1");
}

const BER_CERT: &[u8] = include_bytes!("examples/ber_pkcs7.bin");
