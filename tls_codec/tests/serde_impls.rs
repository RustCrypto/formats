#![cfg(feature = "serde")]
#![allow(deprecated)]

use tls_codec::{SecretVLByteVec, VLByteVec, VLBytes};

#[test]
fn vlbytes_serde_roundtrip() {
    // Verify that `VLBytes` is identical after a serde roundtrip. This guards
    // against changes to the `serde` representation of `VLBytes`, which would
    // break callers that use it as (part of) a map key or otherwise rely on
    // its default `Vec<u8>` representation.
    for value in [
        VLBytes::from(vec![]),
        VLBytes::from(vec![0u8]),
        VLBytes::from(vec![0u8, 1, 2, 3]),
        VLBytes::from(vec![0xAA; 1024]),
    ] {
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf).unwrap();
        let roundtripped: VLBytes = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(value, roundtripped);
    }
}

#[test]
fn vlbytevec_serde_roundtrip() {
    for value in [
        VLByteVec::from(vec![]),
        VLByteVec::from(vec![0u8]),
        VLByteVec::from(vec![0u8, 1, 2, 3]),
        VLByteVec::from(vec![0xAA; 1024]),
    ] {
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf).unwrap();
        let roundtripped: VLByteVec = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(value, roundtripped);
    }
}

#[test]
fn secret_vlbytevec_serde_roundtrip() {
    for value in [
        SecretVLByteVec::new(vec![]),
        SecretVLByteVec::new(vec![0u8, 1, 2, 3]),
        SecretVLByteVec::new(vec![0xAA; 1024]),
    ] {
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf).unwrap();
        let roundtripped: SecretVLByteVec = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(value, roundtripped);
    }
}

#[test]
fn vlbytevec_uses_compact_serde_bytes_encoding() {
    // `VLByteVec` uses `serde_bytes` via `#[serde(transparent)]`, so it should
    // produce a strictly smaller CBOR encoding than `VLBytes` (which serializes
    // as a struct wrapping a sequence of `u8`).
    let payload = vec![0xAAu8; 128];
    let vl_bytes = VLBytes::from(payload.clone());
    let vl_byte_vec = VLByteVec::from(payload);

    let mut vl_bytes_buf = Vec::new();
    ciborium::into_writer(&vl_bytes, &mut vl_bytes_buf).unwrap();
    let mut vl_byte_vec_buf = Vec::new();
    ciborium::into_writer(&vl_byte_vec, &mut vl_byte_vec_buf).unwrap();

    assert!(vl_byte_vec_buf.len() < vl_bytes_buf.len());
}

#[test]
fn vlbytevec_deserializes_legacy_vlbytes_format() {
    // Encoded `VLBytes` data must remain readable by `VLByteVec`'s custom
    // deserializer. We exercise CBOR (native byte type) and JSON (no native
    // byte type, falls back to a sequence of `u8`).
    for payload in [
        Vec::<u8>::new(),
        vec![0u8],
        vec![0u8, 1, 2, 3, 4, 5],
        vec![0xAA; 1024],
    ] {
        let vl_bytes = VLBytes::from(payload.clone());

        // CBOR
        let mut cbor_buf = Vec::new();
        ciborium::into_writer(&vl_bytes, &mut cbor_buf).unwrap();
        let from_cbor: VLByteVec = ciborium::from_reader(cbor_buf.as_slice()).unwrap();
        assert_eq!(from_cbor.as_slice(), payload.as_slice());

        // JSON
        let json = serde_json::to_string(&vl_bytes).unwrap();
        let from_json: VLByteVec = serde_json::from_str(&json).unwrap();
        assert_eq!(from_json.as_slice(), payload.as_slice());
    }
}

#[test]
fn secret_vlbytevec_deserializes_legacy_secret_vlbytes_format() {
    use tls_codec::SecretVLBytes;

    for payload in [Vec::<u8>::new(), vec![0u8, 1, 2, 3], vec![0xAA; 1024]] {
        let secret_vl_bytes = SecretVLBytes::new(payload.clone());

        // CBOR
        let mut cbor_buf = Vec::new();
        ciborium::into_writer(&secret_vl_bytes, &mut cbor_buf).unwrap();
        let from_cbor: SecretVLByteVec = ciborium::from_reader(cbor_buf.as_slice()).unwrap();
        assert_eq!(from_cbor.as_slice(), payload.as_slice());

        // JSON
        let json = serde_json::to_string(&secret_vl_bytes).unwrap();
        let from_json: SecretVLByteVec = serde_json::from_str(&json).unwrap();
        assert_eq!(from_json.as_slice(), payload.as_slice());
    }
}
