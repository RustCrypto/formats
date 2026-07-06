#![no_main]
#![allow(deprecated)]

//! Robustness + differential fuzzing of the deserializers.
//!
//! For raw, potentially malformed input this target checks that:
//!  * deserializing never panics (only returns `Ok`/`Err`), and
//!  * the `Read`-based [`Deserialize`] path and the slice-based
//!    [`DeserializeBytes`] path agree: for the same input both either fail, or
//!    both succeed with the same value and consume the same number of bytes.
//!  * on success, re-serializing honors the [`Size`] contract.

use libfuzzer_sys::fuzz_target;
use tls_codec::{
    Deserialize, DeserializeBytes, Serialize, Size, TlsByteVecU8, TlsByteVecU16, TlsByteVecU24,
    TlsByteVecU32, TlsVarInt, TlsVecU8, TlsVecU16, TlsVecU24, TlsVecU32, VLByteVec, VLBytes,
};

/// Run both deserialization paths on `data` for type `$t` and compare them.
macro_rules! differential {
    ($t:ty, $data:expr) => {{
        let mut read_slice: &[u8] = $data;
        let read_res = <$t as Deserialize>::tls_deserialize(&mut read_slice);
        let bytes_res = <$t as DeserializeBytes>::tls_deserialize_bytes($data);

        match (read_res, bytes_res) {
            (Ok(a), Ok((b, remainder))) => {
                assert_eq!(a, b, "value mismatch for {}", stringify!($t));
                assert_eq!(
                    read_slice.len(),
                    remainder.len(),
                    "consumed-length mismatch for {}",
                    stringify!($t)
                );

                // The `Size` contract: the predicted length matches what is
                // actually written. Note we deliberately do *not* require the
                // re-serialized length to equal the number of bytes consumed:
                // in non-MLS mode `TlsVarInt` accepts non-canonical (non-minimal)
                // encodings that re-serialize to fewer bytes.
                let serialized = a.tls_serialize_detached().unwrap();
                assert_eq!(
                    serialized.len(),
                    a.tls_serialized_len(),
                    "serialized length mismatch for {}",
                    stringify!($t)
                );
            }
            (Err(_), Err(_)) => {}
            (read_res, bytes_res) => panic!(
                "Ok/Err divergence for {}: read_ok={}, bytes_ok={}",
                stringify!($t),
                read_res.is_ok(),
                bytes_res.is_ok()
            ),
        }
    }};
}

fuzz_target!(|data: &[u8]| {
    // Fixed-size primitives.
    differential!(u8, data);
    differential!(u16, data);
    differential!(u32, data);
    differential!(u64, data);
    differential!([u8; 4], data);

    // Length-prefixed byte containers (TLS style).
    differential!(TlsVecU8<u8>, data);
    differential!(TlsVecU16<u8>, data);
    differential!(TlsVecU24<u8>, data);
    differential!(TlsVecU32<u8>, data);
    differential!(TlsByteVecU8, data);
    differential!(TlsByteVecU16, data);
    differential!(TlsByteVecU24, data);
    differential!(TlsByteVecU32, data);

    // Nested length-prefixed vectors.
    differential!(TlsVecU16<TlsVecU8<u8>>, data);

    // QUIC-style variable-length encodings.
    differential!(VLBytes, data);
    differential!(VLByteVec, data);
    differential!(TlsVarInt, data);

    // UTF-8 strings.
    differential!(String, data);
});
