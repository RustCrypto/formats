#![no_main]
#![allow(deprecated)]

//! Round-trip fuzzing of the slice-based [`DeserializeBytes`] path.
//!
//! The existing `inverse` target only exercises the `Read`-based
//! [`Deserialize`] implementation. This one covers `tls_deserialize_bytes`
//! and additionally checks that both paths agree on a valid serialization.

use libfuzzer_sys::fuzz_target;
use tls_codec::{Deserialize, DeserializeBytes, Serialize, Size, VLBytes};

fuzz_target!(|expected: VLBytes| {
    let serialized = expected.tls_serialize_detached().unwrap();

    // Assert that the serialized length matches the predicted length.
    assert_eq!(expected.tls_serialized_len(), serialized.len());

    // Slice-based deserialization round-trips and consumes all bytes.
    let (got, remainder) = VLBytes::tls_deserialize_bytes(&serialized).unwrap();
    assert!(remainder.is_empty());
    assert_eq!(expected, got);

    // The `Read`-based path must agree with the slice-based path.
    let mut read_slice = serialized.as_slice();
    let got_read = VLBytes::tls_deserialize(&mut read_slice).unwrap();
    assert!(read_slice.is_empty());
    assert_eq!(expected, got_read);
});
