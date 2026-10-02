//! `Document` and `SecretDocument` tests.

#![cfg(feature = "alloc")]
#![allow(missing_docs)]

use der::{Decode, Document, ErrorKind, Tag};

/// `Document` holds a DER-encoded `SEQUENCE`. Every way of building one from bytes must
/// enforce that, so the same bytes are accepted or rejected regardless of the constructor
/// (and a document written with `to_pem` can always be read back with `from_pem`).
#[test]
fn document_requires_sequence() {
    let not_a_sequence: &[&[u8]] = &[
        &[0x02, 0x01, 0x00],       // INTEGER 0
        &[0x04, 0x02, 0xAA, 0xBB], // OCTET STRING
        &[0x31, 0x00],             // SET {}
        &[0xA0, 0x00],             // [0] {}
    ];

    for bytes in not_a_sequence {
        let err = Document::from_der(bytes).unwrap_err();
        assert!(
            matches!(
                err.kind(),
                ErrorKind::TagUnexpected {
                    expected: Some(Tag::Sequence),
                    ..
                }
            ),
            "{bytes:02X?}: {err}"
        );
        assert!(Document::try_from(*bytes).is_err(), "{bytes:02X?}");
        assert!(Document::try_from(bytes.to_vec()).is_err(), "{bytes:02X?}");
    }

    let sequence: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x00];
    let doc = Document::from_der(sequence).unwrap();
    assert_eq!(doc.as_bytes(), sequence);
    assert_eq!(Document::try_from(sequence).unwrap(), doc);
    assert_eq!(Document::try_from(sequence.to_vec()).unwrap(), doc);
}
