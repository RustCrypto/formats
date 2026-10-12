//! `SymmetricKeyPackage` (RFC 6031) tests.

use cms::symmetric_key::{OneSymmetricKey, SymmetricKeyPackage};
use der::{Decode, Encode};

/// RFC 6031 Section 2.0: `sKeyAttrs` and `sKey` are both OPTIONAL (at least one present), so a
/// key carried without attributes is valid.
#[test]
fn one_symmetric_key_without_attributes() {
    // OneSymmetricKey { sKey OCTET STRING 01020304 }
    let der = [0x30, 0x06, 0x04, 0x04, 0x01, 0x02, 0x03, 0x04];
    let key = OneSymmetricKey::from_der(&der).unwrap();
    assert!(key.s_key_attrs.is_none());
    assert_eq!(key.s_key.as_ref().unwrap().as_bytes(), &[1, 2, 3, 4]);
    assert_eq!(key.to_der().unwrap(), der);

    // SymmetricKeyPackage { sKeys { that key } } (version DEFAULT v1 omitted)
    let der = [
        0x30, 0x0a, 0x30, 0x08, 0x30, 0x06, 0x04, 0x04, 0x01, 0x02, 0x03, 0x04,
    ];
    let package = SymmetricKeyPackage::from_der(&der).unwrap();
    assert_eq!(package.s_keys.len(), 1);
    assert_eq!(package.to_der().unwrap(), der);
}
