use alloc::vec::Vec;
use der::Enumerated;
use der::Sequence;
use der::asn1::OctetString;
use x509_cert::attr::Attribute;

/// The `SymmetricKeyPackage` type is defined in [RFC 6031 Section 2.0].
///
/// ```text
///      SymmetricKeyPackage ::= SEQUENCE {
///        version           KeyPkgVersion DEFAULT v1,
///        sKeyPkgAttrs  [0] SEQUENCE SIZE (1..MAX) OF Attribute
///                                       {{ SKeyPkgAttributes }} OPTIONAL,
///        sKeys             SymmetricKeys,
///        ... }
/// ```
///
/// [RFC 6031 Section 2.0]: https://datatracker.ietf.org/doc/html/rfc6031#section-2
#[derive(Sequence, PartialEq)]
pub struct SymmetricKeyPackage {
    #[asn1(default = "Default::default")]
    version: KeyPkgVersion,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    s_key_pkg_attrs: Option<Vec<Attribute>>,
    skeys: SymmetricKeys,
}

/// The `SymmetricKeys` type is defined in [RFC 6031 Section 2.0].
///
/// ```text
///      SymmetricKeys ::= SEQUENCE SIZE (1..MAX) OF OneSymmetricKey
/// ```
///
/// [RFC 6031 Section 2.0]: https://datatracker.ietf.org/doc/html/rfc6031#section-2
pub type SymmetricKeys = Vec<OneSymmetricKey>;

/// The `OneSymmetricKey` type is defined in [RFC 6031 Section 2.0].
///
/// ```text
///        sKeyAttrs  SEQUENCE SIZE (1..MAX) OF Attribute
///                                       {{ SKeyAttributes }}  OPTIONAL,
///        sKey       OCTET STRING OPTIONAL }
///        ( WITH COMPONENTS { ..., sKeyAttrs PRESENT } |
///          WITH COMPONENTS { ..., sKey PRESENT } )
/// ```
///
/// [RFC 6031 Section 2.0]: https://datatracker.ietf.org/doc/html/rfc6031#section-2
#[derive(Sequence, PartialEq)]
pub struct OneSymmetricKey {
    s_key_attrs: Vec<Attribute>,
    #[asn1(optional = "true")]
    s_key: Option<OctetString>,
}

/// The `KeyPkgVersion` type is defined in [RFC 6031 Section 2.0].
///
/// ```text
///     KeyPkgVersion ::= INTEGER  { v1(1) } ( v1, ... )
/// ```
#[derive(Default, Clone, Debug, Copy, PartialEq, Eq, PartialOrd, Ord, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
#[allow(missing_docs)]
pub enum KeyPkgVersion {
    #[default]
    V1 = 1,
}
