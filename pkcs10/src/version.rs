//! Certification request information version identifier.

use der::Enumerated;

/// Version identifier for certification request information.
///
/// (RFC 2986 designates `0` as the only valid version)
#[derive(Clone, Debug, Copy, PartialEq, Eq, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum Version {
    /// Denotes PKCS#8 v1
    V1 = 0,
}
