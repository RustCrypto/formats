//! Miscelaneous Extensions

use der::asn1::Null;

/// OcspNoCheck as defined in [RFC 6960 Section 4.2.2.2.1].
///
/// This extension is idenfied by the [`PKIX_OCSP_NOCHECK`](constant.PKIX_OCSP_NOCHECK.html) OID.
///
/// ```text
/// OcspNoCheck ::= NULL
/// ```
///
/// [RFC 6960 Section 4.2.2.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.2.2.1
pub type OcspNoCheck = Null;

/// NACI-indicator as defined in [FIPS 201-2 Appendix B].
///
/// This extension is identified by the [`PIV_NACI_INDICATOR`](constant.PIV_NACI_INDICATOR.html) OID.
///
/// ```text
/// NACI-indicator ::= BOOLEAN
/// ```
///
/// [FIPS 201-2 Appendix B]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.201-2.pdf
pub type PivNaciIndicator = bool;
