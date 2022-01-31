//! PKCS#1 OtherPrimeInfo support.

use der::{asn1::UIntBytes, Sequence};

/// PKCS#1 OtherPrimeInfo as defined in [RFC 8017 Appendix 1.2].
///
/// ASN.1 structure containing an additional prime in a multi-prime RSA key.
///
/// ```text
/// OtherPrimeInfo ::= SEQUENCE {
///     prime             INTEGER,  -- ri
///     exponent          INTEGER,  -- di
///     coefficient       INTEGER   -- ti
/// }
/// ```
///
/// [RFC 8017 Appendix 1.2]: https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.2
#[derive(Clone, Sequence)]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub struct OtherPrimeInfo<'a> {
    /// Prime factor `r_i` of `n`, where `i` >= 3.
    pub prime: UIntBytes<'a>,

    /// Exponent: `d_i = d mod (r_i - 1)`.
    pub exponent: UIntBytes<'a>,

    /// CRT coefficient: `t_i = (r_1 * r_2 * ... * r_(i-1))^(-1) mod r_i`.
    pub coefficient: UIntBytes<'a>,
}
