//! DigestInfo-related types

use der::{asn1::OctetString, Sequence, ValueOrd};
use spki::AlgorithmIdentifierOwned;

/// ```text
/// DigestInfo ::= SEQUENCE {
/// digestAlgorithm DigestAlgorithmIdentifier,
/// digest Digest }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct DigestInfo {
    /// the algorithm.
    pub algorithm: AlgorithmIdentifierOwned,

    /// the digest
    pub digest: OctetString,
}
