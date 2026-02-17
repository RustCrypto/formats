//! DigestInfo-related types

use der::{Sequence, ValueOrd, asn1::OctetString};
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
