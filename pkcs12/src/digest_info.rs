use der::{asn1::OctetString, Sequence, ValueOrd};
use pkcs7::signed_data_content::DigestAlgorithmIdentifier;

/// ```text
/// DigestInfo ::= SEQUENCE {
/// digestAlgorithm DigestAlgorithmIdentifier,
/// digest Digest }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct DigestInfo<'a> {
    /// the algorithm.
    pub algorithm: DigestAlgorithmIdentifier<'a>,

    /// the digest
    pub digest: OctetString,
}
