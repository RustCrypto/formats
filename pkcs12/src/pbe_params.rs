//! pkcs-12PbeParams implementation

use der::{Sequence, ValueOrd, asn1::OctetString};
use spki::AlgorithmIdentifierOwned;

/// The `pkcs-12PbeParams` type is defined in [RFC 7292 Appendix C].
///
///```text
///    pkcs-12PbeParams ::= SEQUENCE {
//        salt        OCTET STRING,
//        iterations  INTEGER
//    }
///```
///
/// [RFC 7292 Appendix C]: https://www.rfc-editor.org/rfc/rfc7292#appendix-C
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct Pkcs12PbeParams {
    /// the MAC digest info
    pub salt: OctetString,

    /// the number of iterations
    pub iterations: i32,
}

/// Password-Based Key Derivation Scheme 2 parameters as defined in
/// [RFC 8018 Appendix A.2].
///
/// ```text
/// PBKDF2-params ::= SEQUENCE {
///     salt CHOICE {
///         specified OCTET STRING,
///         otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
///     },
///     iterationCount INTEGER (1..MAX),
///     keyLength INTEGER (1..MAX) OPTIONAL,
///     prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT
///     algid-hmacWithSHA1 }
/// ```
///
/// [RFC 8018 Appendix A.2]: https://tools.ietf.org/html/rfc8018#appendix-A.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Pbkdf2Params {
    /// PBKDF2 salt
    // TODO(tarcieri): support `CHOICE` with `otherSource`
    pub salt: OctetString,

    /// PBKDF2 iteration count
    pub iteration_count: u32,

    /// PBKDF2 output length
    pub key_length: Option<u16>,

    /// Pseudo-random function to use with PBKDF2
    pub prf: AlgorithmIdentifierOwned,
}

/// EncryptedPrivateKeyInfo ::= SEQUENCE {
///   encryptionAlgorithm  EncryptionAlgorithmIdentifier,
///   encryptedData        EncryptedData }
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct EncryptedPrivateKeyInfo {
    pub encryption_algorithm: AlgorithmIdentifierOwned,
    pub encrypted_data: OctetString,
}

///```text
/// PBES2-params ::= SEQUENCE {
///      keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
///      encryptionScheme AlgorithmIdentifier {{PBES2-Encs}} }
///```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct Pbes2Params {
    pub kdf: AlgorithmIdentifierOwned,
    pub encryption: AlgorithmIdentifierOwned,
}
