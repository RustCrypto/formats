//! pkcs-12PbeParams implementation

use const_oid::ObjectIdentifier;
use der::{
    Decode, DecodeValue, Encode, EncodeValue, Header, Length, Reader, Sequence, ValueOrd, Writer,
    asn1::OctetString,
};
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pbkdf2Params {
    /// PBKDF2 salt
    // TODO(tarcieri): support `CHOICE` with `otherSource`
    pub salt: OctetString,

    /// PBKDF2 iteration count
    pub iteration_count: u32,

    /// PBKDF2 output length
    pub key_length: Option<u16>,

    /// Pseudo-random function to use with PBKDF2 (`DEFAULT algid-hmacWithSHA1`: decoded as
    /// that value when absent, and omitted when encoding it, as DER requires)
    pub prf: AlgorithmIdentifierOwned,
}

impl<'a> DecodeValue<'a> for Pbkdf2Params {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        Ok(Self {
            salt: reader.decode()?,
            iteration_count: reader.decode()?,
            key_length: reader.decode()?,
            prf: Option::<AlgorithmIdentifierOwned>::decode(reader)?.unwrap_or_else(default_prf),
        })
    }
}

impl EncodeValue for Pbkdf2Params {
    fn value_len(&self) -> der::Result<Length> {
        let len = self.salt.encoded_len()?
            + self.iteration_count.encoded_len()?
            + self.key_length.encoded_len()?;
        if self.prf == default_prf() {
            len
        } else {
            len + self.prf.encoded_len()?
        }
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.salt.encode(writer)?;
        self.iteration_count.encode(writer)?;
        self.key_length.encode(writer)?;
        if self.prf != default_prf() {
            self.prf.encode(writer)?;
        }
        Ok(())
    }
}

impl Sequence<'_> for Pbkdf2Params {}

/// `algid-hmacWithSHA1`: `{ algorithm id-hmacWithSHA1, parameters NULL : NULL }`
/// ([RFC 8018 Appendix B.1.1]).
///
/// [RFC 8018 Appendix B.1.1]: https://www.rfc-editor.org/rfc/rfc8018#appendix-B.1.1
fn default_prf() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ObjectIdentifier::new_unwrap("1.2.840.113549.2.7"),
        parameters: Some(der::asn1::Null.into()),
    }
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
