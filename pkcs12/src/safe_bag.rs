//! SafeBag-related types

use alloc::vec::Vec;
use const_oid::ObjectIdentifier;
use der::{Choice, Enumerated, Sequence};
use pkcs8::{EncryptedPrivateKeyInfo};
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::Attributes;
use crate::cert_type::CertTypes;
use crate::crl_type::CrlTypes;

/// The `SafeContents` type is defined in [RFC 7292 Section 4.1].
///
/// ```text
/// SafeContents ::= SEQUENCE OF SafeBag
/// ```
///
/// [RFC 7292 Section 4]: https://www.rfc-editor.org/rfc/rfc7292#section-4.2
pub type SafeContents<'a> = Vec<SafeBag<'a>>;

/// The `SafeBag` type is defined in [RFC 7292 Section 4.1].
///
/// ```text
/// SafeBag ::= SEQUENCE {
///     bagId          BAG-TYPE.&id ({PKCS12BagSet})
///     bagValue       [0] EXPLICIT BAG-TYPE.&Type({PKCS12BagSet}{@bagId}),
///     bagAttributes  SET OF PKCS12Attribute OPTIONAL
/// }
/// ```
///
/// [RFC 7292 Section 4]: https://www.rfc-editor.org/rfc/rfc7292#section-4.2
#[derive(Clone, Debug, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct SafeBag<'a> {
    pub bag_id: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub bag_value: Pkcs12BagSet<'a>,
    pub bag_attributes: Option<Attributes>,
}

/// Version for the PrivateKeyInfo structure as defined in [RFC 5208 Section 5].
///
/// [RFC 5208 Section 5]: https://www.rfc-editor.org/rfc/rfc5208#section-5
#[derive(Clone, Copy, Debug, Enumerated, Eq, PartialEq, PartialOrd, Ord)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum Pkcs8Version {
    /// syntax version 3
    V0 = 0,
}

// PrivateKeyInfo is defined in the pkcs8 crate but without Debug, PartialEq, Eq, Sequence
/// The `PrivateKeyInfo` type is defined in [RFC 5208 Section 5].
///
/// ```text
///       PrivateKeyInfo ::= SEQUENCE {
///         version                   Version,
///         privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
///         privateKey                PrivateKey,
///         attributes           [0]  IMPLICIT Attributes OPTIONAL }
/// ```
///
/// [RFC 5208 Section 5]: https://www.rfc-editor.org/rfc/rfc5208#section-5
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct PrivateKeyInfo {
    /// Syntax version number (always 0 for RFC 5208)
    pub version: Pkcs8Version,

    /// X.509 `AlgorithmIdentifier` for the private key type.
    pub algorithm: AlgorithmIdentifierOwned,

    /// Private key data.
    pub private_key: Vec<u8>,

    /// Public key data, optionally available if version is V2.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub attributes: Option<Attributes>,
}

/// PKCS12BagSet BAG-TYPE ::= {
///     keyBag |
///     pkcs8ShroudedKeyBag |
///     certBag |
///     crlBag |
///     secretBag |
///     safeContentsBag,
///     .. -- For future extensions
/// }
#[derive(Clone, Debug, PartialEq, Choice)]
#[allow(missing_docs)]
#[allow(clippy::large_enum_variant)]
pub enum Pkcs12BagSet<'a> {
    KeyBag(PrivateKeyInfo),
    Pkcs8ShroudedKeyBag(EncryptedPrivateKeyInfo<'a>),
    CertBag(CertTypes),
    CrlBag(CrlTypes),
    // SecretBag omitted due to not instances defined in RFC 7292
    SafeContentsBag(SafeContents<'a>)
}


