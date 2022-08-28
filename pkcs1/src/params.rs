//! PKCS#1 RSA parameters

use crate::{Error, Result};
use der::asn1::{AnyRef, ObjectIdentifier};
use der::{Decode, Enumerated, Sequence, Tag};
use spki::AlgorithmIdentifier;

/// `TrailerField` as defined in [RFC 8017 Appendix 2.3].
/// ```text
/// TrailerField ::= INTEGER { trailerFieldBC(1) }
/// ```
/// [RFC 8017 Appendix 2.3]: https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.2.3
#[derive(Clone, Debug, Copy, PartialEq, Eq, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum TrailerField {
    /// the only supported value (0xbc, default)
    BC = 1,
}

impl Default for TrailerField {
    fn default() -> Self {
        Self::BC
    }
}

const OID_SHA_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const OID_MGF_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");

const SHA_1_AI: AlgorithmIdentifier<'_> = AlgorithmIdentifier {
    oid: OID_SHA_1,
    parameters: None,
};

const SALT_LEN_DEFAULT: u8 = 20;

fn default_sha1<'a>() -> AlgorithmIdentifier<'a> {
    SHA_1_AI
}

fn default_mgf1_sha1<'a>() -> AlgorithmIdentifier<'a> {
    AlgorithmIdentifier {
        oid: OID_MGF_1,
        parameters: Some(
            AnyRef::new(Tag::Sequence, &[0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a])
                .expect("Internal error inside default generation"),
        ),
    }
}

fn default_salt_len() -> u8 {
    SALT_LEN_DEFAULT
}

/// PKCS#1 RSASSA-PSS parameters as defined in [RFC 8017 Appendix 2.3]
///
/// ASN.1 structure containing a serialized RSASSA-PSS parameters:
/// ```text
/// RSASSA-PSS-params ::= SEQUENCE {
///     hashAlgorithm      [0] HashAlgorithm      DEFAULT sha1,
///     maskGenAlgorithm   [1] MaskGenAlgorithm   DEFAULT mgf1SHA1,
///     saltLength         [2] INTEGER            DEFAULT 20,
///     trailerField       [3] TrailerField       DEFAULT trailerFieldBC
/// }
/// HashAlgorithm ::= AlgorithmIdentifier
/// MaskGenAlgorithm ::= AlgorithmIdentifier
/// ```
///
/// [RFC 8017 Appendix 2.3]: https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.2.3
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct RsaPSSParameters<'a> {
    /// `hash`: Hash Algorithm
    #[asn1(context_specific = "0", default = "default_sha1")]
    pub hash: AlgorithmIdentifier<'a>,
    /// Mask Generation Function Algorithm
    #[asn1(context_specific = "1", default = "default_mgf1_sha1")]
    pub mask_gen: AlgorithmIdentifier<'a>,
    /// used salt length
    #[asn1(context_specific = "2", default = "default_salt_len")]
    pub salt_len: u8,
    /// Trailer field, should be TrailerField::BC
    #[asn1(context_specific = "3", default = "Default::default")]
    pub trailer_field: TrailerField,
}

impl<'a> TryFrom<&'a [u8]> for RsaPSSParameters<'a> {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(Self::from_der(bytes)?)
    }
}

impl<'a> Default for RsaPSSParameters<'a> {
    fn default() -> Self {
        Self {
            hash: SHA_1_AI,
            mask_gen: default_mgf1_sha1(),
            salt_len: SALT_LEN_DEFAULT,
            trailer_field: Default::default(),
        }
    }
}
