//! SymmetricKeyPackage types

use alloc::{string::String, vec::Vec};
use der::ErrorKind;
use der::asn1::Utf8StringRef;
use der::{
    DecodeValue, EncodeValue, Enumerated, FixedTag, Header, Length, Reader, Sequence, Tag, Writer,
    asn1::OctetString,
};
use x509_cert::attr::Attribute;

macro_rules! impl_str_enum {
    (
        $(#[$attr:meta])* $vis: vis enum $name: ident {
            $( $(#[$attr_item: meta])* $item: ident => $value: expr,)*
        }
    )=> {
        $(#[$attr])*
        $vis enum $name {
            $( $(#[$attr_item])* $item, )*
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                match self {
                    $( Self::$item => $value, )*
                }
            }
        }

        impl<'d> DecodeValue<'d> for $name {
            type Error = der::Error;

            fn decode_value<R: Reader<'d>>(reader: &mut R, header: Header) -> der::Result<Self> {
                let value = Utf8StringRef::decode_value(reader, header)?;

                match value.as_ref() {
                    $( $value => Ok(Self::$item), )*
                    _ => Err(der::Error::new(
                        ErrorKind::Value { tag: Self::TAG },
                        reader.position(),
                    )),
                }
            }
        }

        impl EncodeValue for $name {
            fn value_len(&self) -> der::Result<Length> {
                Utf8StringRef::new(self.as_ref())?.value_len()
            }

            fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
                Utf8StringRef::new(self.as_ref())?.encode_value(encoder)
            }
        }

        impl FixedTag for $name {
            const TAG: Tag = String::TAG;
        }


    };
}

/// The `SymmetricKeyPackage` type is defined in [RFC 6031 Section 2.0].
///
/// ```text
///      SymmetricKeyPackage ::= SEQUENCE {
///        version           KeyPkgVersion DEFAULT v1,
///        sKeyPkgAttrs  [0] SEQUENCE SIZE (1..MAX) OF Attribute
///                                       {{ SKeyPkgAttributes }} OPTIONAL,
///        sKeys             SymmetricKeys,
///        ... }
/// ```
///
/// [RFC 6031 Section 2.0]: https://datatracker.ietf.org/doc/html/rfc6031#section-2
#[derive(Sequence, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct SymmetricKeyPackage {
    #[asn1(default = "Default::default")]
    pub version: KeyPkgVersion,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub s_key_pkg_attrs: Option<Vec<Attribute>>,
    pub s_keys: SymmetricKeys,
}

/// The `SymmetricKeys` type is defined in [RFC 6031 Section 2.0].
///
/// ```text
///      SymmetricKeys ::= SEQUENCE SIZE (1..MAX) OF OneSymmetricKey
/// ```
///
/// [RFC 6031 Section 2.0]: https://datatracker.ietf.org/doc/html/rfc6031#section-2
pub type SymmetricKeys = Vec<OneSymmetricKey>;

/// The `OneSymmetricKey` type is defined in [RFC 6031 Section 2.0].
///
/// ```text
///      OneSymmetricKey ::= SEQUENCE {
///        sKeyAttrs  SEQUENCE SIZE (1..MAX) OF Attribute
///                                       {{ SKeyAttributes }}  OPTIONAL,
///        sKey       OCTET STRING OPTIONAL }
///        ( WITH COMPONENTS { ..., sKeyAttrs PRESENT } |
///          WITH COMPONENTS { ..., sKey PRESENT } )
/// ```
///
/// [RFC 6031 Section 2.0]: https://datatracker.ietf.org/doc/html/rfc6031#section-2
#[derive(Sequence, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct OneSymmetricKey {
    pub s_key_attrs: Vec<Attribute>,
    #[asn1(optional = "true")]
    pub s_key: Option<OctetString>,
}

/// The `KeyPkgVersion` type is defined in [RFC 6031 Section 2.0].
///
/// ```text
///     KeyPkgVersion ::= INTEGER  { v1(1) } ( v1, ... )
/// ```
/// [RFC 6031 Section 2.0]: https://datatracker.ietf.org/doc/html/rfc6031#section-2
#[derive(Default, Clone, Debug, Copy, PartialEq, Eq, PartialOrd, Ord, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
#[allow(missing_docs)]
pub enum KeyPkgVersion {
    #[default]
    V1 = 1,
}

// todo: determine if all the types below should live in another file such as attr.rs

/// The `FriendlyName` type is defined in [RFC 6031 Section 3.2.6].
///
/// ```text
///    FriendlyName ::= SEQUENCE {
///      friendlyName        UTF8String,
///      friendlyNameLangTag UTF8String OPTIONAL }
/// ```
///
/// [RFC 6031 Section 3.2.6]: https://datatracker.ietf.org/doc/html/rfc6031#section-3.2.6
#[derive(Sequence, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct FriendlyName {
    pub friendly_name: String,
    #[asn1(optional = "true")]
    pub friendly_name_lang_tag: Option<String>,
}

/// The `PSKCAlgorithmParameters` type is defined in [RFC 6031 Section 3.2.7].
///
///  ```text
///    PSKCAlgorithmParameters ::= CHOICE {
///      suite                UTF8String,
///      challengeFormat  [0] ChallengeFormat,
///      responseFormat   [1] ResponseFormat,
///      ... }
/// ```
///
/// [RFC 6031 Section 3.2.7]: https://datatracker.ietf.org/doc/html/rfc6031#section-3.2.7
#[derive(Sequence, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct PSKCAlgorithmParameters {
    pub suite: String,
    pub challenge_format: ChallengeFormat,
    pub response_format: ResponseFormat,
}

/// The `ChallengeFormat` type is defined in [RFC 6031 Section 3.2.7].
///
/// ```text
///    ChallengeFormat ::= SEQUENCE {
///      encoding    Encoding,
///      checkDigit  BOOLEAN DEFAULT FALSE,
///      min         INTEGER (0..MAX),
///      max         INTEGER (0..MAX),
///      ... }
/// ```
///
/// [RFC 6031 Section 3.2.7]: https://datatracker.ietf.org/doc/html/rfc6031#section-3.2.7
#[derive(Sequence, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct ChallengeFormat {
    pub encoding: Encoding,
    #[asn1(default = "Default::default")]
    pub check_digit: bool,
    pub min: der::asn1::Int,
    pub max: der::asn1::Int,
}

impl_str_enum!(
    /// The `Encoding` type is defined in [RFC 6031 Section 3.2.7].
    ///
    /// ```text
    ///    Encoding ::= UTF8STRING ("DECIMAL" | "HEXADECIMAL" |
    ///                 "ALPHANUMERIC" |"BASE64" |"BINARY")
    /// ```
    ///
    /// [RFC 6031 Section 3.2.7]: https://datatracker.ietf.org/doc/html/rfc6031#section-3.2.7
    #[derive(Copy, Clone, PartialEq, Eq)]
    pub enum Encoding {
        /// "DECIMAL"
        Decimal => "DECIMAL",
        /// "HEXADECIMAL",
        Hexadecimal => "HEXADECIMAL",
        /// "ALPHANUMERIC",
        Alphanumeric => "ALPHANUMERIC",
        /// "BASE64",
        Base64 => "BASE64",
        /// "BINARY",
        Binary => "BINARY",
    }
);

/// The `ResponseFormat` type is defined in [RFC 6031 Section 3.2.7].
///
/// ```text
///    ResponseFormat ::= SEQUENCE {
///      encoding     Encoding,
///      length       INTEGER (0..MAX),
///      checkDigit   BOOLEAN DEFAULT FALSE,
///      ... }
/// ```
///
/// [RFC 6031 Section 3.2.7]: https://datatracker.ietf.org/doc/html/rfc6031#section-3.2.7
#[derive(Sequence, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct ResponseFormat {
    pub encoding: Encoding,
    pub length: u32,
    #[asn1(default = "Default::default")]
    pub check_digit: bool,
}

/// The `ValueMac` type is defined in [RFC 6031 Section 3.2.12].
///
/// ```text
///    ValueMac ::= SEQUENCE {
///      macAlgorithm UTF8String,
///      mac          UTF8String }
/// ```
///
/// [RFC 6031 Section 3.2.12]: https://datatracker.ietf.org/doc/html/rfc6031#section-3.2.12
#[derive(Sequence, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct ValueMac {
    pub mac_algorithm: String,
    pub mac: String,
}

/// The `PSKCKeyUsages` type is defined in [RFC 6031 Section 3.3.4].
///
/// ```text
///    PSKCKeyUsages ::= SEQUENCE OF PSKCKeyUsage
/// ```
///
/// [RFC 6031 Section 3.3.4]: https://datatracker.ietf.org/doc/html/rfc6031#section-3.3.4
pub type PSKCKeyUsages = Vec<PSKCKeyUsage>;

impl_str_enum!(
    /// The `PSKCKeyUsage` type is defined in [RFC 6031 Section 3.3.4].
    ///
    /// ```text
    ///    PSKCKeyUsage ::= UTF8String ("OTP" | "CR" | "Encrypt" |
    ///                     "Integrity" | "Verify" | "Unlock" | "Decrypt" |
    ///                     "KeyWrap" | "Unwrap" | "Derive" | "Generate")
    /// ```
    ///
    /// [RFC 6031 Section 3.3.4]: https://datatracker.ietf.org/doc/html/rfc6031#section-3.3.4
    #[derive(Copy, Clone, PartialEq, Eq)]
    pub enum PSKCKeyUsage {
        /// "OTP"
        Otp => "Otp",
        /// "CR"
        Cr => "CR",
        /// "Encrypt"
        Encrypt => "Encrypt",
        /// "Integrity"
        Integrity => "Integrity",
        /// "Verify"
        Verify => "Verify",
        /// "Unlock"
        Unlock => "Unlock",
        /// "Decrypt"
        Decrypt => "Decrypt",
        /// "KeyWrap"
        KeyWrap => "KeyWrap",
        /// "Unwrap"
        Unwrap => "Unwrap",
        /// "Derive"
        Derive => "Derive",
        /// "Generate"
        Generate => "Generate",
    }
);

/// The `PINPolicy` type is defined in [RFC 6031 Section 3.3.5]
///
/// ```text
///    PINPolicy ::= SEQUENCE {
///      pinKeyId          [0] UTF8String OPTIONAL,
///      pinUsageMode      [1] PINUsageMode,
///      maxFailedAttempts [2] INTEGER (0..MAX) OPTIONAL,
///      minLength         [3] INTEGER (0..MAX) OPTIONAL,
///      maxLength         [4] INTEGER (0..MAX) OPTIONAL,
///      pinEncoding       [5] Encoding OPTIONAL }
/// ```
///
/// [RFC 6031 Section 3.3.5]: https://datatracker.ietf.org/doc/html/rfc6031#section-3.3.5
#[derive(Sequence, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct PINPolicy {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub pin_key_id: Option<String>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT")]
    pub pin_usage_mode: PINUsageMode,
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub max_failed_attempts: Option<u32>,
    #[asn1(context_specific = "3", tag_mode = "IMPLICIT", optional = "true")]
    pub min_length: Option<u32>,
    #[asn1(context_specific = "4", tag_mode = "IMPLICIT", optional = "true")]
    pub max_length: Option<u32>,
    #[asn1(context_specific = "5", tag_mode = "IMPLICIT", optional = "true")]
    pub pin_encoding: Option<Encoding>,
}

impl_str_enum!(

    /// The `PINUsageMode` type is defined in [RFC 6031 Section 3.3.5]
    ///
    /// ```text
    ///   PINUsageMode ::= UTF8String ("Local" | "Prepend" | "Append" |
    ///                     "Algorithmic")
    /// ```
    ///
    /// [RFC 6031 Section 3.3.5]: https://datatracker.ietf.org/doc/html/rfc6031#section-3.3.5
    #[derive(Copy, Clone, PartialEq, Eq)]
    pub enum PINUsageMode {
        /// "Local"
        Local => "Local",
        /// "Prepend"
        Prepend => "Prepend",
        /// "Append"
        Append => "Append",
        /// "Algorithmic"
        Algorithmic => "Algorithmic",
    }
);
