#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_docs,
    unused_qualifications
)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod base64;
mod error;
mod fields;

use core::fmt;
pub use error::{Error, Result};
pub use fields::{Field, Fields};

#[cfg(feature = "alloc")]
pub use allocating::PasswordHash;
#[cfg(feature = "base64")]
pub use base64::Base64;

/// Debug message used in panics when invariants aren't properly held.
const INVARIANT_MSG: &str = "should be ensured valid by constructor";

/// Password hash reference type for hashes encoded in the Modular Crypt Format (MCF),
/// e.g. `$<id>$...`.
///
/// For more information, see [`PasswordHash`].
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct PasswordHashRef(str);

impl PasswordHashRef {
    /// Parse the given input string, returning an [`PasswordHashRef`] if valid.
    pub fn new(s: &str) -> Result<&PasswordHashRef> {
        validate(s)?;
        Ok(Self::new_unchecked(s))
    }

    /// Construct a new [`PasswordHashRef`] string from the given input `str` reference without
    /// first asserting its validity.
    fn new_unchecked(s: &str) -> &PasswordHashRef {
        // SAFETY: `Self` is a `repr(transparent)` newtype for `str`
        #[allow(unsafe_code)]
        unsafe {
            &*(s as *const str as *const Self)
        }
    }

    /// Get the contained string as a `str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the algorithm identifier for this MCF hash.
    pub fn id(&self) -> &str {
        Fields::new(self.as_str())
            .next()
            .expect(INVARIANT_MSG)
            .as_str()
    }

    /// Get an iterator over the parts of the password hash as delimited by `$`, excluding the
    /// initial identifier.
    pub fn fields(&self) -> Fields<'_> {
        let mut fields = Fields::new(self.as_str());

        // Remove the leading identifier
        let id = fields.next().expect(INVARIANT_MSG);
        debug_assert_eq!(self.id(), id.as_str());

        fields
    }
}

impl AsRef<str> for &PasswordHashRef {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for PasswordHashRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'a> From<&'a PasswordHashRef> for &'a str {
    fn from(hash: &'a PasswordHashRef) -> &'a str {
        hash.as_str()
    }
}

impl<'a> TryFrom<&'a str> for &'a PasswordHashRef {
    type Error = Error;

    fn try_from(s: &'a str) -> Result<Self> {
        PasswordHashRef::new(s)
    }
}

#[cfg(feature = "alloc")]
mod allocating {
    use crate::{Error, Field, PasswordHashRef, Result, fields, validate, validate_id};
    use alloc::{borrow::ToOwned, string::String};
    use core::{
        borrow::Borrow,
        fmt::{self, Write as _},
        ops::Deref,
        str::FromStr,
    };

    #[cfg(feature = "base64")]
    use crate::Base64;

    /// Password hash encoded in the Modular Crypt Format (MCF). Owned form with builder
    /// functionality.
    ///
    /// Password hashes in this format take the form `${id}$...`, where `{id}` is a short numeric or
    /// alphanumeric algorithm identifier optionally containing a `-`, followed by `$` as a delimiter,
    /// further followed by an algorithm-specific serialization of a password hash, typically
    /// using a variant (often an algorithm-specific variant) of Base64. This algorithm-specific
    /// serialization contains one or more fields `${first}[${second}]...`, where each field only uses
    /// characters in the regexp range `[A-Za-z0-9./+=,\-]`.
    ///
    /// Example (SHA-crypt w\ SHA-512):
    ///
    /// ```text
    /// $6$rounds=100000$exn6tVc2j/MZD8uG$BI1Xh8qQSK9J4m14uwy7abn.ctj/TIAzlaVCto0MQrOFIeTXsc1iwzH16XEWo/a7c7Y9eVJvufVzYAs4EsPOy0
    /// ```
    #[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
    pub struct PasswordHash(String);

    impl PasswordHash {
        /// Parse the given input string, returning an [`PasswordHash`] if valid.
        pub fn new(s: impl Into<String>) -> Result<PasswordHash> {
            let s = s.into();
            validate(&s)?;
            Ok(Self(s))
        }

        /// Borrow the contents of this password hash as a [`PasswordHashRef`].
        ///
        /// Similar conversions can be performed using [`AsRef`], [`Borrow`], and [`Deref`], however
        /// this one is useful when the return type may be ambiguous and avoiding potential
        /// inference bugs is preferable.
        pub fn as_password_hash_ref(&self) -> &PasswordHashRef {
            PasswordHashRef::new_unchecked(&self.0)
        }

        /// Create an [`PasswordHash`] from an identifier.
        ///
        /// # Returns
        ///
        /// Error if the identifier is invalid.
        ///
        /// Allowed characters match the regex: `[a-z0-9\-]`, where the first and last characters do NOT
        /// contain a `-`.
        pub fn from_id(id: &str) -> Result<PasswordHash> {
            validate_id(id)?;

            // TODO(tarcieri): overestimate capacity so most password hashes fit?
            let mut hash = String::with_capacity(1 + id.len());
            hash.push(fields::DELIMITER);
            hash.push_str(id);
            Ok(Self(hash))
        }

        /// Encode the given data as the specified variant of Base64 and push it onto the password
        /// hash string, first adding a `$` delimiter.
        #[cfg(feature = "base64")]
        pub fn push_base64(&mut self, field: &[u8], base64_encoding: Base64) {
            self.0.push(fields::DELIMITER);
            self.0.push_str(&base64_encoding.encode_string(field));
        }

        /// Push a type which impls [`fmt::Display`], first adding a `$` delimiter and ensuring the
        /// added characters comprise a valid field.
        ///
        /// # Errors
        /// - If the added field fails to validate as a [`Field`] (i.e. contains characters outside
        ///   the allowed set)
        /// - If the [`fmt::Display`] impl returns [`fmt::Error`].
        pub fn push_displayable<D: fmt::Display>(&mut self, displayable: D) -> Result<()> {
            // Cache original length to truncate back to on error
            let old_len = self.0.len();
            self.0.push(fields::DELIMITER);

            if let Err(e) = write!(&mut self.0, "{displayable}") {
                self.0.truncate(old_len);
                return Err(e.into());
            }

            if let Err(e) = Field::new(&self.0[(old_len + 1)..]) {
                self.0.truncate(old_len);
                return Err(e);
            }

            Ok(())
        }

        /// Push an additional field onto the password hash string, first adding a `$` delimiter.
        pub fn push_field(&mut self, field: Field<'_>) {
            self.0.push(fields::DELIMITER);
            self.0.push_str(field.as_str());
        }

        /// Push a raw string onto the MCF hash, first adding a `$` delimiter and also ensuring it
        /// validates as a [`Field`].
        ///
        /// # Errors
        /// - If the provided `str` fails to validate as a [`Field`] (i.e. contains characters
        ///   outside the allowed set)
        pub fn push_str(&mut self, s: &str) -> Result<()> {
            let field = Field::new(s)?;
            self.push_field(field);
            Ok(())
        }
    }

    impl AsRef<str> for PasswordHash {
        fn as_ref(&self) -> &str {
            self.0.as_str()
        }
    }

    impl AsRef<PasswordHashRef> for PasswordHash {
        fn as_ref(&self) -> &PasswordHashRef {
            self.as_password_hash_ref()
        }
    }

    impl Borrow<PasswordHashRef> for PasswordHash {
        fn borrow(&self) -> &PasswordHashRef {
            self.as_password_hash_ref()
        }
    }

    impl Deref for PasswordHash {
        type Target = PasswordHashRef;

        fn deref(&self) -> &PasswordHashRef {
            self.as_password_hash_ref()
        }
    }

    impl From<PasswordHash> for String {
        fn from(hash: PasswordHash) -> Self {
            hash.0
        }
    }

    impl From<&PasswordHash> for String {
        fn from(hash: &PasswordHash) -> Self {
            hash.0.clone()
        }
    }

    impl FromStr for PasswordHash {
        type Err = Error;

        fn from_str(s: &str) -> Result<Self> {
            Self::new(s)
        }
    }

    impl TryFrom<String> for PasswordHash {
        type Error = Error;

        fn try_from(s: String) -> Result<Self> {
            Self::new(s)
        }
    }

    impl TryFrom<&str> for PasswordHash {
        type Error = Error;

        fn try_from(s: &str) -> Result<Self> {
            Self::new(s)
        }
    }

    impl fmt::Display for PasswordHash {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.as_str())
        }
    }

    //
    // PasswordHashRef extensions
    //

    impl<'a> From<&'a PasswordHash> for &'a PasswordHashRef {
        fn from(hash: &'a PasswordHash) -> &'a PasswordHashRef {
            hash.as_password_hash_ref()
        }
    }

    impl From<&PasswordHashRef> for PasswordHash {
        fn from(hash: &PasswordHashRef) -> Self {
            PasswordHash(hash.into())
        }
    }

    impl From<&PasswordHashRef> for String {
        fn from(hash: &PasswordHashRef) -> Self {
            hash.0.into()
        }
    }

    impl ToOwned for PasswordHashRef {
        type Owned = PasswordHash;

        fn to_owned(&self) -> PasswordHash {
            self.into()
        }
    }
}

/// Perform validations that the given string is well-formed MCF.
fn validate(s: &str) -> Result<()> {
    // Require leading `$`
    if !s.starts_with(fields::DELIMITER) {
        return Err(Error::DelimiterInvalid);
    }

    // Disallow trailing `$`
    if s.ends_with(fields::DELIMITER) {
        return Err(Error::DelimiterInvalid);
    }

    // Validates the hash begins with a leading `$`
    let mut fields = Fields::new(s);

    // Validate characters in the identifier field
    let id = fields.next().ok_or(Error::IdentifierMissing)?;
    validate_id(id.as_str())?;

    // Validate the remaining fields have an appropriate format
    for field in fields {
        field.validate()?;
    }

    Ok(())
}

/// Validate the password hash identifier is well-formed.
///
/// Allowed characters match the regex: `[a-z0-9\-]`, where the first and last characters do NOT
/// contain a `-`.
fn validate_id(id: &str) -> Result<()> {
    let first = id.chars().next().ok_or(Error::IdentifierInvalid)?;
    let last = id.chars().last().ok_or(Error::IdentifierInvalid)?;

    for c in [first, last] {
        match c {
            'a'..='z' | '0'..='9' => (),
            _ => return Err(Error::IdentifierInvalid),
        }
    }

    for c in id.chars() {
        match c {
            'a'..='z' | '0'..='9' | '-' => (),
            _ => return Err(Error::IdentifierInvalid),
        }
    }

    Ok(())
}

#[cfg(all(test, feature = "alloc"))]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::{Error, PasswordHash};

    #[cfg(feature = "base64")]
    use {crate::Base64, hex_literal::hex};

    const SHA512_HASH: &str = "$6$rounds=100000$exn6tVc2j/MZD8uG$BI1Xh8qQSK9J4m14uwy7abn.ctj/TIAzlaVCto0MQrOFIeTXsc1iwzH16XEWo/a7c7Y9eVJvufVzYAs4EsPOy0";

    #[cfg(feature = "base64")]
    const EXAMPLE_SALT: &[u8] = &hex!("6a3f237988126f80958fa24b");
    #[cfg(feature = "base64")]
    const EXAMPLE_HASH: &[u8] = &hex!(
        "0d358cad62739eb554863c183aef27e6390368fe061fc5fcb1193a392d60dcad4594fa8d383ab8fc3f0dc8088974602668422e6a58edfa1afe24831b10be69be"
    );

    #[test]
    fn from_id() {
        let mcf_hash = PasswordHash::from_id("6").unwrap();
        assert_eq!("$6", mcf_hash.as_str());
    }

    #[test]
    fn parse_malformed() {
        assert!("Hello, world!".parse::<PasswordHash>().is_err());
        assert!("$".parse::<PasswordHash>().is_err());
        assert!("$$".parse::<PasswordHash>().is_err());
        assert!("$$foo".parse::<PasswordHash>().is_err());
        assert!("$foo$".parse::<PasswordHash>().is_err());
        assert!("$-$foo".parse::<PasswordHash>().is_err());
        assert!("$foo-$bar".parse::<PasswordHash>().is_err());
        assert!("$-foo$bar".parse::<PasswordHash>().is_err());
    }

    #[test]
    fn parse_id_only() {
        let hash: PasswordHash = "$6".parse().unwrap();
        assert_eq!("6", hash.id());
    }

    #[test]
    fn parse_sha512_hash() {
        let hash: PasswordHash = SHA512_HASH.parse().unwrap();
        assert_eq!("6", hash.id());

        let mut fields = hash.fields();
        assert_eq!("rounds=100000", fields.next().unwrap().as_str());

        let salt = fields.next().unwrap();
        assert_eq!("exn6tVc2j/MZD8uG", salt.as_str());

        #[cfg(feature = "base64")]
        {
            let salt_bytes = salt.decode_base64(Base64::Crypt).unwrap();
            assert_eq!(EXAMPLE_SALT, salt_bytes.as_slice());
        }

        let hash = fields.next().unwrap();
        assert_eq!(
            "BI1Xh8qQSK9J4m14uwy7abn.ctj/TIAzlaVCto0MQrOFIeTXsc1iwzH16XEWo/a7c7Y9eVJvufVzYAs4EsPOy0",
            hash.as_str()
        );

        #[cfg(feature = "base64")]
        {
            let hash_bytes = hash.decode_base64(Base64::Crypt).unwrap();
            assert_eq!(EXAMPLE_HASH, hash_bytes.as_slice());
        }

        assert_eq!(None, fields.next());
    }

    #[cfg(feature = "base64")]
    #[test]
    fn push_base64() {
        let mut hash = PasswordHash::new("$6$rounds=100000").unwrap();
        hash.push_base64(EXAMPLE_SALT, Base64::Crypt);
        hash.push_base64(EXAMPLE_HASH, Base64::Crypt);
        assert_eq!(SHA512_HASH, hash.as_str());
    }

    #[test]
    fn push_displayable() {
        let mut hash = PasswordHash::from_id("6").unwrap();
        hash.push_displayable("rounds=100000").unwrap();
        assert_eq!("$6$rounds=100000", hash.as_str());
    }

    #[test]
    fn push_displayable_malformed() {
        let mut hash = PasswordHash::from_id("6").unwrap();
        assert_eq!(
            hash.push_displayable("$$$").unwrap_err(),
            Error::EncodingInvalid
        );
        assert_eq!("$6", hash.as_str());
    }
}
