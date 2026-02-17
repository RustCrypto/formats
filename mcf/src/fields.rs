//! Fields of an MCF password hash, delimited by `$`

use crate::{Error, Result};
use core::fmt;

#[cfg(feature = "base64")]
use crate::Base64;
#[cfg(all(feature = "alloc", feature = "base64"))]
use alloc::vec::Vec;

/// MCF field delimiter: `$`.
pub const DELIMITER: char = '$';

/// Iterator over the `$`-delimited fields of an MCF hash.
pub struct Fields<'a>(&'a str);

impl<'a> Fields<'a> {
    /// Create a new field iterator from an MCF hash, returning an error in the event the hash
    /// doesn't start with a leading `$` prefix.
    ///
    /// NOTE: this method is deliberately non-public because it doesn't first validate the fields
    /// are well-formed. Calling it with non-validated inputs can lead to invalid [`Field`] values.
    pub(crate) fn new(s: &'a str) -> Self {
        let mut ret = Self(s);

        let should_be_empty = ret.next().expect("shouldn't be empty");
        debug_assert_eq!(should_be_empty.as_str(), "");

        ret
    }
}

impl<'a> Iterator for Fields<'a> {
    type Item = Field<'a>;

    fn next(&mut self) -> Option<Field<'a>> {
        if self.0.is_empty() {
            return None;
        }

        match self.0.split_once(DELIMITER) {
            Some((field, rest)) => {
                self.0 = rest;
                Some(Field(field))
            }
            None => {
                let ret = self.0;
                self.0 = "";
                Some(Field(ret))
            }
        }
    }
}

/// Individual field of an MCF hash, delimited by `$`.
///
/// Fields are constrained to characters in the regexp range `[A-Za-z0-9./+=,\-]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Field<'a>(&'a str);

impl<'a> Field<'a> {
    /// Create a new [`Field`], validating the provided characters are in the allowed range.
    pub fn new(s: &'a str) -> Result<Self> {
        let field = Field(s);
        field.validate()?;
        Ok(field)
    }

    /// Borrow the field's contents as a `str`.
    pub fn as_str(self) -> &'a str {
        self.0
    }

    /// Decode Base64 into the provided output buffer.
    #[cfg(feature = "base64")]
    pub fn decode_base64_into(self, base64_variant: Base64, out: &mut [u8]) -> Result<&[u8]> {
        Ok(base64_variant.decode(self.0, out)?)
    }

    /// Decode this field as the provided Base64 variant.
    #[cfg(all(feature = "alloc", feature = "base64"))]
    pub fn decode_base64(self, base64_variant: Base64) -> Result<Vec<u8>> {
        Ok(base64_variant.decode_vec(self.0)?)
    }

    /// Validate a field in the password hash is well-formed.
    pub(crate) fn validate(self) -> Result<()> {
        if self.0.is_empty() {
            return Err(Error::FieldInvalid);
        }

        for c in self.0.chars() {
            match c {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '/' | '+' | '=' | ',' | '-' => (),
                _ => return Err(Error::EncodingInvalid),
            }
        }

        Ok(())
    }
}

impl AsRef<str> for Field<'_> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Field<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.0)
    }
}
