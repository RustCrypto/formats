//! Fields of an MCF password hash, delimited by `$`

use crate::{Error, Result};
use core::fmt;

/// MCF field delimiter: `$`.
pub const DELIMITER: char = '$';

/// Iterator over the `$`-delimited fields of an MCF hash.
pub struct Fields<'a>(&'a str);

impl<'a> Fields<'a> {
    /// Create a new field iterator from an MCF hash, returning an error in the event the hash
    /// doesn't start with a leading `$` prefix.
    pub(crate) fn new(s: &'a str) -> Result<Self> {
        let mut ret = Self(s);

        if ret.next() != Some(Field("")) {
            return Err(Error {});
        }

        Ok(ret)
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
    pub fn as_str(&self) -> &'a str {
        self.0
    }

    /// Validate a field in the password hash is well-formed.
    pub(crate) fn validate(&self) -> Result<()> {
        if self.0.is_empty() {
            return Err(Error {});
        }

        for c in self.0.chars() {
            match c {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '/' | '+' | '=' | ',' | '-' => (),
                _ => return Err(Error {}),
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
