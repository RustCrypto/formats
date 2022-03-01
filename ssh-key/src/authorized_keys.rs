//! Parser for `AuthorizedKeysFile`-formatted data.

use crate::{Error, PublicKey, Result};
use core::fmt;

#[cfg(feature = "std")]
use std::{fs, path::Path};

/// Character that begins a comment
const COMMENT_DELIMITER: char = '#';

/// Parser for `AuthorizedKeysFile`-formatted data, typically found in
/// `~/.ssh/authorized_keys`.
///
/// For a full description of the format, see:
/// <https://man7.org/linux/man-pages/man8/sshd.8.html#AUTHORIZED_KEYS_FILE_FORMAT>
///
/// Each line of the file consists of a single public key. Blank lines are ignored.
///
/// Public keys consist of the following space-separated fields:
///
/// ```text
/// options, keytype, base64-encoded key, comment
/// ```
///
/// - The options field is optional.
/// - The keytype is `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`,
///   `ssh-ed25519`, `ssh-dss` or `ssh-rsa`
/// - The comment field is not used for anything (but may be convenient for the user to identify
///   the key).
pub struct AuthorizedKeys<'a> {
    /// Lines of the file being iterated over
    lines: core::str::Lines<'a>,
}

impl<'a> AuthorizedKeys<'a> {
    /// Create a new parser for the given input buffer.
    pub fn new(input: &'a str) -> Self {
        Self {
            lines: input.lines(),
        }
    }

    /// Read a file from the filesystem, calling the given closure with an
    /// [`AuthorizedKeys`] parser which operates over a temporary buffer.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn read_file<T, F>(path: impl AsRef<Path>, f: F) -> Result<T>
    where
        F: FnOnce(AuthorizedKeys<'_>) -> Result<T>,
    {
        // TODO(tarcieri): permissions checks
        let input = fs::read_to_string(path)?;
        f(AuthorizedKeys::new(&input))
    }

    /// Get the next line, trimming any comments and trailing whitespace.
    ///
    /// Ignores empty lines.
    fn next_line_trimmed(&mut self) -> Option<&'a str> {
        loop {
            let mut line = self.lines.next()?;

            // Strip comment, if present
            if let Some((l, _)) = line.split_once(COMMENT_DELIMITER) {
                line = l;
            }

            // Trim trailing whitespace
            line = line.trim_end();

            if !line.is_empty() {
                return Some(line);
            }
        }
    }
}

impl<'a> Iterator for AuthorizedKeys<'a> {
    type Item = Result<Entry<'a>>;

    fn next(&mut self) -> Option<Result<Entry<'a>>> {
        self.next_line_trimmed().map(TryInto::try_into)
    }
}

/// Individual entry in an `authorized_keys` file containing a single public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry<'a> {
    /// Options field, if present.
    pub options: Options<'a>,

    /// Public key
    pub public_key: PublicKey,
}

impl<'a> TryFrom<&'a str> for Entry<'a> {
    type Error = Error;

    fn try_from(line: &'a str) -> Result<Self> {
        // TODO(tarcieri): more liberal whitespace handling?
        match line.matches(' ').count() {
            1..=2 => Ok(Self {
                options: Default::default(),
                public_key: line.parse()?,
            }),
            3 => line
                .split_once(' ')
                .map(|(options_str, public_key_str)| {
                    Ok(Self {
                        options: options_str.try_into()?,
                        public_key: public_key_str.parse()?,
                    })
                })
                .ok_or(Error::FormatEncoding)?,
            _ => Err(Error::FormatEncoding),
        }
    }
}

/// Configuration options associated with a particular public key.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Options<'a>(&'a str);

impl<'a> Options<'a> {
    /// Parse an options string.
    pub fn new(string: &'a str) -> Result<Self> {
        // Ensure options can be iterated over successfully
        let mut opts = Self(string);
        while opts.try_next()?.is_some() {}
        Ok(Self(string))
    }

    /// Attempt to parse the next comma-delimited option string.
    fn try_next(&mut self) -> Result<Option<&'a str>> {
        if self.0.is_empty() {
            return Ok(None);
        }

        let mut quoted = false;
        let mut index = 0;

        while let Some(byte) = self.0.as_bytes().get(index).cloned() {
            match byte {
                b',' => {
                    // Commas inside quoted text are ignored
                    if !quoted {
                        let (next, rest) = self.0.split_at(index);
                        self.0 = &rest[1..]; // Strip comma
                        return Ok(Some(next));
                    }
                }
                // TODO(tarcieri): stricter handling of quotes
                b'"' => {
                    // Toggle quoted mode on-off
                    quoted = !quoted;
                }
                // Valid characters
                b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b'!'..=b'/'
                | b':'..=b'@'
                | b'['..=b'_'
                | b'{'
                | b'}'
                | b'|'
                | b'~' => (),
                _ => return Err(Error::CharacterEncoding),
            }

            index += 1;
        }

        let remaining = self.0;
        self.0 = "";
        Ok(Some(remaining))
    }
}

impl<'a> Iterator for Options<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        // Ensured valid by constructor
        self.try_next().expect("malformed options string")
    }
}

impl<'a> TryFrom<&'a str> for Options<'a> {
    type Error = Error;

    fn try_from(s: &'a str) -> Result<Self> {
        Options::new(s)
    }
}

impl fmt::Display for Options<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::Options;
    use crate::Error;

    #[test]
    fn options_empty() {
        assert_eq!(Options("").try_next(), Ok(None));
    }

    #[test]
    fn options_no_comma() {
        let mut opts = Options("foo");
        assert_eq!(opts.try_next(), Ok(Some("foo")));
        assert_eq!(opts.try_next(), Ok(None));
    }

    #[test]
    fn options_no_comma_quoted() {
        let mut opts = Options("foo=\"bar\"");
        assert_eq!(opts.try_next(), Ok(Some("foo=\"bar\"")));
        assert_eq!(opts.try_next(), Ok(None));

        // Comma inside quoted section
        let mut opts = Options("foo=\"bar,baz\"");
        assert_eq!(opts.try_next(), Ok(Some("foo=\"bar,baz\"")));
        assert_eq!(opts.try_next(), Ok(None));
    }

    #[test]
    fn options_comma_delimited() {
        let mut opts = Options("foo,bar");
        assert_eq!(opts.try_next(), Ok(Some("foo")));
        assert_eq!(opts.try_next(), Ok(Some("bar")));
        assert_eq!(opts.try_next(), Ok(None));
    }

    #[test]
    fn options_comma_delimited_quoted() {
        let mut opts = Options("foo=\"bar\",baz");
        assert_eq!(opts.try_next(), Ok(Some("foo=\"bar\"")));
        assert_eq!(opts.try_next(), Ok(Some("baz")));
        assert_eq!(opts.try_next(), Ok(None));
    }

    #[test]
    fn options_invalid_character() {
        let mut opts = Options("❌");
        assert_eq!(opts.try_next(), Err(Error::CharacterEncoding));

        let mut opts = Options("x,❌");
        assert_eq!(opts.try_next(), Ok(Some("x")));
        assert_eq!(opts.try_next(), Err(Error::CharacterEncoding));
    }
}
