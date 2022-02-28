//! Parser for `AuthorizedKeysFile`-formatted data.

use crate::{Error, PublicKey, Result};

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
}

impl<'a> Iterator for AuthorizedKeys<'a> {
    type Item = Result<Entry<'a>>;

    fn next(&mut self) -> Option<Result<Entry<'a>>> {
        loop {
            let result = LineParser::new(self.lines.next()?);

            match result {
                Ok(LineParser {
                    options_str: None,
                    public_key_str: None,
                }) => (),
                Ok(line) => return Some(line.try_into()),
                Err(err) => return Some(Err(err)),
            }
        }
    }
}

/// Individual entry in an `authorized_keys` file containing a single public key.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Entry<'a> {
    /// Options field, if present.
    pub options: Option<&'a str>,

    /// Public key
    pub public_key: PublicKey,
}

impl<'a> TryFrom<LineParser<'a>> for Entry<'a> {
    type Error = Error;

    fn try_from(line: LineParser<'a>) -> Result<Entry<'a>> {
        let public_key = line
            .public_key_str
            .ok_or(Error::FormatEncoding)?
            .parse::<PublicKey>()?;

        Ok(Self {
            options: line.options_str,
            public_key,
        })
    }
}

/// Parser for an individual line in an `authorized_keys` file.
#[derive(Debug)]
struct LineParser<'a> {
    /// Options field, if present.
    options_str: Option<&'a str>,

    /// Public key data, if present.
    public_key_str: Option<&'a str>,
}

impl<'a> LineParser<'a> {
    /// Parse the given line.
    pub fn new(mut line: &'a str) -> Result<Self> {
        // Strip comment, if present
        if let Some((l, _)) = line.split_once(COMMENT_DELIMITER) {
            line = l;
        }

        // Trim trailing whitespace
        line = line.trim_end();

        if line.is_empty() {
            return Ok(Self {
                options_str: None,
                public_key_str: None,
            });
        }

        match line.matches(' ').count() {
            1..=2 => Ok(Self {
                options_str: None,
                public_key_str: Some(line),
            }),
            3 => match line.split_once(' ') {
                Some((options_str, public_key_str)) => Ok(Self {
                    options_str: Some(options_str),
                    public_key_str: Some(public_key_str),
                }),
                _ => Err(Error::FormatEncoding),
            },
            _ => Err(Error::FormatEncoding),
        }
    }
}
