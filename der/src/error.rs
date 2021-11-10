//! Error types.

pub use core::str::Utf8Error;

use crate::{Length, Tag};
use core::{convert::Infallible, fmt};

#[cfg(feature = "oid")]
use crate::asn1::ObjectIdentifier;

#[cfg(feature = "pem")]
use crate::pem;

/// Result type.
pub type Result<T> = core::result::Result<T, Error>;

/// Error type.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Error {
    /// Kind of error.
    kind: ErrorKind,

    /// Position inside of message where error occurred.
    position: Option<Length>,
}

impl Error {
    /// Create a new [`Error`].
    pub fn new(kind: ErrorKind, position: Length) -> Error {
        Error {
            kind,
            position: Some(position),
        }
    }

    /// If the error's `kind` is an [`ErrorKind::Incomplete`], return the `expected_len`.
    pub fn incomplete(self) -> Option<usize> {
        self.kind().incomplete()
    }

    /// Get the [`ErrorKind`] which occurred.
    pub fn kind(self) -> ErrorKind {
        self.kind
    }

    /// Get the position inside of the message where the error occurred.
    pub fn position(self) -> Option<Length> {
        self.position
    }

    /// For errors occurring inside of a nested message, extend the position
    /// count by the location where the nested message occurs.
    pub(crate) fn nested(self, nested_position: Length) -> Self {
        // TODO(tarcieri): better handle length overflows occurring in this calculation?
        let position = (nested_position + self.position.unwrap_or_default()).ok();

        Self {
            kind: self.kind,
            position,
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;

        if let Some(pos) = self.position {
            write!(f, " at DER byte {}", pos)?;
        }

        Ok(())
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error {
            kind,
            position: None,
        }
    }
}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Error {
        unreachable!()
    }
}

impl From<Utf8Error> for Error {
    fn from(err: Utf8Error) -> Error {
        Error {
            kind: ErrorKind::Utf8(err),
            position: None,
        }
    }
}

#[cfg(feature = "oid")]
impl From<const_oid::Error> for Error {
    fn from(_: const_oid::Error) -> Error {
        ErrorKind::OidMalformed.into()
    }
}

#[cfg(feature = "pem")]
impl From<pem::Error> for Error {
    fn from(err: pem::Error) -> Error {
        ErrorKind::Pem(err).into()
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        match err.kind() {
            std::io::ErrorKind::NotFound => ErrorKind::FileNotFound,
            std::io::ErrorKind::PermissionDenied => ErrorKind::PermissionDenied,
            other => ErrorKind::Io(other),
        }
        .into()
    }
}

#[cfg(feature = "time")]
impl From<time::error::ComponentRange> for Error {
    fn from(_: time::error::ComponentRange) -> Error {
        ErrorKind::DateTime.into()
    }
}
/// Error type.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Date-and-time related errors.
    DateTime,

    /// This error indicates a previous DER parsing operation resulted in
    /// an error and tainted the state of a `Decoder` or `Encoder`.
    ///
    /// Once this occurs, the overall operation has failed and cannot be
    /// subsequently resumed.
    Failed,

    /// File not found error.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    FileNotFound,

    /// Message is incomplete and does not contain all of the expected data.
    Incomplete {
        /// Expected message length.
        ///
        /// Note that this length represents a *minimum* lower bound on how
        /// much additional data is needed to continue parsing the message.
        ///
        /// It's possible upon subsequent message parsing that the parser will
        /// discover even more data is needed.
        expected_len: Length,

        /// Actual length of the message buffer currently being processed.
        actual_len: Length,
    },

    /// I/O errors.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    Io(std::io::ErrorKind),

    /// Incorrect length for a given field.
    Length {
        /// Tag of the value being decoded.
        tag: Tag,
    },

    /// Message is not canonically encoded.
    Noncanonical {
        /// Tag of the value which is not canonically encoded.
        tag: Tag,
    },

    /// OID is improperly encoded.
    OidMalformed,

    /// Unknown OID.
    ///
    /// This error is intended to be used by libraries which parse DER-based
    /// formats which encounter unknown or unsupported OID libraries.
    ///
    /// It enables passing back the OID value to the caller, which allows them
    /// to determine which OID(s) are causing the error (and then potentially
    /// contribute upstream support for algorithms they care about).
    #[cfg(feature = "oid")]
    #[cfg_attr(docsrs, doc(cfg(feature = "oid")))]
    OidUnknown {
        /// OID value that was unrecognized by a parser for a DER-based format.
        oid: ObjectIdentifier,
    },

    /// `SET` ordering error: items not in canonical order.
    SetOrdering,

    /// Integer overflow occurred (library bug!).
    Overflow,

    /// Message is longer than this library's internal limits support.
    Overlength,

    /// PEM encoding errors.
    #[cfg(feature = "pem")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    Pem(pem::Error),

    /// Permission denied reading file.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    PermissionDenied,

    /// Unknown tag mode.
    TagModeUnknown,

    /// Invalid tag number.
    ///
    /// The "tag number" is the lower 5-bits of a tag's octet.
    /// This error occurs in the case that all 5-bits are set to `1`,
    /// which indicates a multi-byte tag which is unsupported by this library.
    TagNumberInvalid,

    /// Unexpected tag.
    TagUnexpected {
        /// Tag the decoder was expecting (if there is a single such tag).
        ///
        /// `None` if multiple tags are expected/allowed, but the `actual` tag
        /// does not match any of them.
        expected: Option<Tag>,

        /// Actual tag encountered in the message.
        actual: Tag,
    },

    /// Unknown/unsupported tag.
    TagUnknown {
        /// Raw byte value of the tag.
        byte: u8,
    },

    /// Undecoded trailing data at end of message.
    TrailingData {
        /// Length of the decoded data.
        decoded: Length,

        /// Total length of the remaining data left in the buffer.
        remaining: Length,
    },

    /// UTF-8 errors.
    Utf8(Utf8Error),

    /// Unexpected value.
    Value {
        /// Tag of the unexpected value.
        tag: Tag,
    },
}

impl ErrorKind {
    /// Annotate an [`ErrorKind`] with context about where it occurred,
    /// returning an error.
    pub fn at(self, position: Length) -> Error {
        Error::new(self, position)
    }

    /// If this is an [`ErrorKind::Incomplete`], return the `expected_len`.
    pub fn incomplete(self) -> Option<usize> {
        match self {
            ErrorKind::Incomplete { expected_len, .. } => usize::try_from(expected_len).ok(),
            _ => None,
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::DateTime => write!(f, "date/time error"),
            ErrorKind::Failed => write!(f, "operation failed"),
            #[cfg(feature = "std")]
            ErrorKind::FileNotFound => f.write_str("file not found"),
            ErrorKind::Incomplete {
                expected_len,
                actual_len,
            } => write!(
                f,
                "ASN.1 DER message is incomplete: expected {}, actual {}",
                expected_len, actual_len
            ),
            #[cfg(feature = "std")]
            ErrorKind::Io(err) => write!(f, "I/O error: {:?}", err),
            ErrorKind::Length { tag } => write!(f, "incorrect length for {}", tag),
            ErrorKind::Noncanonical { tag } => {
                write!(f, "ASN.1 {} not canonically encoded as DER", tag)
            }
            ErrorKind::OidMalformed => write!(f, "malformed OID"),
            #[cfg(feature = "oid")]
            ErrorKind::OidUnknown { oid } => {
                write!(f, "unknown/unsupported OID: {}", oid)
            }
            ErrorKind::SetOrdering => write!(f, "ordering error"),
            ErrorKind::Overflow => write!(f, "integer overflow"),
            ErrorKind::Overlength => write!(f, "ASN.1 DER message is too long"),
            #[cfg(feature = "pem")]
            ErrorKind::Pem(e) => write!(f, "PEM error: {}", e),
            #[cfg(feature = "std")]
            ErrorKind::PermissionDenied => f.write_str("permission denied"),
            ErrorKind::TagModeUnknown => write!(f, "unknown tag mode"),
            ErrorKind::TagNumberInvalid => write!(f, "invalid tag number"),
            ErrorKind::TagUnexpected { expected, actual } => {
                write!(f, "unexpected ASN.1 DER tag: ")?;

                if let Some(tag) = expected {
                    write!(f, "expected {}, ", tag)?;
                }

                write!(f, "got {}", actual)
            }
            ErrorKind::TagUnknown { byte } => {
                write!(f, "unknown/unsupported ASN.1 DER tag: 0x{:02x}", byte)
            }
            ErrorKind::TrailingData { decoded, remaining } => {
                write!(
                    f,
                    "trailing data at end of DER message: decoded {} bytes, {} bytes remaining",
                    decoded, remaining
                )
            }
            ErrorKind::Utf8(e) => write!(f, "{}", e),
            ErrorKind::Value { tag } => write!(f, "malformed ASN.1 DER value for {}", tag),
        }
    }
}
