//! Tag-related functionality.

use proc_macro2::TokenStream;
use quote::quote;
use std::{
    fmt::{self, Display},
    str::FromStr,
};

/// Tag number.
pub type TagNumber = u8;

/// Tagging modes: `EXPLICIT` versus `IMPLICIT`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub(crate) enum TagMode {
    /// `EXPLICIT` tagging.
    ///
    /// Tag is added in addition to the inner tag of the type.
    Explicit,

    /// `IMPLICIT` tagging.
    ///
    /// Tag replaces the existing tag of the inner type.
    Implicit,
}

impl TagMode {
    /// Get a [`TokenStream`] identifying the `der` crate's corresponding
    /// enum variant for this tag mode.
    pub fn tokens(self) -> TokenStream {
        match self {
            TagMode::Explicit => quote!(::der::TagMode::Explicit),
            TagMode::Implicit => quote!(::der::TagMode::Implicit),
        }
    }
}

impl FromStr for TagMode {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        match s {
            "EXPLICIT" | "explicit" => Ok(TagMode::Explicit),
            "IMPLICIT" | "implicit" => Ok(TagMode::Implicit),
            _ => Err(ParseError),
        }
    }
}

impl Default for TagMode {
    fn default() -> TagMode {
        TagMode::Explicit
    }
}

impl Display for TagMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TagMode::Explicit => f.write_str("EXPLICIT"),
            TagMode::Implicit => f.write_str("IMPLICIT"),
        }
    }
}

/// Error type
#[derive(Debug)]
pub(crate) struct ParseError;
