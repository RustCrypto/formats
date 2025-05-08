//! Tag-related functionality.

use crate::Asn1Type;
use proc_macro2::TokenStream;
use quote::quote;
use std::{
    fmt::{self, Display},
    str::FromStr,
};
use syn::{LitStr, parse::Parse};

/// Tag "IR" type.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub(crate) enum Tag {
    /// Universal tags with an associated [`Asn1Type`].
    Universal(Asn1Type),

    /// `APPLICATION` tags with an associated [`TagNumber`].
    Application {
        /// Is the inner ASN.1 type constructed?
        constructed: bool,

        /// Context-specific tag number
        number: TagNumber,
    },

    /// `CONTEXT-SPECIFIC` tags with an associated [`TagNumber`].
    ContextSpecific {
        /// Is the inner ASN.1 type constructed?
        constructed: bool,

        /// Context-specific tag number
        number: TagNumber,
    },

    /// `PRIVATE` tags with an associated [`TagNumber`].
    Private {
        /// Is the inner ASN.1 type constructed?
        constructed: bool,

        /// Context-specific tag number
        number: TagNumber,
    },
}

impl Tag {
    /// Lower this [`Tag`] to a [`TokenStream`].
    pub fn to_tokens(self) -> TokenStream {
        match self {
            Tag::Universal(ty) => ty.tag(),
            Tag::Application {
                constructed,
                number,
            } => {
                let number = number.to_tokens();

                quote! {
                    ::der::Tag::Application {
                        constructed: #constructed,
                        number: #number,
                    }
                }
            }
            Tag::ContextSpecific {
                constructed,
                number,
            } => {
                let number = number.to_tokens();

                quote! {
                    ::der::Tag::ContextSpecific {
                        constructed: #constructed,
                        number: #number,
                    }
                }
            }
            Tag::Private {
                constructed,
                number,
            } => {
                let number = number.to_tokens();

                quote! {
                    ::der::Tag::Private {
                        constructed: #constructed,
                        number: #number,
                    }
                }
            }
        }
    }
}

/// Tagging modes: `EXPLICIT` versus `IMPLICIT`.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub(crate) enum TagMode {
    /// `EXPLICIT` tagging.
    ///
    /// Tag is added in addition to the inner tag of the type.
    #[default]
    Explicit,

    /// `IMPLICIT` tagging.
    ///
    /// Tag replaces the existing tag of the inner type.
    Implicit,
}

impl TagMode {
    /// Lower this [`TagMode`] to a [`TokenStream`] with the `der`
    /// crate's corresponding enum variant for this tag mode.
    pub fn to_tokens(self) -> TokenStream {
        match self {
            TagMode::Explicit => quote!(::der::TagMode::Explicit),
            TagMode::Implicit => quote!(::der::TagMode::Implicit),
        }
    }
}

impl Parse for TagMode {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        let s: LitStr = input.parse()?;

        match s.value().as_str() {
            "EXPLICIT" | "explicit" => Ok(TagMode::Explicit),
            "IMPLICIT" | "implicit" => Ok(TagMode::Implicit),
            _ => Err(syn::Error::new(
                s.span(),
                "invalid tag mode (supported modes are `EXPLICIT` and `IMPLICIT`)",
            )),
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

impl Display for TagMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TagMode::Explicit => f.write_str("EXPLICIT"),
            TagMode::Implicit => f.write_str("IMPLICIT"),
        }
    }
}

/// ASN.1 tag numbers (i.e. lower 5 bits of a [`Tag`]).
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub(crate) struct TagNumber(pub u32);

impl TagNumber {
    /// Get tokens describing this tag.
    pub fn to_tokens(self) -> TokenStream {
        let num = self.0;
        quote!(::der::TagNumber(#num))
    }
}

impl FromStr for TagNumber {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        s.parse::<u32>().map(Self).map_err(|_| ParseError)
    }
}

impl Display for TagNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Error type
#[derive(Debug)]
pub(crate) struct ParseError;
