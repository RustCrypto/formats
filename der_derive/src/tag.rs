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

    /// Context-specific tags with an associated [`TagNumber`].
    ContextSpecific {
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
            Tag::ContextSpecific {
                constructed,
                number,
            } => {
                let constructed = if constructed {
                    quote!(true)
                } else {
                    quote!(false)
                };

                let number = number.to_tokens();

                quote! {
                    ::der::Tag::ContextSpecific {
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
pub(crate) struct TagNumber(pub u8);

impl TagNumber {
    /// Maximum tag number supported (inclusive).
    pub const MAX: u8 = 30;

    /// Get tokens describing this tag.
    pub fn to_tokens(self) -> TokenStream {
        match self.0 {
            0 => quote!(::der::TagNumber::new(0)),
            1 => quote!(::der::TagNumber::new(1)),
            2 => quote!(::der::TagNumber::new(2)),
            3 => quote!(::der::TagNumber::new(3)),
            4 => quote!(::der::TagNumber::new(4)),
            5 => quote!(::der::TagNumber::new(5)),
            6 => quote!(::der::TagNumber::new(6)),
            7 => quote!(::der::TagNumber::new(7)),
            8 => quote!(::der::TagNumber::new(8)),
            9 => quote!(::der::TagNumber::new(9)),
            10 => quote!(::der::TagNumber::new(10)),
            11 => quote!(::der::TagNumber::new(11)),
            12 => quote!(::der::TagNumber::new(12)),
            13 => quote!(::der::TagNumber::new(13)),
            14 => quote!(::der::TagNumber::new(14)),
            15 => quote!(::der::TagNumber::new(15)),
            16 => quote!(::der::TagNumber::new(16)),
            17 => quote!(::der::TagNumber::new(17)),
            18 => quote!(::der::TagNumber::new(18)),
            19 => quote!(::der::TagNumber::new(19)),
            20 => quote!(::der::TagNumber::new(20)),
            21 => quote!(::der::TagNumber::new(21)),
            22 => quote!(::der::TagNumber::new(22)),
            23 => quote!(::der::TagNumber::new(23)),
            24 => quote!(::der::TagNumber::new(24)),
            25 => quote!(::der::TagNumber::new(25)),
            26 => quote!(::der::TagNumber::new(26)),
            27 => quote!(::der::TagNumber::new(27)),
            28 => quote!(::der::TagNumber::new(28)),
            29 => quote!(::der::TagNumber::new(29)),
            30 => quote!(::der::TagNumber::new(30)),
            _ => unreachable!("tag number out of range: {}", self),
        }
    }
}

impl FromStr for TagNumber {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        let n = s.parse::<u8>().map_err(|_| ParseError)?;

        if n <= Self::MAX {
            Ok(Self(n))
        } else {
            Err(ParseError)
        }
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
