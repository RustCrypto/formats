//! ASN.1 types supported by the proc macro

use proc_macro2::TokenStream;
use quote::quote;
use std::{fmt, str::FromStr};

/// ASN.1 built-in types supported by the `#[asn1(type = "...")]` attribute
// TODO(tarcieri): support all ASN.1 types specified in `der::Tag`
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub(crate) enum Asn1Type {
    /// ASN.1 `BIT STRING`.
    BitString,

    /// ASN.1 `IA5String`.
    Ia5String,

    /// ASN.1 `GeneralizedTime`.
    GeneralizedTime,

    /// ASN.1 `OCTET STRING`.
    OctetString,

    /// ASN.1 `PrintableString`.
    PrintableString,

    /// ASN.1 `UTCTime`.
    UtcTime,

    /// ASN.1 `UTF8String`.
    Utf8String,
}

impl Asn1Type {
    /// Get the `::der::Tag` for this ASN.1 type
    pub fn tag(self) -> TokenStream {
        match self {
            Asn1Type::BitString => quote!(::der::Tag::BitString),
            Asn1Type::Ia5String => quote!(::der::Tag::Ia5String),
            Asn1Type::GeneralizedTime => quote!(::der::Tag::GeneralizedTime),
            Asn1Type::OctetString => quote!(::der::Tag::OctetString),
            Asn1Type::PrintableString => quote!(::der::Tag::PrintableString),
            Asn1Type::UtcTime => quote!(::der::Tag::UtcTime),
            Asn1Type::Utf8String => quote!(::der::Tag::Utf8String),
        }
    }

    /// Get a `der::Decoder` object for a particular ASN.1 type
    pub fn decoder(self) -> TokenStream {
        match self {
            Asn1Type::BitString => quote!(decoder.bit_string()),
            Asn1Type::Ia5String => quote!(decoder.ia5_string()),
            Asn1Type::GeneralizedTime => quote!(decoder.generalized_time()),
            Asn1Type::OctetString => quote!(decoder.octet_string()),
            Asn1Type::PrintableString => quote!(decoder.printable_string()),
            Asn1Type::UtcTime => quote!(decoder.utc_time()),
            Asn1Type::Utf8String => quote!(decoder.utf8_string()),
        }
    }

    /// Get a `der::Encoder` object for a particular ASN.1 type
    pub fn encoder(self, binding: &TokenStream) -> TokenStream {
        let type_path = self.type_path();

        match self {
            Asn1Type::Ia5String
            | Asn1Type::OctetString
            | Asn1Type::PrintableString
            | Asn1Type::Utf8String => quote!(#type_path::new(#binding)),
            _ => quote!(#type_path::try_from(#binding)),
        }
    }

    /// Get the Rust type path for a particular ASN.1 type.
    /// Get a `der::Encoder` object for a particular ASN.1 type
    pub fn type_path(self) -> TokenStream {
        match self {
            Asn1Type::BitString => quote!(::der::asn1::BitString),
            Asn1Type::Ia5String => quote!(::der::asn1::Ia5String),
            Asn1Type::GeneralizedTime => quote!(::der::asn1::GeneralizedTime),
            Asn1Type::OctetString => quote!(::der::asn1::OctetString),
            Asn1Type::PrintableString => quote!(::der::asn1::PrintableString),
            Asn1Type::UtcTime => quote!(::der::asn1::UtcTime),
            Asn1Type::Utf8String => quote!(::der::asn1::Utf8String),
        }
    }
}

impl FromStr for Asn1Type {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        match s {
            "BIT STRING" => Ok(Self::BitString),
            "IA5String" => Ok(Self::Ia5String),
            "GeneralizedTime" => Ok(Self::GeneralizedTime),
            "OCTET STRING" => Ok(Self::OctetString),
            "PrintableString" => Ok(Self::PrintableString),
            "UTCTime" => Ok(Self::UtcTime),
            "UTF8String" => Ok(Self::Utf8String),
            _ => Err(ParseError),
        }
    }
}

impl fmt::Display for Asn1Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Asn1Type::BitString => "BIT STRING",
            Asn1Type::Ia5String => "IA5String",
            Asn1Type::GeneralizedTime => "GeneralizedTime",
            Asn1Type::OctetString => "OCTET STRING",
            Asn1Type::PrintableString => "PrintableString",
            Asn1Type::UtcTime => "UTCTime",
            Asn1Type::Utf8String => "UTF8String",
        })
    }
}

/// Error type
#[derive(Debug)]
pub(crate) struct ParseError;
