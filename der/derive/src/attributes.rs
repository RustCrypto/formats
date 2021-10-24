//! Attribute-related types used by the proc macro

use crate::{Asn1Type, TagMode, TagNumber};
use proc_macro2::TokenStream;
use quote::quote;
use std::{fmt::Debug, str::FromStr};
use syn::{Attribute, Lit, Meta, MetaList, MetaNameValue, NestedMeta, Path};

/// Attribute name.
const ATTR_NAME: &str = "asn1";

/// Parsing error message.
const PARSE_ERR_MSG: &str = "error parsing `asn1` attribute";

/// Maximum tag number supported (inclusive).
pub const TAG_NUMBER_MAX: TagNumber = 30;

/// Attributes on a `struct` or `enum` type.
#[derive(Clone, Debug)]
pub(crate) struct TypeAttrs {
    /// Tagging mode for this type's ASN.1 module: `EXPLICIT` or `IMPLICIT`,
    /// supplied as `#[asn1(tag_mode = "...")]`.
    ///
    /// The default value is `EXPLICIT`.
    pub tag_mode: TagMode,
}

impl TypeAttrs {
    /// Parse attributes from a struct field or enum variant.
    pub fn parse(attrs: &[Attribute]) -> Self {
        let mut tag_mode = None;

        for attr in attrs.iter().map(AttrNameValue::new).flatten() {
            // `tag_mode = "..."` attribute
            if let Some(mode) = attr.parse_value("tag_mode") {
                if tag_mode.is_some() {
                    panic!("duplicate ASN.1 `tag_mode` attribute: {}", attr.value);
                }

                tag_mode = Some(mode);
            } else {
                panic!(
                    "unknown field-level `asn1` attribute: {:?} \
                    (valid options are `tag_mode`)",
                    attr.name
                );
            }
        }

        Self {
            tag_mode: tag_mode.unwrap_or_default(),
        }
    }
}

/// Field-level attributes.
#[derive(Clone, Debug)]
pub(crate) struct FieldAttrs {
    /// Value of the `#[asn1(type = "...")]` attribute if provided.
    pub asn1_type: Option<Asn1Type>,

    /// Indicate that this field is a context-specific field with the given
    /// context-specific tag number.
    // TODO(tarcieri): backend support
    #[allow(dead_code)]
    pub context_specific: Option<TagNumber>,
}

impl FieldAttrs {
    /// Parse attributes from a struct field or enum variant.
    pub fn parse(attrs: &[Attribute]) -> Self {
        let mut asn1_type = None;
        let mut context_specific = None;

        for attr in attrs.iter().map(AttrNameValue::new).flatten() {
            // `context_specific = "..."` attribute
            if let Some(tag_number) = attr.parse_value("context_specific") {
                if context_specific.is_some() {
                    panic!(
                        "duplicate ASN.1 `context_specific` attribute: {}",
                        tag_number
                    );
                }

                if tag_number > TAG_NUMBER_MAX {
                    panic!(
                        "error parsing `context_specific` tag number (too big): {}",
                        tag_number
                    );
                }

                context_specific = Some(tag_number);
            // `type = "..."` attribute
            } else if let Some(ty) = attr.parse_value("type") {
                if asn1_type.is_some() {
                    panic!("duplicate ASN.1 `type` attribute: {}", attr.value);
                }

                asn1_type = Some(ty);
            } else {
                panic!(
                    "unknown field-level `asn1` attribute: {:?} \
                    (valid options are `context_specific`, `type`)",
                    attr.name
                );
            }
        }

        Self {
            asn1_type,
            context_specific,
        }
    }

    /// Get a `der::Decoder` object which respects these field attributes.
    pub fn decoder(&self, _type_attrs: &TypeAttrs) -> TokenStream {
        self.asn1_type
            .map(|ty| ty.decoder())
            .unwrap_or_else(|| quote!(decoder.decode()))
    }

    /// Get a `der::Encoder` object which respects these field attributes.
    pub fn encoder(&self, binding: &TokenStream, _type_attrs: &TypeAttrs) -> TokenStream {
        self.asn1_type
            .map(|ty| ty.encoder(binding))
            .unwrap_or_else(|| quote!(encoder.encode(#binding)))
    }
}

/// Name/value pair attribute.
struct AttrNameValue {
    /// Attribute name.
    pub name: Path,

    /// Attribute value.
    pub value: String,
}

impl AttrNameValue {
    /// Parse a given attribute.
    ///
    /// Returns `None` if the attribute name is anything other than `asn1`.
    ///
    /// Expects the value is a string literal.
    pub fn new(attr: &Attribute) -> Option<Self> {
        if !attr.path.is_ident(ATTR_NAME) {
            return None;
        }

        let nested = match attr.parse_meta().expect(PARSE_ERR_MSG) {
            Meta::List(MetaList { nested, .. }) if nested.len() == 1 => nested,
            other => panic!("malformed `asn1` attribute: {:?}", other),
        };

        match nested.first() {
            Some(NestedMeta::Meta(Meta::NameValue(MetaNameValue {
                path,
                lit: Lit::Str(lit_str),
                ..
            }))) => Some(Self {
                name: path.clone(),
                value: lit_str.value(),
            }),
            _ => panic!("malformed `asn1` attribute: {:?}", nested),
        }
    }

    /// Parse an attribute value if the name matches the specified one.
    pub fn parse_value<T>(&self, name: &str) -> Option<T>
    where
        T: FromStr + Debug,
        T::Err: Debug,
    {
        if self.name.is_ident(name) {
            Some(
                self.value
                    .parse()
                    .unwrap_or_else(|_| panic!("error parsing `{}` attribute", name)),
            )
        } else {
            None
        }
    }
}
