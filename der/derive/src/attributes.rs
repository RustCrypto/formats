//! Attribute-related types used by the proc macro

use crate::{Asn1Type, TagMode, TagNumber};
use proc_macro2::TokenStream;
use proc_macro_error::{abort, abort_call_site};
use quote::quote;
use std::{fmt::Debug, str::FromStr};
use syn::{Attribute, Lit, Meta, MetaList, MetaNameValue, NestedMeta, Path};

/// Attribute name.
pub(crate) const ATTR_NAME: &str = "asn1";

/// Parsing error message.
const PARSE_ERR_MSG: &str = "error parsing `asn1` attribute";

/// Attributes on a `struct` or `enum` type.
#[derive(Clone, Debug)]
pub(crate) struct TypeAttrs {
    /// Tagging mode for this type: `EXPLICIT` or `IMPLICIT`, supplied as
    /// `#[asn1(tag_mode = "...")]`.
    ///
    /// The default value is `EXPLICIT`.
    pub tag_mode: TagMode,
}

impl TypeAttrs {
    /// Parse attributes from a struct field or enum variant.
    pub fn parse(attrs: &[Attribute]) -> Self {
        let mut tag_mode = None;

        let mut parsed_attrs = Vec::new();
        AttrNameValue::from_attributes(attrs, &mut parsed_attrs);

        for attr in parsed_attrs {
            // `tag_mode = "..."` attribute
            if let Some(mode) = attr.parse_value("tag_mode") {
                if tag_mode.is_some() {
                    abort!(attr.value, "duplicate ASN.1 `tag_mode` attribute");
                }

                tag_mode = Some(mode);
            } else {
                abort!(
                    attr.name,
                    "invalid `asn1` attribute (valid options are `tag_mode`)",
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

    /// Value of the `#[asn1(context_specific = "...")] attribute if provided.
    pub context_specific: Option<TagNumber>,

    /// Indicates if decoding should be deferred
    pub defer: Option<bool>,

    /// Tagging mode for this type: `EXPLICIT` or `IMPLICIT`, supplied as
    /// `#[asn1(tag_mode = "...")]`.
    ///
    /// Inherits from the type-level tagging mode if specified, or otherwise
    /// defaults to `EXPLICIT`.
    pub tag_mode: TagMode,
}

impl FieldAttrs {
    /// Parse attributes from a struct field or enum variant.
    pub fn parse(attrs: &[Attribute], type_attrs: &TypeAttrs) -> Self {
        let mut asn1_type = None;
        let mut context_specific = None;

        let mut defer = None;

        let mut tag_mode = None;

        let mut parsed_attrs = Vec::new();
        AttrNameValue::from_attributes(attrs, &mut parsed_attrs);

        for attr in parsed_attrs {
            // `context_specific = "..."` attribute
            if let Some(tag_number) = attr.parse_value("context_specific") {
                if context_specific.is_some() {
                    abort!(attr.name, "duplicate ASN.1 `context_specific` attribute");
                }

                context_specific = Some(tag_number);
            // `type = "..."` attribute
            } else if let Some(ty) = attr.parse_value("type") {
                if asn1_type.is_some() {
                    abort!(attr.value, "duplicate ASN.1 `type` attribute: {}");
                }

                asn1_type = Some(ty);
            } else if let Some(ty) = attr.parse_value("defer") {
                if defer.is_some() {
                    panic!("duplicate ASN.1 `defer` attribute: {}", attr.value);
                }

                defer = Some(ty);
            } else if let Some(mode) = attr.parse_value("tag_mode") {
                if tag_mode.is_some() {
                    abort!(attr.value, "duplicate ASN.1 `tag_mode` attribute");
                }

                tag_mode = Some(mode);
            } else {
                abort!(
                    attr.name,
                    "unknown field-level `asn1` attribute \
                    (valid options are `context_specific`, `type`)",
                );
            }
        }

        Self {
            asn1_type,
            context_specific,
            defer,
            tag_mode: tag_mode.unwrap_or(type_attrs.tag_mode),
        }
    }

    /// Get the expected `der::Tag` for this field.
    pub fn tag(&self) -> Option<TokenStream> {
        match self.tag_mode {
            TagMode::Explicit => self.asn1_type.map(|ty| ty.tag()),
            TagMode::Implicit => match self.context_specific {
                Some(tag_number) => {
                    let tag_number = tag_number.to_tokens();

                    // TODO(tarcieri): handle constructed inner types
                    let constructed = quote!(false);

                    Some(quote! {
                        ::der::Tag::ContextSpecific {
                            number: #tag_number,
                            constructed: #constructed
                        }
                    })
                }
                None => abort_call_site!("implicit tagging requires an associated `tag_number`"),
            },
        }
    }

    /// Get a `der::Decoder` object which respects these field attributes.
    pub fn decoder(&self) -> TokenStream {
        if let Some(tag_number) = self.context_specific {
            let type_params = self.asn1_type.map(|ty| ty.type_path()).unwrap_or_default();
            let tag_number = tag_number.to_tokens();

            let context_specific = match self.tag_mode {
                TagMode::Explicit => {
                    quote!(::der::asn1::ContextSpecific::<#type_params>::decode_explicit(decoder, #tag_number)?)
                }
                TagMode::Implicit => {
                    quote!(::der::asn1::ContextSpecific::<#type_params>::decode_implicit(decoder, #tag_number)?)
                }
            };

            // TODO(tarcieri): better error handling?
            quote! {
                #context_specific.ok_or_else(|| {
                    der::Tag::ContextSpecific {
                        number: #tag_number,
                        constructed: false
                    }.value_error()
                })?.value
            }
        } else {
            self.asn1_type
                .map(|ty| ty.decoder())
                .unwrap_or_else(|| quote!(decoder.decode()?))
        }
    }

    /// Get a `der::Encoder` object which respects these field attributes.
    pub fn encoder(&self, binding: &TokenStream) -> TokenStream {
        if let Some(tag_number) = self.context_specific {
            let tag_number = tag_number.to_tokens();
            let tag_mode = self.tag_mode.to_tokens();
            quote!(encoder.context_specific(#tag_number, #tag_mode, #binding))
        } else {
            self.asn1_type
                .map(|ty| {
                    let encoder_obj = ty.encoder(binding);
                    quote!(#encoder_obj?.encode(encoder))
                })
                .unwrap_or_else(|| quote!(encoder.encode(#binding)?))
        }
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
    /// Parse a slice of attributes.
    pub fn from_attributes(attrs: &[Attribute], out: &mut Vec<Self>) {
        for attr in attrs {
            if !attr.path.is_ident(ATTR_NAME) {
                continue;
            }

            let nested = match attr.parse_meta().expect(PARSE_ERR_MSG) {
                Meta::List(MetaList { nested, .. }) => nested,
                other => abort!(other, "malformed `asn1` attribute"),
            };

            for meta in &nested {
                match meta {
                    NestedMeta::Meta(Meta::NameValue(MetaNameValue {
                        path,
                        lit: Lit::Str(lit_str),
                        ..
                    })) => out.push(Self {
                        name: path.clone(),
                        value: lit_str.value(),
                    }),
                    _ => abort!(nested, "malformed `asn1` attribute"),
                }
            }
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
                    .unwrap_or_else(|_| abort!(self.name, "error parsing `{}` attribute")),
            )
        } else {
            None
        }
    }
}
