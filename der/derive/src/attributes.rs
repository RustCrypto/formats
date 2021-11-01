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
        let mut parsed_attrs = Vec::new();
        AttrNameValue::from_attributes(attrs, &mut parsed_attrs);

        for attr in parsed_attrs {
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

    /// Value of the `#[asn1(context_specific = "...")] attribute if provided.
    pub context_specific: Option<TagNumber>,
}

impl FieldAttrs {
    /// Parse attributes from a struct field or enum variant.
    pub fn parse(attrs: &[Attribute]) -> Self {
        let mut asn1_type = None;
        let mut context_specific = None;

        let mut parsed_attrs = Vec::new();
        AttrNameValue::from_attributes(attrs, &mut parsed_attrs);

        for attr in parsed_attrs {
            // `context_specific = "..."` attribute
            if let Some(tag_number) = attr.parse_value("context_specific") {
                if context_specific.is_some() {
                    panic!(
                        "duplicate ASN.1 `context_specific` attribute: {}",
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

    /// Get the expected `der::Tag` for this field.
    pub fn tag(&self, type_attrs: &TypeAttrs) -> Option<TokenStream> {
        match type_attrs.tag_mode {
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
                None => panic!("implicit tagging requires an associated `tag_number`"),
            },
        }
    }

    /// Get a `der::Decoder` object which respects these field attributes.
    pub fn decoder(&self, type_attrs: &TypeAttrs) -> TokenStream {
        if let Some(tag_number) = self.context_specific {
            let type_params = self.asn1_type.map(|ty| ty.type_path()).unwrap_or_default();
            let tag_number = tag_number.to_tokens();

            let context_specific = match type_attrs.tag_mode {
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
    pub fn encoder(&self, binding: &TokenStream, type_attrs: &TypeAttrs) -> TokenStream {
        if let Some(tag_number) = self.context_specific {
            let tag_number = tag_number.to_tokens();
            let tag_mode = type_attrs.tag_mode.tokens();
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
                other => panic!("malformed `asn1` attribute: {:?}", other),
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
                    _ => panic!("malformed `asn1` attribute: {:?}", nested),
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
                    .unwrap_or_else(|_| panic!("error parsing `{}` attribute", name)),
            )
        } else {
            None
        }
    }
}
