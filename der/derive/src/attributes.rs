//! Attribute-related types used by the proc macro

use crate::{Asn1Type, Tag, TagMode, TagNumber};
use proc_macro2::TokenStream;
use proc_macro_error::{abort, abort_call_site};
use quote::quote;
use std::{fmt::Debug, str::FromStr};
use syn::{Attribute, Lit, LitStr, Meta, MetaList, MetaNameValue, NestedMeta, Path};

/// Attribute name.
pub(crate) const ATTR_NAME: &str = "asn1";

/// Parsing error message.
const PARSE_ERR_MSG: &str = "error parsing `asn1` attribute";

/// Attributes on a `struct` or `enum` type.
#[derive(Clone, Debug, Default)]
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
                    abort!(attr.name, "duplicate ASN.1 `tag_mode` attribute");
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
#[derive(Clone, Debug, Default)]
pub(crate) struct FieldAttrs {
    /// Value of the `#[asn1(type = "...")]` attribute if provided.
    pub asn1_type: Option<Asn1Type>,

    /// Value of the `#[asn1(context_specific = "...")] attribute if provided.
    pub context_specific: Option<TagNumber>,

    /// Indicates name of function that supplies the default value, which will be used in cases
    /// where encoding is omitted per DER and to omit the encoding per DER
    pub default: Option<Path>,

    /// Is this field "extensible", i.e. preceded by the `...` extensibility marker?
    pub extensible: bool,

    /// Is this field `OPTIONAL`?
    pub optional: bool,

    /// Tagging mode for this type: `EXPLICIT` or `IMPLICIT`, supplied as
    /// `#[asn1(tag_mode = "...")]`.
    ///
    /// Inherits from the type-level tagging mode if specified, or otherwise
    /// defaults to `EXPLICIT`.
    pub tag_mode: TagMode,
}

impl FieldAttrs {
    /// Return true when either an optional or default ASN.1 attribute is associated
    /// with a field. Default signifies optionality due to omission of default values in
    /// DER encodings.
    fn is_optional(&self) -> bool {
        self.optional || self.default.is_some()
    }

    /// Parse attributes from a struct field or enum variant.
    pub fn parse(attrs: &[Attribute], type_attrs: &TypeAttrs) -> Self {
        let mut asn1_type = None;
        let mut context_specific = None;

        let mut default = None;
        let mut extensible = None;
        let mut optional = None;
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
            // `default` attribute
            } else if attr.parse_value::<String>("default").is_some() {
                if default.is_some() {
                    abort!(attr.name, "duplicate ASN.1 `default` attribute");
                }

                default = Some(attr.value.parse().unwrap_or_else(|e| {
                    abort!(attr.value, "error parsing ASN.1 `default` attribute: {}", e)
                }));
            // `extensible` attribute
            } else if let Some(ext) = attr.parse_value("extensible") {
                if extensible.is_some() {
                    abort!(attr.name, "duplicate ASN.1 `extensible` attribute");
                }

                extensible = Some(ext);
            // `optional` attribute
            } else if let Some(opt) = attr.parse_value("optional") {
                if optional.is_some() {
                    abort!(attr.name, "duplicate ASN.1 `optional` attribute");
                }

                optional = Some(opt);
            // `tag_mode` attribute
            } else if let Some(mode) = attr.parse_value("tag_mode") {
                if tag_mode.is_some() {
                    abort!(attr.name, "duplicate ASN.1 `tag_mode` attribute");
                }

                tag_mode = Some(mode);
            // `type = "..."` attribute
            } else if let Some(ty) = attr.parse_value("type") {
                if asn1_type.is_some() {
                    abort!(attr.name, "duplicate ASN.1 `type` attribute: {}");
                }

                asn1_type = Some(ty);
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
            default,
            extensible: extensible.unwrap_or_default(),
            optional: optional.unwrap_or_default(),
            tag_mode: tag_mode.unwrap_or(type_attrs.tag_mode),
        }
    }

    /// Get the expected [`Tag`] for this field.
    pub fn tag(&self) -> Option<Tag> {
        match self.tag_mode {
            TagMode::Explicit => self.asn1_type.map(Tag::Universal),
            TagMode::Implicit => self
                .context_specific
                .map(|tag_number| {
                    Some(Tag::ContextSpecific {
                        // TODO(tarcieri): handle constructed inner types
                        constructed: false,
                        number: tag_number,
                    })
                })
                .unwrap_or_else(|| {
                    abort_call_site!("implicit tagging requires an associated `tag_number`")
                }),
        }
    }

    /// Get a `der::Decoder` object which respects these field attributes.
    pub fn decoder(&self) -> TokenStream {
        if let Some(tag_number) = self.context_specific {
            let type_params = self.asn1_type.map(|ty| ty.type_path()).unwrap_or_default();
            let tag_number = tag_number.to_tokens();

            let context_specific = match self.tag_mode {
                TagMode::Explicit => {
                    if self.extensible || self.is_optional() {
                        quote! {
                            ::der::asn1::ContextSpecific::<#type_params>::decode_explicit(
                                decoder,
                                #tag_number
                            )?
                        }
                    } else {
                        quote! {
                            match ::der::asn1::ContextSpecific::<#type_params>::decode(decoder)? {
                                field if field.tag_number == #tag_number => Some(field),
                                _ => None
                            }
                        }
                    }
                }
                TagMode::Implicit => {
                    quote! {
                        ::der::asn1::ContextSpecific::<#type_params>::decode_implicit(
                            decoder,
                            #tag_number
                        )?
                    }
                }
            };

            if self.is_optional() {
                if let Some(default) = &self.default {
                    quote!(#context_specific.map(|cs| cs.value).unwrap_or_else(#default))
                } else {
                    quote!(#context_specific.map(|cs| cs.value))
                }
            } else {
                // TODO(tarcieri): better error handling?
                quote! {
                    #context_specific.ok_or_else(|| {
                        der::Tag::ContextSpecific {
                            number: #tag_number,
                            constructed: false
                        }.value_error()
                    })?.value
                }
            }
        } else if let Some(default) = &self.default {
            let type_params = self.asn1_type.map(|ty| ty.type_path()).unwrap_or_default();
            self.asn1_type.map(|ty| ty.decoder()).unwrap_or_else(
                || quote!(decoder.decode::<Option<#type_params>>()?.unwrap_or_else(#default)),
            )
        } else {
            self.asn1_type
                .map(|ty| ty.decoder())
                .unwrap_or_else(|| quote!(decoder.decode()?))
        }
    }

    /// Get tokens to encode the binding using `::der::EncodeValue`.
    pub fn value_encode(&self, binding: &TokenStream) -> TokenStream {
        match self.context_specific {
            Some(tag_number) => {
                let tag_number = tag_number.to_tokens();
                let tag_mode = self.tag_mode.to_tokens();
                quote! {
                    ::der::asn1::ContextSpecificRef {
                        tag_number: #tag_number,
                        tag_mode: #tag_mode,
                        value: #binding,
                    }.encode_value(encoder)
                }
            }

            None => self
                .asn1_type
                .map(|ty| {
                    let encoder_obj = ty.encoder(binding);
                    quote!(#encoder_obj.encode_value(encoder))
                })
                .unwrap_or_else(|| quote!(encoder.encode_value(#binding)?)),
        }
    }
}

/// Name/value pair attribute.
struct AttrNameValue {
    /// Attribute name.
    pub name: Path,

    /// Attribute value.
    pub value: LitStr,
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
                        value: lit_str.clone(),
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
                    .value()
                    .parse()
                    .unwrap_or_else(|_| abort!(self.name, "error parsing `{}` attribute")),
            )
        } else {
            None
        }
    }
}
