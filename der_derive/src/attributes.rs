//! Attribute-related types used by the proc macro

use crate::{Asn1Type, Tag, TagMode, TagNumber};
use proc_macro2::{Span, TokenStream};
use quote::{ToTokens, quote};
use std::{fmt::Debug, str::FromStr};
use syn::punctuated::Punctuated;
use syn::{Attribute, Ident, LitStr, Path, Token, parse::Parse, parse::ParseStream};

/// Error type used by the structure
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub(crate) enum ErrorType {
    /// Represents the ::der::Error type
    #[default]
    Der,
    /// Represents an error designed by Path
    Custom(Path),
}

impl ToTokens for ErrorType {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self {
            Self::Der => {
                let err = quote! { ::der::Error };
                err.to_tokens(tokens)
            }
            Self::Custom(path) => path.to_tokens(tokens),
        }
    }
}

/// Attribute name.
pub(crate) const ATTR_NAME: &str = "asn1";

/// Attributes on a `struct` or `enum` type.
#[derive(Clone, Debug, Default)]
pub(crate) struct TypeAttrs {
    /// Tagging mode for this type: `EXPLICIT` or `IMPLICIT`, supplied as
    /// `#[asn1(tag_mode = "...")]`.
    ///
    /// The default value is `EXPLICIT`.
    pub tag_mode: TagMode,
    pub error: ErrorType,
}

impl TypeAttrs {
    /// Parse attributes from a struct field or enum variant.
    pub fn parse(attrs: &[Attribute]) -> syn::Result<Self> {
        let mut tag_mode = None;
        let mut error = None;

        attrs.iter().try_for_each(|attr| {
            if !attr.path().is_ident(ATTR_NAME) {
                return Ok(());
            }

            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("tag_mode") {
                    if tag_mode.is_some() {
                        abort!(attr, "duplicate ASN.1 `tag_mode` attribute");
                    }

                    tag_mode = Some(meta.value()?.parse()?);
                } else if meta.path.is_ident("error") {
                    if error.is_some() {
                        abort!(attr, "duplicate ASN.1 `error` attribute");
                    }

                    error = Some(ErrorType::Custom(meta.value()?.parse()?));
                } else {
                    return Err(syn::Error::new_spanned(
                        attr,
                        "invalid `asn1` attribute (valid options are `tag_mode` and `error`)",
                    ));
                }

                Ok(())
            })
        })?;

        Ok(Self {
            tag_mode: tag_mode.unwrap_or_default(),
            error: error.unwrap_or_default(),
        })
    }
}

/// Field-level attributes.
#[derive(Clone, Debug, Default)]
pub(crate) struct FieldAttrs {
    /// Value of the `#[asn1(type = "...")]` attribute if provided.
    pub asn1_type: Option<Asn1Type>,

    /// Is the inner type constructed?
    pub constructed: bool,

    /// Class and number from the following attributes:
    /// - `#[asn1(application = "...")]`
    /// - `#[asn1(context_specific = "...")]`
    /// - `#[asn1(private = "...")]`
    pub class_num: Option<ClassNum>,

    /// Indicates name of function that supplies the default value, which will be used in cases
    /// where encoding is omitted per DER and to omit the encoding per DER
    pub default: Option<Path>,

    /// Should we add `&` before `self.field_name`?
    pub should_deref: bool,

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
    pub fn parse(attrs: &[Attribute], type_attrs: &TypeAttrs) -> syn::Result<Self> {
        let mut asn1_type = None;
        let mut constructed = None;
        let mut class_num = None;
        let mut default = None;
        let mut should_deref = None;
        let mut extensible = None;
        let mut optional = None;
        let mut tag_mode = None;

        let mut parsed_attrs = Vec::new();
        AttrNameValue::from_attributes(attrs, &mut parsed_attrs)?;

        for attr in parsed_attrs {
            // `context_specific = "..."` attribute
            if let Some(tag_number) = attr.parse_value("context_specific")? {
                if class_num.is_some() {
                    abort!(
                        attr.name,
                        "duplicate ASN.1 class attribute (`application`, `context_specific`, `private`)"
                    );
                }

                class_num = Some(ClassNum::ContextSpecific(tag_number));
            // `private = "..."` attribute
            } else if let Some(tag_number) = attr.parse_value("private")? {
                if class_num.is_some() {
                    abort!(
                        attr.name,
                        "duplicate ASN.1 class attribute (`application`, `context_specific`, `private`)"
                    );
                }

                class_num = Some(ClassNum::Private(tag_number));
            // `application = "..."` attribute
            } else if let Some(tag_number) = attr.parse_value("application")? {
                if class_num.is_some() {
                    abort!(
                        attr.name,
                        "duplicate ASN.1 class attribute (`application`, `context_specific`, `private`)"
                    );
                }

                class_num = Some(ClassNum::Application(tag_number));
            // `default` attribute
            } else if attr.parse_value::<String>("default")?.is_some() {
                if default.is_some() {
                    abort!(attr.name, "duplicate ASN.1 `default` attribute");
                }

                default = Some(attr.value.parse().map_err(|e| {
                    syn::Error::new_spanned(
                        attr.value,
                        format_args!("error parsing ASN.1 `default` attribute: {e}"),
                    )
                })?);
            // `deref` attribute
            } else if let Some(de) = attr.parse_value("deref")? {
                if should_deref.is_some() {
                    abort!(attr.name, "duplicate ASN.1 `deref` attribute");
                }
                should_deref = Some(de);
            // `extensible` attribute
            } else if let Some(ext) = attr.parse_value("extensible")? {
                if extensible.is_some() {
                    abort!(attr.name, "duplicate ASN.1 `extensible` attribute");
                }

                extensible = Some(ext);
            // `optional` attribute
            } else if let Some(opt) = attr.parse_value("optional")? {
                if optional.is_some() {
                    abort!(attr.name, "duplicate ASN.1 `optional` attribute");
                }

                optional = Some(opt);
            // `tag_mode` attribute
            } else if let Some(mode) = attr.parse_value("tag_mode")? {
                if tag_mode.is_some() {
                    abort!(attr.name, "duplicate ASN.1 `tag_mode` attribute");
                }

                tag_mode = Some(mode);
            // `type = "..."` attribute
            } else if let Some(ty) = attr.parse_value("type")? {
                if asn1_type.is_some() {
                    abort!(attr.name, "duplicate ASN.1 `type` attribute");
                }

                asn1_type = Some(ty);
            // `constructed = "..."` attribute
            } else if let Some(ty) = attr.parse_value("constructed")? {
                if constructed.is_some() {
                    abort!(attr.name, "duplicate ASN.1 `constructed` attribute");
                }

                constructed = Some(ty);
            } else {
                abort!(
                    attr.name,
                    "unknown field-level `asn1` attribute \
                    (valid options are `application`, `constructed`, `context_specific`, `default`, `deref`, `extensible`, `optional`, `private`, `tag_mode`, `type`)",
                );
            }
        }

        Ok(Self {
            asn1_type,
            constructed: constructed.unwrap_or_default(),
            class_num,
            default,
            should_deref: should_deref.unwrap_or_default(),
            extensible: extensible.unwrap_or_default(),
            optional: optional.unwrap_or_default(),
            tag_mode: tag_mode.unwrap_or(type_attrs.tag_mode),
        })
    }

    /// Get the expected [`Tag`] for this field.
    pub fn tag(&self) -> syn::Result<Option<Tag>> {
        match self.class_num {
            Some(ClassNum::Application(tag_number)) => Ok(Some(Tag::Application {
                constructed: self.constructed,
                number: tag_number,
            })),
            Some(ClassNum::ContextSpecific(tag_number)) => Ok(Some(Tag::ContextSpecific {
                constructed: self.constructed,
                number: tag_number,
            })),
            Some(ClassNum::Private(tag_number)) => Ok(Some(Tag::Private {
                constructed: self.constructed,
                number: tag_number,
            })),

            None => match self.tag_mode {
                TagMode::Explicit => Ok(self.asn1_type.map(Tag::Universal)),
                TagMode::Implicit => Err(syn::Error::new(
                    Span::call_site(),
                    "implicit tagging requires a `tag_number`",
                )),
            },
        }
    }

    /// Get a `der::Decoder` object which respects these field attributes.
    pub fn decoder(&self) -> TokenStream {
        if let Some(class_num) = &self.class_num {
            self.custom_class_decoder(class_num)
        } else if let Some(default) = &self.default {
            let type_params = self.asn1_type.map(|ty| ty.type_path()).unwrap_or_default();
            self.asn1_type.map(|ty| ty.decoder()).unwrap_or_else(|| {
                quote! {
                    Option::<#type_params>::decode(reader)?.unwrap_or_else(#default),
                }
            })
        } else if self.is_optional() {
            self.asn1_type
                .map(|ty| ty.decoder_optional())
                .unwrap_or_else(|| quote!(reader.decode()?))
        } else {
            self.asn1_type
                .map(|ty| ty.decoder())
                .unwrap_or_else(|| quote!(reader.decode()?))
        }
    }

    /// Get a `der::DecodeValue` member which respects these field attributes.
    pub fn value_decoder(&self) -> TokenStream {
        if let Some(default) = &self.default {
            let type_params = self.asn1_type.map(|ty| ty.type_path()).unwrap_or_default();
            self.asn1_type.map(|ty| ty.value_decoder()).unwrap_or_else(|| {
                quote! {
                    Option::<#type_params>::decode_value(reader, header)?.unwrap_or_else(#default),
                }
            })
        } else if self.is_optional() {
            self.asn1_type
                .map(|ty| ty.value_decoder_optional())
                .unwrap_or_else(|| quote!(<_>::decode_value(reader, header)?))
        } else {
            self.asn1_type
                .map(|ty| ty.value_decoder())
                .unwrap_or_else(|| quote!(<_>::decode_value(reader, header)?))
        }
    }

    pub fn custom_class_decoder(&self, class_num: &ClassNum) -> TokenStream {
        let type_params = self.asn1_type.map(|ty| ty.type_path()).unwrap_or(quote!(_));
        let ClassTokens {
            tag_type,
            tag_number,
            class_type,
            ..
        } = class_num.to_tokens(type_params, self.tag_mode);

        let context_specific = match self.tag_mode {
            TagMode::Explicit => {
                if self.extensible || self.is_optional() {
                    quote! {
                        #class_type::decode_explicit(
                            reader,
                            #tag_number
                        )?
                    }
                } else {
                    quote! {
                        match #class_type::decode(reader)? {
                            field if field.tag_number == #tag_number => Some(field),
                            _ => None
                        }
                    }
                }
            }
            TagMode::Implicit => {
                quote! {
                    #class_type::decode_implicit(
                        reader,
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
            let constructed = self.constructed;
            quote! {
                #context_specific.ok_or_else(|| {
                    #tag_type {
                        number: #tag_number,
                        constructed: #constructed
                    }.value_error()
                })?.value
            }
        }
    }

    /// Get tokens to encode the binding using `::der::EncodeValue`.
    pub fn value_encode(&self, binding: &TokenStream) -> TokenStream {
        match &self.class_num {
            Some(class_num) => {
                let tag_mode = self.tag_mode.to_tokens();
                let type_params = self.asn1_type.map(|ty| ty.type_path()).unwrap_or(quote!(_));
                let ClassTokens {
                    ref_type,
                    tag_number,
                    ..
                } = class_num.to_tokens(type_params, self.tag_mode);

                quote! {
                    #ref_type {
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
                .unwrap_or_else(|| quote!(#binding.encode_value(encoder))),
        }
    }
}

/// Name/value pair attribute.
pub(crate) struct AttrNameValue {
    /// Attribute name.
    pub name: Path,

    /// Attribute value.
    pub value: LitStr,
}

impl Parse for AttrNameValue {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let name = match input.parse() {
            Ok(name) => name,
            // If it doesn't parse as a path, check if it's the keyword `type`
            // The asn1 macro uses this even though Path cannot technically contain
            // non-identifiers, so it needs to be forced in.
            Err(e) => {
                if let Ok(tok) = input.parse::<Token![type]>() {
                    Path::from(Ident::new("type", tok.span))
                } else {
                    // If it still doesn't parse, report the original error rather than the
                    // one produced by the workaround.
                    return Err(e);
                }
            }
        };
        input.parse::<Token![=]>()?;
        let value = input.parse()?;
        Ok(Self { name, value })
    }
}

impl AttrNameValue {
    pub fn parse_attribute(attr: &Attribute) -> syn::Result<impl IntoIterator<Item = Self>> {
        attr.parse_args_with(Punctuated::<Self, Token![,]>::parse_terminated)
    }

    /// Parse a slice of attributes.
    pub fn from_attributes(attrs: &[Attribute], out: &mut Vec<Self>) -> syn::Result<()> {
        for attr in attrs {
            if !attr.path().is_ident(ATTR_NAME) {
                continue;
            }

            match Self::parse_attribute(attr) {
                Ok(parsed) => out.extend(parsed),
                Err(e) => abort!(attr, e),
            }
        }

        Ok(())
    }

    /// Parse an attribute value if the name matches the specified one.
    pub fn parse_value<T>(&self, name: &str) -> syn::Result<Option<T>>
    where
        T: FromStr + Debug,
        T::Err: Debug,
    {
        Ok(if self.name.is_ident(name) {
            Some(
                self.value
                    .value()
                    .parse()
                    .map_err(|_| syn::Error::new_spanned(&self.name, "error parsing attribute"))?,
            )
        } else {
            None
        })
    }
}

/// Class and tag number
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ClassNum {
    ContextSpecific(TagNumber),
    Private(TagNumber),
    Application(TagNumber),
}

pub(crate) struct ClassTokens {
    pub tag_type: TokenStream,
    pub tag_number: TokenStream,

    pub class_type: TokenStream,
    pub ref_type: TokenStream,
}

impl ClassNum {
    pub fn to_tokens(&self, type_params: TokenStream, tag_mode: TagMode) -> ClassTokens {
        // Future-proof for potential ContextSpecificExplicit / ContextSpecificImplicit split
        match (tag_mode, self) {
            (TagMode::Explicit, Self::ContextSpecific(tag_number)) => ClassTokens {
                tag_type: quote!(::der::Tag::ContextSpecific),
                class_type: quote!(::der::asn1::ContextSpecific::<#type_params>),
                ref_type: quote!(::der::asn1::ContextSpecificRef),
                tag_number: tag_number.to_tokens(),
            },
            (TagMode::Implicit, Self::ContextSpecific(tag_number)) => ClassTokens {
                tag_type: quote!(::der::Tag::ContextSpecific),
                class_type: quote!(::der::asn1::ContextSpecific::<#type_params>),
                ref_type: quote!(::der::asn1::ContextSpecificRef),
                tag_number: tag_number.to_tokens(),
            },
            (TagMode::Explicit, Self::Private(tag_number)) => ClassTokens {
                tag_type: quote!(::der::Tag::Private),
                class_type: quote!(::der::asn1::Private::<#type_params>),
                ref_type: quote!(::der::asn1::PrivateRef),
                tag_number: tag_number.to_tokens(),
            },
            (TagMode::Implicit, Self::Private(tag_number)) => ClassTokens {
                tag_type: quote!(::der::Tag::Private),
                class_type: quote!(::der::asn1::Private::<#type_params>),
                ref_type: quote!(::der::asn1::PrivateRef),
                tag_number: tag_number.to_tokens(),
            },
            (TagMode::Explicit, Self::Application(tag_number)) => ClassTokens {
                tag_type: quote!(::der::Tag::Application),
                class_type: quote!(::der::asn1::Application::<#type_params>),
                ref_type: quote!(::der::asn1::ApplicationRef),
                tag_number: tag_number.to_tokens(),
            },
            (TagMode::Implicit, Self::Application(tag_number)) => ClassTokens {
                tag_type: quote!(::der::Tag::Application),
                class_type: quote!(::der::asn1::Application::<#type_params>),
                ref_type: quote!(::der::asn1::ApplicationRef),
                tag_number: tag_number.to_tokens(),
            },
        }
    }
    pub fn tag_number(&self) -> TagNumber {
        match self {
            ClassNum::ContextSpecific(tag_number) => *tag_number,
            ClassNum::Private(tag_number) => *tag_number,
            ClassNum::Application(tag_number) => *tag_number,
        }
    }
}
