//! Sequence field IR and lowerings

use crate::{Asn1Type, FieldAttrs, TypeAttrs};
use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{Field, Ident, Path, Type};

/// "IR" for a field of a derived `Sequence`.
pub(super) struct SequenceField {
    /// Variant name.
    pub(super) ident: Ident,

    /// Field-level attributes.
    pub(super) attrs: FieldAttrs,

    /// Field type
    pub(super) field_type: Type,
}

impl SequenceField {
    /// Create a new [`SequenceField`] from the input [`Field`].
    pub(super) fn new(field: &Field, type_attrs: &TypeAttrs) -> Self {
        let ident = field.ident.as_ref().cloned().unwrap_or_else(|| {
            abort!(
                field,
                "no name on struct field i.e. tuple structs unsupported"
            )
        });

        let attrs = FieldAttrs::parse(&field.attrs, type_attrs);

        if attrs.asn1_type.is_some() && attrs.default.is_some() {
            abort!(
                ident,
                "ASN.1 `type` and `default` options cannot be combined"
            );
        }

        Self {
            ident,
            attrs,
            field_type: field.ty.clone(),
        }
    }

    /// Derive code for decoding a field of a sequence.
    pub(super) fn to_decode_tokens(&self) -> TokenStream {
        let mut lowerer = LowerFieldDecoder::new(&self.attrs);

        if self.attrs.asn1_type.is_some() {
            lowerer.apply_asn1_type(self.attrs.optional);
        }

        if let Some(default) = &self.attrs.default {
            // TODO(tarcieri): default in conjunction with ASN.1 types?
            debug_assert!(
                self.attrs.asn1_type.is_none(),
                "`type` and `default` are mutually exclusive"
            );

            // TODO(tarcieri): support for context-specific fields with defaults?
            if self.attrs.context_specific.is_none() {
                lowerer.apply_default(default, &self.field_type);
            }
        }

        lowerer.into_tokens(&self.ident)
    }

    /// Derive code for encoding a field of a sequence.
    pub(super) fn to_encode_tokens(&self) -> TokenStream {
        let mut lowerer = LowerFieldEncoder::new(&self.ident);

        if let Some(ty) = &self.attrs.asn1_type {
            lowerer.apply_asn1_type(ty, self.attrs.optional);
        }

        if let Some(default) = &self.attrs.default {
            // TODO(tarcieri): default in conjunction with ASN.1 types?
            debug_assert!(
                self.attrs.asn1_type.is_none(),
                "`type` and `default` are mutually exclusive"
            );

            lowerer.apply_default(default);
        }

        lowerer.into_tokens()
    }
}

/// AST lowerer for field decoders.
struct LowerFieldDecoder {
    /// Decoder-in-progress.
    decoder: TokenStream,
}

impl LowerFieldDecoder {
    /// Create a new field decoder lowerer.
    fn new(attrs: &FieldAttrs) -> Self {
        Self {
            decoder: attrs.decoder(),
        }
    }

    ///  the field decoder to tokens.
    fn into_tokens(self, ident: &Ident) -> TokenStream {
        let decoder = self.decoder;

        quote! {
            let #ident = #decoder;
        }
    }

    /// Apply the ASN.1 type (if defined).
    fn apply_asn1_type(&mut self, optional: bool) {
        let decoder = &self.decoder;

        self.decoder = if optional {
            quote! {
                #decoder.map(TryInto::try_into).transpose()?
            }
        } else {
            quote! {
                #decoder.try_into()?
            }
        }
    }

    /// Handle default value for a type.
    fn apply_default(&mut self, default: &Path, field_type: &Type) {
        self.decoder = quote! {
            decoder.decode::<Option<#field_type>>()?.unwrap_or_else(#default);
        }
    }
}

/// AST lowerer for field encoders.
struct LowerFieldEncoder {
    /// Encoder-in-progress.
    encoder: TokenStream,
}

impl LowerFieldEncoder {
    /// Create a new field encoder lowerer.
    fn new(ident: &Ident) -> Self {
        Self {
            encoder: quote!(&self.#ident),
        }
    }

    ///  the field encoder to tokens.
    fn into_tokens(self) -> TokenStream {
        self.encoder
    }

    /// Apply the ASN.1 type (if defined).
    fn apply_asn1_type(&mut self, asn1_type: &Asn1Type, optional: bool) {
        let binding = &self.encoder;

        self.encoder = if optional {
            let map_arg = quote!(field);
            let encoder = asn1_type.encoder(&map_arg);

            // TODO(tarcieri): refactor this to get rid of `Result` type annotation
            quote! {
                #binding.as_ref().map(|#map_arg| {
                    let res: der::Result<_> = Ok(#encoder);
                    res
                }).transpose()?
            }
        } else {
            let encoder = asn1_type.encoder(binding);
            quote!(&#encoder)
        };
    }

    /// Handle default value for a type.
    fn apply_default(&mut self, default: &Path) {
        let encoder = &self.encoder;

        self.encoder = quote! {
            &::der::asn1::OptionalRef(if #encoder == &#default() {
                None
            } else {
                Some(#encoder)
            })
        };
    }
}

#[cfg(test)]
mod tests {
    use super::SequenceField;
    use crate::{FieldAttrs, TagMode};
    use proc_macro2::Span;
    use syn::{punctuated::Punctuated, Ident, Path, PathSegment, Type, TypePath};

    /// Create a [`Type::Path`].
    pub fn type_path(ident: Ident) -> Type {
        let mut segments = Punctuated::new();
        segments.push_value(PathSegment {
            ident,
            arguments: Default::default(),
        });

        Type::Path(TypePath {
            qself: None,
            path: Path {
                leading_colon: None,
                segments,
            },
        })
    }

    #[test]
    fn simple() {
        let span = Span::call_site();
        let ident = Ident::new("example_field", span);

        let attrs = FieldAttrs {
            asn1_type: None,
            context_specific: None,
            default: None,
            extensible: false,
            optional: false,
            tag_mode: TagMode::Explicit,
        };

        let field_type = Ident::new("String", span);

        let field = SequenceField {
            ident,
            attrs,
            field_type: type_path(field_type),
        };

        // TODO(tarcieri): better comparison, possibly using `quote!`
        assert_eq!(
            field.to_decode_tokens().to_string(),
            "let example_field = decoder . decode () ? ;"
        );

        assert_eq!(
            field.to_encode_tokens().to_string(),
            "& self . example_field"
        );
    }
}
