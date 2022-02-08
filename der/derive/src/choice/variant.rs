//! Choice variant IR and lowerings

use crate::{FieldAttrs, Tag, TypeAttrs};
use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{Fields, Ident, Variant};

/// "IR" for a variant of a derived `Choice`.
pub(super) struct ChoiceVariant {
    /// Variant name.
    pub(super) ident: Ident,

    /// "Field" (in this case variant)-level attributes.
    pub(super) attrs: FieldAttrs,

    /// Tag for the ASN.1 type.
    pub(super) tag: Tag,
}

impl ChoiceVariant {
    /// Create a new [`ChoiceVariant`] from the input [`Variant`].
    pub(super) fn new(input: &Variant, type_attrs: &TypeAttrs) -> Self {
        let ident = input.ident.clone();
        let attrs = FieldAttrs::parse(&input.attrs, type_attrs);

        if attrs.extensible {
            abort!(&ident, "`extensible` is not allowed on CHOICE");
        }

        // Validate that variant is a 1-element tuple struct
        match &input.fields {
            // TODO(tarcieri): handle 0 bindings for ASN.1 NULL
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => (),
            _ => abort!(&ident, "enum variant must be a 1-element tuple struct"),
        }

        let tag = attrs
            .tag()
            .unwrap_or_else(|| abort!(&ident, "no #[asn1(type=...)] specified for enum variant",));

        Self { ident, attrs, tag }
    }

    /// Derive a match arm of the impl body for `TryFrom<der::asn1::Any<'_>>`.
    pub(super) fn to_decode_tokens(&self) -> TokenStream {
        let tag = self.tag.to_tokens();
        let ident = &self.ident;
        let decoder = self.attrs.decoder();

        match self.attrs.asn1_type {
            Some(..) => quote! { #tag => Ok(Self::#ident(#decoder.try_into()?)), },
            None => quote! { #tag => Ok(Self::#ident(#decoder)), },
        }
    }

    /// Derive a match arm for the impl body for `der::EncodeValue::encode_value`.
    pub(super) fn to_encode_value_tokens(&self) -> TokenStream {
        let ident = &self.ident;
        let binding = quote!(variant);
        let encoder = self.attrs.value_encode(&binding);
        quote! {
            Self::#ident(#binding) => #encoder,
        }
    }

    /// Derive a match arm for the impl body for `der::EncodeValue::value_len`.
    pub(super) fn to_value_len_tokens(&self) -> TokenStream {
        let ident = &self.ident;
        quote! {
            Self::#ident(variant) => variant.value_len(),
        }
    }

    /// Derive a match arm for the impl body for `der::Tagged::tag`.
    pub(super) fn to_tagged_tokens(&self) -> TokenStream {
        let ident = &self.ident;
        let tag = self.tag.to_tokens();
        quote! {
            Self::#ident(_) => #tag,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ChoiceVariant;
    use crate::{Asn1Type, FieldAttrs, Tag, TagNumber};
    use proc_macro2::Span;
    use quote::quote;
    use syn::Ident;

    #[test]
    fn simple() {
        let span = Span::call_site();

        let variant = ChoiceVariant {
            ident: Ident::new("ExampleVariant", span),
            attrs: FieldAttrs::default(),
            tag: Tag::Universal(Asn1Type::Utf8String),
        };

        assert_eq!(
            variant.to_decode_tokens().to_string(),
            quote! {
                ::der::Tag::Utf8String => Ok(Self::ExampleVariant(
                    decoder.decode()?
                )),
            }
            .to_string()
        );

        assert_eq!(
            variant.to_encode_value_tokens().to_string(),
            quote! {
                Self::ExampleVariant(variant) => encoder.encode_value(variant)?,
            }
            .to_string()
        );

        assert_eq!(
            variant.to_value_len_tokens().to_string(),
            quote! {
                Self::ExampleVariant(variant) => variant.value_len(),
            }
            .to_string()
        );

        assert_eq!(
            variant.to_tagged_tokens().to_string(),
            quote! {
                Self::ExampleVariant(_) => ::der::Tag::Utf8String,
            }
            .to_string()
        )
    }

    #[test]
    fn utf8string() {
        let span = Span::call_site();

        let variant = ChoiceVariant {
            ident: Ident::new("ExampleVariant", span),
            attrs: FieldAttrs {
                asn1_type: Some(Asn1Type::Utf8String),
                ..Default::default()
            },
            tag: Tag::Universal(Asn1Type::Utf8String),
        };

        assert_eq!(
            variant.to_decode_tokens().to_string(),
            quote! {
                ::der::Tag::Utf8String => Ok(Self::ExampleVariant(
                    decoder.utf8_string()?
                    .try_into()?
                )),
            }
            .to_string()
        );

        assert_eq!(
            variant.to_encode_value_tokens().to_string(),
            quote! {
                Self::ExampleVariant(variant) => ::der::asn1::Utf8String::new(variant)?.encode_value(encoder),
            }
            .to_string()
        );

        assert_eq!(
            variant.to_value_len_tokens().to_string(),
            quote! {
                Self::ExampleVariant(variant) => variant.value_len(),
            }
            .to_string()
        );

        assert_eq!(
            variant.to_tagged_tokens().to_string(),
            quote! {
                Self::ExampleVariant(_) => ::der::Tag::Utf8String,
            }
            .to_string()
        )
    }

    #[test]
    fn implicit() {
        let span = Span::call_site();

        let variant = ChoiceVariant {
            ident: Ident::new("ImplicitVariant", span),
            attrs: FieldAttrs::default(),
            tag: Tag::ContextSpecific {
                constructed: false,
                number: TagNumber(0),
            },
        };

        assert_eq!(
            variant.to_decode_tokens().to_string(),
            quote! {
                ::der::Tag::ContextSpecific {
                    constructed: false,
                    number: ::der::TagNumber::N0,
                } => Ok(Self::ImplicitVariant(decoder.decode()?)),
            }
            .to_string()
        );

        assert_eq!(
            variant.to_encode_value_tokens().to_string(),
            quote! {
                Self::ImplicitVariant(variant) => encoder.encode_value(variant)?,
            }
            .to_string()
        );

        assert_eq!(
            variant.to_value_len_tokens().to_string(),
            quote! {
                Self::ImplicitVariant(variant) => variant.value_len(),
            }
            .to_string()
        );

        assert_eq!(
            variant.to_tagged_tokens().to_string(),
            quote! {
                Self::ImplicitVariant(_) => ::der::Tag::ContextSpecific {
                    constructed: false,
                    number: ::der::TagNumber::N0,
                },
            }
            .to_string()
        )
    }
}
