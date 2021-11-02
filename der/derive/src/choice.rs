//! Support for deriving the `Decodable` and `Encodable` traits on enums for
//! the purposes of decoding/encoding ASN.1 `CHOICE` types as mapped to
//! enum variants.

use crate::{FieldAttrs, TypeAttrs};
use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{DataEnum, Lifetime, Variant};
use synstructure::{Structure, VariantInfo};

/// Derive the `Choice` trait for an enum.
pub(crate) struct DeriveChoice {
    /// `asn1` attributes defined at the type level.
    type_attrs: TypeAttrs,

    /// Tags included in the impl body for `der::Choice`.
    choice_body: TokenStream,

    /// Enum match arms for the impl body for `TryFrom<der::asn1::Any<'_>>`.
    decode_body: TokenStream,

    /// Enum match arms for the impl body for `der::Encodable::encode`.
    encode_body: TokenStream,

    /// Enum match arms for the impl body for `der::Encodable::encoded_len`.
    encoded_len_body: TokenStream,
}

impl DeriveChoice {
    /// Derive `Decodable` on an enum.
    pub fn derive(s: Structure<'_>, data: &DataEnum, lifetime: Option<&Lifetime>) -> TokenStream {
        assert_eq!(
            s.variants().len(),
            data.variants.len(),
            "enum variant count mismatch"
        );

        let mut state = Self {
            type_attrs: TypeAttrs::parse(&s.ast().attrs),
            choice_body: TokenStream::new(),
            decode_body: TokenStream::new(),
            encode_body: TokenStream::new(),
            encoded_len_body: TokenStream::new(),
        };

        for (variant_info, variant) in s.variants().iter().zip(&data.variants) {
            let field_attrs = FieldAttrs::parse(&variant.attrs);
            let tag = field_attrs.tag(&state.type_attrs).unwrap_or_else(|| {
                panic!(
                    "no #[asn1(type=...)] specified for enum variant: {}",
                    variant.ident
                )
            });

            state.derive_variant_choice(&tag);
            state.derive_variant_decoder(variant, &tag, &field_attrs);

            match variant_info.bindings().len() {
                // TODO(tarcieri): handle 0 bindings for ASN.1 NULL
                1 => {
                    state.derive_variant_encoder(variant_info, &field_attrs);
                    state.derive_variant_encoded_len(variant_info);
                }
                other => panic!(
                    "unsupported number of ASN.1 variant bindings for {}: {}",
                    &variant.ident, other
                ),
            }
        }

        state.finish(s, lifetime)
    }

    /// Derive the body of `Choice::can_decode
    fn derive_variant_choice(&mut self, tag: &TokenStream) {
        if self.choice_body.is_empty() {
            tag.clone()
        } else {
            quote!(| #tag)
        }
        .to_tokens(&mut self.choice_body);
    }

    /// Derive a match arm of the impl body for `TryFrom<der::asn1::Any<'_>>`.
    fn derive_variant_decoder(
        &mut self,
        variant: &Variant,
        tag: &TokenStream,
        field_attrs: &FieldAttrs,
    ) {
        let variant_ident = &variant.ident;
        let decoder = field_attrs.decoder(&self.type_attrs);
        { quote!(#tag => Ok(Self::#variant_ident(#decoder.try_into()?)),) }
            .to_tokens(&mut self.decode_body);
    }

    /// Derive a match arm for the impl body for `der::Encodable::encode`.
    fn derive_variant_encoder(&mut self, variant: &VariantInfo<'_>, field_attrs: &FieldAttrs) {
        assert_eq!(
            variant.bindings().len(),
            1,
            "unexpected number of variant bindings"
        );

        variant
            .each(|bi| {
                let binding = &bi.binding;
                field_attrs.encoder(&quote!(#binding), &self.type_attrs)
            })
            .to_tokens(&mut self.encode_body);
    }

    /// Derive a match arm for the impl body for `der::Encodable::encode`.
    fn derive_variant_encoded_len(&mut self, variant: &VariantInfo<'_>) {
        assert_eq!(
            variant.bindings().len(),
            1,
            "unexpected number of variant bindings"
        );

        variant
            .each(|bi| {
                let binding = &bi.binding;
                quote!(#binding.encoded_len())
            })
            .to_tokens(&mut self.encoded_len_body);
    }

    /// Finish deriving an enum
    fn finish(self, s: Structure<'_>, lifetime: Option<&Lifetime>) -> TokenStream {
        let lifetime = match lifetime {
            Some(lifetime) => quote!(#lifetime),
            None => quote!('_),
        };

        let Self {
            choice_body,
            decode_body,
            encode_body,
            encoded_len_body,
            ..
        } = self;

        s.gen_impl(quote! {
            gen impl ::der::Choice<#lifetime> for @Self {
                fn can_decode(tag: ::der::Tag) -> bool {
                    matches!(tag, #choice_body)
                }
            }

            gen impl ::der::Decodable<#lifetime> for @Self {
                fn decode(decoder: &mut ::der::Decoder<#lifetime>) -> ::der::Result<Self> {
                    match decoder.peek_tag()? {
                        #decode_body
                        actual => Err(der::ErrorKind::TagUnexpected {
                            expected: None,
                            actual
                        }
                        .into()),
                    }
                }
            }

            gen impl ::der::Encodable for @Self {
                fn encode(&self, encoder: &mut ::der::Encoder<'_>) -> ::der::Result<()> {
                    match self {
                        #encode_body
                    }
                }

                fn encoded_len(&self) -> ::der::Result<::der::Length> {
                    match self {
                        #encoded_len_body
                    }
                }
            }
        })
    }
}
