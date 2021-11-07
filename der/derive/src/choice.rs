//! Support for deriving the `Decodable` and `Encodable` traits on enums for
//! the purposes of decoding/encoding ASN.1 `CHOICE` types as mapped to
//! enum variants.

use crate::{FieldAttrs, TypeAttrs};
use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{Attribute, DataEnum, Fields, Ident, Lifetime, Variant};

/// Derive the `Choice` trait for an enum.
pub(crate) struct DeriveChoice {
    /// Name of the enum type.
    ident: Ident,

    /// `asn1` attributes defined at the type level.
    type_attrs: TypeAttrs,

    /// Lifetime of the type.
    lifetime: Option<Lifetime>,

    /// Tags included in the impl body for `der::Choice`.
    choice_body: TokenStream,

    /// Enum match arms for the impl body for `TryFrom<der::asn1::Any<'_>>`.
    decode_body: TokenStream,

    /// Enum match arms for the impl body for `der::Encodable::encode`.
    encode_body: TokenStream,

    /// Enum match arms for the impl body for `der::Encodable::encoded_len`.
    encoded_len_body: TokenStream,

    /// Enum match arms for the impl body for `der::Tagged::tag`.
    tagged_body: TokenStream,
}

impl DeriveChoice {
    /// Derive `Decodable` on an enum.
    pub fn derive(
        ident: Ident,
        data: DataEnum,
        attrs: &[Attribute],
        lifetime: Option<Lifetime>,
    ) -> TokenStream {
        let mut state = Self {
            ident,
            type_attrs: TypeAttrs::parse(attrs),
            lifetime,
            choice_body: TokenStream::new(),
            decode_body: TokenStream::new(),
            encode_body: TokenStream::new(),
            encoded_len_body: TokenStream::new(),
            tagged_body: TokenStream::new(),
        };

        for variant in &data.variants {
            let field_attrs = FieldAttrs::parse(&variant.attrs);
            let tag = field_attrs.tag(&state.type_attrs).unwrap_or_else(|| {
                panic!(
                    "no #[asn1(type=...)] specified for enum variant: {}",
                    variant.ident
                )
            });

            state.derive_variant_choice(&tag);
            state.derive_variant_decoder(variant, &tag, &field_attrs);

            match &variant.fields {
                // TODO(tarcieri): handle 0 bindings for ASN.1 NULL
                Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                    state.derive_variant_encoder(variant, &field_attrs);
                    state.derive_variant_encoded_len(variant);
                    state.derive_variant_tagged(variant, &tag);
                }
                _ => panic!(
                    "enum variant `{}` must be a 1-element tuple struct",
                    &variant.ident
                ),
            }
        }

        state.to_tokens()
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
    fn derive_variant_encoder(&mut self, variant: &Variant, field_attrs: &FieldAttrs) {
        let variant_ident = &variant.ident;
        let binding = quote!(variant);
        let encoder = field_attrs.encoder(&binding, &self.type_attrs);
        { quote!(Self::#variant_ident(#binding) => #encoder,) }.to_tokens(&mut self.encode_body);
    }

    /// Derive a match arm for the impl body for `der::Encodable::encode`.
    fn derive_variant_encoded_len(&mut self, variant: &Variant) {
        let variant_ident = &variant.ident;
        { quote!(Self::#variant_ident(variant) => variant.encoded_len(),) }
            .to_tokens(&mut self.encoded_len_body);
    }

    /// Derive a match arm for the impl body for `der::Encodable::encode`.
    fn derive_variant_tagged(&mut self, variant: &Variant, tag: &TokenStream) {
        let variant_ident = &variant.ident;
        { quote!(Self::#variant_ident(_) => #tag,) }.to_tokens(&mut self.tagged_body);
    }

    /// Lower the derived output into a [`TokenStream`].
    fn to_tokens(&self) -> TokenStream {
        let lifetime = match self.lifetime {
            Some(ref lifetime) => quote!(#lifetime),
            None => quote!('_),
        };

        let lt_param = self
            .lifetime
            .as_ref()
            .map(|_| lifetime.clone())
            .unwrap_or_default();

        let Self {
            ident,
            choice_body,
            decode_body,
            encode_body,
            encoded_len_body,
            tagged_body,
            ..
        } = self;

        quote! {
            impl<#lt_param> ::der::Choice<#lifetime> for #ident<#lt_param> {
                fn can_decode(tag: ::der::Tag) -> bool {
                    matches!(tag, #choice_body)
                }
            }

            impl<#lt_param> ::der::Decodable<#lifetime> for #ident<#lt_param> {
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

            impl<#lt_param> ::der::Encodable for #ident<#lt_param> {
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

            impl<#lt_param> ::der::Tagged for #ident<#lt_param> {
                fn tag(&self) -> ::der::Tag {
                    match self {
                        #tagged_body
                    }
                }
            }
        }
    }
}
