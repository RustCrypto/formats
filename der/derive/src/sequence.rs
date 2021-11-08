//! Support for deriving the `Sequence` trait on structs for the purposes of
//! decoding/encoding ASN.1 `SEQUENCE` types as mapped to struct fields.

use crate::{FieldAttrs, TagMode, TypeAttrs};
use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::{quote, ToTokens};
use syn::{DeriveInput, Field, Ident, Lifetime};

/// Derive the `Sequence` trait for a struct
pub(crate) struct DeriveSequence {
    /// Name of the enum type.
    ident: Ident,

    /// `asn1` attributes defined at the type level.
    type_attrs: TypeAttrs,

    /// Lifetime of the type.
    lifetime: Option<Lifetime>,

    /// Field decoders
    decode_fields: TokenStream,

    /// Bound fields of a struct to be returned
    decode_result: TokenStream,

    /// Fields of a struct to be serialized
    encode_fields: TokenStream,
}

impl DeriveSequence {
    /// Parse [`DeriveInput`].
    pub fn new(input: DeriveInput) -> Self {
        let lifetime = input
            .generics
            .lifetimes()
            .next()
            .map(|lt| lt.lifetime.clone());

        let data = match input.data {
            syn::Data::Struct(data) => data,
            _ => abort!(
                input.ident,
                "can't derive `Sequence` on this type: only `struct` types are allowed",
            ),
        };

        let mut state = Self {
            ident: input.ident,
            type_attrs: TypeAttrs::parse(&input.attrs),
            lifetime,
            decode_fields: TokenStream::new(),
            decode_result: TokenStream::new(),
            encode_fields: TokenStream::new(),
        };

        for field in &data.fields {
            state.derive_field(field);
        }

        state
    }

    /// Derive handling for a particular `#[field(...)]`
    fn derive_field(&mut self, field: &Field) {
        let name = field
            .ident
            .as_ref()
            .cloned()
            .expect("no name on struct field i.e. tuple structs unsupported");

        let field_attrs = FieldAttrs::parse(&field.attrs);
        self.derive_field_decoder(&name, &field_attrs);
        self.derive_field_encoder(&name, &field_attrs);
    }

    /// Derive code for decoding a field of a sequence
    fn derive_field_decoder(&mut self, name: &Ident, field_attrs: &FieldAttrs) {
        let field_binding = if field_attrs.asn1_type.is_some() {
            let field_decoder = field_attrs.decoder(&self.type_attrs);
            quote! { let #name = #field_decoder.try_into()?; }
        } else {
            // TODO(tarcieri): IMPLICIT support
            if self.type_attrs.tag_mode == TagMode::Implicit {
                abort!(
                    name,
                    "IMPLICIT tagging not presently supported for `Sequence`"
                );
            }

            quote! { let #name = decoder.decode()?; }
        };
        field_binding.to_tokens(&mut self.decode_fields);

        let field_result = quote!(#name,);
        field_result.to_tokens(&mut self.decode_result);
    }

    /// Derive code for encoding a field of a sequence
    fn derive_field_encoder(&mut self, name: &Ident, field_attrs: &FieldAttrs) {
        let binding = quote!(&self.#name);
        field_attrs
            .asn1_type
            .map(|ty| {
                let encoder = ty.encoder(&binding);
                quote!(&#encoder?,)
            })
            .unwrap_or_else(|| quote!(#binding,))
            .to_tokens(&mut self.encode_fields);
    }

    /// Lower the derived output into a [`TokenStream`].
    pub fn to_tokens(&self) -> TokenStream {
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
            decode_fields,
            decode_result,
            encode_fields,
            ..
        } = self;

        quote! {
            impl<#lt_param> ::der::Decodable<#lifetime> for #ident<#lt_param> {
                fn decode(decoder: &mut ::der::Decoder<#lifetime>) -> ::der::Result<Self> {
                    decoder.sequence(|decoder| {
                        #decode_fields
                        Ok(Self { #decode_result })
                    })
                }
            }

            impl<#lt_param> ::der::Sequence<#lifetime> for #ident<#lt_param> {
                fn fields<F, T>(&self, f: F) -> ::der::Result<T>
                where
                    F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
                {
                    f(&[#encode_fields])
                }
            }
        }
    }
}
