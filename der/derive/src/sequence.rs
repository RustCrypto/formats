//! Support for deriving the `Sequence` trait on structs for the purposes of
//! decoding/encoding ASN.1 `SEQUENCE` types as mapped to struct fields.

use crate::{FieldAttrs, TagMode, TypeAttrs};
use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{DataStruct, Field, Ident, Lifetime};
use synstructure::Structure;

/// Derive the `Sequence` trait for a struct
pub(crate) struct DeriveSequence {
    /// `asn1` attributes defined at the type level.
    type_attrs: TypeAttrs,

    /// Field decoders
    decode_fields: TokenStream,

    /// Bound fields of a struct to be returned
    decode_result: TokenStream,

    /// Fields of a struct to be serialized
    encode_fields: TokenStream,
}

impl DeriveSequence {
    pub fn derive(s: Structure<'_>, data: &DataStruct, lifetime: Option<&Lifetime>) -> TokenStream {
        let mut state = Self {
            type_attrs: TypeAttrs::parse(&s.ast().attrs),
            decode_fields: TokenStream::new(),
            decode_result: TokenStream::new(),
            encode_fields: TokenStream::new(),
        };

        for field in &data.fields {
            state.derive_field(field);
        }

        state.finish(&s, lifetime)
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
            quote! { let #name = #field_decoder?.try_into()?; }
        } else {
            // TODO(tarcieri): IMPLICIT support
            if self.type_attrs.tag_mode == TagMode::Implicit {
                panic!(
                    "IMPLICIT tagging not presently supported in this context: {}",
                    name
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

    /// Finish deriving a struct
    fn finish(self, s: &Structure<'_>, lifetime: Option<&Lifetime>) -> TokenStream {
        let lifetime = match lifetime {
            Some(lifetime) => quote!(#lifetime),
            None => quote!('_),
        };

        let decode_fields = self.decode_fields;
        let decode_result = self.decode_result;
        let encode_fields = self.encode_fields;

        s.gen_impl(quote! {
            gen impl ::der::Decodable<#lifetime> for @Self {
                fn decode(decoder: &mut ::der::Decoder<#lifetime>) -> ::der::Result<Self> {
                    decoder.sequence(|decoder| {
                        #decode_fields
                        Ok(Self { #decode_result })
                    })
                }
            }

            gen impl ::der::Sequence<#lifetime> for @Self {
                fn fields<F, T>(&self, f: F) -> ::der::Result<T>
                where
                    F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
                {
                    f(&[#encode_fields])
                }
            }
        })
    }
}
