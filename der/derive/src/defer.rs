//! Support for deriving structs featuring `to be signed` contents as-is without decoding on structs
//! that follow the SIGNED{} macro pattern.

use crate::{FieldAttrs, TagMode, TypeAttrs};
use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::{quote, ToTokens};
use syn::{DataStruct, DeriveInput, Field, Ident, Lifetime};

/// Derive a `Sequence` struct for a given struct with Defer'ed decoding of designated fields
pub(crate) struct DeriveDefer {
    /// Name of the enum type.
    ident: Ident,

    /// Lifetime of the type.
    lifetime: Option<Lifetime>,

    /// Field decoders
    decode_fields: TokenStream,

    /// Bound fields of a struct to be returned
    decode_result: TokenStream,

    /// Bound fields of a struct to be returned
    alt_struct: TokenStream,

    /// Name of alternative struct
    alt_struct_name: String,
}

impl DeriveDefer {
    pub fn new(input: DeriveInput) -> Self {
        let data = match input.data {
            syn::Data::Struct(data) => data,
            _ => abort!(
                input.ident,
                "can't derive `Sequence` on this type: only `struct` types are allowed",
            ),
        };

        // TODO(tarcieri): properly handle multiple lifetimes
        let lifetime = input
            .generics
            .lifetimes()
            .next()
            .map(|lt| lt.lifetime.clone());

        let mut state = Self {
            ident: input.ident,
            lifetime,
            decode_fields: TokenStream::new(),
            decode_result: TokenStream::new(),
            alt_struct: TokenStream::new(),
            alt_struct_name: String::new(),
        };

        let type_attrs = TypeAttrs::parse(&input.attrs);

        // keep track of field index so first field can be handled differently (i.e., by deferring
        // decoding and returning bytes instead of a structure.
        for (_field_count, field) in (&data.fields).into_iter().enumerate() {
            let field_attrs = FieldAttrs::parse(&field.attrs, &type_attrs);
            if Some(true) == field_attrs.defer {
                state.derive_field_defer(field);
            } else {
                state.derive_field(field, &type_attrs);
            }
        }

        state.derive_alt_struct(&data, &type_attrs);
        state
    }

    /// Derive code for a structure based on a given structure but with Defer prepended to the name
    /// and the first field served up as undecoded bytes instead of as a parsed structure.
    fn derive_alt_struct(&mut self, data: &DataStruct, type_attrs: &TypeAttrs) {
        self.alt_struct_name = format!("Defer{}", self.ident);
        let sname = syn::Ident::new(&self.alt_struct_name, self.ident.span());

        let lifetime2 = match self.lifetime {
            Some(ref lifetime) => quote!(#lifetime),
            None => quote!('_),
        };

        let mut fields = TokenStream::new();

        let mut comment: String = String::new();
        for (_field_count, field) in (&data.fields).into_iter().enumerate() {
            let name = field
                .ident
                .as_ref()
                .cloned()
                .expect("no name on struct field i.e. tuple structs unsupported");

            let ty = field.ty.clone();
            let field_attrs = FieldAttrs::parse(&field.attrs, type_attrs);
            let f = if Some(true) == field_attrs.defer {
                comment = format!(
                    "Structure supporting deferred decoding of {} field in the {} SEQUENCE",
                    name, self.ident
                );
                quote! {
                     /// Defer decoded field
                     pub #name: &#lifetime2 [u8],
                }
            } else {
                quote! {
                     /// Decoded field
                     pub #name: #ty,
                }
            };
            f.to_tokens(&mut fields);
        }

        let decode_fields = &self.decode_fields;
        let decode_result = &self.decode_result;

        let struct_def = quote! {
            #[doc = #comment]
            pub struct #sname <#lifetime2> {
                #fields
            }

            impl<#lifetime2> Decodable<#lifetime2> for #sname<#lifetime2> {
                fn decode(decoder: &mut Decoder<#lifetime2>) -> der::Result<#sname<#lifetime2>> {
                    decoder.sequence(|decoder| {
                        #decode_fields
                        Ok(Self { #decode_result })
                    })
                }
            }
        };
        struct_def.to_tokens(&mut self.alt_struct);
    }

    /// Derive handling for a particular `#[field(...)]`
    fn derive_field(&mut self, field: &Field, type_attrs: &TypeAttrs) {
        let name = field
            .ident
            .as_ref()
            .cloned()
            .expect("no name on struct field i.e. tuple structs unsupported");

        let field_attrs = FieldAttrs::parse(&field.attrs, type_attrs);
        self.derive_field_decoder(&name, &field_attrs, type_attrs);
    }

    /// Derive code for deferring decoding of a field of a sequence
    fn derive_field_defer(&mut self, field: &Field) {
        let name = field
            .ident
            .as_ref()
            .cloned()
            .expect("no name on struct field i.e. tuple structs unsupported");

        let field_decoder = quote! {
            let #name = decoder.tlv_slice()?;
        };

        field_decoder.to_tokens(&mut self.decode_fields);
        let field_result = quote!(#name,);
        field_result.to_tokens(&mut self.decode_result);
    }

    /// Derive code for decoding a field of a sequence
    fn derive_field_decoder(
        &mut self,
        name: &Ident,
        field_attrs: &FieldAttrs,
        type_attrs: &TypeAttrs,
    ) {
        let field_binding = if field_attrs.asn1_type.is_some() {
            let field_decoder = field_attrs.decoder();
            quote! { let #name = #field_decoder?.try_into()?; }
        } else {
            // TODO(tarcieri): IMPLICIT support
            if type_attrs.tag_mode == TagMode::Implicit {
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

    /// Finish deriving a struct
    pub fn to_tokens(&self) -> TokenStream {
        self.alt_struct.to_token_stream()
    }
}
