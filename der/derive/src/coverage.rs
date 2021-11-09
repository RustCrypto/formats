//! Support for deriving structs featuring `to be signed` contents as-is without decoding on structs
//! that follow the SIGNED{} macro pattern.

use crate::{FieldAttrs, TagMode, TypeAttrs};
use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::{quote, ToTokens};
use syn::{DataStruct, DeriveInput, Field, Ident, Lifetime};

/// Derive a `Sequence` struct for a given struct with Defer'ed decoding of designated fields
pub(crate) struct DeriveCoverage {
    /// Name of the enum type.
    ident: Ident,

    /// Lifetime of the type.
    lifetime: Option<Lifetime>,

    /// Bound fields of a struct to be returned
    alt_struct: TokenStream,

    /// Number of fields
    field_count: u8,
}

impl DeriveCoverage {
    /// Parse [`DeriveInput`].
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
            alt_struct: TokenStream::new(),
            field_count: 0,
        };

        let type_attrs = TypeAttrs::parse(&input.attrs);

        // keep track of field index so first field can be handled differently (i.e., by deferring
        // decoding and returning bytes instead of a structure.
        for (field_count_out, _field_out) in (&data.fields).into_iter().enumerate() {
            let mut decode_fields = TokenStream::new();
            let mut decode_result = TokenStream::new();

            for (field_count_in, field) in (&data.fields).into_iter().enumerate() {
                if field_count_in == field_count_out {
                    state.derive_field_defer(field, &mut decode_fields, &mut decode_result);
                } else {
                    state.derive_field(field, &mut decode_fields, &mut decode_result, &type_attrs);
                }
            }
            state.derive_alt_struct(&data, field_count_out, &decode_fields, &decode_result);
            if field_count_out > 9 {
                panic!("Too many fields for Coverage macro to handle. Max is 10.");
            } else {
                state.field_count += 1;
            }
        }

        let mut func_invokes = TokenStream::new();
        for (field_count_out, _field_out) in (&data.fields).into_iter().enumerate() {
            let alt_func_name = format!("coverage{}_{}", field_count_out, state.ident);
            let fname = syn::Ident::new(&alt_func_name.to_lowercase(), state.ident.span());
            let f2 = quote! {
                #fname(der_encoded);
            };
            f2.to_tokens(&mut func_invokes);
        }

        let compound_func_name = format!("coverage_{}", state.ident);
        let cfname = syn::Ident::new(&compound_func_name.to_lowercase(), state.ident.span());

        let comment = format!(
            "Structure supporting deferred decode/reencode test for each field the {} SEQUENCE",
            state.ident
        );

        let f1 = quote! {
            #[doc = #comment]
            pub fn #cfname(der_encoded: &[u8]) {
                #func_invokes
            }
        };
        f1.to_tokens(&mut state.alt_struct);

        state
    }

    /// Derive code for a structure based on a given structure but with Defer prepended to the name
    /// and the first field served up as undecoded bytes instead of as a parsed structure.
    fn derive_alt_struct(
        &mut self,
        data: &DataStruct,
        counter: usize,
        decode_fields: &TokenStream,
        decode_result: &TokenStream,
    ) {
        let alt_struct_name = format!("Coverage{}{}", counter, self.ident);
        let sname = syn::Ident::new(&alt_struct_name, self.ident.span());

        let alt_func_name = format!("coverage{}_{}", counter, self.ident);
        let fname = syn::Ident::new(&alt_func_name.to_lowercase(), self.ident.span());

        let oname = &self.ident;

        let lifetime2 = match self.lifetime {
            Some(ref lifetime) => quote!(#lifetime),
            None => quote!('_),
        };

        let mut fields = TokenStream::new();

        self.field_count = 0;
        let mut comment: String = String::new();
        let mut defer_name = proc_macro2::Ident::new(&alt_struct_name, self.ident.span());
        for (field_count, field) in (&data.fields).into_iter().enumerate() {
            self.field_count += 1;
            let name = field
                .ident
                .as_ref()
                .cloned()
                .expect("no name on struct field i.e. tuple structs unsupported");

            let ty = field.ty.clone();
            let f = if field_count == counter {
                comment = format!(
                    "Structure supporting deferred decoding of {} field in the {} SEQUENCE",
                    name, self.ident
                );
                defer_name = name.clone();
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

            /// coverage test for defer decoded field
            pub fn #fname(der_encoded: &[u8]) {
                let defer_result = #sname::from_der(der_encoded);
                let defer = defer_result.unwrap();

                let full_result = #oname::from_der(der_encoded);
                let full = full_result.unwrap();
                let reencoded = full.#defer_name.to_vec().unwrap();
                assert_eq!(defer.#defer_name, reencoded);
            }
        };

        struct_def.to_tokens(&mut self.alt_struct);
    }

    /// Derive handling for a particular `#[field(...)]`
    fn derive_field(
        &mut self,
        field: &Field,
        decode_fields: &mut TokenStream,
        decode_result: &mut TokenStream,
        type_attrs: &TypeAttrs,
    ) {
        let name = field
            .ident
            .as_ref()
            .cloned()
            .expect("no name on struct field i.e. tuple structs unsupported");

        let field_attrs = FieldAttrs::parse(&field.attrs, type_attrs);
        self.derive_field_decoder(
            &name,
            &field_attrs,
            decode_fields,
            decode_result,
            type_attrs,
        );
    }

    /// Derive code for deferring decoding of a field of a sequence
    fn derive_field_defer(
        &mut self,
        field: &Field,
        decode_fields: &mut TokenStream,
        decode_result: &mut TokenStream,
    ) {
        let name = field
            .ident
            .as_ref()
            .cloned()
            .expect("no name on struct field i.e. tuple structs unsupported");

        let field_decoder = quote! {
            let #name = decoder.tlv_slice()?;
        };

        field_decoder.to_tokens(decode_fields);
        let field_result = quote!(#name,);
        field_result.to_tokens(decode_result);
    }

    /// Derive code for decoding a field of a sequence
    fn derive_field_decoder(
        &mut self,
        name: &Ident,
        field_attrs: &FieldAttrs,
        decode_fields: &mut TokenStream,
        decode_result: &mut TokenStream,
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
        field_binding.to_tokens(decode_fields);

        let field_result = quote!(#name,);
        field_result.to_tokens(decode_result);
    }

    /// Finish deriving a struct
    pub fn to_tokens(&self) -> TokenStream {
        self.alt_struct.to_token_stream()
    }
}
