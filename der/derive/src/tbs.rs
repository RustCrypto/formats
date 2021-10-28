//! Support for deriving structs featuring `to be signed` contents as-is without decoding on structs
//! that follow the SIGNED{} macro pattern.

use crate::{FieldAttrs, TagMode, TypeAttrs};
use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{DataStruct, Field, Ident, Lifetime};
use synstructure::Structure;

/// Derive a `to be signed` struct for a given struct
pub(crate) struct DeriveTBS {
    /// `asn1` attributes defined at the type level.
    type_attrs: TypeAttrs,

    /// Field decoders
    decode_fields: TokenStream,

    /// Bound fields of a struct to be returned
    decode_result: TokenStream,

    /// Bound fields of a struct to be returned
    alt_struct: TokenStream,

    /// Name of alternative struct
    alt_struct_name: String,
}

impl DeriveTBS {
    pub fn derive(s: Structure<'_>, data: &DataStruct, lifetime: Option<&Lifetime>) -> TokenStream {
        let mut state = Self {
            type_attrs: TypeAttrs::parse(&s.ast().attrs),
            decode_fields: TokenStream::new(),
            decode_result: TokenStream::new(),
            alt_struct: TokenStream::new(),
            alt_struct_name: String::new(),
        };

        // keep track of field index so first field can be handled differently (i.e., by deferring
        // decoding and returning bytes instead of a structure.
        for (field_count, field) in (&data.fields).into_iter().enumerate() {
            if 0 == field_count {
                state.derive_field_defer(field);
            } else {
                state.derive_field(field);
            }
        }
        state.derive_alt_struct(&s, data, lifetime);
        state.finish(&s, lifetime)
    }

    /// Derive code for a structure based on a given structure but with Defer prepended to the name
    /// and the first field served up as undecoded bytes instead of as a parsed structure.
    fn derive_alt_struct(
        &mut self,
        s: &Structure<'_>,
        data: &DataStruct,
        lifetime: Option<&Lifetime>,
    ) {
        let ident = &s.ast().ident;
        self.alt_struct_name = format!("Defer{}", ident);
        let sname = syn::Ident::new(&self.alt_struct_name, ident.span());

        let mut fields = TokenStream::new();

        for (field_count, field) in (&data.fields).into_iter().enumerate() {
            let name = field
                .ident
                .as_ref()
                .cloned()
                .expect("no name on struct field i.e. tuple structs unsupported");

            let ty = field.ty.clone();

            let f = if 0 == field_count {
                quote! {
                     /// Defer decoded field
                     pub #name: &#lifetime [u8],
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
            /// Structure supporting deferred decoding of first field in SEQUENCE
            pub struct #sname <#lifetime> {
                #fields
            }

            impl<#lifetime> Decodable<#lifetime> for #sname<#lifetime> {
                fn decode(decoder: &mut Decoder<#lifetime>) -> der::Result<#sname<#lifetime>> {
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
    fn derive_field(&mut self, field: &Field) {
        let name = field
            .ident
            .as_ref()
            .cloned()
            .expect("no name on struct field i.e. tuple structs unsupported");

        let field_attrs = FieldAttrs::parse(&field.attrs);
        self.derive_field_decoder(&name, &field_attrs);
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

    /// Finish deriving a struct
    fn finish(self, _s: &Structure<'_>, _lifetime: Option<&Lifetime>) -> TokenStream {
        self.alt_struct
    }
}
