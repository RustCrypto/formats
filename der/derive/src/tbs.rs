//! Support for deriving structs featuring `to be signed` contents as-is without decoding on structs
//! that follow the SIGNED{} macro pattern.

use crate::{Asn1Attrs, Asn1Type};
use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{DataStruct, Field, Ident, Lifetime};
use synstructure::Structure;

/// Derive a `to be signed` struct for a given struct
pub(crate) struct DeriveTBS {
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
            decode_fields: TokenStream::new(),
            decode_result: TokenStream::new(),
            alt_struct: TokenStream::new(),
            alt_struct_name: String::new(),
        };

        // keep track of field index so first field can be handled differently (i.e., by deferring
        // decoding and returning bytes instead of a structure.
        let mut field_count = 0;
        for field in &data.fields {
            if 0 == field_count {
                state.derive_field_defer(field);
            } else {
                state.derive_field(field);
            }
            field_count += 1;
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

        let mut field_count = 0;
        for field in &data.fields {
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

            field_count += 1;
        }

        let decode_fields = &self.decode_fields;
        let decode_result = &self.decode_result;

        let struct_def = quote! {
            /// Structure supporting deferred decoding of first field in SEQUENCE
            pub struct #sname <#lifetime> {
                #fields
            }

            impl<#lifetime> Decodable<#lifetime> for DeferCertificate<#lifetime> {
                fn decode(decoder: &mut Decoder<#lifetime>) -> der::Result<DeferCertificate<#lifetime>> {
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

        let asn1_type = Asn1Attrs::new(&field.attrs).asn1_type;
        self.derive_field_decoder(&name, asn1_type);
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
    fn derive_field_decoder(&mut self, name: &Ident, asn1_type: Option<Asn1Type>) {
        let field_decoder = match asn1_type {
            Some(Asn1Type::BitString) => quote! {
                let #name = decoder.bit_string()?.try_into()?;
            },
            Some(Asn1Type::GeneralizedTime) => quote! {
                let #name = decoder.generalized_time()?.try_into()?;
            },
            Some(Asn1Type::OctetString) => quote! {
                let #name = decoder.octet_string()?.try_into()?;
            },
            Some(Asn1Type::PrintableString) => quote! {
                let #name = decoder.printable_string()?.try_into()?;
            },
            Some(Asn1Type::UtcTime) => quote! {
                let #name = decoder.utc_time()?.try_into()?;
            },
            Some(Asn1Type::Utf8String) => quote! {
                let #name = decoder.utf8_string()?.try_into()?;
            },
            None => quote! { let #name = decoder.decode()?; },
        };
        field_decoder.to_tokens(&mut self.decode_fields);

        let field_result = quote!(#name,);
        field_result.to_tokens(&mut self.decode_result);
    }

    /// Finish deriving a struct
    fn finish(self, _s: &Structure<'_>, _lifetime: Option<&Lifetime>) -> TokenStream {
        let alt_struct = self.alt_struct;
        alt_struct
    }
}
