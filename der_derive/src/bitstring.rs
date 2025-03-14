//! Support for deriving the `BitString` trait on bool structs for the purposes of
//! decoding/encoding ASN.1 `BITSTRING` types as mapped to struct fields.

use crate::{TypeAttrs, default_lifetime};
use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, GenericParam, Generics, Ident, LifetimeParam};

use self::field::BitStringField;

mod field;

/// Derive the `BitString` trait for a struct
pub(crate) struct DeriveBitString {
    /// Name of the bitsting struct.
    ident: Ident,

    /// Generics of the struct.
    generics: Generics,

    /// Fields of the struct.
    fields: Vec<BitStringField>,
}

impl DeriveBitString {
    /// Parse [`DeriveInput`].
    pub fn new(input: DeriveInput) -> syn::Result<Self> {
        let data = match input.data {
            syn::Data::Struct(data) => data,
            _ => abort!(
                input.ident,
                "can't derive `BitString` on this type: only `struct` types are allowed",
            ),
        };

        let type_attrs = TypeAttrs::parse(&input.attrs)?;

        let fields = data
            .fields
            .iter()
            .map(|field| BitStringField::new(field, &type_attrs))
            .collect::<syn::Result<_>>()?;

        Ok(Self {
            ident: input.ident,
            generics: input.generics.clone(),
            fields,
        })
    }

    /// Lower the derived output into a [`TokenStream`].
    pub fn to_tokens(&self) -> TokenStream {
        let ident = &self.ident;
        let mut generics = self.generics.clone();

        // Use the first lifetime parameter as lifetime for Decode/Encode lifetime
        // if none found, add one.
        let lifetime = generics
            .lifetimes()
            .next()
            .map(|lt| lt.lifetime.clone())
            .unwrap_or_else(|| {
                let lt = default_lifetime();
                generics
                    .params
                    .insert(0, GenericParam::Lifetime(LifetimeParam::new(lt.clone())));
                lt
            });

        // We may or may not have inserted a lifetime.
        let (_, ty_generics, where_clause) = self.generics.split_for_impl();
        let (impl_generics, _, _) = generics.split_for_impl();

        let mut decode_body = Vec::new();

        let mut min_expected_fields: u16 = 0;
        let mut max_expected_fields: u16 = 0;
        for field in &self.fields {
            max_expected_fields += 1;

            if !field.attrs.optional {
                min_expected_fields += 1;
            }
        }
        let min_expected_bytes = (min_expected_fields + 7) / 8;

        for (i, field) in self.fields.iter().enumerate().rev() {
            let field_name = &field.ident;

            decode_body.push(quote!(
                #field_name: bs.get(#i).unwrap_or(false)
            ));
        }

        let mut encode_bytes = Vec::new();

        for chunk in self.fields.chunks(8) {
            let mut encode_bits = Vec::with_capacity(8);

            for (i, field) in chunk.iter().enumerate() {
                let bitn = 7 - i;
                let field_name = &field.ident;
                encode_bits.push(quote!(
                        bits |= (self.#field_name as u8) << #bitn;
                ));
            }
            encode_bytes.push(quote!({
                let mut bits: u8 = 0;
                #(#encode_bits)*
                bits
            }));
        }

        quote! {
            impl ::der::FixedTag for #ident #ty_generics #where_clause {
                const TAG: der::Tag = ::der::Tag::BitString;
            }
            impl ::der::FixedLenBitString for #ident #ty_generics #where_clause {
                const ALLOWED_LEN_RANGE: ::core::ops::RangeInclusive<u16> = #min_expected_fields..=#max_expected_fields;
            }

            impl #impl_generics ::der::DecodeValue<#lifetime> for #ident #ty_generics #where_clause {
                type Error = ::der::Error;

                fn decode_value<R: ::der::Reader<#lifetime>>(
                    reader: &mut R,
                    header: ::der::Header,
                ) -> ::core::result::Result<Self, ::der::Error> {
                    use ::der::{Decode as _, DecodeValue as _, Reader as _};
                    use ::der::FixedLenBitString as _;


                    let bs = ::der::asn1::BitStringRef::decode_value(reader, header)?;

                    Self::check_bit_len(bs.bit_len() as u16)?;

                    let b = bs.raw_bytes();
                    let flags = Self {
                        #(#decode_body),*

                    };
                    Ok(flags)

                }

            }

            impl #impl_generics ::der::EncodeValue for #ident #ty_generics #where_clause {
                fn value_len(&self) -> der::Result<der::Length> {
                    Ok(der::Length::new(#min_expected_bytes + 1))
                }

                fn encode_value(&self, writer: &mut impl ::der::Writer) -> ::der::Result<()> {
                    use ::der::Encode as _;
                    use der::FixedLenBitString as _;

                    let arr = [#(#encode_bytes),*];

                    let min_bits = {
                        let max_bits = *Self::ALLOWED_LEN_RANGE.end();
                        let last_byte_bits = (max_bits % 8) as u8;
                        let bs = ::der::asn1::BitStringRef::new(8 - last_byte_bits, &arr)?;

                        let mut min_bits = *Self::ALLOWED_LEN_RANGE.start();

                        // find last lit bit
                        for bit_index in Self::ALLOWED_LEN_RANGE.rev() {
                            if bs.get(bit_index as usize).unwrap_or_default() {
                                min_bits = bit_index + 1;
                                break;
                            }
                        }
                        min_bits
                    };

                    let last_byte_bits = (min_bits % 8) as u8;
                    let bs = ::der::asn1::BitStringRef::new(8 - last_byte_bits, &arr)?;
                    bs.encode_value(writer)
                }
            }
        }
    }
}
