//! Support for deriving the `Sequence` trait on structs for the purposes of
//! decoding/encoding ASN.1 `SEQUENCE` types as mapped to struct fields.

use crate::{FieldAttrs, TagMode, TypeAttrs};
use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::{quote, ToTokens};
use syn::{DeriveInput, Field, Ident, Lifetime};

/// Derive the `Sequence` trait for a struct
pub(crate) struct DeriveSequence {
    /// Name of the sequence struct.
    ident: Ident,

    /// Lifetime of the struct.
    lifetime: Option<Lifetime>,

    /// Fields of the struct.
    fields: Vec<SequenceField>,
}

impl DeriveSequence {
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

        let type_attrs = TypeAttrs::parse(&input.attrs);

        let fields = data
            .fields
            .iter()
            .map(|field| SequenceField::new(field, &type_attrs))
            .collect();

        Self {
            ident: input.ident,
            lifetime,
            fields,
        }
    }

    /// Lower the derived output into a [`TokenStream`].
    pub fn to_tokens(&self) -> TokenStream {
        let ident = &self.ident;

        // Explicit lifetime or `'_`
        let lifetime = match self.lifetime {
            Some(ref lifetime) => quote!(#lifetime),
            None => quote!('_),
        };

        // Lifetime parameters
        // TODO(tarcieri): support multiple lifetimes
        let lt_params = self
            .lifetime
            .as_ref()
            .map(|_| lifetime.clone())
            .unwrap_or_default();

        let count = self.fields.len();
        let mut decode_fields = TokenStream::new();
        let mut decode_result = TokenStream::new();
        let mut encode_fields = quote! {
            let placeholder = false;
            let mut index = 0;
            let mut a: [&dyn der::Encodable; #count] = [&placeholder;#count];
        };

        for field in &self.fields {
            field.write_decode_tokens(&mut decode_fields, &mut decode_result);
            field.write_encode_tokens(&mut encode_fields);
        }

        quote!(f(&a[..index])).to_tokens(&mut encode_fields);

        quote! {
            impl<#lt_params> ::der::Decodable<#lifetime> for #ident<#lt_params> {
                fn decode(decoder: &mut ::der::Decoder<#lifetime>) -> ::der::Result<Self> {
                    decoder.sequence(|decoder| {
                        #decode_fields
                        Ok(Self { #decode_result })
                    })
                }
            }

            impl<#lt_params> ::der::Sequence<#lifetime> for #ident<#lt_params> {
                fn fields<F, T>(&self, f: F) -> ::der::Result<T>
                where
                    F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
                {
                    #encode_fields
                }
            }
        }
    }
}

/// "IR" for a field of a derived `Sequence`.
pub struct SequenceField {
    /// Variant name.
    ident: Ident,

    /// Field-level attributes.
    attrs: FieldAttrs,
}

impl SequenceField {
    /// Create a new [`SequenceField`] from the input [`Field`].
    fn new(field: &Field, type_attrs: &TypeAttrs) -> Self {
        let ident = field.ident.as_ref().cloned().unwrap_or_else(|| {
            abort!(
                field,
                "no name on struct field i.e. tuple structs unsupported"
            )
        });

        let attrs = FieldAttrs::parse(&field.attrs, type_attrs);

        if attrs.tag_mode == TagMode::Implicit {
            abort!(ident, "IMPLICIT tagging not supported for `Sequence`");
        }

        Self { ident, attrs }
    }

    /// Derive code for decoding a field of a sequence.
    fn write_decode_tokens(&self, fields_body: &mut TokenStream, result_body: &mut TokenStream) {
        let ident = &self.ident;
        let mut field_binding = if self.attrs.asn1_type.is_some() {
            let field_decoder = self.attrs.decoder();
            quote! { let mut #ident = #field_decoder.try_into()?; }
        } else {
            quote! { let mut #ident = decoder.decode()?; }
        };
        if None != self.attrs.default {
            let fname = syn::Ident::new(&self.attrs.default.clone().unwrap(), self.ident.span());
            quote!(
                if None == #ident {
                    #ident = Some(#fname());
                }
            )
            .to_tokens(&mut field_binding);
        }

        field_binding.to_tokens(fields_body);

        let field_result = quote!(#ident,);
        field_result.to_tokens(result_body);
    }

    /// Derive code for encoding a field of a sequence.
    fn write_encode_tokens(&self, body: &mut TokenStream) {
        let ident = &self.ident;
        let binding = quote!(&self.#ident);
        // self.attrs
        //     .asn1_type
        //     .map(|ty| {
        //         let encoder = ty.encoder(&binding);
        //         quote!(&#encoder?,)
        //     })
        //     .unwrap_or_else(|| quote!(#binding,))
        //     .to_tokens(body);
        //TODO - do we need the asn1_type support on SEQUENCEs?
        if None != self.attrs.default {
            let fname = syn::Ident::new(&self.attrs.default.clone().unwrap(), self.ident.span());
            let ts = quote!(
                if &Some(#fname()) != #binding {
                    a[index] = #binding;
                    index += 1;
                }
            );
            ts.to_tokens(body);
        } else {
            let ts = quote!(
                a[index] = #binding;
                index += 1;
            );
            ts.to_tokens(body);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DeriveSequence;
    use crate::{Asn1Type, TagMode};
    use syn::parse_quote;

    /// X.509 SPKI `AlgorithmIdentifier`.
    #[test]
    fn algorithm_identifier_example() {
        let input = parse_quote! {
            pub struct AlgorithmIdentifier<'a> {
                pub algorithm: ObjectIdentifier,
                pub parameters: Option<Any<'a>>,
            }
        };

        let ir = DeriveSequence::new(input);
        assert_eq!(ir.ident, "AlgorithmIdentifier");
        assert_eq!(ir.lifetime.unwrap().to_string(), "'a");
        assert_eq!(ir.fields.len(), 2);

        let algorithm_field = &ir.fields[0];
        assert_eq!(algorithm_field.ident, "algorithm");
        assert_eq!(algorithm_field.attrs.asn1_type, None);
        assert_eq!(algorithm_field.attrs.context_specific, None);
        assert_eq!(algorithm_field.attrs.tag_mode, TagMode::Explicit);

        let parameters_field = &ir.fields[1];
        assert_eq!(parameters_field.ident, "parameters");
        assert_eq!(parameters_field.attrs.asn1_type, None);
        assert_eq!(parameters_field.attrs.context_specific, None);
        assert_eq!(parameters_field.attrs.tag_mode, TagMode::Explicit);
    }

    /// X.509 `SubjectPublicKeyInfo`.
    #[test]
    fn spki_example() {
        let input = parse_quote! {
            pub struct SubjectPublicKeyInfo<'a> {
                pub algorithm: AlgorithmIdentifier<'a>,

                #[asn1(type = "BIT STRING")]
                pub subject_public_key: &'a [u8],
            }
        };

        let ir = DeriveSequence::new(input);
        assert_eq!(ir.ident, "SubjectPublicKeyInfo");
        assert_eq!(ir.lifetime.unwrap().to_string(), "'a");
        assert_eq!(ir.fields.len(), 2);

        let algorithm_field = &ir.fields[0];
        assert_eq!(algorithm_field.ident, "algorithm");
        assert_eq!(algorithm_field.attrs.asn1_type, None);
        assert_eq!(algorithm_field.attrs.context_specific, None);
        assert_eq!(algorithm_field.attrs.tag_mode, TagMode::Explicit);

        let subject_public_key_field = &ir.fields[1];
        assert_eq!(subject_public_key_field.ident, "subject_public_key");
        assert_eq!(
            subject_public_key_field.attrs.asn1_type,
            Some(Asn1Type::BitString)
        );
        assert_eq!(subject_public_key_field.attrs.context_specific, None);
        assert_eq!(subject_public_key_field.attrs.tag_mode, TagMode::Explicit);
    }
}
