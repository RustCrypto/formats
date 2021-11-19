//! Support for deriving the `Sequence` trait on structs for the purposes of
//! decoding/encoding ASN.1 `SEQUENCE` types as mapped to struct fields.

use crate::{FieldAttrs, TypeAttrs};
use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{DeriveInput, Field, Ident, Lifetime, Type};

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

        let mut decode_body = Vec::new();
        let mut decode_result = Vec::new();
        let mut encode_body = Vec::new();

        for field in &self.fields {
            decode_body.push(field.to_decode_tokens());
            decode_result.push(&field.ident);
            encode_body.push(field.to_encode_tokens());
        }

        quote! {
            impl<#lt_params> ::der::Decodable<#lifetime> for #ident<#lt_params> {
                fn decode(decoder: &mut ::der::Decoder<#lifetime>) -> ::der::Result<Self> {
                    decoder.sequence(|decoder| {
                        #(#decode_body)*

                        Ok(Self {
                            #(#decode_result),*
                        })
                    })
                }
            }

            impl<#lt_params> ::der::Sequence<#lifetime> for #ident<#lt_params> {
                fn fields<F, T>(&self, f: F) -> ::der::Result<T>
                where
                    F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
                {
                    f(&[
                        #(#encode_body),*
                    ])
                }
            }
        }
    }
}

/// "IR" for a field of a derived `Sequence`.
struct SequenceField {
    /// Variant name.
    ident: Ident,

    /// Field-level attributes.
    attrs: FieldAttrs,

    /// Field type
    field_type: Type,
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

        if attrs.asn1_type.is_some() && attrs.default.is_some() {
            abort!(
                ident,
                "ASN.1 `type` and `default` options cannot be combined"
            );
        }

        Self {
            ident,
            attrs,
            field_type: field.ty.clone(),
        }
    }

    /// Derive code for decoding a field of a sequence.
    fn to_decode_tokens(&self) -> TokenStream {
        // NOTE: `type` and `default` are mutually exclusive
        // This is checked above in `SequenceField::new`
        debug_assert!(self.attrs.asn1_type.is_none() || self.attrs.default.is_none());

        let ident = &self.ident;
        let ty = &self.field_type;
        let decoder = self.attrs.decoder();

        if self.attrs.asn1_type.is_some() {
            if self.attrs.optional {
                quote! {
                    let #ident = #decoder.map(TryInto::try_into).transpose()?;
                }
            } else {
                quote! {
                    let #ident = #decoder.try_into()?;
                }
            }
        } else if self.attrs.context_specific.is_none() && self.attrs.default.is_some() {
            let default = &self.attrs.default;
            quote! {
                let #ident = decoder.decode::<Option<#ty>>()?.unwrap_or_else(#default);
            }
        } else {
            quote! {
                let #ident = #decoder;
            }
        }
    }

    /// Derive code for encoding a field of a sequence.
    fn to_encode_tokens(&self) -> TokenStream {
        // NOTE: `type` and `default` are mutually exclusive
        // This is checked above in `SequenceField::new`
        debug_assert!(self.attrs.asn1_type.is_none() || self.attrs.default.is_none());

        let ident = &self.ident;
        let binding = quote!(&self.#ident);

        if let Some(ty) = &self.attrs.asn1_type {
            if self.attrs.optional {
                let map_arg = quote!(field);
                let encoder = ty.encoder(&map_arg);

                // TODO(tarcieri): refactor this to get rid of `Result` type annotation
                quote! {
                    #binding.as_ref().map(|#map_arg| {
                        let res: der::Result<_> = Ok(#encoder);
                        res
                    }).transpose()?
                }
            } else {
                let encoder = ty.encoder(&binding);
                quote!(&#encoder)
            }
        } else if let Some(default) = &self.attrs.default {
            quote! {
                &::der::asn1::OptionalRef(if #binding == &#default() {
                    None
                } else {
                    Some(#binding)
                })
            }
        } else {
            quote!(#binding)
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
            #[derive(Sequence)]
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
            #[derive(Sequence)]
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

    /// PKCS#8v2 `OneAsymmetricKey`.
    ///
    /// ```text
    /// OneAsymmetricKey ::= SEQUENCE {
    ///     version                   Version,
    ///     privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
    ///     privateKey                PrivateKey,
    ///     attributes            [0] Attributes OPTIONAL,
    ///     ...,
    ///     [[2: publicKey        [1] PublicKey OPTIONAL ]],
    ///     ...
    ///   }
    ///
    /// Version ::= INTEGER { v1(0), v2(1) } (v1, ..., v2)
    ///
    /// PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
    ///
    /// PrivateKey ::= OCTET STRING
    ///
    /// Attributes ::= SET OF Attribute
    ///
    /// PublicKey ::= BIT STRING
    /// ```
    #[test]
    fn pkcs8_example() {
        let input = parse_quote! {
            #[derive(Sequence)]
            pub struct OneAsymmetricKey<'a> {
                pub version: u8,
                pub private_key_algorithm: AlgorithmIdentifier<'a>,
                #[asn1(type = "OCTET STRING")]
                pub private_key: &'a [u8],
                #[asn1(context_specific = "0", extensible = "true", optional = "true")]
                pub attributes: Option<SetOf<Any<'a>, 1>>,
                #[asn1(
                    context_specific = "1",
                    extensible = "true",
                    optional = "true",
                    type = "BIT STRING"
                )]
                pub public_key: Option<&'a [u8]>,
            }
        };

        let ir = DeriveSequence::new(input);
        assert_eq!(ir.ident, "OneAsymmetricKey");
        assert_eq!(ir.lifetime.unwrap().to_string(), "'a");
        assert_eq!(ir.fields.len(), 5);

        let version_field = &ir.fields[0];
        assert_eq!(version_field.ident, "version");
        assert_eq!(version_field.attrs.asn1_type, None);
        assert_eq!(version_field.attrs.context_specific, None);
        assert_eq!(version_field.attrs.extensible, false);
        assert_eq!(version_field.attrs.optional, false);
        assert_eq!(version_field.attrs.tag_mode, TagMode::Explicit);

        let algorithm_field = &ir.fields[1];
        assert_eq!(algorithm_field.ident, "private_key_algorithm");
        assert_eq!(algorithm_field.attrs.asn1_type, None);
        assert_eq!(algorithm_field.attrs.context_specific, None);
        assert_eq!(algorithm_field.attrs.extensible, false);
        assert_eq!(algorithm_field.attrs.optional, false);
        assert_eq!(algorithm_field.attrs.tag_mode, TagMode::Explicit);

        let private_key_field = &ir.fields[2];
        assert_eq!(private_key_field.ident, "private_key");
        assert_eq!(
            private_key_field.attrs.asn1_type,
            Some(Asn1Type::OctetString)
        );
        assert_eq!(private_key_field.attrs.context_specific, None);
        assert_eq!(private_key_field.attrs.extensible, false);
        assert_eq!(private_key_field.attrs.optional, false);
        assert_eq!(private_key_field.attrs.tag_mode, TagMode::Explicit);

        let attributes_field = &ir.fields[3];
        assert_eq!(attributes_field.ident, "attributes");
        assert_eq!(attributes_field.attrs.asn1_type, None);
        assert_eq!(
            attributes_field.attrs.context_specific,
            Some("0".parse().unwrap())
        );
        assert_eq!(attributes_field.attrs.extensible, true);
        assert_eq!(attributes_field.attrs.optional, true);
        assert_eq!(attributes_field.attrs.tag_mode, TagMode::Explicit);

        let public_key_field = &ir.fields[4];
        assert_eq!(public_key_field.ident, "public_key");
        assert_eq!(public_key_field.attrs.asn1_type, Some(Asn1Type::BitString));
        assert_eq!(
            public_key_field.attrs.context_specific,
            Some("1".parse().unwrap())
        );
        assert_eq!(public_key_field.attrs.extensible, true);
        assert_eq!(public_key_field.attrs.optional, true);
        assert_eq!(public_key_field.attrs.tag_mode, TagMode::Explicit);
    }
}
