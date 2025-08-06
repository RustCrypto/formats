//! Support for deriving the `Decode` and `Encode` traits on enums for
//! the purposes of decoding/encoding ASN.1 `CHOICE` types as mapped to
//! enum variants.

mod variant;

use self::variant::ChoiceVariant;
use crate::{ErrorType, TypeAttrs, default_lifetime};
use proc_macro2::TokenStream;
use quote::{ToTokens, quote};
use syn::{DeriveInput, GenericParam, Generics, Ident, LifetimeParam};

/// Derive the `Choice` trait for an enum.
pub(crate) struct DeriveChoice {
    /// Name of the enum type.
    ident: Ident,

    /// Generics of the enum.
    generics: Generics,

    /// Variants of this `Choice`.
    variants: Vec<ChoiceVariant>,

    /// Error type for `DecodeValue` implementation.
    error: ErrorType,
}

impl DeriveChoice {
    /// Parse [`DeriveInput`].
    pub fn new(input: DeriveInput) -> syn::Result<Self> {
        let data = match input.data {
            syn::Data::Enum(data) => data,
            _ => abort!(
                input.ident,
                "can't derive `Choice` on this type: only `enum` types are allowed",
            ),
        };

        let type_attrs = TypeAttrs::parse(&input.attrs)?;
        let variants = data
            .variants
            .iter()
            .map(|variant| ChoiceVariant::new(variant, &type_attrs))
            .collect::<syn::Result<_>>()?;

        Ok(Self {
            ident: input.ident,
            generics: input.generics.clone(),
            variants,
            error: type_attrs.error.clone(),
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

        let mut can_decode_body = Vec::new();
        let mut decode_body = Vec::new();
        let mut decode_value_body = Vec::new();
        let mut encode_body = Vec::new();
        let mut value_len_body = Vec::new();
        let mut tagged_body = Vec::new();

        for variant in &self.variants {
            can_decode_body.push(variant.tag.to_tokens());
            decode_body.push(variant.to_decode_tokens());
            decode_value_body.push(variant.to_decode_value_tokens());
            encode_body.push(variant.to_encode_value_tokens());
            value_len_body.push(variant.to_value_len_tokens());
            tagged_body.push(variant.to_tagged_tokens());
        }

        let error = self.error.to_token_stream();

        quote! {
            impl #impl_generics ::der::Choice<#lifetime> for #ident #ty_generics #where_clause {
                fn can_decode(tag: ::der::Tag) -> bool {
                    matches!(tag, #(#can_decode_body)|*)
                }
            }

            impl #impl_generics ::der::IsConstructed for #ident #ty_generics #where_clause {
                const CONSTRUCTED: bool = true;
            }

            impl #impl_generics ::der::Decode<#lifetime> for #ident #ty_generics #where_clause {
                type Error = #error;

                fn decode<R: ::der::Reader<#lifetime>>(reader: &mut R) -> ::core::result::Result<Self, #error> {
                    use der::Reader as _;
                    match ::der::Tag::peek(reader)? {
                        #(#decode_body)*
                        actual => Err(::der::Error::new(
                            ::der::ErrorKind::TagUnexpected {
                                expected: None,
                                actual
                            },
                            reader.position()
                        ).into()
                        ),
                    }
                }
            }

            impl #impl_generics ::der::DecodeValue<#lifetime> for #ident #ty_generics #where_clause {
                type Error = #error;

                fn decode_value<R: ::der::Reader<#lifetime>>(reader: &mut R, header: der::Header) -> ::core::result::Result<Self, #error> {
                    match header.tag() {
                        #(#decode_value_body)*
                        actual => Err(::der::Error::new(
                            ::der::ErrorKind::TagUnexpected {
                                expected: None,
                                actual
                            },
                            reader.position()
                        ).into()
                        ),
                    }
                }
            }

            impl #impl_generics ::der::EncodeValue for #ident #ty_generics #where_clause {
                fn encode_value(&self, encoder: &mut impl ::der::Writer) -> ::der::Result<()> {
                    match self {
                        #(#encode_body)*
                    }
                }

                fn value_len(&self) -> ::der::Result<::der::Length> {
                    match self {
                        #(#value_len_body)*
                    }
                }
            }

            impl #impl_generics ::der::Tagged for #ident #ty_generics #where_clause {
                fn tag(&self) -> ::der::Tag {
                    match self {
                        #(#tagged_body)*
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::DeriveChoice;
    use crate::{Asn1Type, Tag, TagMode, attributes::ClassNum};
    use syn::parse_quote;

    /// Based on `Time` as defined in RFC 5280:
    /// <https://tools.ietf.org/html/rfc5280#page-117>
    ///
    /// ```text
    /// Time ::= CHOICE {
    ///      utcTime        UTCTime,
    ///      generalTime    GeneralizedTime }
    /// ```
    #[test]
    fn time_example() {
        let input = parse_quote! {
            pub enum Time {
                #[asn1(type = "UTCTime")]
                UtcTime(UtcTime),

                #[asn1(type = "GeneralizedTime")]
                GeneralTime(GeneralizedTime),
            }
        };

        let ir = DeriveChoice::new(input).unwrap();
        assert_eq!(ir.ident, "Time");
        assert_eq!(ir.generics.lifetimes().next(), None);
        assert_eq!(ir.variants.len(), 2);

        let utc_time = &ir.variants[0];
        assert_eq!(utc_time.ident, "UtcTime");
        assert_eq!(utc_time.attrs.asn1_type, Some(Asn1Type::UtcTime));
        assert_eq!(utc_time.attrs.class_num, None);
        assert_eq!(utc_time.attrs.tag_mode, TagMode::Explicit);
        assert_eq!(utc_time.tag, Tag::Universal(Asn1Type::UtcTime));

        let general_time = &ir.variants[1];
        assert_eq!(general_time.ident, "GeneralTime");
        assert_eq!(
            general_time.attrs.asn1_type,
            Some(Asn1Type::GeneralizedTime)
        );
        assert_eq!(general_time.attrs.class_num, None);
        assert_eq!(general_time.attrs.tag_mode, TagMode::Explicit);
        assert_eq!(general_time.tag, Tag::Universal(Asn1Type::GeneralizedTime));
    }

    /// `IMPLICIT` tagged example
    #[test]
    fn implicit_example() {
        let input = parse_quote! {
            #[asn1(tag_mode = "IMPLICIT")]
            pub enum ImplicitChoice<'a> {
                #[asn1(context_specific = "0", type = "BIT STRING")]
                BitString(BitString<'a>),

                #[asn1(context_specific = "1", type = "GeneralizedTime")]
                Time(GeneralizedTime),

                #[asn1(context_specific = "2", type = "UTF8String")]
                Utf8String(String),
            }
        };

        let ir = DeriveChoice::new(input).unwrap();
        assert_eq!(ir.ident, "ImplicitChoice");
        assert_eq!(
            ir.generics.lifetimes().next().unwrap().lifetime.to_string(),
            "'a"
        );
        assert_eq!(ir.variants.len(), 3);

        let bit_string = &ir.variants[0];
        assert_eq!(bit_string.ident, "BitString");
        assert_eq!(bit_string.attrs.asn1_type, Some(Asn1Type::BitString));
        assert_eq!(
            bit_string.attrs.class_num,
            Some(ClassNum::ContextSpecific("0".parse().unwrap()))
        );
        assert_eq!(bit_string.attrs.tag_mode, TagMode::Implicit);
        assert_eq!(
            bit_string.tag,
            Tag::ContextSpecific {
                constructed: false,
                number: "0".parse().unwrap()
            }
        );

        let time = &ir.variants[1];
        assert_eq!(time.ident, "Time");
        assert_eq!(time.attrs.asn1_type, Some(Asn1Type::GeneralizedTime));
        assert_eq!(
            time.attrs.class_num,
            Some(ClassNum::ContextSpecific("1".parse().unwrap()))
        );
        assert_eq!(time.attrs.tag_mode, TagMode::Implicit);
        assert_eq!(
            time.tag,
            Tag::ContextSpecific {
                constructed: false,
                number: "1".parse().unwrap()
            }
        );

        let utf8_string = &ir.variants[2];
        assert_eq!(utf8_string.ident, "Utf8String");
        assert_eq!(utf8_string.attrs.asn1_type, Some(Asn1Type::Utf8String));
        assert_eq!(
            utf8_string.attrs.class_num,
            Some(ClassNum::ContextSpecific("2".parse().unwrap()))
        );
        assert_eq!(utf8_string.attrs.tag_mode, TagMode::Implicit);
        assert_eq!(
            utf8_string.tag,
            Tag::ContextSpecific {
                constructed: false,
                number: "2".parse().unwrap()
            }
        );
    }
}
