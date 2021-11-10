//! Support for deriving the `Decodable` and `Encodable` traits on enums for
//! the purposes of decoding/encoding ASN.1 `CHOICE` types as mapped to
//! enum variants.

use crate::{FieldAttrs, Tag, TypeAttrs};
use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{DeriveInput, Fields, Ident, Lifetime, Variant};

/// Derive the `Choice` trait for an enum.
pub(crate) struct DeriveChoice {
    /// Name of the enum type.
    ident: Ident,

    /// Lifetime of the type.
    lifetime: Option<Lifetime>,

    /// Variants of this `Choice`.
    variants: Vec<ChoiceVariant>,
}

impl DeriveChoice {
    /// Parse [`DeriveInput`].
    pub fn new(input: DeriveInput) -> Self {
        let data = match input.data {
            syn::Data::Enum(data) => data,
            _ => abort!(
                input.ident,
                "can't derive `Choice` on this type: only `enum` types are allowed",
            ),
        };

        // TODO(tarcieri): properly handle multiple lifetimes
        let lifetime = input
            .generics
            .lifetimes()
            .next()
            .map(|lt| lt.lifetime.clone());

        let type_attrs = TypeAttrs::parse(&input.attrs);
        let variants = data
            .variants
            .iter()
            .map(|variant| ChoiceVariant::new(variant, &type_attrs))
            .collect();

        Self {
            ident: input.ident,
            lifetime,
            variants,
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

        let mut can_decode_body = Vec::new();
        let mut decode_body = Vec::new();
        let mut encode_body = Vec::new();
        let mut encoded_len_body = Vec::new();
        let mut tagged_body = Vec::new();

        for variant in &self.variants {
            can_decode_body.push(variant.tag.to_tokens());
            decode_body.push(variant.to_decode_tokens());
            encode_body.push(variant.to_encode_tokens());
            encoded_len_body.push(variant.to_encoded_len_tokens());
            tagged_body.push(variant.to_tagged_tokens());
        }

        quote! {
            impl<#lt_params> ::der::Choice<#lifetime> for #ident<#lt_params> {
                fn can_decode(tag: ::der::Tag) -> bool {
                    matches!(tag, #(#can_decode_body)|*)
                }
            }

            impl<#lt_params> ::der::Decodable<#lifetime> for #ident<#lt_params> {
                fn decode(decoder: &mut ::der::Decoder<#lifetime>) -> ::der::Result<Self> {
                    match decoder.peek_tag()? {
                        #(#decode_body)*
                        actual => Err(der::ErrorKind::TagUnexpected {
                            expected: None,
                            actual
                        }
                        .into()),
                    }
                }
            }

            impl<#lt_params> ::der::Encodable for #ident<#lt_params> {
                fn encode(&self, encoder: &mut ::der::Encoder<'_>) -> ::der::Result<()> {
                    match self {
                        #(#encode_body)*
                    }
                }

                fn encoded_len(&self) -> ::der::Result<::der::Length> {
                    match self {
                        #(#encoded_len_body)*
                    }
                }
            }

            impl<#lt_params> ::der::Tagged for #ident<#lt_params> {
                fn tag(&self) -> ::der::Tag {
                    match self {
                        #(#tagged_body)*
                    }
                }
            }
        }
    }
}

/// "IR" for a variant of a derived `Choice`.
pub struct ChoiceVariant {
    /// Variant name.
    ident: Ident,

    /// "Field" (in this case variant)-level attributes.
    attrs: FieldAttrs,

    /// Tag for the ASN.1 type.
    tag: Tag,
}

impl ChoiceVariant {
    /// Create a new [`ChoiceVariant`] from the input [`Variant`].
    fn new(input: &Variant, type_attrs: &TypeAttrs) -> Self {
        let ident = input.ident.clone();
        let attrs = FieldAttrs::parse(&input.attrs, type_attrs);

        // Validate that variant is a 1-element tuple struct
        match &input.fields {
            // TODO(tarcieri): handle 0 bindings for ASN.1 NULL
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => (),
            _ => abort!(&ident, "enum variant must be a 1-element tuple struct"),
        }

        let tag = attrs
            .tag()
            .unwrap_or_else(|| abort!(&ident, "no #[asn1(type=...)] specified for enum variant",));

        Self { ident, attrs, tag }
    }

    /// Derive a match arm of the impl body for `TryFrom<der::asn1::Any<'_>>`.
    fn to_decode_tokens(&self) -> TokenStream {
        let tag = self.tag.to_tokens();
        let ident = &self.ident;
        let decoder = self.attrs.decoder();
        quote! {
            #tag => Ok(Self::#ident(#decoder.try_into()?)),
        }
    }

    /// Derive a match arm for the impl body for `der::Encodable::encode`.
    fn to_encode_tokens(&self) -> TokenStream {
        let ident = &self.ident;
        let binding = quote!(variant);
        let encoder = self.attrs.encoder(&binding);
        quote! {
            Self::#ident(#binding) => #encoder,
        }
    }

    /// Derive a match arm for the impl body for `der::Encodable::encode`.
    fn to_encoded_len_tokens(&self) -> TokenStream {
        let ident = &self.ident;
        quote! {
            Self::#ident(variant) => variant.encoded_len(),
        }
    }

    /// Derive a match arm for the impl body for `der::Tagged::tag`.
    fn to_tagged_tokens(&self) -> TokenStream {
        let ident = &self.ident;
        let tag = self.tag.to_tokens();
        quote! {
            Self::#ident(_) => #tag,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DeriveChoice;
    use crate::{Asn1Type, Tag, TagMode};
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

        let ir = DeriveChoice::new(input);
        assert_eq!(ir.ident, "Time");
        assert_eq!(ir.lifetime, None);
        assert_eq!(ir.variants.len(), 2);

        let utc_time = &ir.variants[0];
        assert_eq!(utc_time.ident, "UtcTime");
        assert_eq!(utc_time.attrs.asn1_type, Some(Asn1Type::UtcTime));
        assert_eq!(utc_time.attrs.context_specific, None);
        assert_eq!(utc_time.attrs.tag_mode, TagMode::Explicit);
        assert_eq!(utc_time.tag, Tag::Universal(Asn1Type::UtcTime));

        let general_time = &ir.variants[1];
        assert_eq!(general_time.ident, "GeneralTime");
        assert_eq!(
            general_time.attrs.asn1_type,
            Some(Asn1Type::GeneralizedTime)
        );
        assert_eq!(general_time.attrs.context_specific, None);
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

        let ir = DeriveChoice::new(input);
        assert_eq!(ir.ident, "ImplicitChoice");
        assert_eq!(ir.lifetime.unwrap().to_string(), "'a");
        assert_eq!(ir.variants.len(), 3);

        let bit_string = &ir.variants[0];
        assert_eq!(bit_string.ident, "BitString");
        assert_eq!(bit_string.attrs.asn1_type, Some(Asn1Type::BitString));
        assert_eq!(
            bit_string.attrs.context_specific,
            Some("0".parse().unwrap())
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
        assert_eq!(time.attrs.context_specific, Some("1".parse().unwrap()));
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
            utf8_string.attrs.context_specific,
            Some("2".parse().unwrap())
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
