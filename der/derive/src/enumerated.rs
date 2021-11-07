//! Support for deriving the `Decodable` and `Encodable` traits on enums for
//! the purposes of decoding/encoding ASN.1 `ENUMERATED` types as mapped to
//! enum variants.

use crate::ATTR_NAME;
use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{Attribute, DataEnum, Expr, ExprLit, Ident, Lit, LitInt};

/// Valid options for the `#[repr]` attribute on `Enumerated` types.
const REPR_TYPES: &[&str] = &["u8", "u16", "u32"];

/// Derive the `Enumerated` trait for an enum.
pub(crate) struct DeriveEnumerated {
    /// Name of the enum type.
    ident: Ident,

    /// Value of the `repr` attribute.
    repr: Ident,

    /// Variants of this enum.
    variants: Vec<(Ident, LitInt)>,
}

impl DeriveEnumerated {
    /// Derive `Decodable` on an enum.
    pub fn derive(ident: Ident, data: DataEnum, attrs: &[Attribute]) -> TokenStream {
        // Reject `asn1` attributes, parse the `repr` attribute
        let mut repr: Option<Ident> = None;
        for attr in attrs {
            if attr.path.is_ident(ATTR_NAME) {
                panic!("`asn1` attribute is not allowed on `Enumerated` types");
            } else if attr.path.is_ident("repr") {
                if let Some(r) = repr {
                    panic!(
                        "multiple `#[repr]` attributes encountered on `Enumerated`: {}",
                        r.to_string()
                    );
                }

                let r = attr
                    .parse_args::<Ident>()
                    .expect("error parsing `#[repr]` attribute");

                // Validate
                if !REPR_TYPES.contains(&r.to_string().as_str()) {
                    panic!("invalid `#[repr]` type: allowed types are {:?}", REPR_TYPES);
                }

                repr = Some(r);
            }
        }

        // Parse enum variants
        let mut variants = Vec::new();
        for variant in &data.variants {
            for attr in &variant.attrs {
                if attr.path.is_ident(ATTR_NAME) {
                    panic!("`asn1` attribute is not allowed on fields of `Enumerated` types");
                }
            }

            match &variant.discriminant {
                Some((
                    _,
                    Expr::Lit(ExprLit {
                        lit: Lit::Int(discriminant),
                        ..
                    }),
                )) => variants.push((variant.ident.clone(), discriminant.clone())),
                Some((_, other)) => panic!("invalid discriminant for `Enumerated`: {:#?}", other),
                None => panic!("`Enumerated` variant has no discriminant"),
            }
        }

        Self {
            ident,
            repr: repr.unwrap_or_else(|| {
                panic!(
                    "no `#[repr]` attribute on enum: must be one of {:?}",
                    REPR_TYPES
                )
            }),
            variants,
        }
        .to_tokens()
    }

    /// Lower the derived output into a [`TokenStream`].
    fn to_tokens(&self) -> TokenStream {
        let mut try_from_body = TokenStream::new();
        for (ident, discriminant) in &self.variants {
            { quote!(#discriminant => Ok(Self::#ident),) }.to_tokens(&mut try_from_body);
        }

        let Self { ident, repr, .. } = self;

        quote! {
            impl ::der::DecodeValue<'static> for #ident {
                fn decode_value(
                    decoder: &mut ::der::Decoder<'_>,
                    length: ::der::Length
                ) -> ::der::Result<Self> {
                    <#repr as ::der::DecodeValue>::decode_value(decoder, length)?.try_into()
                }
            }

            impl ::der::EncodeValue for #ident {
                fn value_len(&self) -> ::der::Result<::der::Length> {
                    ::der::EncodeValue::value_len(&(*self as #repr))
                }

                fn encode_value(&self, encoder: &mut ::der::Encoder<'_>) -> ::der::Result<()> {
                    ::der::EncodeValue::encode_value(&(*self as #repr), encoder)
                }
            }

            impl ::der::FixedTag for #ident {
                const TAG: ::der::Tag = ::der::Tag::Enumerated;
            }

            impl TryFrom<#repr> for #ident {
                type Error = ::der::Error;

                fn try_from(n: #repr) -> ::der::Result<Self> {
                    match n {
                        #try_from_body
                        _ => Err(der::Tag::Enumerated.value_error())
                    }
                }
            }
        }
    }
}
