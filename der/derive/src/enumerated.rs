//! Support for deriving the `Decodable` and `Encodable` traits on enums for
//! the purposes of decoding/encoding ASN.1 `ENUMERATED` types as mapped to
//! enum variants.

use crate::ATTR_NAME;
use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{DeriveInput, Expr, ExprLit, Ident, Lit, LitInt, Variant};

/// Valid options for the `#[repr]` attribute on `Enumerated` types.
const REPR_TYPES: &[&str] = &["u8", "u16", "u32"];

/// Derive the `Enumerated` trait for an enum.
pub(crate) struct DeriveEnumerated {
    /// Name of the enum type.
    ident: Ident,

    /// Value of the `repr` attribute.
    repr: Ident,

    /// Variants of this enum.
    variants: Vec<EnumeratedVariant>,
}

impl DeriveEnumerated {
    /// Parse [`DeriveInput`].
    pub fn new(input: DeriveInput) -> Self {
        let data = match input.data {
            syn::Data::Enum(data) => data,
            _ => abort!(
                input.ident,
                "can't derive `Enumerated` on this type: only `enum` types are allowed",
            ),
        };

        // Reject `asn1` attributes, parse the `repr` attribute
        let mut repr: Option<Ident> = None;

        for attr in &input.attrs {
            if attr.path.is_ident(ATTR_NAME) {
                abort!(
                    attr.path,
                    "`asn1` attribute is not allowed on `Enumerated` types"
                );
            } else if attr.path.is_ident("repr") {
                if repr.is_some() {
                    abort!(
                        attr,
                        "multiple `#[repr]` attributes encountered on `Enumerated`",
                    );
                }

                let r = attr
                    .parse_args::<Ident>()
                    .unwrap_or_else(|_| abort!(attr, "error parsing `#[repr]` attribute"));

                // Validate
                if !REPR_TYPES.contains(&r.to_string().as_str()) {
                    abort!(
                        attr,
                        "invalid `#[repr]` type: allowed types are {:?}",
                        REPR_TYPES
                    );
                }

                repr = Some(r);
            }
        }

        // Parse enum variants
        let variants = data.variants.iter().map(EnumeratedVariant::new).collect();

        Self {
            ident: input.ident.clone(),
            repr: repr.unwrap_or_else(|| {
                abort!(
                    &input.ident,
                    "no `#[repr]` attribute on enum: must be one of {:?}",
                    REPR_TYPES
                )
            }),
            variants,
        }
    }

    /// Lower the derived output into a [`TokenStream`].
    pub fn to_tokens(&self) -> TokenStream {
        let ident = &self.ident;
        let repr = &self.repr;

        let mut try_from_body = Vec::new();
        for variant in &self.variants {
            try_from_body.push(variant.to_try_from_tokens());
        }

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
                        #(#try_from_body)*
                        _ => Err(der::Tag::Enumerated.value_error())
                    }
                }
            }
        }
    }
}

/// "IR" for a variant of a derived `Enumerated`.
pub struct EnumeratedVariant {
    /// Variant name.
    ident: Ident,

    /// Integer value that this variant corresponds to.
    discriminant: LitInt,
}

impl EnumeratedVariant {
    /// Create a new [`ChoiceVariant`] from the input [`Variant`].
    fn new(input: &Variant) -> Self {
        for attr in &input.attrs {
            if attr.path.is_ident(ATTR_NAME) {
                abort!(
                    attr,
                    "`asn1` attribute is not allowed on fields of `Enumerated` types"
                );
            }
        }

        match &input.discriminant {
            Some((
                _,
                Expr::Lit(ExprLit {
                    lit: Lit::Int(discriminant),
                    ..
                }),
            )) => Self {
                ident: input.ident.clone(),
                discriminant: discriminant.clone(),
            },
            Some((_, other)) => abort!(other, "invalid discriminant for `Enumerated`"),
            None => abort!(input, "`Enumerated` variant has no discriminant"),
        }
    }

    /// Write the body for the derived [`TryFrom`] impl.
    pub fn to_try_from_tokens(&self) -> TokenStream {
        let ident = &self.ident;
        let discriminant = &self.discriminant;
        quote! {
            #discriminant => Ok(Self::#ident),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DeriveEnumerated;
    use syn::parse_quote;

    /// X.509 `CRLReason`.
    #[test]
    fn crlreason_example() {
        let input = parse_quote! {
            #[repr(u32)]
            pub enum CrlReason {
                Unspecified = 0,
                KeyCompromise = 1,
                CaCompromise = 2,
                AffiliationChanged = 3,
                Superseded = 4,
                CessationOfOperation = 5,
                CertificateHold = 6,
                RemoveFromCrl = 8,
                PrivilegeWithdrawn = 9,
                AaCompromised = 10,
            }
        };

        let ir = DeriveEnumerated::new(input);
        assert_eq!(ir.ident, "CrlReason");
        assert_eq!(ir.repr, "u32");
        assert_eq!(ir.variants.len(), 10);

        let unspecified = &ir.variants[0];
        assert_eq!(unspecified.ident, "Unspecified");
        assert_eq!(unspecified.discriminant.to_string(), "0");

        let key_compromise = &ir.variants[1];
        assert_eq!(key_compromise.ident, "KeyCompromise");
        assert_eq!(key_compromise.discriminant.to_string(), "1");

        let key_compromise = &ir.variants[2];
        assert_eq!(key_compromise.ident, "CaCompromise");
        assert_eq!(key_compromise.discriminant.to_string(), "2");
    }
}
