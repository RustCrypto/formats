//! Support for deriving the `ValueOrd` trait on enums and structs.
//!
//! This trait is used in conjunction with ASN.1 `SET OF` types to determine
//! the lexicographical order of their DER encodings.

// TODO(tarcieri): enum support

use crate::{FieldAttrs, TypeAttrs};
use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{DeriveInput, Field, Ident, Lifetime, Variant};

/// Derive the `Enumerated` trait for an enum.
pub(crate) struct DeriveValueOrd {
    /// Name of the enum.
    ident: Ident,

    /// Lifetime of the struct.
    lifetime: Option<Lifetime>,

    /// Fields of structs or enum variants.
    fields: Vec<ValueField>,
}

impl DeriveValueOrd {
    /// Parse [`DeriveInput`].
    pub fn new(input: DeriveInput) -> Self {
        let ident = input.ident;
        let type_attrs = TypeAttrs::parse(&input.attrs);

        // TODO(tarcieri): properly handle multiple lifetimes
        let lifetime = input
            .generics
            .lifetimes()
            .next()
            .map(|lt| lt.lifetime.clone());

        let fields = match input.data {
            syn::Data::Enum(data) => data
                .variants
                .into_iter()
                .map(|variant| ValueField::new_enum(variant, &type_attrs))
                .collect(),
            syn::Data::Struct(data) => data
                .fields
                .into_iter()
                .map(|field| ValueField::new_struct(field, &type_attrs))
                .collect(),
            _ => abort!(
                ident,
                "can't derive `ValueOrd` on this type: \
                 only `enum` and `struct` types are allowed",
            ),
        };

        Self {
            ident,
            lifetime,
            fields,
        }
    }

    /// Lower the derived output into a [`TokenStream`].
    pub fn to_tokens(&self) -> TokenStream {
        let ident = &self.ident;

        // Lifetime parameters
        // TODO(tarcieri): support multiple lifetimes
        let lt_params = self
            .lifetime
            .as_ref()
            .map(|lt| vec![lt.clone()])
            .unwrap_or_default();

        let mut body = Vec::new();

        for field in &self.fields {
            body.push(field.to_tokens());
        }

        quote! {
            impl<#(#lt_params)*> ::der::ValueOrd for #ident<#(#lt_params)*> {
                fn value_cmp(&self, other: &Self) -> ::der::Result<::core::cmp::Ordering> {
                    #[allow(unused_imports)]
                    use ::der::DerOrd;

                    #(#body)*

                    Ok(::core::cmp::Ordering::Equal)
                }
            }
        }
    }
}

struct ValueField {
    /// Name of the field
    ident: Ident,

    /// Field-level attributes.
    attrs: FieldAttrs,
}

impl ValueField {
    /// Create from an `enum` variant.
    fn new_enum(variant: Variant, _: &TypeAttrs) -> Self {
        abort!(
            variant,
            "deriving `ValueOrd` only presently supported for structs"
        );
    }

    /// Create from a `struct` field.
    fn new_struct(field: Field, type_attrs: &TypeAttrs) -> Self {
        let ident = field
            .ident
            .as_ref()
            .cloned()
            .unwrap_or_else(|| abort!(&field, "tuple structs are not supported"));

        let attrs = FieldAttrs::parse(&field.attrs, type_attrs);
        Self { ident, attrs }
    }

    /// Lower to [`TokenStream`].
    fn to_tokens(&self) -> TokenStream {
        let ident = &self.ident;
        let mut binding1 = quote!(self.#ident);
        let mut binding2 = quote!(other.#ident);

        if let Some(ty) = &self.attrs.asn1_type {
            binding1 = ty.encoder(&binding1);
            binding2 = ty.encoder(&binding2);
        }

        quote! {
            match #binding1.der_cmp(&#binding2)? {
                ::core::cmp::Ordering::Equal => (),
                other => return Ok(other),
            }
        }
    }
}
