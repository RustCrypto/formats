use crate::TypeAttrs;
use proc_macro2::TokenStream;
use quote::quote;
use std::cmp::Ordering;
use syn::Ident;

/// A small helper for `Ident` to do comparison of `Ident` ignoring its callsite
trait IdentEq {
    fn ident_eq(&self, ident: &Ident) -> bool;
}

impl IdentEq for Ident {
    fn ident_eq(&self, ident: &Ident) -> bool {
        // Implementation detail, ordering comparison only compares the name
        self.cmp(ident) == Ordering::Equal
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum BindMode {
    ValueOrd,
    Sequence,
}

/// Trait for extending `syn::Ident` with a helper to generate the TokenStream for binding the type
pub(crate) trait BindTokens {
    fn to_bind_tokens(
        &self,
        lifetime: &TokenStream,
        attrs: &TypeAttrs,
        bind_mode: BindMode,
    ) -> Option<TokenStream>;
}

impl BindTokens for Ident {
    fn to_bind_tokens(
        &self,
        lifetime: &TokenStream,
        attrs: &TypeAttrs,
        bind_mode: BindMode,
    ) -> Option<TokenStream> {
        let ident = self;

        let mut bounds = Vec::new();

        if attrs.params.iter().any(|i| ident.ident_eq(i)) {
            match bind_mode {
                BindMode::ValueOrd => bounds.push(quote! {
                    ::der::Decode<#lifetime> + ::der::Encode + ::der::FixedTag + ::der::ValueOrd + ::der::DerOrd
                }),

                BindMode::Sequence => bounds.push(quote! {
                    ::der::Choice<#lifetime> + ::der::Encode
                }),
            }
        }
        if attrs.key.iter().any(|i| ident.ident_eq(i)) {
            match bind_mode {
                BindMode::ValueOrd => bounds.push(quote! {
                    ::der::Decode<#lifetime> + ::der::Encode + ::der::FixedTag + ::der::ValueOrd + ::der::DerOrd
                }),
                BindMode::Sequence => bounds.push(quote! {
                    ::der::Decode<#lifetime> + ::der::Encode + ::der::FixedTag
                }),
            }
        }

        if !bounds.is_empty() {
            Some(quote! {
                #ident: #(#bounds)+*
            })
        } else {
            None
        }
    }
}
