use proc_macro2::{Ident, TokenStream};
use quote::quote;

use crate::spec::Spec;

use std::collections::{btree_map::Entry, BTreeMap};

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Kind(BTreeMap<Ident, Spec>);

impl Kind {
    pub fn entry(&mut self, key: Ident) -> Entry<'_, Ident, Spec> {
        self.0.entry(key)
    }

    pub fn symbols(&self, path: TokenStream) -> TokenStream {
        let mut stream = TokenStream::default();

        for (spec, s) in &self.0 {
            stream.extend(s.symbols(quote! { #path::#spec }))
        }

        stream
    }

    pub fn module<'a>(&'a self, kind: &Ident, docs: &TokenStream) -> TokenStream {
        let mut mods = TokenStream::default();
        let mut syms = TokenStream::default();

        for (spec, s) in &self.0 {
            mods.extend(s.module(spec));
            syms.extend(s.symbols(quote! { &#spec }));
        }

        quote! {
            pub mod #kind {
                #docs
                #mods

                pub const DB: super::super::Database<'static> = super::super::Database(&[
                    #syms
                ]);
            }
        }
    }
}
