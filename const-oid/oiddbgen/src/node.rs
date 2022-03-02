use convert_case::{Case, Casing};
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    obid: String,
    name: String,
    symb: Ident,
}

impl Node {
    pub fn new(obid: String, name: String) -> Self {
        // Raise the first letter in the beginning or after a hyphen.
        // This produces more natural UpperSnake conversions below.
        let mut upper = true;
        let mut symb = String::new();
        for c in name.chars() {
            match upper {
                false => symb.push(c),
                true => symb.push(c.to_ascii_uppercase()),
            }

            match c {
                '-' => upper = true,
                _ => upper = false,
            }
        }

        // Create the symbol.
        let symb = symb.to_case(Case::UpperSnake);
        let symb = Ident::new(&symb, Span::call_site());

        Self { obid, name, symb }
    }

    pub fn symbol(&self) -> &Ident {
        &self.symb
    }

    pub fn definition(&self) -> TokenStream {
        let obid = self.obid.replace(' ', ""); // Fix a typo.
        let symb = &self.symb;
        let name = &self.name;

        quote! {
            pub const #symb: crate::NamedOid<'_> = crate::NamedOid {
                oid: crate::ObjectIdentifier::new_unwrap(#obid),
                name: #name,
            };
        }
    }
}
