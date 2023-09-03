use const_oid::ObjectIdentifier;
use convert_case::{Case, Casing};
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Node {
    oid: ObjectIdentifier,
    name: String,
    symb: Ident,
}

impl Node {
    pub fn new(oid: ObjectIdentifier, name: String) -> Self {
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

        Self { oid, name, symb }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn symbol(&self) -> &Ident {
        &self.symb
    }

    pub fn definition(&self) -> TokenStream {
        let symb = &self.symb;
        let oid = self.oid.to_string();
        let doc = format!("#[doc=\"{}: {}\"]", &self.oid, &self.name)
            .parse::<TokenStream>()
            .expect("malformed doc comment");

        let bytes = format!("&{:?}", oid.as_bytes())
            .parse::<TokenStream>()
            .expect("malformed byte slice literal");

        quote! {
            #doc
            pub const #symb: crate::ObjectIdentifierRef<'static> = crate::ObjectIdentifierRef::from_bytes_unchecked(#bytes);
        }
    }
}
