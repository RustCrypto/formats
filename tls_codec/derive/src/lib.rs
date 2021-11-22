//! # Derive macros for traits in `tls_codec`
//!
//! The following attribute is available:
//!
//! ```text
//! #[tls_codec(with = "module")]
//! ```
//! This attribute may be applied to a struct field. It indicates that deriving any of the
//! `tls_codec` traits for the containing struct uses the following functions defined in the
//! module `module`:
//! - `tls_deserialize` when deriving `Deserialize`
//! - `tls_serialize` when deriving `Serialize`
//! - `tls_serialized_len` when deriving `Size`
//!
//! Their expected signatures match the corresponding methods in the traits.
//!
//! ```
//! use tls_codec_derive::{TlsSerialize, TlsSize};
//!
//! #[derive(TlsSerialize, TlsSize)]
//! struct Bytes {
//!     #[tls_codec(with = "bytes")]
//!     values: Vec<u8>,
//! }
//!
//! mod bytes {
//!     use std::io::Write;
//!     use tls_codec::{Serialize, Size, TlsByteSliceU32};
//!
//!     pub fn tls_serialized_len(v: &[u8]) -> usize {
//!         TlsByteSliceU32(v).tls_serialized_len()
//!     }
//!
//!     pub fn tls_serialize<W: Write>(v: &[u8], writer: &mut W) -> Result<usize, tls_codec::Error> {
//!         TlsByteSliceU32(v).tls_serialize(writer)
//!     }
//! }
//! ```

extern crate proc_macro;
extern crate proc_macro2;

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{
    self, parenthesized,
    parse::{ParseStream, Parser, Result},
    parse_macro_input, Attribute, Data, DeriveInput, ExprPath, Field, Generics, Ident, Index, Lit,
    Member, Meta, NestedMeta, Type,
};

/// Attribute name to identify attributes to be processed by derive-macros in this crate.
const ATTR_IDENT: &str = "tls_codec";

/// Prefix to add to `tls_codec` functions
///
/// This is either `<Type as Trait>` or a custom module containing the functions.
#[derive(Clone)]
enum Prefix {
    Type(Type),
    Custom(ExprPath),
}

impl Prefix {
    /// Returns the path prefix to use for functions from the given trait.
    fn for_trait(&self, trait_name: &str) -> TokenStream2 {
        let trait_name = Ident::new(trait_name, Span::call_site());
        match self {
            Prefix::Type(ty) => quote! { <#ty as tls_codec::#trait_name> },
            Prefix::Custom(p) => quote! { #p },
        }
    }
}

#[derive(Clone)]
struct Struct {
    call_site: Span,
    ident: Ident,
    generics: Generics,
    members: Vec<Member>,
    member_prefixes: Vec<Prefix>,
}

#[derive(Clone)]
struct TupleStruct {
    call_site: Span,
    ident: Ident,
    generics: Generics,
    field_indices: Vec<Index>,
    field_paths: Vec<TokenStream2>,
}

#[derive(Clone)]
struct Enum {
    call_site: Span,
    ident: Ident,
    generics: Generics,
    repr: Ident,
    parsed_variants: Vec<TokenStream2>,
    discriminants: Vec<TokenStream2>,
    matched: Vec<TokenStream2>,
}

#[derive(Clone)]
enum TlsStruct {
    Struct(Struct),
    Enum(Enum),
}

/// Attributes supported by derive-macros in this crate
#[derive(Clone)]
enum TlsAttr {
    With(ExprPath),
}

impl TlsAttr {
    /// Parses attributes of the form:
    /// ```text
    /// #[tls_codec(with = "module")]
    /// ```
    fn parse(attr: &Attribute) -> Result<Vec<TlsAttr>> {
        if attr.path.get_ident().map_or(true, |id| id != ATTR_IDENT) {
            return Ok(Vec::new());
        }
        let meta = match attr.parse_meta()? {
            Meta::List(list) => Ok(list),
            _ => Err(syn::Error::new_spanned(attr, "Invalid attribute syntax")),
        }?;
        meta.nested
            .iter()
            .map(|item| match item {
                NestedMeta::Meta(Meta::NameValue(kv)) => kv
                    .path
                    .get_ident()
                    .map(|ident| {
                        if ident == "with" {
                            match &kv.lit {
                                Lit::Str(s) => s.parse::<ExprPath>().map(TlsAttr::With),
                                _ => {
                                    Err(syn::Error::new_spanned(&kv.lit, "Expected string literal"))
                                }
                            }
                        } else {
                            Err(syn::Error::new_spanned(
                                ident,
                                format!("Unexpected identifier {}", ident),
                            ))
                        }
                    })
                    .unwrap_or_else(|| {
                        Err(syn::Error::new_spanned(&kv.path, "Expected identifier"))
                    }),
                _ => Err(syn::Error::new_spanned(item, "Invalid attribute syntax")),
            })
            .collect()
    }
}

/// Gets the [`Prefix`] for a field, i.e. the type itself or a module containing the `tls_codec`
/// functions.
fn function_prefix(field: &Field) -> Result<Prefix> {
    let prefix = field
        .attrs
        .iter()
        .flat_map(|attr| {
            let (known_attrs, error) = match TlsAttr::parse(attr) {
                Ok(attrs) => (attrs, None),
                Err(e) => (Vec::new(), Some(Err(e))),
            };
            known_attrs
                .into_iter()
                .map(|TlsAttr::With(p)| Ok(p))
                .chain(error)
        })
        .try_fold(None, |path, p| {
            let p = p?;
            match path {
                None => Ok(Some(p)),
                Some(_) => Err(syn::Error::new_spanned(
                    p,
                    "Attribute `with` specified more than once",
                )),
            }
        })?
        .map(Prefix::Custom)
        .unwrap_or_else(|| Prefix::Type(field.ty.clone()));
    Ok(prefix)
}

fn parse_ast(ast: DeriveInput) -> Result<TlsStruct> {
    let call_site = Span::call_site();
    let ident = ast.ident.clone();
    let generics = ast.generics.clone();
    match ast.data {
        Data::Struct(st) => {
            let members = st
                .fields
                .iter()
                .enumerate()
                .map(|(i, field)| {
                    field
                        .ident
                        .clone()
                        .map_or_else(|| Member::Unnamed(syn::Index::from(i)), Member::Named)
                })
                .collect();
            let member_prefixes = st
                .fields
                .iter()
                .map(function_prefix)
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(TlsStruct::Struct(Struct {
                call_site,
                ident,
                generics,
                members,
                member_prefixes,
            }))
        }
        // Enums.
        // Note that they require a repr attribute.
        Data::Enum(syn::DataEnum { variants, .. }) => {
            let mut repr = None;
            for attr in ast.attrs {
                if attr.path.is_ident("repr") {
                    fn repr_arg(input: ParseStream) -> Result<Ident> {
                        let content;
                        parenthesized!(content in input);
                        content.parse()
                    }
                    let ty = repr_arg.parse2(attr.tokens)?;
                    repr = Some(ty);
                    break;
                }
            }
            let repr =
                repr.ok_or_else(|| syn::Error::new(call_site, "missing #[repr(...)] attribute"))?;
            let parsed_variants: Vec<TokenStream2> = variants
                .iter()
                .map(|variant| {
                    let variant = &variant.ident;
                    quote! {
                        #ident::#variant => #ident::#variant as #repr,
                    }
                })
                .collect();

            let discriminants: Vec<TokenStream2> = variants
                .iter()
                .map(|variant| {
                    let variant = &variant.ident;
                    quote! {
                        const #variant: #repr = #ident::#variant as #repr;
                    }
                })
                .collect();

            let matched: Vec<TokenStream2> = variants
                .iter()
                .map(|variant| {
                    let variant = &variant.ident;
                    quote! {
                        #variant => core::result::Result::Ok(#ident::#variant),
                    }
                })
                .collect();

            Ok(TlsStruct::Enum(Enum {
                call_site,
                ident,
                generics,
                repr,
                parsed_variants,
                discriminants,
                matched,
            }))
        }
        Data::Union(_) => unimplemented!(),
    }
}

#[proc_macro_derive(TlsSize, attributes(tls_codec))]
pub fn size_macro_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let parsed_ast = parse_ast(ast).unwrap();
    impl_tls_size(parsed_ast).into()
}

#[proc_macro_derive(TlsSerialize, attributes(tls_codec))]
pub fn serialize_macro_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let parsed_ast = parse_ast(ast).unwrap();
    impl_serialize(parsed_ast).into()
}

#[proc_macro_derive(TlsDeserialize, attributes(tls_codec))]
pub fn deserialize_macro_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let parsed_ast = parse_ast(ast).unwrap();
    impl_deserialize(parsed_ast).into()
}

#[allow(unused_variables)]
fn impl_tls_size(parsed_ast: TlsStruct) -> TokenStream2 {
    match parsed_ast {
        TlsStruct::Struct(Struct {
            call_site,
            ident,
            generics,
            members,
            member_prefixes,
        }) => {
            let prefixes = member_prefixes
                .iter()
                .map(|p| p.for_trait("Size"))
                .collect::<Vec<_>>();
            quote! {
                impl #generics tls_codec::Size for #ident #generics {
                    #[inline]
                    fn tls_serialized_len(&self) -> usize {
                        #(#prefixes::tls_serialized_len(&self.#members) + )*
                        0
                    }
                }

                impl #generics tls_codec::Size for &#ident #generics {
                    #[inline]
                    fn tls_serialized_len(&self) -> usize {
                        tls_codec::Size::tls_serialized_len(*self)
                    }
                }
            }
        }
        TlsStruct::Enum(Enum {
            call_site,
            ident,
            generics,
            repr,
            parsed_variants,
            discriminants,
            matched,
        }) => {
            quote! {
                impl #generics tls_codec::Size for #ident #generics {
                    #[inline]
                    fn tls_serialized_len(&self) -> usize {
                        std::mem::size_of::<#repr>()
                    }
                }

                impl #generics tls_codec::Size for &#ident #generics {
                    #[inline]
                    fn tls_serialized_len(&self) -> usize {
                        std::mem::size_of::<#repr>()
                    }
                }
            }
        }
    }
}

#[allow(unused_variables)]
fn impl_serialize(parsed_ast: TlsStruct) -> TokenStream2 {
    match parsed_ast {
        TlsStruct::Struct(Struct {
            call_site,
            ident,
            generics,
            members,
            member_prefixes,
        }) => {
            let prefixes = member_prefixes
                .iter()
                .map(|p| p.for_trait("Serialize"))
                .collect::<Vec<_>>();
            quote! {
                impl #generics tls_codec::Serialize for #ident #generics {
                    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> core::result::Result<usize, tls_codec::Error> {
                        let mut written = 0usize;
                        #(
                            written += #prefixes::tls_serialize(&self.#members, writer)?;
                        )*
                        if cfg!(debug_assertions) {
                            let expected_written = tls_codec::Size::tls_serialized_len(&self);
                            debug_assert_eq!(written, expected_written, "Expected to serialize {} bytes but only {} were generated.", expected_written, written);
                            if written != expected_written {
                                Err(tls_codec::Error::EncodingError(format!("Expected to serialize {} bytes but only {} were generated.", expected_written, written)))
                            } else {
                                Ok(written)
                            }
                        } else {
                            Ok(written)
                        }
                    }
                }

                impl #generics tls_codec::Serialize for &#ident #generics {
                    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> core::result::Result<usize, tls_codec::Error> {
                        tls_codec::Serialize::tls_serialize(*self, writer)
                    }
                }
            }
        }
        TlsStruct::Enum(Enum {
            call_site,
            ident,
            generics,
            repr,
            parsed_variants,
            discriminants,
            matched,
        }) => {
            quote! {
                impl #generics tls_codec::Serialize for #ident #generics {
                    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> core::result::Result<usize, tls_codec::Error> {
                        let enum_value: #repr = match self {
                            #(#parsed_variants)*
                        };
                        enum_value.tls_serialize(writer)
                    }
                }

                impl #generics tls_codec::Serialize for &#ident #generics {
                    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> core::result::Result<usize, tls_codec::Error> {
                        let enum_value: #repr = match self {
                            #(#parsed_variants)*
                        };
                        enum_value.tls_serialize(writer)
                    }
                }
            }
        }
    }
}

#[allow(unused_variables)]
fn impl_deserialize(parsed_ast: TlsStruct) -> TokenStream2 {
    match parsed_ast {
        TlsStruct::Struct(Struct {
            call_site,
            ident,
            generics,
            members,
            member_prefixes,
        }) => {
            let prefixes = member_prefixes
                .iter()
                .map(|p| p.for_trait("Deserialize"))
                .collect::<Vec<_>>();
            quote! {
                impl tls_codec::Deserialize for #ident {
                    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> core::result::Result<Self, tls_codec::Error> {
                        Ok(Self {
                            #(#members: #prefixes::tls_deserialize(bytes)?,)*
                        })
                    }
                }
            }
        }
        TlsStruct::Enum(Enum {
            call_site,
            ident,
            generics,
            repr,
            parsed_variants,
            discriminants,
            matched,
        }) => {
            quote! {
                impl tls_codec::Deserialize for #ident {
                    #[allow(non_upper_case_globals)]
                    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> core::result::Result<Self, tls_codec::Error> {
                        #(#discriminants)*

                        let value = #repr::tls_deserialize(bytes)?;
                        match value {
                            #(#matched)*
                            // XXX: This assumes non-exhaustive matches only.
                            _ => {
                                Err(tls_codec::Error::DecodingError(format!("Unmatched value {:?} in tls_deserialize", value)))
                            },
                        }
                    }
                }
            }
        }
    }
}
