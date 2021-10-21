extern crate proc_macro;
extern crate proc_macro2;

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{quote, ToTokens};
use syn::{
    self, parenthesized,
    parse::{ParseStream, Parser, Result},
    parse_macro_input, Data, DeriveInput, Fields, FieldsNamed, FieldsUnnamed, Generics, Ident,
    Index,
};

#[derive(Clone)]
struct Struct {
    call_site: Span,
    ident: Ident,
    generics: Generics,
    field_idents: Vec<Option<Ident>>,
    field_paths: Vec<TokenStream2>,
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
    TupleStruct(TupleStruct),
    Enum(Enum),
}

fn parse_ast(ast: DeriveInput) -> Result<TlsStruct> {
    let call_site = Span::call_site();
    let ident = &ast.ident;
    let generics = &ast.generics;
    match ast.data {
        Data::Struct(st) => match st.fields {
            Fields::Named(FieldsNamed { named, .. }) => {
                let field_idents: Vec<Option<Ident>> =
                    named.iter().map(|f| f.ident.clone()).collect();
                let paths = named.iter().map(|f| match f.ty.clone() {
                    syn::Type::Path(mut p) => {
                        let path = &mut p.path;
                        // Convert generic arguments in the path to const arguments.
                        path.segments.iter_mut().for_each(|mut p| {
                            if let syn::PathArguments::AngleBracketed(ab) = &mut p.arguments {
                                let mut ab = ab.clone();
                                ab.colon2_token = Some(syn::token::Colon2::default());
                                p.arguments = syn::PathArguments::AngleBracketed(ab);
                            }
                        });
                        syn::Type::Path(p).to_token_stream()
                    }
                    syn::Type::Array(a) => {
                        quote! { <#a> }
                    }
                    #[allow(unused_variables)]
                    syn::Type::Reference(syn::TypeReference {
                        and_token,
                        lifetime,
                        mutability,
                        elem,
                    }) => {
                        // println!(
                        //     "(Struct::Named) contains a type reference for field \"{}\"\nThis struct can not be deserialized",
                        //     f.ident.clone().unwrap()
                        // );
                        quote! {}
                    }
                    _ => panic!(
                        "(Struct::Named) Invalid field type for field \"{}\"",
                        f.ident.clone().unwrap()
                    ),
                });
                let field_paths: Vec<TokenStream2> = paths.collect();
                Ok(TlsStruct::Struct(Struct {
                    call_site,
                    ident: ident.clone(),
                    generics: generics.clone(),
                    field_idents,
                    field_paths,
                }))
            }
            #[allow(unused_variables)]
            Fields::Unnamed(FieldsUnnamed {
                paren_token,
                unnamed,
            }) => {
                let iterator = unnamed.iter().enumerate();
                let field_indices: Vec<Index> =
                    iterator.map(|(i, _)| syn::Index::from(i)).collect();
                let paths = unnamed.iter().map(|f| match f.ty.clone() {
                    syn::Type::Path(mut p) => {
                        let path = &mut p.path;
                        // Convert generic arguments in the path to const arguments.
                        path.segments.iter_mut().for_each(|mut p| {
                            if let syn::PathArguments::AngleBracketed(ab) = &mut p.arguments {
                                let mut ab = ab.clone();
                                ab.colon2_token = Some(syn::token::Colon2::default());
                                p.arguments = syn::PathArguments::AngleBracketed(ab);
                            }
                        });
                        syn::Type::Path(p).to_token_stream()
                    }
                    syn::Type::Array(a) => {
                        quote! { <#a> }
                    }
                    _ => panic!("(Struct::Unnamed) Invalid field type for {:?}", f.ident),
                });

                let field_paths: Vec<TokenStream2> = paths.collect();
                Ok(TlsStruct::TupleStruct(TupleStruct {
                    call_site,
                    ident: ident.clone(),
                    generics: generics.clone(),
                    field_indices,
                    field_paths,
                }))
            }
            _ => unimplemented!(),
        },
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
                ident: ident.clone(),
                generics: generics.clone(),
                repr,
                parsed_variants,
                discriminants,
                matched,
            }))
        }
        Data::Union(_) => unimplemented!(),
    }
}

#[proc_macro_derive(TlsSize)]
pub fn size_macro_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let parsed_ast = parse_ast(ast).unwrap();
    impl_tls_size(parsed_ast).into()
}

#[proc_macro_derive(TlsSerialize)]
pub fn serialize_macro_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let parsed_ast = parse_ast(ast).unwrap();
    impl_serialize(parsed_ast).into()
}

#[proc_macro_derive(TlsDeserialize)]
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
            field_idents,
            field_paths,
        }) => {
            quote! {
                impl #generics tls_codec::Size for #ident #generics {
                    #[inline]
                    fn tls_serialized_len(&self) -> usize {
                        #(self.#field_idents.tls_serialized_len() + )*
                        0
                    }
                }

                impl #generics tls_codec::Size for &#ident #generics {
                    #[inline]
                    fn tls_serialized_len(&self) -> usize {
                        #(self.#field_idents.tls_serialized_len() + )*
                        0
                    }
                }
            }
        }
        TlsStruct::TupleStruct(TupleStruct {
            call_site,
            ident,
            generics,
            field_indices,
            field_paths,
        }) => {
            quote! {
                impl #generics tls_codec::Size for #ident #generics {
                    #[inline]
                    fn tls_serialized_len(&self) -> usize {
                        #(self.#field_indices.tls_serialized_len() + )*
                        0
                    }
                }

                impl #generics tls_codec::Size for &#ident #generics {
                    #[inline]
                    fn tls_serialized_len(&self) -> usize {
                        #(self.#field_indices.tls_serialized_len() + )*
                        0
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
            field_idents,
            field_paths,
        }) => {
            quote! {
                impl #generics tls_codec::Serialize for #ident #generics {
                    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> core::result::Result<usize, tls_codec::Error> {
                        let mut written = 0usize;
                        #(
                            written += self.#field_idents.tls_serialize(writer)?;
                        )*
                        if cfg!(debug_assertions) {
                            let expected_written = self.tls_serialized_len();
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
                        let mut written = 0usize;
                        #(written += self.#field_idents.tls_serialize(writer)?;)*
                        if cfg!(debug_assertions) {
                            let expected_written = self.tls_serialized_len();
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
            }
        }
        TlsStruct::TupleStruct(TupleStruct {
            call_site,
            ident,
            generics,
            field_indices,
            field_paths,
        }) => {
            quote! {
                impl #generics tls_codec::Serialize for #ident #generics {
                    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> core::result::Result<usize, tls_codec::Error> {
                        let mut written = 0usize;
                        #(written += self.#field_indices.tls_serialize(writer)?;)*
                        if cfg!(debug_assertions) {
                            let expected_written = self.tls_serialized_len();
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
                        let mut written = 0usize;
                        #(written += self.#field_indices.tls_serialize(writer)?;)*
                        if cfg!(debug_assertions) {
                            let expected_written = self.tls_serialized_len();
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
            field_idents,
            field_paths,
        }) => {
            quote! {
                impl tls_codec::Deserialize for #ident {
                    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> core::result::Result<Self, tls_codec::Error> {
                        Ok(Self {
                            #(#field_idents: #field_paths::tls_deserialize(bytes)?,)*
                        })
                    }
                }
            }
        }
        TlsStruct::TupleStruct(TupleStruct {
            call_site,
            ident,
            generics,
            field_indices,
            field_paths,
        }) => {
            quote! {
                impl tls_codec::Deserialize for #ident {
                    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> core::result::Result<Self, tls_codec::Error> {
                        Ok(Self(
                            #(#field_paths::tls_deserialize(bytes)?,)*
                        ))
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
