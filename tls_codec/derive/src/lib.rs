extern crate proc_macro;
extern crate proc_macro2;

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote, ToTokens};
use syn::{
    self, parenthesized,
    parse::{ParseStream, Parser, Result},
    parse_macro_input,
    punctuated::Punctuated,
    token::Comma,
    Data, DeriveInput, Fields, FieldsNamed, FieldsUnnamed, Generics, Ident, Index, Variant,
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
enum EnumStyle {
    Repr(Ident),
    TupleStruct,
}

#[derive(Clone)]
struct Enum {
    call_site: Span,
    ident: Ident,
    generics: Generics,
    enum_style: EnumStyle,
    variants: Punctuated<Variant, Comma>,
}

const ENUM_TYPE_POSTFIX: &str = "Type";

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

            // The enum either has to have a repr or all variants need to be
            // tuple structs with a single field that has a path-style type.
            let only_tuple_structs = !variants.iter().any(|variant| match variant.fields {
                syn::Fields::Unnamed(ref fields_unnamed) => {
                    if fields_unnamed.unnamed.len() == 1 {
                        let field_type = fields_unnamed.unnamed.first().unwrap().ty.clone();
                        if let syn::Type::Path(_) = field_type {
                            false
                        } else {
                            true
                        }
                    } else {
                        true
                    }
                }
                _ => true,
            });

            let enum_style = if let Some(ref ty) = repr {
                EnumStyle::Repr(ty.clone())
            } else if only_tuple_structs {
                EnumStyle::TupleStruct
            } else {
                return Err(syn::Error::new(call_site, "enums either have to have a #[repr(...)] attribute or consist only of tuple structs"));
            };

            Ok(TlsStruct::Enum(Enum {
                call_site,
                ident: ident.clone(),
                generics: generics.clone(),
                enum_style,
                variants,
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
                impl#generics tls_codec::Size for #ident#generics {
                    #[inline]
                    fn tls_serialized_len(&self) -> usize {
                        #(self.#field_idents.tls_serialized_len() + )*
                        0
                    }
                }

                impl#generics tls_codec::Size for &#ident#generics {
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
                impl#generics tls_codec::Size for #ident#generics {
                    #[inline]
                    fn tls_serialized_len(&self) -> usize {
                        #(self.#field_indices.tls_serialized_len() + )*
                        0
                    }
                }

                impl#generics tls_codec::Size for &#ident#generics {
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
            enum_style,
            variants,
        }) => {
            let deconstructed_variants: Vec<TokenStream2> = variants
                .iter()
                .map(|variant| {
                    let variant = &variant.ident;
                    quote! {
                        #ident::#variant(variable) => variable
                    }
                })
                .collect();

            let function_block = match enum_style {
                EnumStyle::Repr(repr) => {
                    quote! {
                        std::mem::size_of::<#repr>()
                    }
                }
                EnumStyle::TupleStruct => {
                    let enum_type = &format_ident!("{}{}", ident, ENUM_TYPE_POSTFIX);
                    quote! {
                        std::mem::size_of::<#enum_type>() +
                            match self {
                                #(#deconstructed_variants.tls_serialized_len(),)*
                            }
                    }
                }
            };
            quote! {
                impl#generics tls_codec::Size for #ident#generics {
                    #[inline]
                    fn tls_serialized_len(&self) -> usize {
                        #function_block
                    }
                }

                impl#generics tls_codec::Size for &#ident#generics {
                    #[inline]
                    fn tls_serialized_len(&self) -> usize {
                        #function_block
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
                impl#generics tls_codec::Serialize for #ident#generics {
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

                impl#generics tls_codec::Serialize for &#ident#generics {
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
                impl#generics tls_codec::Serialize for #ident#generics {
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

                impl#generics tls_codec::Serialize for &#ident#generics {
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
            enum_style,
            variants,
        }) => {
            let function_block = match enum_style {
                EnumStyle::Repr(repr) => {
                    let parsed_variants: Vec<TokenStream2> = variants
                        .iter()
                        .map(|variant| {
                            let variant = &variant.ident;
                            quote! {
                                #ident::#variant => #ident::#variant as #repr,
                            }
                        })
                        .collect();
                    quote! {
                        let enum_value = match self {
                            #(#parsed_variants)*
                        };
                        enum_value.tls_serialize(writer)
                    }
                }
                EnumStyle::TupleStruct => {
                    let type_mapping: Vec<TokenStream2> = variants
                        .iter()
                        .map(|variant| {
                            let variant = &variant.ident;
                            let enum_type = &format_ident!("{}{}", ident, ENUM_TYPE_POSTFIX);
                            quote! {
                                #ident::#variant(_) => #enum_type::#variant
                            }
                        })
                        .collect();

                    let deconstructed_variants: Vec<TokenStream2> = variants
                        .iter()
                        .map(|variant| {
                            let variant = &variant.ident;
                            quote! {
                                #ident::#variant(variable) => variable
                            }
                        })
                        .collect();

                    quote! {
                        let mut written = match self {
                            #(#type_mapping.tls_serialize(writer)?,)*
                        };
                        match self {
                            #(#deconstructed_variants.tls_serialize(writer),)*
                        }.map(|l| l + written)
                    }
                }
            };
            quote! {
                impl#generics tls_codec::Serialize for #ident#generics {
                    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> core::result::Result<usize, tls_codec::Error> {
                        #function_block
                    }
                }

                impl#generics tls_codec::Serialize for &#ident#generics {
                    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> core::result::Result<usize, tls_codec::Error> {
                        #function_block
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
            enum_style,
            variants,
        }) => {
            match enum_style {
                EnumStyle::Repr(ref enum_repr) => {
                    let discriminants: Vec<TokenStream2> = variants
                        .iter()
                        .map(|variant| {
                            let variant = &variant.ident;
                            quote! {
                                const #variant: #enum_repr = #ident::#variant as #enum_repr;
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

                    quote! {
                        impl tls_codec::Deserialize for #ident {
                            #[allow(non_upper_case_globals)]
                            fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> core::result::Result<Self, tls_codec::Error> {
                                #(#discriminants)*

                                let value = #enum_repr::tls_deserialize(bytes)?;
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
                EnumStyle::TupleStruct => {
                    let variant_mapping: Vec<TokenStream2> = variants
                        .iter()
                        .map(|variant| {
                            let field_type = match variant.fields {
                                Fields::Unnamed(ref fields_unnamed) => fields_unnamed.unnamed.first().unwrap().ty.clone(),
                                _ => panic!("non-repr enums can only consist of tuple structs with a single unnamed field"),
                            };
                            let type_path = match field_type {
                                syn::Type::Path(tp) => tp.path,
                                _ => panic!("fields of the tuple struct can only have a simple path-style type"),
                            };
                            let variant_ident = &variant.ident;
                            let enum_type = &format_ident!("{}{}", ident, ENUM_TYPE_POSTFIX);
                            quote! {
                                #enum_type::#variant_ident => Ok(#ident::#variant_ident(#type_path::tls_deserialize(bytes)?))
                            }
                        })
                        .collect();
                    let enum_type = &format_ident!("{}{}", ident, ENUM_TYPE_POSTFIX);
                    quote! {
                        impl tls_codec::Deserialize for #ident {
                            #[allow(non_upper_case_globals)]
                            fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> core::result::Result<Self, tls_codec::Error> {

                                let value: #enum_type = #enum_type::tls_deserialize(bytes)?;
                                match value {
                                    #(#variant_mapping, )*
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
    }
}
