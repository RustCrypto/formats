//! # Derive macros for traits in `tls_codec`
//!
//! ## Warning
//!
//! The derive macros support deriving the `tls_codec` traits for enumerations and the resulting
//! serialized format complies with [the "variants" section of the TLS RFC](https://datatracker.ietf.org/doc/html/rfc8446#section-3.8).
//! However support is limited to enumerations that are serialized with their discriminant
//! immediately followed by the variant data. If this is not appropriate (e.g. the format requires
//! other fields between the discriminant and variant data), the `tls_codec` traits can be
//! implemented manually.
//!
//! ## Available attributes
//!
//! ### `with`
//!
//! ```text
//! #[tls_codec(with = "prefix")]
//! ```
//!
//! This attribute may be applied to a struct field. It indicates that deriving any of the
//! `tls_codec` traits for the containing struct calls the following functions:
//! - `prefix::tls_deserialize` when deriving `Deserialize`
//! - `prefix::tls_serialize` when deriving `Serialize`
//! - `prefix::tls_serialized_len` when deriving `Size`
//!
//! `prefix` can be a path to a module, type or trait where the functions are defined.
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
//!
//! ### `discriminant`
//!
//! ```text
//! #[tls_codec(discriminant = 123)]
//! ```
//!
//! This attribute may be applied to an enum variant to specify the discriminant to use when
//! serializing it. If all variants are units (e.g. they do not have any data), this attribute
//! must not be used and the desired discriminants should be assigned to the variants using
//! standard Rust syntax (`Variant = Discriminant`).
//!
//! For enumerations with non-unit variants, if no variant has this attribute, the serialization
//! discriminants will start from zero. If this attribute is used on a variant and the following
//! variant does not have it, its discriminant will be equal to the previous variant discriminant
//! plus 1.
//!
//! ```
//! use tls_codec_derive::{TlsSerialize, TlsSize};
//!
//! #[derive(TlsSerialize, TlsSize)]
//! #[repr(u8)]
//! enum Token {
//!     #[tls_codec(discriminant = 5)]
//!     Int(u32),
//!     Bytes([u8; 16]),
//! }
//! ```
//!
//! ### `skip`
//!
//! ```text
//! #[tls_codec(skip)]
//! ```
//!
//! This attribute may be applied to a struct field to specify that it should be skipped. Skipping
//! means that the field at hand will neither be serialized into TLS bytes nor deserialized from TLS
//! bytes. For deserialization, it is required to populate the field with a known value. Thus, when
//! `skip` is used, the field type needs to implement the [Default] trait so it can be populated
//! with a default value.
//!
//! ```
//! use tls_codec_derive::{TlsSerialize, TlsDeserialize, TlsSize};
//!
//! struct CustomStruct;
//!
//! impl Default for CustomStruct {
//!     fn default() -> Self {
//!         CustomStruct {}
//!     }
//! }
//!
//! #[derive(TlsSerialize, TlsDeserialize, TlsSize)]
//! struct StructWithSkip {
//!     a: u8,
//!     #[tls_codec(skip)]
//!     b: CustomStruct,
//!     c: u8,
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
    parse_macro_input,
    punctuated::Punctuated,
    token::Comma,
    Attribute, Data, DeriveInput, ExprPath, Field, Generics, Ident, Lit, Member, Meta, NestedMeta,
    Type,
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
    member_skips: Vec<bool>,
}

#[derive(Clone)]
struct Enum {
    call_site: Span,
    ident: Ident,
    generics: Generics,
    repr: Ident,
    variants: Vec<Variant>,
    discriminant_constants: TokenStream2,
}

#[derive(Clone)]
struct Variant {
    ident: Ident,
    members: Vec<Member>,
    member_prefixes: Vec<Prefix>,
}

#[derive(Clone)]
enum TlsStruct {
    Struct(Struct),
    Enum(Enum),
}

/// Attributes supported by derive-macros in this crate
#[derive(Clone)]
enum TlsAttr {
    /// Prefix for custom serialization functions
    With(ExprPath),
    /// Custom discriminant for an enum variant
    Discriminant(u32),
    /// Skip this attribute during (de)serialization.
    ///
    /// Note: The type of the attribute needs to implement [Default].
    ///       This is required to populate the field with a known
    ///       value during deserialization.
    Skip,
}

impl TlsAttr {
    fn name(&self) -> &'static str {
        match self {
            TlsAttr::With(_) => "with",
            TlsAttr::Discriminant(_) => "discriminant",
            TlsAttr::Skip => "skip",
        }
    }

    /// Parses attributes of the form, `#[tls_codec(with = <string>)]`,
    /// `#[tls_codec(discriminant = <number>)]`, and `#[tls_codec(skip)]`.
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
                        let ident_str = ident.to_string();
                        match &*ident_str {
                            "discriminant" => match &kv.lit {
                                Lit::Int(i) => i.base10_parse::<u32>().map(TlsAttr::Discriminant),
                                _ => Err(syn::Error::new_spanned(
                                    &kv.lit,
                                    "Expected integer literal",
                                )),
                            },
                            "with" => match &kv.lit {
                                Lit::Str(s) => s.parse::<ExprPath>().map(TlsAttr::With),
                                _ => {
                                    Err(syn::Error::new_spanned(&kv.lit, "Expected string literal"))
                                }
                            },
                            _ => Err(syn::Error::new_spanned(
                                ident,
                                format!("Unexpected identifier {}", ident),
                            )),
                        }
                    })
                    .unwrap_or_else(|| {
                        Err(syn::Error::new_spanned(&kv.path, "Expected identifier"))
                    }),
                NestedMeta::Meta(Meta::Path(path)) => {
                    if let Some(ident) = path.get_ident() {
                        // TODO: Should we accept "skip" case-insensitive?
                        match ident.to_string().to_ascii_lowercase().as_ref() {
                            "skip" => Ok(TlsAttr::Skip),
                            _ => Err(syn::Error::new_spanned(
                                ident,
                                format!("Unexpected identifier {}", ident),
                            )),
                        }
                    } else {
                        Err(syn::Error::new_spanned(path, "Expected identifier"))
                    }
                }
                _ => Err(syn::Error::new_spanned(item, "Invalid attribute syntax")),
            })
            .collect()
    }

    /// Parses attributes of the form:
    /// ```text
    /// #[tls_codec(with = "module", ...)]
    /// ```
    fn parse_multi(attrs: &[Attribute]) -> Result<Vec<TlsAttr>> {
        attrs.iter().try_fold(Vec::new(), |mut acc, attr| {
            acc.extend(TlsAttr::parse(attr)?);
            Ok(acc)
        })
    }
}

/// Gets the [`Prefix`] for a field, i.e. the type itself or a path to prepend to the `tls_codec`
/// functions (e.g. a module or type).
fn function_prefix(field: &Field) -> Result<Prefix> {
    let prefix = TlsAttr::parse_multi(&field.attrs)?
        .into_iter()
        .try_fold(None, |path, attr| match (path, attr) {
            (None, TlsAttr::With(p)) => Ok(Some(p)),
            (Some(_), TlsAttr::With(p)) => Err(syn::Error::new_spanned(
                p,
                "Attribute `with` specified more than once",
            )),
            (path, _) => Ok(path),
        })?
        .map(Prefix::Custom)
        .unwrap_or_else(|| Prefix::Type(field.ty.clone()));
    Ok(prefix)
}

fn function_skip(field: &Field) -> Result<bool> {
    let skip = TlsAttr::parse_multi(&field.attrs)?
        .into_iter()
        .try_fold(None, |skip, attr| match (skip, attr) {
            (None, TlsAttr::Skip) => Ok(Some(true)),
            (Some(_), TlsAttr::Skip) => Err(syn::Error::new(
                Span::call_site(),
                "Attribute `skip` specified more than once",
            )),
            (skip, _) => Ok(skip),
        })?
        .unwrap_or(false);

    Ok(skip)
}

/// Gets the serialization discriminant if specified.
fn discriminant_value(attrs: &[Attribute]) -> Result<Option<u32>> {
    TlsAttr::parse_multi(attrs)?
        .into_iter()
        .try_fold(None, |discriminant, attr| match (discriminant, attr) {
            (None, TlsAttr::Discriminant(d)) => Ok(Some(d)),
            (Some(_), TlsAttr::Discriminant(_)) => Err(syn::Error::new(
                Span::call_site(),
                "Attribute `discriminant` specified more than once",
            )),
            (_, attr) => Err(syn::Error::new(
                Span::call_site(),
                format!("Unrecognized variant attribute `{}`", attr.name()),
            )),
        })
}

fn fields_to_members(fields: &syn::Fields) -> Vec<Member> {
    fields
        .iter()
        .enumerate()
        .map(|(i, field)| {
            field
                .ident
                .clone()
                .map_or_else(|| Member::Unnamed(syn::Index::from(i)), Member::Named)
        })
        .collect()
}

/// Gets the [`Prefix`]es for all fields, i.e. the types themselves or paths to prepend to the
/// `tls_codec` functions (e.g. a module or type).
fn fields_to_member_prefixes(fields: &syn::Fields) -> Result<Vec<Prefix>> {
    fields.iter().map(function_prefix).collect()
}

fn fields_to_member_skips(fields: &syn::Fields) -> Result<Vec<bool>> {
    fields.iter().map(function_skip).collect()
}

fn parse_ast(ast: DeriveInput) -> Result<TlsStruct> {
    let call_site = Span::call_site();
    let ident = ast.ident.clone();
    let generics = ast.generics.clone();
    match ast.data {
        Data::Struct(st) => {
            let members = fields_to_members(&st.fields);
            let member_prefixes = fields_to_member_prefixes(&st.fields)?;
            let member_skips = fields_to_member_skips(&st.fields)?;
            Ok(TlsStruct::Struct(Struct {
                call_site,
                ident,
                generics,
                members,
                member_prefixes,
                member_skips,
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
            let discriminant_constants = define_discriminant_constants(&ident, &repr, &variants)?;
            let variants = variants
                .into_iter()
                .map(|variant| {
                    Ok(Variant {
                        ident: variant.ident,
                        members: fields_to_members(&variant.fields),
                        member_prefixes: fields_to_member_prefixes(&variant.fields)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;

            Ok(TlsStruct::Enum(Enum {
                call_site,
                ident,
                generics,
                repr,
                variants,
                discriminant_constants,
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

/// Returns identifiers to use as bindings in generated code
fn make_n_ids(n: usize) -> Vec<Ident> {
    (0..n)
        .map(|i| Ident::new(&format!("__arg{}", i), Span::call_site()))
        .collect()
}

/// Returns identifier to define a constant equal to the discriminant of a variant
fn discriminant_id(variant: &Ident) -> Ident {
    Ident::new(&format!("__TLS_CODEC_{}", variant), Span::call_site())
}

/// Returns definitions of constants equal to the discriminants of each variant
fn define_discriminant_constants(
    enum_ident: &Ident,
    repr: &Ident,
    variants: &Punctuated<syn::Variant, Comma>,
) -> Result<TokenStream2> {
    let all_variants_are_unit = variants
        .iter()
        .all(|variant| matches!(variant.fields, syn::Fields::Unit));
    let discriminant_constants = if all_variants_are_unit {
        variants
            .iter()
            .map(|variant| {
                let variant_id = &variant.ident;
                let constant_id = discriminant_id(variant_id);
                if discriminant_value(&variant.attrs)?.is_some() {
                    Err(syn::Error::new(
                        Span::call_site(),
                        "The tls_codec discriminant attribute must only be used in enumerations \
                        with at least one non-unit variant. When all variants are units, \
                        discriminants can be assigned to variants directly.",
                    ))
                } else {
                    Ok(quote! {
                        const #constant_id: #repr = #enum_ident::#variant_id as #repr;
                    })
                }
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        variants
            .iter()
            .try_fold((0, Vec::new()), |(next, mut acc), variant| {
                let constant_id = discriminant_id(&variant.ident);
                let value = discriminant_value(&variant.attrs)?.unwrap_or(next);
                acc.push(quote! {
                    const #constant_id: #repr = #value as #repr;
                });
                Ok::<_, syn::Error>((value + 1, acc))
            })?
            .1
    };
    Ok(quote! { #(#discriminant_constants)* })
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
            member_skips,
        }) => {
            // Filter out skipped members.
            let (members, member_prefixes) = {
                let mut tmp_members: Vec<Member> = Vec::new();
                let mut tmp_member_prefixes: Vec<Prefix> = Vec::new();

                for ((member, prefix), skip) in members
                    .into_iter()
                    .zip(member_prefixes.into_iter())
                    .zip(member_skips.into_iter())
                {
                    if !skip {
                        tmp_members.push(member);
                        tmp_member_prefixes.push(prefix);
                    }
                }

                (tmp_members, tmp_member_prefixes)
            };

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
            variants,
            ..
        }) => {
            let field_arms = variants
                .iter()
                .map(|variant| {
                    let variant_id = &variant.ident;
                    let members = &variant.members;
                    let bindings = make_n_ids(members.len());
                    let prefixes = variant.member_prefixes.iter().map(|p| p.for_trait("Size")).collect::<Vec<_>>();
                    quote! {
                        #ident::#variant_id { #(#members: #bindings,)* } => 0 #(+ #prefixes::tls_serialized_len(#bindings))*,
                    }
                })
                .collect::<Vec<_>>();
            quote! {
                impl #generics tls_codec::Size for #ident #generics {
                    #[inline]
                    fn tls_serialized_len(&self) -> usize {
                        let field_len = match self {
                            #(#field_arms)*
                        };
                        std::mem::size_of::<#repr>() + field_len
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
            member_skips,
        }) => {
            // Filter out skipped members.
            let (members, member_prefixes) = {
                let mut tmp_members: Vec<Member> = Vec::new();
                let mut tmp_member_prefixes: Vec<Prefix> = Vec::new();

                for ((member, prefix), skip) in members
                    .into_iter()
                    .zip(member_prefixes.into_iter())
                    .zip(member_skips.into_iter())
                {
                    if !skip {
                        tmp_members.push(member);
                        tmp_member_prefixes.push(prefix);
                    }
                }

                (tmp_members, tmp_member_prefixes)
            };

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
            variants,
            discriminant_constants,
        }) => {
            let arms = variants
                .iter()
                .map(|variant| {
                    let variant_id = &variant.ident;
                    let discriminant = discriminant_id(variant_id);
                    let members = &variant.members;
                    let bindings = make_n_ids(members.len());
                    let prefixes = variant
                        .member_prefixes
                        .iter()
                        .map(|p| p.for_trait("Serialize"))
                        .collect::<Vec<_>>();
                    quote! {
                        #ident::#variant_id { #(#members: #bindings,)* } => Ok(
                            tls_codec::Serialize::tls_serialize(&#discriminant, writer)?
                            #(+ #prefixes::tls_serialize(#bindings, writer)?)*
                        ),
                    }
                })
                .collect::<Vec<_>>();
            quote! {
                impl #generics tls_codec::Serialize for #ident #generics {
                    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> core::result::Result<usize, tls_codec::Error> {
                        #discriminant_constants
                        match self {
                            #(#arms)*
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
            member_skips,
        }) => {
            // Partition skipped and non-skipped members.
            let (members, member_prefixes, members_default, member_prefixes_default) = {
                let mut tmp_members: Vec<Member> = Vec::new();
                let mut tmp_member_prefixes: Vec<Prefix> = Vec::new();
                let mut tmp_members_default: Vec<Member> = Vec::new();
                let mut tmp_member_prefixes_default: Vec<Prefix> = Vec::new();

                for ((member, prefix), skip) in members
                    .into_iter()
                    .zip(member_prefixes.into_iter())
                    .zip(member_skips.into_iter())
                {
                    if !skip {
                        tmp_members.push(member);
                        tmp_member_prefixes.push(prefix);
                    } else {
                        tmp_members_default.push(member);
                        tmp_member_prefixes_default.push(prefix);
                    }
                }

                (
                    tmp_members,
                    tmp_member_prefixes,
                    tmp_members_default,
                    tmp_member_prefixes_default,
                )
            };

            let prefixes = member_prefixes
                .iter()
                .map(|p| p.for_trait("Deserialize"))
                .collect::<Vec<_>>();
            quote! {
                impl tls_codec::Deserialize for #ident {
                    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> core::result::Result<Self, tls_codec::Error> {
                        Ok(Self {
                            #(#members: #prefixes::tls_deserialize(bytes)?,)*
                            #(#members_default: Default::default(),)*
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
            variants,
            discriminant_constants,
        }) => {
            let arms = variants
                .iter()
                .map(|variant| {
                    let variant_id = &variant.ident;
                    let discriminant = discriminant_id(variant_id);
                    let members = &variant.members;
                    let prefixes = variant
                        .member_prefixes
                        .iter()
                        .map(|p| p.for_trait("Deserialize"))
                        .collect::<Vec<_>>();
                    quote! {
                        #discriminant => Ok(#ident::#variant_id {
                            #(#members: #prefixes::tls_deserialize(bytes)?,)*
                        }),
                    }
                })
                .collect::<Vec<_>>();
            quote! {
                impl tls_codec::Deserialize for #ident {
                    #[allow(non_upper_case_globals)]
                    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> core::result::Result<Self, tls_codec::Error> {
                        #discriminant_constants
                        let discriminant = <#repr as tls_codec::Deserialize>::tls_deserialize(bytes)?;
                        match discriminant {
                            #(#arms)*
                            _ => {
                                Err(tls_codec::Error::DecodingError(format!("Unmatched discriminant {:?} in tls_deserialize", discriminant)))
                            },
                        }
                    }
                }
            }
        }
    }
}
