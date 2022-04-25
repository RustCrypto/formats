//! Support for deriving newtypes.

use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::punctuated::Punctuated;
use syn::{Data, DeriveInput, Fields, FieldsUnnamed, Ident, LifetimeDef, Type};

trait PunctuatedExt<T, P> {
    fn only(&self) -> Option<&T>;
}

impl<T, P> PunctuatedExt<T, P> for Punctuated<T, P> {
    fn only(&self) -> Option<&T> {
        let mut iter = self.iter();

        let first = iter.next();
        if let Some(..) = iter.next() {
            return None;
        }

        first
    }
}

pub(crate) struct DeriveNewtype {
    ident: Ident,
    ltime: Vec<LifetimeDef>,
    ftype: Type,
}

impl DeriveNewtype {
    pub fn new(input: DeriveInput) -> Self {
        if let Data::Struct(data) = &input.data {
            if let Fields::Unnamed(FieldsUnnamed { unnamed, .. }) = &data.fields {
                if let Some(field) = unnamed.only() {
                    return Self {
                        ident: input.ident.clone(),
                        ltime: input.generics.lifetimes().cloned().collect(),
                        ftype: field.ty.clone(),
                    };
                }
            }
        }

        abort!(input, "only derivable on a newtype");
    }

    pub fn to_tokens(&self) -> TokenStream {
        let ident = &self.ident;
        let ftype = &self.ftype;
        let ltime = &self.ltime;

        let (limpl, ltype, param) = match self.ltime.len() {
            0 => (quote! { impl }, quote! { #ident }, quote! { '_ }),
            _ => (
                quote! { impl<#(#ltime)*> },
                quote! { #ident<#(#ltime)*> },
                quote! { #(#ltime)* },
            ),
        };

        quote! {
            #limpl From<#ftype> for #ltype {
                #[inline]
                fn from(value: #ftype) -> Self {
                    Self(value)
                }
            }

            #limpl From<#ltype> for #ftype {
                #[inline]
                fn from(value: #ltype) -> Self {
                    value.0
                }
            }

            #limpl ::core::convert::AsRef<#ftype> for #ltype {
                #[inline]
                fn as_ref(&self) -> &#ftype {
                    &self.0
                }
            }

            #limpl ::core::convert::AsMut<#ftype> for #ltype {
                #[inline]
                fn as_mut(&mut self) -> &mut #ftype {
                    &mut self.0
                }
            }

            #limpl ::der::FixedTag for #ltype {
                const TAG: ::der::Tag = <#ftype as ::der::FixedTag>::TAG;
            }

            #limpl ::der::DecodeValue<#param> for #ltype {
                fn decode_value(
                    decoder: &mut ::der::Decoder<#param>,
                    header: ::der::Header,
                ) -> ::der::Result<Self> {
                    Ok(Self(<#ftype as ::der::DecodeValue>::decode_value(decoder, header)?))
                }
            }

            #limpl ::der::EncodeValue for #ltype {
                fn encode_value(&self, encoder: &mut dyn ::der::Writer) -> ::der::Result<()> {
                    self.0.encode_value(encoder)
                }

                fn value_len(&self) -> ::der::Result<::der::Length> {
                    self.0.value_len()
                }
            }
        }
    }
}
