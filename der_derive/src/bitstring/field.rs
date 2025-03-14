//! Sequence field IR and lowerings

use crate::{FieldAttrs, TypeAttrs};

use syn::{Field, Ident};

/// "IR" for a field of a derived `BitString`.
pub(super) struct BitStringField {
    /// Variant name.
    pub(super) ident: Ident,

    /// Field-level attributes.
    pub(super) attrs: FieldAttrs,
}

impl BitStringField {
    /// Create a new [`BitStringField`] from the input [`Field`].
    pub(super) fn new(field: &Field, type_attrs: &TypeAttrs) -> syn::Result<Self> {
        let ident = field.ident.as_ref().cloned().ok_or_else(|| {
            syn::Error::new_spanned(
                field,
                "no name on struct field i.e. tuple structs unsupported",
            )
        })?;

        let attrs = FieldAttrs::parse(&field.attrs, type_attrs)?;

        if attrs.asn1_type.is_some() && attrs.default.is_some() {
            return Err(syn::Error::new_spanned(
                ident,
                "ASN.1 `type` and `default` options cannot be combined",
            ));
        }

        if attrs.default.is_some() && attrs.optional {
            return Err(syn::Error::new_spanned(
                ident,
                "`optional` and `default` field qualifiers are mutually exclusive",
            ));
        }

        Ok(Self { ident, attrs })
    }
}
