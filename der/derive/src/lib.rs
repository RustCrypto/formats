//! Custom derive support for the [`der`] crate.
//!
//! This crate contains custom derive macros intended to be used in the
//! following way:
//!
//! - [`Choice`][`derive@Choice`]: map ASN.1 `CHOICE` to a Rust enum.
//! - [`Sequence`][`derive@Sequence`]: map ASN.1 `SEQUENCE` to a Rust struct.
//!
//! Note that this crate shouldn't be used directly, but instead accessed
//! by using the `derive` feature of the `der` crate.
//!
//! # Why not `serde`?
//!
//! The `der` crate is designed to be easily usable in embedded environments,
//! including ones where code size comes at a premium.
//!
//! This crate (i.e. `der_derive`) is able to generate code which is
//! significantly smaller than `serde_derive`. This is because the `der`
//! crate has been designed with high-level abstractions which reduce
//! code size, including trait object-based encoders which allow encoding
//! logic which is duplicated in `serde` serializers to be implemented in
//! a single place in the `der` crate.
//!
//! This is a deliberate tradeoff in terms of performance, flexibility, and
//! code size. At least for now, the `der` crate is optimizing for leveraging
//! as many abstractions as it can to minimize code size.
//!
//! # Toplevel attributes
//!
//! The following attributes can be added to an `enum` or `struct` when
//! deriving either [`Choice`] or [`Sequence`] respectively:
//!
//! ## `#[asn1(tag_mode = "...")` attribute: `EXPLICIT` vs `IMPLICIT`
//!
//! This attribute can be used to declare the tagging mode used by a particular
//! ASN.1 module.
//!
//! It's used when parsing `CONTEXT-SENSITIVE` fields.
//!
//! The default is `EXPLICIT`, so the attribute only needs to be added when
//! a particular module is declared `IMPLICIT`.
//!
//! # Field-level attributes
//!
//! The following attributes can be added to either the fields of a particular
//! `struct` or the variants of a particular `enum`:
//!
//! ## `#[asn1(context_specific = "...")]` attribute: `CONTEXT-SPECIFIC` support
//!
//! This attribute can be added to associate a particular `CONTEXT-SPECIFIC`
//! tag number with a given enum variant or struct field.
//!
//! The value must be quoted and contain a number, e.g. `#[asn1(context_specific = "42"]`.
//!
//! ## `#[asn1(type = "...")]` attribute: ASN.1 type declaration
//!
//! This attribute can be used to specify the ASN.1 type for a particular
//! `enum` variant or `struct` field.
//!
//! It's presently mandatory for all `enum` variants, even when using one of
//! the ASN.1 types defined by this crate.
//!
//! For structs, placing this attribute on a field makes it possible to
//! decode/encode types which don't directly implement the `Decode`/`Encode`
//! traits but do impl `From` and `TryInto` and `From` for one of the ASN.1 types
//! listed below (use the ASN.1 type keywords as the `type`):
//!
//! - `BIT STRING`: performs an intermediate conversion to [`der::asn1::BitString`]
//! - `IA5String`: performs an intermediate conversion to [`der::asn1::IA5String`]
//! - `GeneralizedTime`: performs an intermediate conversion to [`der::asn1::GeneralizedTime`]
//! - `OCTET STRING`: performs an intermediate conversion to [`der::asn1::OctetString`]
//! - `PrintableString`: performs an intermediate conversion to [`der::asn1::PrintableString`]
//! - `UTCTime`: performs an intermediate conversion to [`der::asn1::UtcTime`]
//! - `UTF8String`: performs an intermediate conversion to [`der::asn1::Utf8String`]
//!
//! Note: please open a GitHub Issue if you would like to request support
//! for additional ASN.1 types.
//!
//! [`der`]: https://docs.rs/der/
//! [`Choice`]: derive@Choice
//! [`Sequence`]: derive@Sequence
//! [`der::asn1::BitString`]: https://docs.rs/der/latest/der/asn1/struct.BitString.html
//! [`der::asn1::Ia5String`]: https://docs.rs/der/latest/der/asn1/struct.Ia5String.html
//! [`der::asn1::GeneralizedTime`]: https://docs.rs/der/latest/der/asn1/struct.GeneralizedTime.html
//! [`der::asn1::OctetString`]: https://docs.rs/der/latest/der/asn1/struct.OctetString.html
//! [`der::asn1::PrintableString`]: https://docs.rs/der/latest/der/asn1/struct.PrintableString.html
//! [`der::asn1::UtcTime`]: https://docs.rs/der/latest/der/asn1/struct.UtcTime.html
//! [`der::asn1::Utf8String`]: https://docs.rs/der/latest/der/asn1/struct.Utf8String.html

#![crate_type = "proc-macro"]
#![warn(rust_2018_idioms, trivial_casts, unused_qualifications)]

mod attributes;
mod choice;
mod enumerated;
mod sequence;
mod tag;
mod tbs;
mod types;

use crate::{
    attributes::{FieldAttrs, TypeAttrs, ATTR_NAME},
    choice::DeriveChoice,
    enumerated::DeriveEnumerated,
    sequence::DeriveSequence,
    tag::{TagMode, TagNumber},
    tbs::DeriveTBS,
    types::Asn1Type,
};
use proc_macro2::TokenStream;
use syn::{Generics, Lifetime};
use synstructure::{decl_derive, Structure};

decl_derive!(
    [Choice, attributes(asn1)] =>

    /// Derive the [`Choice`][1] trait on an enum.
    ///
    /// This custom derive macro can be used to automatically impl the
    /// [`Decodable`][2] and [`Encodable`][3] traits along with the
    /// [`Choice`][1] supertrait for any enum representing an ASN.1 `CHOICE`.
    ///
    /// The enum must consist entirely of 1-tuple variants wrapping inner
    /// types which must also impl the [`Decodable`][2] and [`Encodable`][3]
    /// traits. It will will also generate [`From`] impls for each of the
    /// inner types of the variants into the enum that wraps them.
    ///
    /// # Usage
    ///
    /// ```ignore
    /// // NOTE: requires the `derive` feature of `der`
    /// use der::Choice;
    ///
    /// /// `Time` as defined in RFC 5280
    /// #[derive(Choice)]
    /// pub enum Time {
    ///     #[asn1(type = "UTCTime")]
    ///     UtcTime(UtcTime),
    ///
    ///     #[asn1(type = "GeneralizedTime")]
    ///     GeneralTime(GeneralizedTime),
    /// }
    /// ```
    ///
    /// # `#[asn1(type = "...")]` attribute
    ///
    /// See [toplevel documentation for the `der_derive` crate][4] for more
    /// information about the `#[asn1]` attribute.
    ///
    /// [1]: https://docs.rs/der/latest/der/trait.Choice.html
    /// [2]: https://docs.rs/der/latest/der/trait.Decodable.html
    /// [3]: https://docs.rs/der/latest/der/trait.Encodable.html
    /// [4]: https://docs.rs/der_derive/
    derive_choice
);

decl_derive!(
    [Enumerated, attributes(asn1)] =>

    /// Derive decoders and encoders for ASN.1 [`Enumerated`] types.
    ///
    /// # Usage
    ///
    /// The `Enumerated` proc macro requires a C-like enum which impls `Copy`
    /// and has a `#[repr]` of `u8`, `u16`, or `u32`:
    ///
    /// ```ignore
    /// use der::Enumerated;
    ///
    /// #[derive(Enumerated, Copy, Clone, Debug, Eq, PartialEq)]
    /// #[repr(u32)]
    /// pub enum CrlReason {
    ///     Unspecified = 0,
    ///     KeyCompromise = 1,
    ///     CaCompromise = 2,
    ///     AffiliationChanged = 3,
    ///     Superseded = 4,
    ///     CessationOfOperation = 5,
    ///     CertificateHold = 6,
    ///     RemoveFromCrl = 8,
    ///     PrivilegeWithdrawn = 9,
    ///     AaCompromised = 10
    /// }
    /// ```
    ///
    /// Note that the derive macro will write a `TryFrom<...>` impl for the
    /// provided `#[repr]`, which is used by the decoder.
    derive_enumerated
);

decl_derive!(
    [Sequence, attributes(asn1)] =>

    /// Derive the [`Sequence`][1] trait on a struct.
    ///
    /// This custom derive macro can be used to automatically impl the
    /// `Sequence` trait for any struct which can be decoded/encoded as an
    /// ASN.1 `SEQUENCE`.
    ///
    /// # Usage
    ///
    /// ```ignore
    /// use der::{
    ///     asn1::{Any, ObjectIdentifier},
    ///     Sequence
    /// };
    ///
    /// /// X.509 `AlgorithmIdentifier`
    /// #[derive(Sequence)]
    /// pub struct AlgorithmIdentifier<'a> {
    ///     /// This field contains an ASN.1 `OBJECT IDENTIFIER`, a.k.a. OID.
    ///     pub algorithm: ObjectIdentifier,
    ///
    ///     /// This field is `OPTIONAL` and contains the ASN.1 `ANY` type, which
    ///     /// in this example allows arbitrary algorithm-defined parameters.
    ///     pub parameters: Option<Any<'a>>
    /// }
    /// ```
    ///
    /// # `#[asn1(type = "...")]` attribute
    ///
    /// See [toplevel documentation for the `der_derive` crate][2] for more
    /// information about the `#[asn1]` attribute.
    ///
    /// [1]: https://docs.rs/der/latest/der/trait.Sequence.html
    /// [2]: https://docs.rs/der_derive/
    derive_sequence
);

decl_derive!(
    [TBS, attributes(asn1)] =>

    /// Support for deriving the `to be signed` trait on structs for the purposes of
    /// verifying ASN.1 `SEQUENCE` types that follow the to be signed/algorithm/signature pattern.
    /// In some ASN.1 modules, the `to be signed` pattern is denoted by the SIGNED{} macro. For example,
    /// RFC 5912 features the following definition for an X.509 Certificate structure:
    ///
    /// Certificate  ::=  SIGNED{TBSCertificate}
    ///
    /// It defines the SIGNED{} macro as follows:
    ///
    /// SIGNED{ToBeSigned} ::= SEQUENCE {
    ///      toBeSigned           ToBeSigned,
    ///      algorithmIdentifier  SEQUENCE {
    ///          algorithm        SIGNATURE-ALGORITHM.
    ///                             &id({SignatureAlgorithms}),
    ///          parameters       SIGNATURE-ALGORITHM.
    ///                             &Params({SignatureAlgorithms}
    ///                               {@algorithmIdentifier.algorithm}) OPTIONAL
    ///      },
    ///      signature BIT STRING (CONTAINING SIGNATURE-ALGORITHM.&Value(
    ///                               {SignatureAlgorithms}
    ///                               {@algorithmIdentifier.algorithm}))
    ///   }
    ///
    /// Where the TBS derive macro is used, the first field is not decoded and is instead served as
    /// bytes containing the entire encoded TLV production of that field. The second and third fields
    /// are decoded to feature an AlgorithmIdentifier and a BIT STRING, as indicated above.
    ///
    /// Sample usage of the TBS macro is below.
    ///
    /// #[derive(Clone, Debug, Eq, PartialEq, Sequence, TBS)]
    /// pub struct Certificate<'a> {
    ///     /// tbsCertificate       TBSCertificate,
    ///     pub tbs_certificate: TBSCertificate<'a>,
    ///     /// signatureAlgorithm   AlgorithmIdentifier,
    ///     pub signature_algorithm: AlgorithmIdentifier<'a>,
    ///     /// signature            BIT STRING
    ///     pub signature: BitString<'a>,
    /// }
    ///
    /// This definition will cause encoders and decoders to be generated for the Certificate structure
    /// (via the Sequence macro) enabling access to fully decoded contents along with a new structure
    /// named DeferCertificate and corresponding decoder.
    ///
    /// pub struct DeferCertificate<'a> {
    ///     pub tbs_certificate: &'a [u8],
    ///     pub signature_algorithm: AlgorithmIdentifier<'a>,
    ///     pub signature: BitString<'a>,
    /// }
    derive_tbs
);
/// Custom derive for `der::Choice`.
fn derive_choice(s: Structure<'_>) -> TokenStream {
    let ast = s.ast();
    let lifetime = parse_lifetime(&ast.generics);

    let data_label = match &ast.data {
        syn::Data::Enum(data) => return DeriveChoice::derive(s, data, lifetime),
        syn::Data::Struct(_) => "struct",
        syn::Data::Union(_) => "union",
    };

    panic!(
        "can't derive `Choice` on `{}`: only `enum` types are allowed",
        data_label
    )
}

/// Custom derive for `der::Enumerated`.
fn derive_enumerated(s: Structure<'_>) -> TokenStream {
    let ast = s.ast();

    if let Some(lifetime) = parse_lifetime(&ast.generics) {
        panic!("lifetimes not allowed on `Enumerated` types: {}", lifetime);
    }

    let data_label = match &ast.data {
        syn::Data::Enum(data) => return DeriveEnumerated::derive(s, data),
        syn::Data::Struct(_) => "struct",
        syn::Data::Union(_) => "union",
    };

    panic!(
        "can't derive `Enumerated` on `{}`: only `enum` types are allowed",
        data_label
    )
}

/// Custom derive for `der::Sequence`.
fn derive_sequence(s: Structure<'_>) -> TokenStream {
    let ast = s.ast();
    let lifetime = parse_lifetime(&ast.generics);

    let data_label = match &ast.data {
        syn::Data::Enum(_) => "enum",
        syn::Data::Struct(data) => return DeriveSequence::derive(s, data, lifetime),
        syn::Data::Union(_) => "union",
    };

    panic!(
        "can't derive `Sequence` on `{}`: only `struct` types are allowed",
        data_label
    )
}

/// Custom derive for `der::TBS`
fn derive_tbs(s: Structure<'_>) -> TokenStream {
    let ast = s.ast();
    let lifetime = parse_lifetime(&ast.generics);

    match &ast.data {
        syn::Data::Struct(data) => DeriveTBS::derive(s, data, lifetime),
        other => panic!("can't derive `TBS` on: {:?}", other),
    }
}

/// Parse the first lifetime of the "self" type of the custom derive
///
/// Returns `None` if there is no first lifetime.
fn parse_lifetime(generics: &Generics) -> Option<&Lifetime> {
    generics.lifetimes().next().map(|lt_ref| &lt_ref.lifetime)
}
