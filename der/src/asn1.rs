//! Module containing all of the various ASN.1 built-in types supported by
//! this library.

#[macro_use]
mod internal_macros;

mod any;
mod bit_string;
mod boolean;
mod choice;
mod context_specific;
mod generalized_time;
mod ia5_string;
mod integer;
mod null;
mod octet_string;
#[cfg(feature = "oid")]
mod oid;
mod optional;
mod printable_string;
#[cfg(feature = "real")]
mod real;
mod sequence;
mod sequence_of;
mod set_of;
mod teletex_string;
mod utc_time;
mod utf8_string;
mod videotex_string;

#[cfg(feature = "oid")]
#[cfg_attr(docsrs, doc(cfg(feature = "oid")))]
pub use const_oid::ObjectIdentifier;

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub use self::{
    any::Any, bit_string::BitString, integer::bigint::Int, integer::bigint::Uint,
    octet_string::OctetString, set_of::SetOfVec,
};
pub use self::{
    any::AnyRef,
    bit_string::{BitStringIter, BitStringRef},
    choice::Choice,
    context_specific::{ContextSpecific, ContextSpecificRef},
    generalized_time::GeneralizedTime,
    ia5_string::Ia5StringRef,
    integer::bigint::IntRef,
    integer::bigint::UintRef,
    null::Null,
    octet_string::OctetStringRef,
    printable_string::PrintableStringRef,
    sequence::{Sequence, SequenceRef},
    sequence_of::{SequenceOf, SequenceOfIter},
    set_of::{SetOf, SetOfIter},
    teletex_string::TeletexStringRef,
    utc_time::UtcTime,
    utf8_string::Utf8StringRef,
    videotex_string::VideotexStringRef,
};
