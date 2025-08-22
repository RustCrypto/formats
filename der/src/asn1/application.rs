//! Application class field.

use crate::{
    Choice, Class, Decode, DecodeValue, DerOrd, Encode, EncodeValue, EncodeValueRef, Error, Header,
    Length, Reader, Tag, TagMode, TagNumber, Tagged, ValueOrd, Writer,
    asn1::{AnyRef, class_tagged::ClassTaggedExplicit},
    tag::{IsConstructed, class::CLASS_APPLICATION},
};
use core::cmp::Ordering;

#[cfg(doc)]
use crate::ErrorKind;

impl_custom_class!(Application, Application, "APPLICATION", "0b01000000");
impl_custom_class_ref!(ApplicationRef, Application, "APPLICATION", "0b01000000");

/// Application class, EXPLICIT
pub type ApplicationExplicit<const NUMBER: u32, T> =
    ClassTaggedExplicit<NUMBER, T, CLASS_APPLICATION>;
