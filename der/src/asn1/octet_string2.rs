//! ASN.1 `OCTET STRING` support.

use crate::{
    Decode, DecodeValue, EncodeValue, Error, ErrorKind, FixedTag, Header, Length, Reader, Tag,
    Writer, bytes_ref2::BytesRef, ord::OrdIsValueOrd,
};

#[cfg(feature = "alloc")]
use {
    super::OctetString,
    alloc::borrow::{Borrow, ToOwned},
};

/// ASN.1 `OCTET STRING` type: borrowed form.
///
/// Octet strings represent contiguous sequences of octets, a.k.a. bytes.
///
/// This is a zero-copy reference type which borrows from the input data.
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct OctetStringRef(BytesRef);

impl OctetStringRef {
    /// Create a new ASN.1 `OCTET STRING` from a byte slice.
    pub fn new(slice: &[u8]) -> Result<&Self, Error> {
        let bytes = BytesRef::new(slice).map_err(|_| ErrorKind::Length { tag: Self::TAG })?;
        Ok(Self::from_bytes_ref(bytes))
    }

    /// Reference constructor which keeps `BytesRef` out of the public API.
    fn from_bytes_ref(bytes: &BytesRef) -> &Self {
        // SAFETY: `Self` is a `repr(transparent)` newtype for `BytesRef`
        #[allow(unsafe_code)]
        unsafe {
            &*(bytes as *const BytesRef as *const Self)
        }
    }

    /// Borrow the inner byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Get the length of the inner byte slice.
    pub fn len(&self) -> Length {
        self.0.len()
    }

    /// Is the inner byte slice empty?
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Parse `T` from this `OCTET STRING`'s contents.
    pub fn decode_into<'a, T: Decode<'a>>(&'a self) -> Result<T, T::Error> {
        Decode::from_der(self.as_bytes())
    }
}

impl<'a> DecodeValue<'a> for &'a OctetStringRef {
    type Error = Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self, Error> {
        <&BytesRef>::decode_value(reader, header).map(OctetStringRef::from_bytes_ref)
    }
}

impl EncodeValue for OctetStringRef {
    fn value_len(&self) -> Result<Length, Error> {
        self.0.value_len()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<(), Error> {
        self.0.encode_value(writer)
    }
}

impl FixedTag for OctetStringRef {
    const TAG: Tag = Tag::OctetString;
}

impl OrdIsValueOrd for OctetStringRef {}

impl<'a> From<&'a OctetStringRef> for &'a [u8] {
    fn from(octet_string: &'a OctetStringRef) -> &'a [u8] {
        octet_string.as_bytes()
    }
}

impl<'a> TryFrom<&'a [u8]> for &'a OctetStringRef {
    type Error = Error;

    fn try_from(byte_slice: &'a [u8]) -> Result<Self, Error> {
        OctetStringRef::new(byte_slice)
    }
}

#[cfg(feature = "alloc")]
impl Borrow<OctetStringRef> for OctetString {
    fn borrow(&self) -> &OctetStringRef {
        // TODO(tarcieri): avoid panic
        OctetStringRef::new(self.as_bytes()).expect("should not be overlength")
    }
}

#[cfg(feature = "alloc")]
impl From<&OctetStringRef> for OctetString {
    fn from(string_ref: &OctetStringRef) -> Self {
        // TODO(tarcieri): avoid panic
        OctetString::new(string_ref.as_bytes()).expect("should not be overlength")
    }
}

#[cfg(feature = "alloc")]
impl ToOwned for OctetStringRef {
    type Owned = OctetString;

    fn to_owned(&self) -> Self::Owned {
        self.into()
    }
}
