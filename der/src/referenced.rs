//! A module for working with referenced data.

/// A trait for borrowing data from an owned struct
///
/// This converts an object owning the data to one that will borrowing the content.
/// The newly created object lifetime will be tied to the object owning the data.
///
/// This is similar to [`alloc::borrow::Borrow`] or [`core::convert::AsRef`] but this returns
/// an owned structure that references directly the backing slices instead of borrowing
/// the whole structure.
pub trait OwnedToRef {
    /// The resulting type referencing back to Self
    type Borrowed<'a>
    where
        Self: 'a;

    /// Creates a new object referencing back to the self for storage
    fn owned_to_ref(&self) -> Self::Borrowed<'_>;
}

/// A trait for cloning a referenced structure and getting owned objects
///
/// This is the pendant to [`OwnedToRef`].
///
/// This converts an object borrowing data to one that will copy the data over and
/// own the content.
pub trait RefToOwned<'a> {
    /// The resulting type after obtaining ownership.
    type Owned: OwnedToRef<Borrowed<'a> = Self>
    where
        Self: 'a;

    /// Creates a new object taking ownership of the data
    fn ref_to_owned(&self) -> Self::Owned;
}

impl<T> OwnedToRef for Option<T>
where
    T: OwnedToRef,
{
    type Borrowed<'a>
        = Option<T::Borrowed<'a>>
    where
        T: 'a;

    fn owned_to_ref(&self) -> Self::Borrowed<'_> {
        self.as_ref().map(|o| o.owned_to_ref())
    }
}

impl<'a, T> RefToOwned<'a> for Option<T>
where
    T: RefToOwned<'a> + 'a,
    T::Owned: OwnedToRef,
{
    type Owned = Option<T::Owned>;
    fn ref_to_owned(&self) -> Self::Owned {
        self.as_ref().map(|o| o.ref_to_owned())
    }
}

#[cfg(feature = "alloc")]
mod allocating {
    use std::borrow::Cow;

    use crate::{
        DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Tag, Tagged, Writer,
    };

    use super::{OwnedToRef, RefToOwned};
    use alloc::boxed::Box;

    impl<'a> RefToOwned<'a> for &'a [u8] {
        type Owned = Box<[u8]>;

        fn ref_to_owned(&self) -> Self::Owned {
            Box::from(*self)
        }
    }

    impl OwnedToRef for Box<[u8]> {
        type Borrowed<'a> = &'a [u8];

        fn owned_to_ref(&self) -> Self::Borrowed<'_> {
            self.as_ref()
        }
    }

    impl<'a, T> FixedTag for Cow<'a, T>
    where
        T: Clone,
        &'a T: FixedTag,
    {
        const TAG: Tag = <&'a T as FixedTag>::TAG;
    }

    // impl<'a, T> Tagged for Cow<'a, T>
    // where
    //     T: Clone,
    //     &'a T: Tagged,
    // {
    //     fn tag(&self) -> Tag {
    //         match self {
    //             Cow::Borrowed(object) => object.tag(),
    //             Cow::Owned(object) => object.tag(),
    //         }
    //     }
    // }

    // impl<'a, T> Decode<'a> for Cow<'a, T>
    // where
    //     T: Clone,
    //     &'a T: Decode<'a>,
    // {
    //     type Error = <&'a T as Decode<'a>>::Error;

    //     fn decode<R: Reader<'a>>(reader: &mut R) -> Result<Self, Self::Error> {
    //         let object = <&'a T as Decode<'a>>::decode(reader)?;
    //         Ok(Self::Borrowed(object))
    //     }
    // }

    impl<'a, T> DecodeValue<'a> for Cow<'a, T>
    where
        T: Clone,
        &'a T: DecodeValue<'a>,
    {
        type Error = <&'a T as DecodeValue<'a>>::Error;

        fn decode_value<R: Reader<'a>>(
            reader: &mut R,
            header: Header,
        ) -> Result<Self, Self::Error> {
            let value = <&'a T as DecodeValue<'a>>::decode_value(reader, header)?;
            Ok(Self::Borrowed(value))
        }
    }

    impl<'a, T> Encode for &'a Cow<'a, T>
    where
        T: Clone,
        &'a T: Encode,
    {
        fn encoded_len(&self) -> crate::Result<Length> {
            match self {
                Cow::Borrowed(object) => object.encoded_len(),
                Cow::Owned(object) => object.encoded_len(),
            }
        }

        fn encode(&self, encoder: &mut impl Writer) -> crate::Result<()> {
            match self {
                Cow::Borrowed(object) => object.encode(encoder),
                Cow::Owned(object) => object.encode(encoder),
            }
        }
    }

    impl<'a, T> EncodeValue for &'a Cow<'a, T>
    where
        T: Clone,
        &'a T: EncodeValue,
    {
        fn value_len(&self) -> crate::Result<Length> {
            match self {
                Cow::Borrowed(value) => value.value_len(),
                Cow::Owned(value) => value.value_len(),
            }
        }

        fn encode_value(&self, encoder: &mut impl Writer) -> crate::Result<()> {
            match self {
                Cow::Borrowed(value) => value.encode_value(encoder),
                Cow::Owned(value) => value.encode_value(encoder),
            }
        }
    }
}
