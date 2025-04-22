//! A module for working with referenced data.

use crate::FixedTag;

/// A trait for borrowing data from an owned struct
///
/// This converts an object owning the data to one that will borrowing the content.
/// The newly created object lifetime will be tied to the object owning the data.
///
/// This is similar to [`alloc::borrow::Borrow`] or [`core::convert::AsRef`] but this returns
/// an owned structure that references directly the backing slices instead of borrowing
/// the whole structure.
pub trait OwnedToRef<'a> {
    /// The resulting type referencing back to Self
    type Borrowed: 'a;

    /// Creates a new object referencing back to the self for storage
    fn owned_to_ref(&'a self) -> Self::Borrowed;
}

/// A trait for cloning a referenced structure and getting owned objects
///
/// This is the pendant to [`OwnedToRef`].
///
/// This converts an object borrowing data to one that will copy the data over and
/// own the content.
pub trait RefToOwned<'a> {
    /// The resulting type after obtaining ownership.
    type Owned: OwnedToRef<'a, Borrowed = Self>
    where
        Self: 'a;

    /// Creates a new object taking ownership of the data
    fn ref_to_owned(&self) -> Self::Owned;
}

impl<'a, T> OwnedToRef<'a> for Option<T>
where
    T: OwnedToRef<'a>,
{
    type Borrowed = Option<T::Borrowed>;

    fn owned_to_ref(&'a self) -> Self::Borrowed {
        self.as_ref().map(|o| o.owned_to_ref())
    }
}

impl<'a, T> RefToOwned<'a> for Option<T>
where
    T: RefToOwned<'a> + 'a,
    T::Owned: OwnedToRef<'a>,
{
    type Owned = Option<T::Owned>;
    fn ref_to_owned(&self) -> Self::Owned {
        self.as_ref().map(|o| o.ref_to_owned())
    }
}

/// der crate version of `Cow`
pub enum DerCow<'a, B>
where
    B: RefToOwned<'a> + ?Sized,
{
    /// referenced, for example `OctetStringRef`
    Borrowed(&'a B),
    /// allocated, for example `OctetString`
    Owned(<B as RefToOwned<'a>>::Owned),
}

impl<'a, B> core::fmt::Debug for DerCow<'a, B>
where
    B: RefToOwned<'a> + ?Sized + core::fmt::Debug,
    <B as RefToOwned<'a>>::Owned: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Borrowed(arg0) => f.debug_tuple("Borrowed").field(arg0).finish(),
            Self::Owned(arg0) => f.debug_tuple("Owned").field(arg0).finish(),
        }
    }
}

impl<'a, B> Clone for DerCow<'a, B>
where
    B: RefToOwned<'a> + ?Sized,
    <B as RefToOwned<'a>>::Owned: Clone,
{
    fn clone(&self) -> Self {
        match self {
            Self::Borrowed(arg0) => Self::Borrowed(arg0),
            Self::Owned(arg0) => Self::Owned(arg0.clone()),
        }
    }
}

impl<'a, B> FixedTag for DerCow<'a, B>
where
    B: RefToOwned<'a> + ?Sized + FixedTag,
{
    const TAG: crate::Tag = B::TAG;
}

// impl<'a, B> PartialEq for DerCow<'a, B>
// where
//     B: RefToOwned<'a> + Sized + PartialEq,
//     <B as RefToOwned<'a>>::Owned: PartialEq + OwnedToRef<'a>,
// {
//     fn eq(&self, other: &Self) -> bool {
//         match (self, other) {
//             (Self::Borrowed(l0), Self::Borrowed(r0)) => l0 == r0,
//             (Self::Owned(l0), Self::Owned(r0)) => l0 == r0,
//             (Self::Owned(l0), Self::Borrowed(r0)) => {
//                 let l1 = l0.owned_to_ref();
//                 *r0 == &l1
//             }
//             _ => false,
//         }
//     }
// }

// impl<'a, B> Deref for DerCow<'a, B>
// where
//     B: RefToOwned<'a> + ?Sized,
//     <B as RefToOwned<'a>>::Owned: OwnedToRef,
// {
//     type Target = B;

//     fn deref(&self) -> &B {
//         match *self {
//             Self::Borrowed(borrowed) => borrowed,
//             Self::Owned(owned) => owned.owned_to_ref(),
//         }
//     }
// }

#[cfg(feature = "alloc")]
mod allocating {
    use super::{OwnedToRef, RefToOwned};
    use alloc::boxed::Box;

    impl<'a> RefToOwned<'a> for &'a [u8] {
        type Owned = Box<[u8]>;

        fn ref_to_owned(&self) -> Self::Owned {
            Box::from(*self)
        }
    }

    impl<'a> OwnedToRef<'a> for Box<[u8]> {
        type Borrowed = &'a [u8];

        fn owned_to_ref(&'a self) -> Self::Borrowed {
            self.as_ref()
        }
    }
}
