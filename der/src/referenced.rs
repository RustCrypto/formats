//! A module for working with referenced data.

/// A trait for borrowing data from an owned struct
#[rustversion::since(1.65)] // Generic associated types support is required
pub trait OwnedToRef {
    /// The resulting type referencing back to Self
    type Borrowed<'a>
    where
        Self: 'a;

    /// Creates a new object referencing back to the self for storage
    fn to_ref(&self) -> Self::Borrowed<'_>;
}

/// A trait for cloning a referenced structure and getting owned objects
///
/// This is the pendant to [`OwnedToRef`]
#[rustversion::since(1.65)] // Generic associated types support is required
pub trait RefToOwned<'a> {
    /// The resulting type after obtaining ownership.
    type Owned: OwnedToRef<Borrowed<'a> = Self>
    where
        Self: 'a;

    /// Creates a new object taking ownership of the data
    fn to_owned(&self) -> Self::Owned;
}

#[rustversion::since(1.65)] // Generic associated types support is required
impl<T> OwnedToRef for Option<T>
where
    T: OwnedToRef,
{
    // TODO: when upgrading to rust 1.65, we can use the new syntax
    //       MSRV 1.60 requires us to use the old syntax
    #[allow(unknown_lints)]
    #[allow(deprecated_where_clause_location)]
    type Borrowed<'a>
    where
        T: 'a,
    = Option<T::Borrowed<'a>>;

    fn to_ref(&self) -> Self::Borrowed<'_> {
        self.as_ref().map(|o| o.to_ref())
    }
}

#[rustversion::since(1.65)] // Generic associated types support is required
impl<'a, T> RefToOwned<'a> for Option<T>
where
    T: RefToOwned<'a> + 'a,
    T::Owned: OwnedToRef,
{
    type Owned = Option<T::Owned>;
    fn to_owned(&self) -> Self::Owned {
        self.as_ref().map(|o| o.to_owned())
    }
}
