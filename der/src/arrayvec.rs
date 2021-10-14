//! Array-backed append-only vector type.
// TODO(tarcieri): use `core` impl of `ArrayVec`
// See: https://github.com/rust-lang/rfcs/pull/2990

use crate::{ErrorKind, Result};

/// Array-backed append-only vector type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ArrayVec<T, const N: usize> {
    /// Elements of the set.
    elements: [Option<T>; N],

    /// Last populated element.
    length: usize,
}

impl<T, const N: usize> ArrayVec<T, N> {
    /// Create a new [`ArrayVec`].
    pub fn new() -> Self {
        Self {
            elements: [(); N].map(|_| None),
            length: 0,
        }
    }

    /// Add an element to this [`ArrayVec`].
    ///
    /// Items MUST be added in lexicographical order according to the `Ord`
    /// impl on `T`.
    pub fn add(&mut self, element: T) -> Result<()> {
        match self.length.checked_add(1) {
            Some(n) if n < N => {
                self.elements[self.length] = Some(element);
                self.length = n;
                Ok(())
            }
            _ => Err(ErrorKind::Overlength.into()),
        }
    }

    /// Borrow the elements of this [`ArrayVec`].
    pub fn elements(&self) -> &[Option<T>; N] {
        &self.elements
    }

    /// Get an element from this [`ArrayVec`].
    pub fn get(&self, index: usize) -> Option<&T> {
        match self.elements.get(index) {
            Some(Some(ref item)) => Some(item),
            _ => None,
        }
    }

    /// Get the last item from this [`ArrayVec`].
    pub fn last(&self) -> Option<&T> {
        self.length.checked_sub(1).and_then(|n| self.get(n))
    }
}

impl<T, const N: usize> Default for ArrayVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}
