// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// A type that can be updated with bytes.
///
/// This type is similar to `std::io::Write` or `digest::Update`.
pub trait Update {
    /// The error that may occur during update.
    type Error;

    /// Update the instance with the provided bytes.
    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error>;

    /// Perform a chain update.
    fn chain(mut self, chunk: impl AsRef<[u8]>) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        self.update(chunk)?;
        Ok(self)
    }
}

impl<T: Update> Update for &mut T {
    type Error = T::Error;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        (*self).update(chunk)
    }
}

impl<T: Update> Update for [T] {
    type Error = T::Error;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        for x in self.iter_mut() {
            x.update(chunk.as_ref())?;
        }

        Ok(())
    }
}

#[cfg(feature = "alloc")]
impl<T: Update> Update for alloc::boxed::Box<[T]> {
    type Error = T::Error;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        (**self).update(chunk)
    }
}

#[cfg(feature = "alloc")]
impl<T: Update> Update for alloc::vec::Vec<T> {
    type Error = T::Error;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        (**self).update(chunk)
    }
}

#[cfg(feature = "alloc")]
impl Update for alloc::vec::Vec<u8> {
    type Error = core::convert::Infallible;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        self.extend(chunk.as_ref());
        Ok(())
    }
}
