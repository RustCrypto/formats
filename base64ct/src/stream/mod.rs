// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Streamed encoding/decoding types
//!
//! NOTE WELL: These types are not suitable for managing secrets. For more
//! details, see the documentation for each type.

mod dec;
mod either;
mod enc;
mod update;

pub use dec::Decoder;
pub use either::Either;
pub use enc::Encoder;
pub use update::Update;

/// A streaming error.
#[derive(Debug)]
pub enum Error<T> {
    /// An embedded error.
    Inner(T),

    /// The length is invalid.
    Length,

    /// An invalid value was found.
    Value,
}

impl<T> From<T> for Error<T> {
    fn from(error: T) -> Self {
        Self::Inner(error)
    }
}

impl Error<core::convert::Infallible> {
    /// Casts an infallible error to any other kind of error.
    pub fn cast<T>(&self) -> Error<T> {
        match self {
            Self::Inner(..) => unreachable!(),
            Self::Length => Error::Length,
            Self::Value => Error::Value,
        }
    }
}
