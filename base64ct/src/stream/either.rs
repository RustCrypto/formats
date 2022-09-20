// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::Update;

/// A runtime choice between updaters.
pub enum Either<A, B> {
    #[allow(missing_docs)]
    A(A),

    #[allow(missing_docs)]
    B(B),
}

impl<A: Update, B: Update> Update for Either<A, B>
where
    A::Error: From<B::Error>,
{
    type Error = A::Error;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        match self {
            Self::A(x) => x.update(chunk)?,
            Self::B(x) => x.update(chunk)?,
        }

        Ok(())
    }
}
