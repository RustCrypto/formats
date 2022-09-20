// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::marker::PhantomData;

use super::Update;
use crate::{Base64UrlUnpadded, Encoding};

/// A streaming encoder.
///
/// NOTE WELL: DO NOT use this type for encoding secrets. This encoder uses an
/// internal buffer which is not zeroed. This property makes it unsuitable for
/// encoding secrets.
pub struct Encoder<T, E = Base64UrlUnpadded> {
    decoded: [u8; 3],
    encoded: [u8; 4],
    config: PhantomData<E>,
    used: usize,
    next: T,
}

impl<T: Default, E> Default for Encoder<T, E> {
    fn default() -> Self {
        Self::from(T::default())
    }
}

impl<T, E> From<T> for Encoder<T, E> {
    fn from(next: T) -> Self {
        Self {
            decoded: Default::default(),
            encoded: Default::default(),
            config: Default::default(),
            used: Default::default(),
            next,
        }
    }
}

impl<T: Update, E: Encoding> Update for Encoder<T, E> {
    type Error = T::Error;

    // Integer arithmetic is fine here since we only have values `0..3`.
    #[allow(clippy::integer_arithmetic)]
    fn update(&mut self, buf: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        for byte in buf.as_ref() {
            self.decoded[self.used] = *byte;

            match self.used {
                2 => {
                    E::encode_3bytes(&self.decoded[..], &mut self.encoded[..]);
                    self.next.update(&self.encoded)?;
                    self.used = 0
                }

                _ => self.used += 1,
            }
        }

        Ok(())
    }
}

impl<T: Update, E: Encoding> Encoder<T, E> {
    /// Finish base64 encoding and return the inner type.
    pub fn finish(mut self) -> Result<T, T::Error> {
        let decoded = &self.decoded[..self.used];
        let encoded = E::encode(decoded, &mut self.encoded[..]).expect("unreachable");
        self.next.update(encoded.as_bytes())?;
        Ok(self.next)
    }
}
