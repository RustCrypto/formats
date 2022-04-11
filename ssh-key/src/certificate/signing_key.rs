//! Certificate signing key trait.

use crate::{public, Signature};
use signature::Signer;

#[cfg(doc)]
use super::Builder;

/// Certificate signing key trait for the certificate [`Builder`].
///
/// This trait is automatically impl'd for any types which impl the
/// [`Signer`] trait for the OpenSSH certificate [`Signature`] type and also
/// support a [`From`] conversion for [`public::KeyData`].
pub trait SigningKey: Signer<Signature> {
    /// Get the [`public::KeyData`] for this signing key.
    fn public_key(&self) -> public::KeyData;
}

impl<T> SigningKey for T
where
    T: Signer<Signature>,
    public::KeyData: for<'a> From<&'a T>,
{
    fn public_key(&self) -> public::KeyData {
        self.into()
    }
}
