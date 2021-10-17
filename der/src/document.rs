//! ASN.1 DER-encoded documents stored on the heap.

use crate::{Decodable, Encodable, Error, Result};
use alloc::{boxed::Box, vec::Vec};
use core::convert::{TryFrom, TryInto};

#[cfg(feature = "pem")]
use {crate::pem, alloc::string::String};

#[cfg(feature = "std")]
use std::{fs, path::Path};

/// ASN.1 DER-encoded document.
///
/// This trait is intended to impl on types which contain an ASN.1 DER-encoded
/// document which is guaranteed to encode as the associated `Message` type.
///
/// It implements common functionality related to encoding/decoding such
/// documents, such as PEM encapsulation as well as reading/writing documents
/// from/to the filesystem.
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub trait Document<'a>: AsRef<[u8]> + Sized + TryFrom<Vec<u8>, Error = Error> {
    /// ASN.1 message type this document decodes to.
    type Message: Decodable<'a> + Encodable + Sized;

    /// Borrow the inner serialized bytes of this document.
    fn as_der(&self) -> &[u8] {
        self.as_ref()
    }

    /// Return an allocated ASN.1 DER serialization as a boxed slice.
    fn to_der(&self) -> Box<[u8]> {
        self.as_ref().to_vec().into_boxed_slice()
    }

    /// Decode this document as ASN.1 DER.
    fn decode(&'a self) -> Self::Message {
        Self::Message::from_der(self.as_ref()).expect("ASN.1 DER document malformed")
    }

    /// Create a new document from the provided ASN.1 DER bytes.
    fn from_der(bytes: &[u8]) -> Result<Self> {
        bytes.to_vec().try_into()
    }

    /// Encode the provided type as ASN.1 DER.
    fn from_msg(msg: &Self::Message) -> Result<Self> {
        msg.to_vec()?.try_into()
    }

    /// Decode ASN.1 DER document from PEM.
    #[cfg(feature = "pem")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    fn from_pem(s: &str) -> Result<Self>
    where
        Self: pem::PemLabel,
    {
        let (label, der_bytes) = pem::decode_vec(s.as_bytes())?;

        if label != Self::TYPE_LABEL {
            return Err(pem::Error::Label.into());
        }

        der_bytes.try_into()
    }

    /// Encode ASN.1 DER document as a PEM string.
    #[cfg(feature = "pem")]
    #[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
    fn to_pem(&self, line_ending: pem::LineEnding) -> Result<String>
    where
        Self: pem::PemLabel,
    {
        Ok(pem::encode_string(
            Self::TYPE_LABEL,
            line_ending,
            self.as_ref(),
        )?)
    }

    /// Read ASN.1 DER document from a file.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn read_der_file(path: impl AsRef<Path>) -> Result<Self> {
        fs::read(path)?.try_into()
    }

    /// Read PEM-encoded ASN.1 DER document from a file.
    #[cfg(all(feature = "pem", feature = "std"))]
    #[cfg_attr(docsrs, doc(cfg(all(feature = "pem", feature = "std"))))]
    fn read_pem_file(path: impl AsRef<Path>) -> Result<Self>
    where
        Self: pem::PemLabel,
    {
        Self::from_pem(&fs::read_to_string(path)?)
    }

    /// Write ASN.1 DER document to a file.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn write_der_file(&self, path: &Path) -> Result<()> {
        fs::write(path, self.as_ref())?;
        Ok(())
    }

    /// Write PEM-encoded ASN.1 DER document to a file.
    #[cfg(all(feature = "pem", feature = "std"))]
    #[cfg_attr(docsrs, doc(cfg(all(feature = "pem", feature = "std"))))]
    fn write_pem_file(&self, path: &Path, line_ending: pem::LineEnding) -> Result<()>
    where
        Self: pem::PemLabel,
    {
        fs::write(path, self.to_pem(line_ending)?.as_bytes())?;
        Ok(())
    }
}
