#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]

//! ## Usage
//!
//! ```
//! # #[cfg(feature = "std")]
//! # {
//! use tls_codec::{TlsVecU8, Serialize, Deserialize};
//! let mut b = &[1u8, 4, 77, 88, 1, 99] as &[u8];
//!
//! let a = u8::tls_deserialize(&mut b).expect("Unable to tls_deserialize");
//! assert_eq!(1, a);
//! println!("b: {:?}", b);
//! let v = TlsVecU8::<u8>::tls_deserialize(&mut b).expect("Unable to tls_deserialize");
//! assert_eq!(&[77, 88, 1, 99], v.as_slice());
//! # }
//! ```

#[cfg_attr(feature = "std", macro_use)]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::string::String;
use core::fmt::{self, Display};
#[cfg(feature = "std")]
use {
    alloc::vec::Vec,
    std::io::{Read, Write},
};

mod arrays;
mod primitives;
#[cfg(feature = "std")]
mod quic_vec;
mod tls_vec;

pub use tls_vec::{
    SecretTlsVecU16, SecretTlsVecU32, SecretTlsVecU8, TlsByteSliceU16, TlsByteSliceU32,
    TlsByteSliceU8, TlsByteVecU16, TlsByteVecU32, TlsByteVecU8, TlsSliceU16, TlsSliceU32,
    TlsSliceU8, TlsVecU16, TlsVecU32, TlsVecU8,
};

#[cfg(feature = "std")]
pub use quic_vec::{VLByteSlice, VLBytes};

#[cfg(feature = "derive")]
pub use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

/// Errors that are thrown by this crate.
#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    /// An error occurred during encoding.
    EncodingError(String),

    /// The length of a vector is invalid.
    InvalidVectorLength,

    /// Error writing everything out.
    InvalidWriteLength(String),

    /// Invalid input when trying to decode a primitive integer.
    InvalidInput,

    /// An error occurred during decoding.
    DecodingError(String),

    /// Reached the end of a byte stream.
    EndOfStream,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::UnexpectedEof => Self::EndOfStream,
            _ => Self::DecodingError(format!("io error: {:?}", e)),
        }
    }
}

/// The `Size` trait needs to be implemented by any struct that should be
/// efficiently serialized.
/// This allows to collect the length of a serialized structure before allocating
/// memory.
pub trait Size {
    fn tls_serialized_len(&self) -> usize;
}

/// The `Serialize` trait provides functions to serialize a struct or enum.
///
/// The trait provides two functions:
/// * `tls_serialize` that takes a buffer to write the serialization to
/// * `tls_serialize_detached` that returns a byte vector
pub trait Serialize: Size {
    /// Serialize `self` and write it to the `writer`.
    /// The function returns the number of bytes written to `writer`.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error>;

    /// Serialize `self` and return it as a byte vector.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn tls_serialize_detached(&self) -> Result<Vec<u8>, Error> {
        let mut buffer = Vec::with_capacity(self.tls_serialized_len());
        let written = self.tls_serialize(&mut buffer)?;
        debug_assert_eq!(
            written,
            buffer.len(),
            "Expected that {} bytes were written but the output holds {} bytes",
            written,
            buffer.len()
        );
        if written != buffer.len() {
            Err(Error::EncodingError(format!(
                "Expected that {} bytes were written but the output holds {} bytes",
                written,
                buffer.len()
            )))
        } else {
            Ok(buffer)
        }
    }
}

/// The `Deserialize` trait defines functions to deserialize a byte slice to a
/// struct or enum.
pub trait Deserialize: Size {
    /// This function deserializes the `bytes` from the provided a [`std::io::Read`]
    /// and returns the populated struct.
    ///
    /// In order to get the amount of bytes read, use [`Size::tls_serialized_len`].
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error>
    where
        Self: Sized;
}
