#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_root_url = "https://docs.rs/const-oid/0.8.0"
)]
#![forbid(unsafe_code, clippy::unwrap_used)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

mod arcs;
mod encoder;
mod error;
mod parser;

#[cfg(feature = "db")]
#[cfg_attr(docsrs, doc(cfg(feature = "db")))]
pub mod db;

pub use crate::{
    arcs::{Arc, Arcs},
    error::{Error, Result},
};

use crate::encoder::Encoder;
use core::{fmt, str::FromStr};

/// A trait which associates an OID with a type.
pub trait AssociatedOid {
    /// The OID associated with this type.
    const OID: ObjectIdentifier;
}

/// Object identifier (OID).
///
/// OIDs are hierarchical structures consisting of "arcs", i.e. integer
/// identifiers.
///
/// # Validity
///
/// In order for an OID to be considered valid by this library, it must meet
/// the following criteria:
///
/// - The OID MUST have at least 3 arcs
/// - The first arc MUST be within the range 0-2
/// - The second arc MUST be within the range 0-39
/// - The BER/DER encoding of the OID MUST be shorter than
///   [`ObjectIdentifier::MAX_SIZE`]
#[derive(Copy, Clone, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct ObjectIdentifier {
    /// Length in bytes
    length: u8,

    /// Array containing BER/DER-serialized bytes (no header)
    bytes: [u8; Self::MAX_SIZE],
}

#[allow(clippy::len_without_is_empty)]
impl ObjectIdentifier {
    /// Maximum size of a BER/DER-encoded OID in bytes.
    pub const MAX_SIZE: usize = 39; // makes `ObjectIdentifier` 40-bytes total w\ 1-byte length

    /// Parse an [`ObjectIdentifier`] from the dot-delimited string form,
    /// panicking on parse errors.
    ///
    /// This function exists as a workaround for `unwrap` not yet being
    /// stable in `const fn` contexts, and is intended to allow the result to
    /// be bound to a constant value:
    ///
    /// ```
    /// use const_oid::ObjectIdentifier;
    ///
    /// pub const MY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
    /// ```
    ///
    /// In future versions of Rust it should be possible to replace this with
    /// `ObjectIdentifier::new(...).unwrap()`.
    ///
    /// Use [`ObjectIdentifier::new`] for fallible parsing.
    // TODO(tarcieri): remove this when `Result::unwrap` is `const fn`
    pub const fn new_unwrap(s: &str) -> Self {
        match Self::new(s) {
            Ok(oid) => oid,
            Err(Error::ArcInvalid { .. } | Error::ArcTooBig) => panic!("OID contains invalid arc"),
            Err(Error::Base128) => panic!("OID contains arc with invalid base 128 encoding"),
            Err(Error::DigitExpected { .. }) => panic!("OID expected to start with digit"),
            Err(Error::Empty) => panic!("OID value is empty"),
            Err(Error::Length) => panic!("OID length invalid"),
            Err(Error::NotEnoughArcs) => panic!("OID requires minimum of 3 arcs"),
            Err(Error::TrailingDot) => panic!("OID ends with invalid trailing '.'"),
        }
    }

    /// Parse an [`ObjectIdentifier`] from the dot-delimited string form.
    pub const fn new(s: &str) -> Result<Self> {
        // TODO(tarcieri): use `?` when stable in `const fn`
        match parser::Parser::parse(s) {
            Ok(parser) => parser.finish(),
            Err(err) => Err(err),
        }
    }

    /// Parse an OID from a slice of [`Arc`] values (i.e. integers).
    pub fn from_arcs<'a>(arcs: impl IntoIterator<Item = &'a Arc>) -> Result<Self> {
        let mut encoder = Encoder::new();

        for &arc in arcs {
            encoder = encoder.arc(arc)?;
        }

        encoder.finish()
    }

    /// Parse an OID from from its BER/DER encoding.
    pub fn from_bytes(ber_bytes: &[u8]) -> Result<Self> {
        let len = ber_bytes.len();

        if !(2..=Self::MAX_SIZE).contains(&len) {
            return Err(Error::Length);
        }

        let mut bytes = [0u8; Self::MAX_SIZE];
        bytes[..len].copy_from_slice(ber_bytes);

        let oid = Self {
            bytes,
            length: len as u8,
        };

        // Ensure arcs are well-formed
        let mut arcs = oid.arcs();
        while arcs.try_next()?.is_some() {}

        Ok(oid)
    }

    /// Get the BER/DER serialization of this OID as bytes.
    ///
    /// Note that this encoding omits the tag/length, and only contains the
    /// value portion of the encoded OID.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length as usize]
    }

    /// Return the arc with the given index, if it exists.
    pub fn arc(&self, index: usize) -> Option<Arc> {
        self.arcs().nth(index)
    }

    /// Iterate over the arcs (a.k.a. nodes) of an [`ObjectIdentifier`].
    ///
    /// Returns [`Arcs`], an iterator over [`Arc`] values.
    pub fn arcs(&self) -> Arcs<'_> {
        Arcs::new(self)
    }
}

impl AsRef<[u8]> for ObjectIdentifier {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl FromStr for ObjectIdentifier {
    type Err = Error;

    fn from_str(string: &str) -> Result<Self> {
        Self::new(string)
    }
}

impl TryFrom<&[u8]> for ObjectIdentifier {
    type Error = Error;

    fn try_from(ber_bytes: &[u8]) -> Result<Self> {
        Self::from_bytes(ber_bytes)
    }
}

impl From<&ObjectIdentifier> for ObjectIdentifier {
    fn from(oid: &ObjectIdentifier) -> ObjectIdentifier {
        *oid
    }
}

impl fmt::Debug for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectIdentifier({})", self)
    }
}

impl fmt::Display for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.arcs().count();

        for (i, arc) in self.arcs().enumerate() {
            write!(f, "{}", arc)?;

            if i < len - 1 {
                write!(f, ".")?;
            }
        }

        Ok(())
    }
}
