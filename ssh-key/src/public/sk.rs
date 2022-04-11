//! Security Key (FIDO/U2F) public keys as described in [PROTOCOL.u2f].
//!
//! [PROTOCOL.u2f]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.u2f?annotate=HEAD

use super::Ed25519PublicKey;
use crate::{
    checked::CheckedSum, decode::Decode, encode::Encode, reader::Reader, writer::Writer, Result,
};

#[cfg(feature = "alloc")]
use alloc::{borrow::ToOwned, string::String};

#[cfg(feature = "ecdsa")]
use {
    super::ecdsa::EcdsaNistP256PublicKey,
    crate::{EcdsaCurve, Error},
};

/// Default FIDO/U2F Security Key application string.
const DEFAULT_APPLICATION_STRING: &str = "ssh:";

/// Security Key (FIDO/U2F) ECDSA/NIST P-256 public key as specified in
/// [PROTOCOL.u2f](https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.u2f?annotate=HEAD).
#[cfg(feature = "ecdsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct SkEcdsaSha2NistP256 {
    /// Elliptic curve point representing a public key.
    ec_point: EcdsaNistP256PublicKey,

    /// FIDO/U2F application (typically `ssh:`)
    #[cfg(feature = "alloc")]
    application: String,
}

#[cfg(feature = "ecdsa")]
impl SkEcdsaSha2NistP256 {
    /// Get the elliptic curve point for this Security Key.
    pub fn ec_point(&self) -> &EcdsaNistP256PublicKey {
        &self.ec_point
    }

    /// Get the FIDO/U2F application (typically `ssh:`).
    #[cfg(not(feature = "alloc"))]
    pub fn application(&self) -> &str {
        DEFAULT_APPLICATION_STRING
    }

    /// Get the FIDO/U2F application (typically `ssh:`).
    #[cfg(feature = "alloc")]
    pub fn application(&self) -> &str {
        &self.application
    }
}

#[cfg(feature = "ecdsa")]
impl Decode for SkEcdsaSha2NistP256 {
    fn decode(reader: &mut impl Reader) -> Result<Self> {
        if EcdsaCurve::decode(reader)? != EcdsaCurve::NistP256 {
            return Err(Error::Crypto);
        }

        let mut buf = [0u8; 65];
        let ec_point = EcdsaNistP256PublicKey::from_bytes(reader.read_byten(&mut buf)?)?;

        // application string (e.g. `ssh:`)
        #[cfg(not(feature = "alloc"))]
        reader.drain_prefixed()?;

        Ok(Self {
            ec_point,

            #[cfg(feature = "alloc")]
            application: String::decode(reader)?,
        })
    }
}

#[cfg(feature = "ecdsa")]
impl Encode for SkEcdsaSha2NistP256 {
    fn encoded_len(&self) -> Result<usize> {
        [
            EcdsaCurve::NistP256.encoded_len()?,
            self.ec_point.as_bytes().encoded_len()?,
            self.application().encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        EcdsaCurve::NistP256.encode(writer)?;
        self.ec_point.as_bytes().encode(writer)?;
        self.application().encode(writer)
    }
}

#[cfg(feature = "ecdsa")]
impl From<EcdsaNistP256PublicKey> for SkEcdsaSha2NistP256 {
    fn from(ec_point: EcdsaNistP256PublicKey) -> SkEcdsaSha2NistP256 {
        SkEcdsaSha2NistP256 {
            ec_point,
            #[cfg(feature = "alloc")]
            application: DEFAULT_APPLICATION_STRING.to_owned(),
        }
    }
}

#[cfg(feature = "ecdsa")]
impl From<SkEcdsaSha2NistP256> for EcdsaNistP256PublicKey {
    fn from(sk: SkEcdsaSha2NistP256) -> EcdsaNistP256PublicKey {
        sk.ec_point
    }
}

/// Security Key (FIDO/U2F) Ed25519 public key as specified in
/// [PROTOCOL.u2f](https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.u2f?annotate=HEAD).
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct SkEd25519 {
    /// Ed25519 public key.
    public_key: Ed25519PublicKey,

    /// FIDO/U2F application (typically `ssh:`)
    #[cfg(feature = "alloc")]
    application: String,
}

impl SkEd25519 {
    /// Get the Ed25519 private key for this security key.
    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    /// Get the FIDO/U2F application (typically `ssh:`).
    #[cfg(not(feature = "alloc"))]
    pub fn application(&self) -> &str {
        DEFAULT_APPLICATION_STRING
    }

    /// Get the FIDO/U2F application (typically `ssh:`).
    #[cfg(feature = "alloc")]
    pub fn application(&self) -> &str {
        &self.application
    }
}

impl Decode for SkEd25519 {
    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let public_key = Ed25519PublicKey::decode(reader)?;

        // application string (e.g. `ssh:`)
        #[cfg(not(feature = "alloc"))]
        reader.drain_prefixed()?;

        Ok(Self {
            public_key,

            #[cfg(feature = "alloc")]
            application: String::decode(reader)?,
        })
    }
}

impl Encode for SkEd25519 {
    fn encoded_len(&self) -> Result<usize> {
        [
            self.public_key.encoded_len()?,
            self.application().encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        self.public_key.encode(writer)?;
        self.application().encode(writer)
    }
}

impl From<Ed25519PublicKey> for SkEd25519 {
    fn from(public_key: Ed25519PublicKey) -> SkEd25519 {
        SkEd25519 {
            public_key,
            #[cfg(feature = "alloc")]
            application: DEFAULT_APPLICATION_STRING.to_owned(),
        }
    }
}

impl From<SkEd25519> for Ed25519PublicKey {
    fn from(sk: SkEd25519) -> Ed25519PublicKey {
        sk.public_key
    }
}
