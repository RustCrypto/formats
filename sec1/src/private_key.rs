//! SEC1 elliptic curve private key support.
//!
//! Support for ASN.1 DER-encoded elliptic curve private keys as described in
//! SEC1: Elliptic Curve Cryptography (Version 2.0) Appendix C.4 (p.108):
//!
//! <https://www.secg.org/sec1-v2.pdf>

#[cfg(feature = "alloc")]
pub(crate) mod document;

use crate::{EcParameters, Error};
use core::fmt;
use der::{
    asn1::{BitString, ContextSpecific, OctetString},
    Decodable, Decoder, Encodable, Sequence, Tag, TagMode, TagNumber,
};

/// `ECPrivateKey` version.
///
/// From [RFC5913 Section 3]:
/// > version specifies the syntax version number of the elliptic curve
/// > private key structure.  For this version of the document, it SHALL
/// > be set to ecPrivkeyVer1, which is of type INTEGER and whose value
/// > is one (1).
///
/// [RFC5915 Section 3]: https://datatracker.ietf.org/doc/html/rfc5915#section-3
const VERSION: u8 = 1;

/// Context-specific tag number for the elliptic curve parameters.
const EC_PARAMETERS_TAG: TagNumber = TagNumber::new(0);

/// Context-specific tag number for the public key.
const PUBLIC_KEY_TAG: TagNumber = TagNumber::new(1);

/// SEC1 elliptic curve private key.
///
/// Described in [SEC1: Elliptic Curve Cryptography (Version 2.0)]
/// Appendix C.4 (p.108) and also [RFC5915 Section 3]:
///
/// ```text
/// ECPrivateKey ::= SEQUENCE {
///   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
///   privateKey     OCTET STRING,
///   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
///   publicKey  [1] BIT STRING OPTIONAL
/// }
/// ```
///
/// When encoded as PEM (text), keys in this format begin with the following:
///
/// ```text
/// -----BEGIN EC PRIVATE KEY-----
/// ```
///
/// [SEC1: Elliptic Curve Cryptography (Version 2.0)]: https://www.secg.org/sec1-v2.pdf
/// [RFC5915 Section 3]: https://datatracker.ietf.org/doc/html/rfc5915#section-3
#[derive(Clone)]
pub struct EcPrivateKey<'a> {
    /// Private key data.
    pub private_key: &'a [u8],

    /// Elliptic curve parameters.
    pub parameters: Option<EcParameters>,

    /// Public key data, optionally available if version is V2.
    pub public_key: Option<&'a [u8]>,
}

impl<'a> Decodable<'a> for EcPrivateKey<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            if decoder.uint8()? != VERSION {
                return Err(der::Tag::Integer.value_error());
            }

            let private_key = decoder.octet_string()?.as_bytes();
            let parameters = decoder.context_specific(EC_PARAMETERS_TAG, TagMode::Explicit)?;
            let public_key = decoder
                .context_specific::<BitString<'_>>(PUBLIC_KEY_TAG, TagMode::Explicit)?
                .map(|bs| bs.as_bytes().ok_or_else(|| Tag::BitString.value_error()))
                .transpose()?;

            Ok(EcPrivateKey {
                private_key,
                parameters,
                public_key,
            })
        })
    }
}

impl<'a> Sequence<'a> for EcPrivateKey<'a> {
    fn fields<F, T>(&self, f: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        f(&[
            &VERSION,
            &OctetString::new(self.private_key)?,
            &self.parameters.as_ref().map(|params| ContextSpecific {
                tag_number: EC_PARAMETERS_TAG,
                tag_mode: TagMode::Explicit,
                value: *params,
            }),
            &self
                .public_key
                .map(|pk| {
                    BitString::from_bytes(pk).map(|value| ContextSpecific {
                        tag_number: PUBLIC_KEY_TAG,
                        tag_mode: TagMode::Explicit,
                        value,
                    })
                })
                .transpose()?,
        ])
    }
}

impl<'a> TryFrom<&'a [u8]> for EcPrivateKey<'a> {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<EcPrivateKey<'a>, Error> {
        Ok(Self::from_der(bytes)?)
    }
}

impl<'a> fmt::Debug for EcPrivateKey<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcPrivateKey")
            .field("parameters", &self.parameters)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}
