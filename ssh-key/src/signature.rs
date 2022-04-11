//! Signatures (e.g. CA signatures over SSH certificates)

use crate::{
    checked::CheckedSum, decode::Decode, encode::Encode, private, public, reader::Reader,
    writer::Writer, Algorithm, EcdsaCurve, Error, PrivateKey, PublicKey, Result,
};
use alloc::vec::Vec;
use core::fmt;
use signature::{Signer, Verifier};

#[cfg(feature = "ed25519")]
use crate::{private::Ed25519Keypair, public::Ed25519PublicKey};

#[cfg(feature = "p256")]
use crate::{
    private::{EcdsaKeypair, EcdsaPrivateKey},
    public::EcdsaPublicKey,
};

#[cfg(feature = "rsa")]
use {
    crate::{private::RsaKeypair, public::RsaPublicKey, HashAlg},
    rsa::PublicKey as _,
    sha2::{Digest, Sha256, Sha512},
};

const DSA_SIGNATURE_SIZE: usize = 40;
const ECDSA_NISTP256_SIGNATURE_SIZE: usize = 72;
const ECDSA_NISTP384_SIGNATURE_SIZE: usize = 104;
const ECDSA_NISTP521_SIGNATURE_SIZE: usize = 140;
const ED25519_SIGNATURE_SIZE: usize = 64;

/// Digital signature (e.g. DSA, ECDSA, Ed25519).
///
/// These are used as part of the OpenSSH certificate format to represent
/// signatures by certificate authorities (CAs).
///
/// From OpenSSH's [PROTOCOL.certkeys] specification:
///
/// > Signatures are computed and encoded according to the rules defined for
/// > the CA's public key algorithm ([RFC4253 section 6.6] for ssh-rsa and
/// > ssh-dss, [RFC5656] for the ECDSA types, and [RFC8032] for Ed25519).
///
/// RSA signature support is implemented using the SHA2 family extensions as
/// described in [RFC8332].
///
/// [PROTOCOL.certkeys]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
/// [RFC4253 section 6.6]: https://datatracker.ietf.org/doc/html/rfc4253#section-6.6
/// [RFC5656]: https://datatracker.ietf.org/doc/html/rfc5656
/// [RFC8032]: https://datatracker.ietf.org/doc/html/rfc8032
/// [RFC8332]: https://datatracker.ietf.org/doc/html/rfc8332
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord)]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub struct Signature {
    /// Signature algorithm.
    algorithm: Algorithm,

    /// Raw signature serialized as algorithm-specific byte encoding.
    data: Vec<u8>,
}

impl Signature {
    /// Create a new signature with the given algorithm and raw signature data.
    ///
    /// See specifications in toplevel [`Signature`] documentation for how to
    /// format the raw signature data for a given algorithm.
    ///
    /// # Returns
    /// - [`Error::Length`] if the signature is not the correct length.
    pub fn new(algorithm: Algorithm, data: impl Into<Vec<u8>>) -> Result<Self> {
        let data = data.into();

        // Validate signature is well-formed per OpensSH encoding
        match algorithm {
            Algorithm::Dsa if data.len() == DSA_SIGNATURE_SIZE => (),
            Algorithm::Ecdsa { curve } => {
                let expected_len = match curve {
                    EcdsaCurve::NistP256 => ECDSA_NISTP256_SIGNATURE_SIZE,
                    EcdsaCurve::NistP384 => ECDSA_NISTP384_SIGNATURE_SIZE,
                    EcdsaCurve::NistP521 => ECDSA_NISTP521_SIGNATURE_SIZE,
                };

                if data.len() != expected_len {
                    return Err(Error::Length);
                }

                let component_len = expected_len.checked_sub(8).ok_or(Error::Length)? / 2;
                let reader = &mut data.as_slice();

                for _ in 0..2 {
                    if reader.drain_prefixed()? != component_len {
                        return Err(Error::Length);
                    }
                }

                if !reader.is_finished() {
                    return Err(Error::Length);
                }
            }
            Algorithm::Ed25519 if data.len() == ED25519_SIGNATURE_SIZE => (),
            Algorithm::Rsa { hash: Some(_) } => (),
            _ => return Err(Error::Length),
        }

        Ok(Self { algorithm, data })
    }

    /// Placeholder signature used by the certificate builder.
    ///
    /// This is guaranteed generate an error if anything attempts to encode it.
    pub(crate) fn placeholder() -> Self {
        Self {
            algorithm: Algorithm::default(),
            data: Vec::new(),
        }
    }

    /// Check if this signature is the placeholder signature.
    pub(crate) fn is_placeholder(&self) -> bool {
        self.algorithm == Algorithm::default() && self.data.is_empty()
    }
}

impl Signature {
    /// Get the [`Algorithm`] associated with this signature.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Get the raw signature as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Decode for Signature {
    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let algorithm = Algorithm::decode(reader)?;
        let data = Vec::decode(reader)?;
        Self::new(algorithm, data)
    }
}

impl Encode for Signature {
    fn encoded_len(&self) -> Result<usize> {
        [
            self.algorithm().encoded_len()?,
            4, // signature data length prefix (uint32)
            self.as_bytes().len(),
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        if self.is_placeholder() {
            return Err(Error::Length);
        }

        self.algorithm().encode(writer)?;
        self.as_bytes().encode(writer)
    }
}

impl signature::Signature for Signature {
    fn from_bytes(bytes: &[u8]) -> signature::Result<Self> {
        Self::try_from(bytes).map_err(|_| signature::Error::new())
    }
}

/// Decode [`Signature`] from an [`Algorithm`]-prefixed OpenSSH-encoded bytestring.
impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    fn try_from(mut bytes: &[u8]) -> Result<Self> {
        Self::decode(&mut bytes)
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Signature {{ algorithm: {:?}, data: {:X} }}",
            self.algorithm, self
        )
    }
}

impl fmt::LowerHex for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl Signer<Signature> for PrivateKey {
    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        self.key_data().try_sign(message)
    }
}

impl Signer<Signature> for private::KeypairData {
    #[allow(unused_variables)]
    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        match self {
            #[cfg(feature = "p256")]
            Self::Ecdsa(keypair) => keypair.try_sign(message),
            #[cfg(feature = "ed25519")]
            Self::Ed25519(keypair) => keypair.try_sign(message),
            #[cfg(feature = "rsa")]
            Self::Rsa(keypair) => keypair.try_sign(message),
            _ => Err(signature::Error::new()),
        }
    }
}

impl Verifier<Signature> for PublicKey {
    fn verify(&self, message: &[u8], signature: &Signature) -> signature::Result<()> {
        self.key_data().verify(message, signature)
    }
}

impl Verifier<Signature> for public::KeyData {
    #[allow(unused_variables)]
    fn verify(&self, message: &[u8], signature: &Signature) -> signature::Result<()> {
        match self {
            #[cfg(feature = "p256")]
            Self::Ecdsa(pk) => pk.verify(message, signature),
            #[cfg(feature = "ed25519")]
            Self::Ed25519(pk) => pk.verify(message, signature),
            #[cfg(feature = "rsa")]
            Self::Rsa(pk) => pk.verify(message, signature),
            _ => Err(signature::Error::new()),
        }
    }
}

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
impl TryFrom<Signature> for ed25519_dalek::Signature {
    type Error = Error;

    fn try_from(signature: Signature) -> Result<ed25519_dalek::Signature> {
        ed25519_dalek::Signature::try_from(&signature)
    }
}

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
impl TryFrom<&Signature> for ed25519_dalek::Signature {
    type Error = Error;

    fn try_from(signature: &Signature) -> Result<ed25519_dalek::Signature> {
        match signature.algorithm {
            Algorithm::Ed25519 => Ok(ed25519_dalek::Signature::try_from(signature.as_bytes())?),
            _ => Err(Error::Algorithm),
        }
    }
}

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
impl Signer<Signature> for Ed25519Keypair {
    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        let signature = ed25519_dalek::Keypair::try_from(self)?.sign(message);

        Ok(Signature {
            algorithm: Algorithm::Ed25519,
            data: signature.as_ref().to_vec(),
        })
    }
}

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
impl Verifier<Signature> for Ed25519PublicKey {
    fn verify(&self, message: &[u8], signature: &Signature) -> signature::Result<()> {
        let signature = ed25519_dalek::Signature::try_from(signature)?;
        ed25519_dalek::PublicKey::try_from(self)?.verify(message, &signature)
    }
}

#[cfg(feature = "p256")]
#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
impl TryFrom<p256::ecdsa::Signature> for Signature {
    type Error = Error;

    fn try_from(signature: p256::ecdsa::Signature) -> Result<Signature> {
        Signature::try_from(&signature)
    }
}

#[cfg(feature = "p256")]
#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
impl TryFrom<&p256::ecdsa::Signature> for Signature {
    type Error = Error;

    fn try_from(signature: &p256::ecdsa::Signature) -> Result<Signature> {
        let (r, s) = signature.as_ref().split_at(32);

        let mut data = Vec::with_capacity(72);
        r.encode(&mut data)?;
        s.encode(&mut data)?;

        Ok(Signature {
            algorithm: Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            data,
        })
    }
}

#[cfg(feature = "p256")]
#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
impl TryFrom<Signature> for p256::ecdsa::Signature {
    type Error = Error;

    fn try_from(signature: Signature) -> Result<p256::ecdsa::Signature> {
        p256::ecdsa::Signature::try_from(&signature)
    }
}

#[cfg(feature = "p256")]
#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
impl TryFrom<&Signature> for p256::ecdsa::Signature {
    type Error = Error;

    fn try_from(signature: &Signature) -> Result<p256::ecdsa::Signature> {
        match signature.algorithm {
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            } => {
                let reader = &mut signature.as_bytes();
                let mut bytes = [0u8; 64];

                // Decode `r` and `s` components of the signature concatenated.
                for chunk in bytes.chunks_mut(32) {
                    let len = reader.read_byten(chunk)?.len();

                    if len != 32 {
                        return Err(Error::Crypto);
                    }
                }

                Ok(p256::ecdsa::Signature::try_from(bytes.as_slice())?)
            }
            _ => Err(Error::Algorithm),
        }
    }
}

#[cfg(feature = "p256")]
#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
impl Signer<Signature> for EcdsaKeypair {
    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        match self {
            Self::NistP256 { private, .. } => private.try_sign(message),
            _ => Err(signature::Error::new()),
        }
    }
}

#[cfg(feature = "p256")]
#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
impl Signer<Signature> for EcdsaPrivateKey<32> {
    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        Ok(p256::ecdsa::SigningKey::from_bytes(self.as_ref())?
            .try_sign(message)?
            .try_into()?)
    }
}

#[cfg(feature = "p256")]
#[cfg_attr(docsrs, doc(cfg(feature = "p256")))]
impl Verifier<Signature> for EcdsaPublicKey {
    fn verify(&self, message: &[u8], signature: &Signature) -> signature::Result<()> {
        match signature.algorithm {
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            } => {
                let verifying_key = p256::ecdsa::VerifyingKey::try_from(self)?;
                let signature = p256::ecdsa::Signature::try_from(signature)?;
                verifying_key.verify(message, &signature)
            }
            _ => Err(signature::Error::new()),
        }
    }
}

#[cfg(feature = "rsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl Signer<Signature> for RsaKeypair {
    fn try_sign(&self, message: &[u8]) -> signature::Result<Signature> {
        let padding = rsa::padding::PaddingScheme::PKCS1v15Sign {
            hash: Some(rsa::hash::Hash::SHA2_512),
        };
        let digest = sha2::Sha512::digest(message);
        let data = rsa::RsaPrivateKey::try_from(self)?
            .sign(padding, digest.as_ref())
            .map_err(|_| signature::Error::new())?;

        Ok(Signature {
            algorithm: Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            data,
        })
    }
}

#[cfg(feature = "rsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl Verifier<Signature> for RsaPublicKey {
    fn verify(&self, message: &[u8], signature: &Signature) -> signature::Result<()> {
        let key = rsa::RsaPublicKey::try_from(self)?;

        match signature.algorithm {
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            } => {
                let digest = Sha256::digest(message);
                let padding = rsa::padding::PaddingScheme::PKCS1v15Sign {
                    hash: Some(rsa::hash::Hash::SHA2_256),
                };
                key.verify(padding, digest.as_ref(), signature.as_bytes())
                    .map_err(|_| signature::Error::new())
            }
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            } => {
                let padding = rsa::padding::PaddingScheme::PKCS1v15Sign {
                    hash: Some(rsa::hash::Hash::SHA2_512),
                };
                let digest = Sha512::digest(message);
                key.verify(padding, digest.as_ref(), signature.as_bytes())
                    .map_err(|_| signature::Error::new())
            }
            _ => Err(signature::Error::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Signature;
    use crate::{encode::Encode, Algorithm, EcdsaCurve, Error, HashAlg};
    use alloc::vec::Vec;
    use hex_literal::hex;

    #[cfg(feature = "ed25519")]
    use {
        super::Ed25519Keypair,
        signature::{Signer, Verifier},
    };

    const DSA_SIGNATURE: &[u8] = &hex!("000000077373682d6473730000002866725bf3c56100e975e21fff28a60f73717534d285ea3e1beefc2891f7189d00bd4d94627e84c55c");
    const ECDSA_SHA2_P256_SIGNATURE: &[u8] = &hex!("0000001365636473612d736861322d6e6973747032353600000048000000201298ab320720a32139cda8a40c97a13dc54ce032ea3c6f09ea9e87501e48fa1d0000002046e4ac697a6424a9870b9ef04ca1182cd741965f989bd1f1f4a26fd83cf70348");
    const ED25519_SIGNATURE: &[u8] = &hex!("0000000b7373682d65643235353139000000403d6b9906b76875aef1e7b2f1e02078a94f439aebb9a4734da1a851a81e22ce0199bbf820387a8de9c834c9c3cc778d9972dcbe70f68d53cc6bc9e26b02b46d04");
    const RSA_SHA512_SIGNATURE: &[u8] = &hex!("0000000c7273612d736861322d3531320000018085a4ad1a91a62c00c85de7bb511f38088ff2bce763d76f4786febbe55d47624f9e2cffce58a680183b9ad162c7f0191ea26cab001ac5f5055743eced58e9981789305c208fc98d2657954e38eb28c7e7f3fbe92393a14324ed77aebb772a41aa7a107b38cb9bd1d9ad79b275135d1d7e019bb1d56d74f2450be6db0771f48f6707d3fcf9789592ca2e55595acc16b6e8d0139b56c5d1360b3a1e060f4151a3d7841df2c2a8c94d6f8a1bf633165ee0bcadac5642763df0dd79d3235ae5506595145f199d8abe8f9980411bf70a16e30f273736324d047043317044c36374d6a5ed34cac251e01c6795e4578393f9090bf4ae3e74a0009275a197315fc9c62f1c9aec1ba3b2d37c3b207e5500df19e090e7097ebc038fb9c9e35aea9161479ba6b5190f48e89e1abe51e8ec0e120ef89776e129687ca52d1892c8e88e6ef062a7d96b8a87682ca6a42ff1df0cdf5815c3645aeed7267ca7093043db0565e0f109b796bf117b9d2bb6d6debc0c67a4c9fb3aae3e29b00c7bd70f6c11cf53c295ff");

    /// Example test vector for signing.
    #[cfg(feature = "ed25519")]
    const EXAMPLE_MSG: &[u8] = b"Hello, world!";

    #[test]
    fn decode_dsa() {
        let signature = Signature::try_from(DSA_SIGNATURE).unwrap();
        assert_eq!(Algorithm::Dsa, signature.algorithm());
    }

    #[test]
    fn decode_ecdsa_sha2_p256() {
        let signature = Signature::try_from(ECDSA_SHA2_P256_SIGNATURE).unwrap();
        assert_eq!(
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256
            },
            signature.algorithm()
        );
    }

    #[test]
    fn decode_ed25519() {
        let signature = Signature::try_from(ED25519_SIGNATURE).unwrap();
        assert_eq!(Algorithm::Ed25519, signature.algorithm());
    }

    #[test]
    fn decode_rsa() {
        let signature = Signature::try_from(RSA_SHA512_SIGNATURE).unwrap();
        assert_eq!(
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512)
            },
            signature.algorithm()
        );
    }

    #[test]
    fn encode_dsa() {
        let signature = Signature::try_from(DSA_SIGNATURE).unwrap();

        let mut result = Vec::new();
        signature.encode(&mut result).unwrap();
        assert_eq!(DSA_SIGNATURE, &result);
    }

    #[test]
    fn encode_ecdsa_sha2_p256() {
        let signature = Signature::try_from(ECDSA_SHA2_P256_SIGNATURE).unwrap();

        let mut result = Vec::new();
        signature.encode(&mut result).unwrap();
        assert_eq!(ECDSA_SHA2_P256_SIGNATURE, &result);
    }

    #[test]
    fn encode_ed25519() {
        let signature = Signature::try_from(ED25519_SIGNATURE).unwrap();

        let mut result = Vec::new();
        signature.encode(&mut result).unwrap();
        assert_eq!(ED25519_SIGNATURE, &result);
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn sign_and_verify_ed25519() {
        let keypair = Ed25519Keypair::from_seed(&[42; 32]);
        let signature = keypair.sign(EXAMPLE_MSG);
        assert!(keypair.public.verify(EXAMPLE_MSG, &signature).is_ok());
    }

    #[test]
    fn placeholder() {
        assert!(!Signature::try_from(ED25519_SIGNATURE)
            .unwrap()
            .is_placeholder());

        let placeholder = Signature::placeholder();
        assert!(placeholder.is_placeholder());

        let mut writer = Vec::new();
        assert_eq!(placeholder.encode(&mut writer), Err(Error::Length));
    }
}
