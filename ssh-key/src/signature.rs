//! Signatures (e.g. CA signatures over SSH certificates)

use crate::{
    checked::CheckedSum,
    decoder::{Decode, Decoder},
    encoder::{Encode, Encoder},
    Algorithm, EcdsaCurve, Error, Result,
};
use alloc::vec::Vec;

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
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
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
                let decoder = &mut data.as_slice();

                for _ in 0..2 {
                    if decoder.drain_prefixed()? != component_len {
                        return Err(Error::Length);
                    }
                }

                if !decoder.is_finished() {
                    return Err(Error::Length);
                }
            }
            Algorithm::Ed25519 if data.len() == ED25519_SIGNATURE_SIZE => (),
            Algorithm::Rsa { hash: Some(_) } => (),
            _ => return Err(Error::Length),
        }

        Ok(Self { algorithm, data })
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
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        let algorithm = Algorithm::decode(decoder)?;
        let data = Vec::decode(decoder)?;
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

    fn encode(&self, encoder: &mut impl Encoder) -> Result<()> {
        self.algorithm().encode(encoder)?;
        self.as_bytes().encode(encoder)
    }
}

/// Decode [`Signature`] from an [`Algorithm`]-prefixed OpenSSH-encoded bytestring.
impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    fn try_from(mut bytes: &[u8]) -> Result<Self> {
        Self::decode(&mut bytes)
    }
}

impl signature::Signature for Signature {
    fn from_bytes(bytes: &[u8]) -> signature::Result<Self> {
        Self::try_from(bytes).map_err(|_| signature::Error::new())
    }
}

#[cfg(test)]
mod tests {
    use super::Signature;
    use crate::{Algorithm, EcdsaCurve, HashAlg};
    use hex_literal::hex;

    #[cfg(feature = "alloc")]
    use {crate::encoder::Encode, alloc::vec::Vec};

    const DSA_SIGNATURE: &[u8] = &hex!("000000077373682d6473730000002866725bf3c56100e975e21fff28a60f73717534d285ea3e1beefc2891f7189d00bd4d94627e84c55c");
    const ECDSA_SHA2_P256_SIGNATURE: &[u8] = &hex!("0000001365636473612d736861322d6e6973747032353600000048000000201298ab320720a32139cda8a40c97a13dc54ce032ea3c6f09ea9e87501e48fa1d0000002046e4ac697a6424a9870b9ef04ca1182cd741965f989bd1f1f4a26fd83cf70348");
    const ED25519_SIGNATURE: &[u8] = &hex!("0000000b7373682d65643235353139000000403d6b9906b76875aef1e7b2f1e02078a94f439aebb9a4734da1a851a81e22ce0199bbf820387a8de9c834c9c3cc778d9972dcbe70f68d53cc6bc9e26b02b46d04");
    const RSA_SHA512_SIGNATURE: &[u8] = &hex!("0000000c7273612d736861322d3531320000018085a4ad1a91a62c00c85de7bb511f38088ff2bce763d76f4786febbe55d47624f9e2cffce58a680183b9ad162c7f0191ea26cab001ac5f5055743eced58e9981789305c208fc98d2657954e38eb28c7e7f3fbe92393a14324ed77aebb772a41aa7a107b38cb9bd1d9ad79b275135d1d7e019bb1d56d74f2450be6db0771f48f6707d3fcf9789592ca2e55595acc16b6e8d0139b56c5d1360b3a1e060f4151a3d7841df2c2a8c94d6f8a1bf633165ee0bcadac5642763df0dd79d3235ae5506595145f199d8abe8f9980411bf70a16e30f273736324d047043317044c36374d6a5ed34cac251e01c6795e4578393f9090bf4ae3e74a0009275a197315fc9c62f1c9aec1ba3b2d37c3b207e5500df19e090e7097ebc038fb9c9e35aea9161479ba6b5190f48e89e1abe51e8ec0e120ef89776e129687ca52d1892c8e88e6ef062a7d96b8a87682ca6a42ff1df0cdf5815c3645aeed7267ca7093043db0565e0f109b796bf117b9d2bb6d6debc0c67a4c9fb3aae3e29b00c7bd70f6c11cf53c295ff");

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
    #[cfg(feature = "alloc")]
    fn encode_dsa() {
        let signature = Signature::try_from(DSA_SIGNATURE).unwrap();

        let mut result = Vec::new();
        signature.encode(&mut result).unwrap();
        assert_eq!(DSA_SIGNATURE, &result);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn encode_ecdsa_sha2_p256() {
        let signature = Signature::try_from(ECDSA_SHA2_P256_SIGNATURE).unwrap();

        let mut result = Vec::new();
        signature.encode(&mut result).unwrap();
        assert_eq!(ECDSA_SHA2_P256_SIGNATURE, &result);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn encode_ed25519() {
        let signature = Signature::try_from(ED25519_SIGNATURE).unwrap();

        let mut result = Vec::new();
        signature.encode(&mut result).unwrap();
        assert_eq!(ED25519_SIGNATURE, &result);
    }
}
