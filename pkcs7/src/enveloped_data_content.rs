//! `enveloped-data` content type [RFC 2315 § 10](https://datatracker.ietf.org/doc/html/rfc2315#section-10)

use crate::ContentType;

use der::{
    asn1::{ContextSpecific, OctetString},
    Decodable, Decoder, Encodable, Sequence, TagMode, TagNumber,
};
use spki::AlgorithmIdentifier;

type ContentEncryptionAlgorithmIdentifier<'a> = AlgorithmIdentifier<'a>;

const ENCRYPTED_CONTENT_TAG: TagNumber = TagNumber::new(0);

/// Encrypted content information [RFC 2315 § 10.1](https://datatracker.ietf.org/doc/html/rfc2315#section-10.1)
///
/// ```text
/// EncryptedContentInfo ::= SEQUENCE {
///   contentType ContentType,
///   contentEncryptionAlgorithm
///     ContentEncryptionAlgorithmIdentifier,
///   encryptedContent
///     [0] IMPLICIT EncryptedContent OPTIONAL }
///
/// ContentEncryptionAlgorithmIdentifier ::=
///   AlgorithmIdentifier
///
/// EncryptedContent ::= OCTET STRING
/// ```
///
/// The fields of type `EncryptedContentInfo` have the following meanings:
///   - [`content_type`](EncryptedContentInfo::content_type) indicates the type of content.
///   - [`content_encryption_algorithm`](EncryptedContentInfo::content_encryption_algorithm)
///     identifies the content-encryption algorithm (and any associated parameters) under
///     which the content is encrypted.
///     The content-encryption process is described in
///     [RFC 2315 § 10.3](https://datatracker.ietf.org/doc/html/rfc2315#section-10.3).
///     This algorithm is the same for all recipients.
///   - [`encrypted_content`](EncryptedContentInfo::encrypted_content) is the result of
///     encrypting the content. The field is optional, and if the field is not present,
///     its intended value must be supplied by other means.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncryptedContentInfo<'a> {
    /// indicates the type of content.
    pub content_type: ContentType,
    /// identifies the content-encryption algorithm (and any associated parameters) under
    /// which the content is encrypted.
    pub content_encryption_algorithm: ContentEncryptionAlgorithmIdentifier<'a>,
    /// the encrypted contents;
    /// when not present, its intended value must be supplied by other means.
    pub encrypted_content: Option<&'a [u8]>,
}

impl<'a> Decodable<'a> for EncryptedContentInfo<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<EncryptedContentInfo<'a>> {
        decoder.sequence(|decoder| {
            Ok(EncryptedContentInfo {
                content_type: decoder.decode()?,
                content_encryption_algorithm: decoder.decode()?,
                encrypted_content: decoder
                    .context_specific::<OctetString<'_>>(ENCRYPTED_CONTENT_TAG, TagMode::Implicit)?
                    .map(|o| o.as_bytes()),
            })
        })
    }
}

impl<'a> Sequence<'a> for EncryptedContentInfo<'a> {
    fn fields<F, T>(&self, f: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        let opt_octet = self.encrypted_content.map(OctetString::new).transpose()?;
        f(&[
            &self.content_type,
            &self.content_encryption_algorithm,
            &opt_octet.as_ref().map(|d| ContextSpecific {
                tag_number: ENCRYPTED_CONTENT_TAG,
                tag_mode: TagMode::Implicit,
                value: *d,
            }),
        ])
    }
}
