//! `enveloped-data` content type [RFC 5652 § 6](https://datatracker.ietf.org/doc/html/rfc5652#section-6)

use crate::ContentType;

use der::{
    asn1::{ContextSpecific, OctetString},
    DecodeValue, Encode, Header, Reader, Sequence, TagMode, TagNumber,
};
use spki::AlgorithmIdentifier;

type ContentEncryptionAlgorithmIdentifier<'a> = AlgorithmIdentifier<'a>;

const ENCRYPTED_CONTENT_TAG: TagNumber = TagNumber::new(0);

/// Encrypted content information [RFC 5652 § 6](https://datatracker.ietf.org/doc/html/rfc5652#section-6)
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

impl<'a> DecodeValue<'a> for EncryptedContentInfo<'a> {
    fn decode_value<R: Reader<'a>>(
        reader: &mut R,
        header: Header,
    ) -> der::Result<EncryptedContentInfo<'a>> {
        reader.read_nested(header.length, |reader| {
            Ok(EncryptedContentInfo {
                content_type: reader.decode()?,
                content_encryption_algorithm: reader.decode()?,
                encrypted_content: reader
                    .context_specific::<OctetString<'_>>(ENCRYPTED_CONTENT_TAG, TagMode::Implicit)?
                    .map(|o| o.as_bytes()),
            })
        })
    }
}

impl<'a> Sequence<'a> for EncryptedContentInfo<'a> {
    fn fields<F, T>(&self, f: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encode]) -> der::Result<T>,
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
