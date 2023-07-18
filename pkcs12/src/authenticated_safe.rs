//! AuthenticatedSafe-related types

use alloc::vec::Vec;
use cms::content_info::ContentInfo;

/// The `AuthenticatedSafe` type is defined in [RFC 7292 Section 4.1].
///
/// ```text
/// AuthenticatedSafe ::= SEQUENCE OF ContentInfo
///        -- Data if unencrypted
///        -- EncryptedData if password-encrypted
///        -- EnvelopedData if public key-encrypted
/// ```
///
/// [RFC 7292 Section 4.1]: https://www.rfc-editor.org/rfc/rfc7292#section-4.1
pub type AuthenticatedSafe<'a> = Vec<ContentInfo>;


