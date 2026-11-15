//! AuthEnvelopedData-related types

use der::{Sequence, asn1::SetOfVec};
use x509_cert::attr::Attribute;
use x509_cert::certificate::{Profile, Rfc5280};

use crate::{
    authenticated_data::MessageAuthenticationCode,
    content_info::CmsVersion,
    enveloped_data::{EncryptedContentInfo, OriginatorInfo, RecipientInfos},
};

/// The `AuthEnvelopedData` type is defined in [RFC 5083 Section 4].
///
/// ```text
/// AuthEnvelopedData ::= SEQUENCE {
///     version CMSVersion,
///     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
///     recipientInfos RecipientInfos,
///     authEncryptedContentInfo EncryptedContentInfo,
///     authAttrs [1] IMPLICIT AuthAttributes OPTIONAL,
///     mac MessageAuthenticationCode,
///     unauthAttrs [2] IMPLICIT UnauthAttributes OPTIONAL }
/// ```
///
/// [RFC 5083 Section 4]: https://www.rfc-editor.org/rfc/rfc5083#section-4
#[derive(Clone, Debug, Sequence)]
#[allow(missing_docs)]
pub struct AuthEnvelopedData<P: Profile = Rfc5280> {
    pub version: CmsVersion,
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub originator_info: Option<OriginatorInfo<P>>,
    pub recip_infos: RecipientInfos<P>,
    pub auth_encrypted_content_info: EncryptedContentInfo,
    #[asn1(
        context_specific = "1",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub auth_attrs: Option<AuthAttributes>,
    pub mac: MessageAuthenticationCode,
    #[asn1(
        context_specific = "2",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub unauth_attrs: Option<UnauthAttributes>,
}

/// ```text
/// AuthAttributes ::= SET SIZE (1..MAX) OF Attribute
/// ```
pub type AuthAttributes = SetOfVec<Attribute>;

/// ```text
/// UnauthAttributes ::= SET SIZE (1..MAX) OF Attribute
/// ```
pub type UnauthAttributes = SetOfVec<Attribute>;
