//! Trust anchor-related structures as defined in RFC 5914

use crate::{Certificate, CertificatePolicies, Extensions, NameConstraints};
use der::asn1::{BitString, OctetString, Utf8String};
use der::{
    DecodeValue, Decoder, Encodable, EncodeValue, ErrorKind, FixedTag, Header, Sequence, Tag,
    TagMode, TagNumber,
};
use spki::SubjectPublicKeyInfo;
use x501::name::Name;

/// ```text
/// TrustAnchorInfo ::= SEQUENCE {
///     version         TrustAnchorInfoVersion DEFAULT v1,
///     pubKey          SubjectPublicKeyInfo,
///     keyId           KeyIdentifier,
///     taTitle         TrustAnchorTitle OPTIONAL,
///     certPath        CertPathControls OPTIONAL,
///     exts            [1] EXPLICIT Extensions   OPTIONAL,
///     taTitleLangTag  [2] UTF8String OPTIONAL
/// }
///
/// TrustAnchorInfoVersion ::= INTEGER { v1(1) }
///
/// TrustAnchorTitle ::= UTF8String (SIZE (1..64))
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[allow(missing_docs)]
pub struct TrustAnchorInfo<'a> {
    #[asn1(default = "Default::default")]
    pub version: u8,

    pub pub_key: SubjectPublicKeyInfo<'a>,

    pub key_id: OctetString<'a>,

    #[asn1(optional = "true")]
    pub ta_title: Option<Utf8String<'a>>,

    #[asn1(optional = "true")]
    pub cert_path: Option<CertPathControls<'a>>,

    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub extensions: Option<Extensions<'a>>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub ta_title_lang_tag: Option<Utf8String<'a>>,
}

/// ```text
/// CertPathControls ::= SEQUENCE {
///     taName              Name,
///     certificate         [0] Certificate OPTIONAL,
///     policySet           [1] CertificatePolicies OPTIONAL,
///     policyFlags         [2] CertPolicyFlags OPTIONAL,
///     nameConstr          [3] NameConstraints OPTIONAL,
///     pathLenConstraint   [4] INTEGER (0..MAX) OPTIONAL
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct CertPathControls<'a> {
    pub ta_name: Name<'a>,

    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub certificate: Option<Certificate<'a>>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub policy_set: Option<CertificatePolicies<'a>>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub policy_flags: Option<CertPolicyFlags<'a>>,

    #[asn1(context_specific = "3", tag_mode = "IMPLICIT", optional = "true")]
    pub name_constr: Option<NameConstraints<'a>>,

    #[asn1(context_specific = "4", tag_mode = "IMPLICIT", optional = "true")]
    pub path_len_constraint: Option<u32>,
}

/// CertPolicyFlags ::= BIT STRING {
///  inhibitPolicyMapping    (0),
///  requireExplicitPolicy   (1),
///  inhibitAnyPolicy        (2) }
pub type CertPolicyFlags<'a> = BitString<'a>;

/// TrustAnchorChoice ::= CHOICE {
///   certificate  Certificate,
///   tbsCert      \[1\] EXPLICIT TBSCertificate,
///   taInfo       \[2\] EXPLICIT TrustAnchorInfo }
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum TrustAnchorChoice<'a> {
    ///   certificate  Certificate,
    Certificate(Certificate<'a>),
    // Not supporting TBSCertificate option
    //   tbsCert      \[1\] EXPLICIT TBSCertificate,
    //TbsCertificate(TBSCertificate<'a>),
    ///   taInfo       \[2\] EXPLICIT TrustAnchorInfo }
    TaInfo(TrustAnchorInfo<'a>),
}

//const TAC_TBS_CERTIFICATE_TAG: TagNumber = TagNumber::new(1);
const TAC_TA_INFO_TAG: TagNumber = TagNumber::new(2);

impl<'a> DecodeValue<'a> for TrustAnchorChoice<'a> {
    fn decode_value(decoder: &mut Decoder<'a>, _header: Header) -> der::Result<Self> {
        let t = decoder.peek_tag()?;
        let o = t.octet();
        // Context specific support always returns an Option<>, just ignore since OPTIONAL does not apply here
        match o {
            0x30 => {
                let cert = decoder.decode()?;
                Ok(TrustAnchorChoice::Certificate(cert))
            }
            // TODO - need DecodeValue on TBSCertificate to support this
            // 0xA1 => {
            //     let on = decoder
            //         .context_specific::<TBSCertificate<'a>>(TAC_TBS_CERTIFICATE_TAG, TagMode::Explicit)?;
            //     match on {
            //         Some(on) => Ok(TrustAnchorChoice::TbsCertificate(on)),
            //         _ => Err(ErrorKind::Failed.into()),
            //     }
            // }
            0xA2 => {
                let on = decoder
                    .context_specific::<TrustAnchorInfo<'a>>(TAC_TA_INFO_TAG, TagMode::Explicit)?;
                match on {
                    Some(on) => Ok(TrustAnchorChoice::TaInfo(on)),
                    _ => Err(ErrorKind::Failed.into()),
                }
            }
            _ => Err(ErrorKind::TagUnknown { byte: o }.into()),
        }
    }
}

impl<'a> EncodeValue for TrustAnchorChoice<'a> {
    fn encode_value(&self, encoder: &mut ::der::Encoder<'_>) -> ::der::Result<()> {
        match self {
            Self::Certificate(certificate) => certificate.encode(encoder),
            // Self::TbsCertificate(variant) => ContextSpecific {
            //     tag_number: TAC_TBS_CERTIFICATE_TAG,
            //     tag_mode: TagMode::Explicit,
            //     value: variant.clone(),
            // }.encode(encoder),
            Self::TaInfo(variant) => variant.encode(encoder),
        }
    }
    fn value_len(&self) -> ::der::Result<::der::Length> {
        match self {
            Self::Certificate(certificate) => certificate.encoded_len(),
            // Self::TbsCertificate(variant) => ContextSpecific {
            //     tag_number: TAC_TBS_CERTIFICATE_TAG,
            //     tag_mode: TagMode::Explicit,
            //     value: variant.clone(),
            // }.encoded_len(),
            Self::TaInfo(variant) => variant.encoded_len(),
        }
    }
}

//TODO - see why this is necessary to avoid problem at line 78 in context_specific.rs due to mismatched tag
impl<'a> FixedTag for TrustAnchorChoice<'a> {
    const TAG: Tag = ::der::Tag::ContextSpecific {
        constructed: true,
        number: TAC_TA_INFO_TAG,
    };
}

// Not supporting these structures
// TrustAnchorList ::= SEQUENCE SIZE (1..MAX) OF TrustAnchorChoice
//
// id-ct-trustAnchorList      OBJECT IDENTIFIER ::= { iso(1)
//     member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
//     id-smime(16) id-ct(1) 34 }
