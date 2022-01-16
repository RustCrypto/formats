//! Trust anchor-related structures as defined in RFC 5914

use crate::{Certificate, CertificatePolicies, Extensions, Name, NameConstraints};
use der::asn1::{BitString, ContextSpecific, OctetString, Utf8String};
use der::{
    DecodeValue, Decoder, Encodable, EncodeValue, ErrorKind, FixedTag, Length, Tag, TagMode,
    TagNumber,
};
use spki::SubjectPublicKeyInfo;

/// TrustAnchorInfo ::= SEQUENCE {
///       version   TrustAnchorInfoVersion DEFAULT v1,
///       pubKey    SubjectPublicKeyInfo,
///       keyId     KeyIdentifier,
///       taTitle   TrustAnchorTitle OPTIONAL,
///       certPath  CertPathControls OPTIONAL,
///       exts      \[1\] EXPLICIT Extensions   OPTIONAL,
///       taTitleLangTag   \[2\] UTF8String OPTIONAL }
///
/// TrustAnchorInfoVersion ::= INTEGER { v1(1) }
///
/// TrustAnchorTitle ::= UTF8String (SIZE (1..64))
#[derive(Clone, Eq, PartialEq)]
pub struct TrustAnchorInfo<'a> {
    /// version   TrustAnchorInfoVersion DEFAULT v1,
    pub version: Option<u8>,

    /// pubKey    SubjectPublicKeyInfo,
    pub pub_key: SubjectPublicKeyInfo<'a>,

    /// keyId     KeyIdentifier,
    pub key_id: OctetString<'a>,

    /// taTitle   TrustAnchorTitle OPTIONAL,
    pub ta_title: Option<Utf8String<'a>>,

    /// certPath  CertPathControls OPTIONAL,
    pub cert_path: Option<CertPathControls<'a>>,

    /// exts      \[1\] EXPLICIT Extensions   OPTIONAL,
    pub extensions: Option<Extensions<'a>>,

    /// taTitleLangTag   \[2\] UTF8String OPTIONAL }
    pub ta_title_lang_tag: Option<Utf8String<'a>>,
}
// impl<'a> ::der::Decodable<'a> for TrustAnchorInfo<'a> {
//     fn decode(decoder: &mut ::der::Decoder<'a>) -> ::der::Result<Self> {
impl<'a> DecodeValue<'a> for TrustAnchorInfo<'a> {
    fn decode_value(decoder: &mut Decoder<'a>, _length: Length) -> der::Result<Self> {
        let version = match decoder.decode()? {
            Some(v) => Some(v),
            _ => Some(1),
        };

        let pub_key = decoder.decode()?;
        let key_id = decoder.decode()?;
        let ta_title = decoder.decode()?;
        let cert_path = decoder.decode()?;
        let extensions =
            ::der::asn1::ContextSpecific::decode_explicit(decoder, ::der::TagNumber::N1)?
                .map(|cs| cs.value);
        let ta_title_lang_tag =
            ::der::asn1::ContextSpecific::decode_explicit(decoder, ::der::TagNumber::N2)?
                .map(|cs| cs.value);
        Ok(Self {
            version,
            pub_key,
            key_id,
            ta_title,
            cert_path,
            extensions,
            ta_title_lang_tag,
        })
    }
}
const TAF_EXTENSIONS_TAG: TagNumber = TagNumber::new(1);
const TA_TITLE_LANG_TAG: TagNumber = TagNumber::new(0);
impl<'a> ::der::Sequence<'a> for TrustAnchorInfo<'a> {
    fn fields<F, T>(&self, f: F) -> ::der::Result<T>
    where
        F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
    {
        #[allow(unused_imports)]
        use core::convert::TryFrom;
        f(&[
            &::der::asn1::OptionalRef(if self.version == Some(1) {
                None
            } else {
                Some(&self.version)
            }),
            &self.pub_key,
            &self.key_id,
            &self.ta_title,
            &self.cert_path,
            &self.extensions.as_ref().map(|exts| ContextSpecific {
                tag_number: TAF_EXTENSIONS_TAG,
                tag_mode: TagMode::Explicit,
                value: exts.clone(),
            }),
            &self
                .ta_title_lang_tag
                .as_ref()
                .map(|ta_title_lang_tag| ContextSpecific {
                    tag_number: TA_TITLE_LANG_TAG,
                    tag_mode: TagMode::Implicit,
                    value: *ta_title_lang_tag,
                }),
        ])
    }
}

impl<'a> ::core::fmt::Debug for TrustAnchorInfo<'a> {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        f.write_fmt(format_args!("\n\tVersion: {:02X?}\n", self.version))?;
        f.write_fmt(format_args!("\tPublic Key Info: {:?}\n", self.pub_key))?;
        f.write_fmt(format_args!("\tKey ID: {:?}\n", self.key_id))?;
        f.write_fmt(format_args!("\tTA title: {:?}\n", self.ta_title))?;
        f.write_fmt(format_args!(
            "\tTA title language tag: {:?}\n",
            self.ta_title_lang_tag
        ))?;
        f.write_fmt(format_args!(
            "\tCertificate path controls: {:?}\n",
            self.cert_path
        ))?;
        if let Some(exts) = self.extensions.as_ref() {
            for (i, e) in exts.iter().enumerate() {
                f.write_fmt(format_args!("\tExtension #{}: {:?}\n", i, e))?;
            }
        } else {
            f.write_fmt(format_args!("\tExtensions: None\n"))?;
        }
        Ok(())
    }
}

/// CertPathControls ::= SEQUENCE {
///  taName           Name,
///  certificate      \[0\] Certificate OPTIONAL,
///  policySet        \[1\] CertificatePolicies OPTIONAL,
///  policyFlags      \[2\] CertPolicyFlags OPTIONAL,
///  nameConstr       \[3\] NameConstraints OPTIONAL,
///  pathLenConstraint\[4\] INTEGER (0..MAX) OPTIONAL}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertPathControls<'a> {
    /// taName               Name,
    pub ta_name: Name<'a>,

    /// certificate      \[0\] Certificate OPTIONAL,
    pub certificate: Option<Certificate<'a>>,

    /// policySet        \[1\] CertificatePolicies OPTIONAL,
    pub policy_set: Option<CertificatePolicies<'a>>,

    /// policyFlags      \[2\] CertPolicyFlags OPTIONAL,
    pub policy_flags: Option<CertPolicyFlags<'a>>,

    /// nameConstr       \[3\] NameConstraints OPTIONAL,
    pub name_constr: Option<NameConstraints<'a>>,

    /// pathLenConstraint\[4\] INTEGER (0..MAX) OPTIONAL}
    pub path_len_constraint: Option<u32>,
}
impl<'a> ::der::Decodable<'a> for CertPathControls<'a> {
    fn decode(decoder: &mut ::der::Decoder<'a>) -> ::der::Result<Self> {
        decoder.sequence(|decoder| {
            let ta_name = decoder.decode()?;

            let certificate =
                ::der::asn1::ContextSpecific::decode_implicit(decoder, ::der::TagNumber::N0)?
                    .map(|cs| cs.value);
            let policy_set =
                ::der::asn1::ContextSpecific::decode_implicit(decoder, ::der::TagNumber::N1)?
                    .map(|cs| cs.value);
            let policy_flags =
                ::der::asn1::ContextSpecific::decode_implicit(decoder, ::der::TagNumber::N2)?
                    .map(|cs| cs.value);

            let name_constr =
                ::der::asn1::ContextSpecific::decode_implicit(decoder, ::der::TagNumber::N3)?
                    .map(|cs| cs.value);
            let path_len_constraint =
                ::der::asn1::ContextSpecific::decode_implicit(decoder, ::der::TagNumber::N4)?
                    .map(|cs| cs.value);
            Ok(Self {
                ta_name,
                certificate,
                policy_set,
                policy_flags,
                name_constr,
                path_len_constraint,
            })
        })
    }
}
const CPC_CERTIFICATE_TAG: TagNumber = TagNumber::new(0);
const CPC_POLICY_SET_TAG: TagNumber = TagNumber::new(1);
const CPC_POLICY_FLAGS_TAG: TagNumber = TagNumber::new(2);
const CPC_NAME_CONSTRAINTS_TAG: TagNumber = TagNumber::new(3);
const CPC_PATH_LEN_CONSTRAINT_TAG: TagNumber = TagNumber::new(4);
impl<'a> ::der::Sequence<'a> for CertPathControls<'a> {
    fn fields<F, T>(&self, f: F) -> ::der::Result<T>
    where
        F: FnOnce(&[&dyn der::Encodable]) -> ::der::Result<T>,
    {
        #[allow(unused_imports)]
        use core::convert::TryFrom;
        f(&[
            &self.ta_name,
            &self.certificate.as_ref().map(|exts| ContextSpecific {
                tag_number: CPC_CERTIFICATE_TAG,
                tag_mode: TagMode::Implicit,
                value: exts.clone(),
            }),
            &self.policy_set.as_ref().map(|exts| ContextSpecific {
                tag_number: CPC_POLICY_SET_TAG,
                tag_mode: TagMode::Implicit,
                value: exts.clone(),
            }),
            &self
                .policy_flags
                .as_ref()
                .map(|policy_flags| ContextSpecific {
                    tag_number: CPC_POLICY_FLAGS_TAG,
                    tag_mode: TagMode::Implicit,
                    value: *policy_flags,
                }),
            &self.name_constr.as_ref().map(|exts| ContextSpecific {
                tag_number: CPC_NAME_CONSTRAINTS_TAG,
                tag_mode: TagMode::Implicit,
                value: exts.clone(),
            }),
            &self
                .path_len_constraint
                .as_ref()
                .map(|path_len_constraint| ContextSpecific {
                    tag_number: CPC_PATH_LEN_CONSTRAINT_TAG,
                    tag_mode: TagMode::Implicit,
                    value: *path_len_constraint,
                }),
        ])
    }
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
    fn decode_value(decoder: &mut Decoder<'a>, _length: Length) -> der::Result<Self> {
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
