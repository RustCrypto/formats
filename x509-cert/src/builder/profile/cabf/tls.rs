//! <https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-v2.0.1.pdf>
//! 7.1.2.6 TLS Subordinate CA Certificate Profile
use alloc::vec;

use const_oid::db::{
    rfc4519,
    rfc5280::{ID_KP_CLIENT_AUTH, ID_KP_SERVER_AUTH},
};
use der::asn1::SetOfVec;

#[cfg(feature = "hazmat")]
use const_oid::db::rfc5912;

use crate::{
    attr::AttributeTypeAndValue,
    builder::{BuilderProfile, Result},
    certificate::TbsCertificate,
    ext::{
        Extension, ToExtension,
        pkix::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
            SubjectKeyIdentifier, name::GeneralNames,
        },
    },
    name::{Name, RelativeDistinguishedName},
};
use spki::SubjectPublicKeyInfoRef;

/// TLS Subordinate CA Certificate Profile
///
/// BR 7.1.2.6 TLS Subordinate CA Certificate Profile
pub struct Subordinate {
    /// issuer   Name,
    /// represents the name signing the certificate
    pub issuer: Name,

    /// subject Name,
    /// represents the name of the newly issued certificated
    pub subject: Name,

    /// pathLenConstraint       INTEGER (0..MAX) OPTIONAL
    /// BasicConstraints as defined in [RFC 5280 Section 4.2.1.9].
    pub path_len_constraint: Option<u8>,

    /// `emits_ocsp_response` will append the [`KeyUsages::DigitalSignature`]. This is meant for
    /// CAs that will reply to OCSP requests.
    pub emits_ocsp_response: bool,

    /// Allows this subordinate CA to issue certificates capable of doing client authentication
    pub client_auth: bool,
}

impl BuilderProfile for Subordinate {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> Result<vec::Vec<Extension>> {
        let mut extensions: vec::Vec<Extension> = vec::Vec::new();

        // # 7.1.2.6.1 TLS Subordinate CA Extensions

        // ## authorityKeyIdentifier MUST
        // 7.1.2.11.1 Authority Key Identifier
        extensions.push(
            AuthorityKeyIdentifier::try_from(issuer_spk.clone())?
                .to_extension(&tbs.subject, &extensions)?,
        );

        // ## basicConstraints MUST
        // Spec: 7.1.2.10.4 CA Certificate Basic Constraints
        extensions.push(
            BasicConstraints {
                // MUST be set TRUE
                ca: true,
                // May be present
                path_len_constraint: self.path_len_constraint,
            }
            .to_extension(&tbs.subject, &extensions)?,
        );

        // ## keyUsage MUST
        // Spec: 7.1.2.10.7 CA Certificate Key Usage
        let mut key_usage = KeyUsages::KeyCertSign | KeyUsages::CRLSign;
        if self.emits_ocsp_response {
            key_usage |= KeyUsages::DigitalSignature;
        }
        extensions.push(KeyUsage(key_usage).to_extension(&tbs.subject, &extensions)?);

        // ## subjectKeyIdentifier MUST
        let ski = SubjectKeyIdentifier::try_from(spk)?;
        extensions.push(ski.to_extension(&tbs.subject, &extensions)?);

        // ## extKeyUsage MUST
        // Spec 7.1.2.10.6 CA Certificate Extended Key Usage
        let mut eku = ExtendedKeyUsage(vec![ID_KP_SERVER_AUTH]);
        if self.client_auth {
            eku.0.push(ID_KP_CLIENT_AUTH);
        }
        extensions.push(eku.to_extension(&tbs.subject, &extensions)?);

        // ## authorityInformationAccess SHOULD
        // Spec 7.1.2.10.3 CA Certificate Authority Information Access
        // NOTE(baloo): this is a should and we can't put a generic value here, it's mostly up to
        // the consumer of the API.

        Ok(extensions)
    }

    // 7.1.2.6.1 TLS Subordinate CA Extensions
    // Check certificatePolicies MUST
    // check crlDistributionPoints MUST
}

/// Type of Subscriber Certificates that may be issued.
#[derive(Debug, Clone, PartialEq)]
pub enum CertificateType {
    /// Subscriber Certificate to be Domain Validated
    DomainValidated(DomainValidated),
    /// Subscriber Certificate to be Individual Validated
    IndividualValidated,
    /// Subscriber Certificate to be Organization Validated
    OrganizationValidated,
    /// Subscriber Certificate to be Extended Validation
    ExtendedValidation,
}

impl CertificateType {
    /// Creates a new [`CertificateType`] that has been domain validated
    pub fn domain_validated(subject: Name, names: GeneralNames) -> Result<Self> {
        // # 7.1.2.7.2 Domain Validated
        // CountryName MAY
        // CommonName NOT RECOMMENDED
        // Any other attribute MUST NOT

        // TODO(baloo): not very happy with all that, might as well throw that in a helper
        // or something.
        let rdns: vec::Vec<RelativeDistinguishedName> = subject
            .iter_rdn()
            .filter_map(|rdn| {
                let out = SetOfVec::<AttributeTypeAndValue>::from_iter(
                    rdn.iter()
                        .filter(|attr_value| {
                            attr_value.oid == rfc4519::COUNTRY_NAME
                                || attr_value.oid == rfc4519::COMMON_NAME
                        })
                        .cloned(),
                )
                .ok()?;

                Some(RelativeDistinguishedName(out))
            })
            .filter(|rdn| !rdn.is_empty())
            .collect();

        let subject: Name = Name(rdns.into());

        Ok(Self::DomainValidated(DomainValidated { subject, names }))
    }
}

/// Subscriber Certificate to be Domain Validated
#[derive(Debug, Clone, PartialEq)]
pub struct DomainValidated {
    subject: Name,
    names: GeneralNames,
}

/// 7.1.2.7 Subscriber (Server) Certificate Profile
pub struct Subscriber {
    /// Subtype of the Subscriber Certificate Profile
    pub certificate_type: CertificateType,

    /// issuer   Name,
    /// represents the name signing the certificate
    pub issuer: Name,

    /// Enable client authentication with the newly issued certificate
    pub client_auth: bool,

    /// TLS1.2 specific flags
    ///
    /// It is only available under the `hazmat` feature flag.
    #[cfg(feature = "hazmat")]
    pub tls12_options: Tls12Options,

    /// Enable `dataEncipherment` bit on `KeyUsage`.
    /// This bit is not recommended and is [`Pending Prohibition`].
    ///
    /// It is only available under the `hazmat` feature flag.
    ///
    /// [`Pending Prohibition`]: https://github.com/cabforum/servercert/issues/384
    #[cfg(feature = "hazmat")]
    pub enable_data_encipherment: bool,
}

/// [`Tls12Options`] stores the KeyUsage bits that are required by specific uses of TLS1.2.
///
/// This specifically refers to the [section 7.4.2 of RFC 5246]:
/// ``` text
///  RSA                RSA public key; the certificate MUST allow the
///  RSA_PSK            key to be used for encryption (the
///                     keyEncipherment bit MUST be set if the key
///                     usage extension is present).
///                     Note: RSA_PSK is defined in [TLSPSK].
/// [...]
///  DH_DSS             Diffie-Hellman public key; the keyAgreement bit
///  DH_RSA             MUST be set if the key usage extension is
///                     present.
/// ```
///
/// Those are meant for consumers relying on non-DH schemes with RSA keys and non-ECDH schemes
/// with ECC keys.
///
/// This behavior is no longer provided by TLS 1.3 and is NOT RECOMMENDED by CABF as it is
/// [`Pending Prohibition`].
///
/// [section 7.4.2 of RFC 5246]: https://www.rfc-editor.org/rfc/rfc5246#section-7.4.2
/// [`Pending Prohibition`]: https://github.com/cabforum/servercert/issues/384
#[derive(Default)]
pub struct Tls12Options {
    /// Enable `keyEncipherment` on RSA keys.
    pub enable_key_encipherment: bool,
    /// Enable `keyAgreement` on ECC keys.
    pub enable_key_agreement: bool,
}

impl BuilderProfile for Subscriber {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        match &self.certificate_type {
            CertificateType::DomainValidated(DomainValidated { subject, .. }) => subject.clone(),
            _ => todo!(),
        }
    }

    #[cfg_attr(not(feature = "hazmat"), allow(unused_variables))]
    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> Result<vec::Vec<Extension>> {
        let mut extensions: vec::Vec<Extension> = vec::Vec::new();

        // # 7.1.2.7.6 Subscriber Certificate Extensions

        // ## authorityInformationAccess MUST
        // 7.1.2.7.7 Subscriber Certificate Authority Information Access
        // TODO

        // ## authorityKeyIdentifier MUST
        // 7.1.2.11.1 Authority Key Identifier
        extensions.push(
            AuthorityKeyIdentifier::try_from(issuer_spk.clone())?
                .to_extension(&tbs.subject, &extensions)?,
        );

        // ## extKeyUsage MUST
        // 7.1.2.7.10 Subscriber Certificate Extended Key Usage
        let mut eku = ExtendedKeyUsage(vec![ID_KP_SERVER_AUTH]);
        if self.client_auth {
            eku.0.push(ID_KP_CLIENT_AUTH);
        }
        extensions.push(eku.to_extension(&tbs.subject, &extensions)?);

        // ## basicConstraints MUST
        // Spec: 7.1.2.7.8 Subscriber Certificate Basic Constraints
        extensions.push(
            BasicConstraints {
                // MUST be set FALSE
                ca: false,
                // MUST NOT be preset
                path_len_constraint: None,
            }
            .to_extension(&tbs.subject, &extensions)?,
        );

        // ## subjectAltName MUST
        // TODO: move that to validation?

        // ## keyUsage SHOULD
        // 7.1.2.7.11 Subscriber Certificate Key Usage
        #[cfg_attr(not(feature = "hazmat"), allow(unused_mut))]
        let mut key_usage = KeyUsages::DigitalSignature.into();
        #[cfg(feature = "hazmat")]
        {
            if spk.is_rsa() {
                if self.enable_data_encipherment {
                    key_usage |= KeyUsages::DataEncipherment;
                }
                if self.tls12_options.enable_key_encipherment {
                    key_usage |= KeyUsages::KeyEncipherment;
                }
            }
            if self.tls12_options.enable_key_agreement && spk.is_ecc() {
                key_usage |= KeyUsages::KeyAgreement;
            }
        }
        extensions.push(KeyUsage(key_usage).to_extension(&tbs.subject, &extensions)?);

        // ## subjectKeyIdentifier NOT RECOMMENDED
        // TODO(baloo): there is a conflict between BRG and RFC 5280 4.2.1.2
        // RFC marks it as SHOULD, BRG marks it as NOT RECOMMENDED.
        //
        // Zlint (our linter) also emits an error if not applied.
        // upstream PR: https://github.com/zmap/zlint/pull/788
        //let ski = SubjectKeyIdentifier::try_from(spk)?;
        //extensions.push(ski.to_extension(&tbs.subject, &extensions)?);

        Ok(extensions)
    }
}

#[cfg(feature = "hazmat")]
trait KeyType {
    fn is_rsa(&self) -> bool;
    fn is_ecc(&self) -> bool;
}

#[cfg(feature = "hazmat")]
impl KeyType for SubjectPublicKeyInfoRef<'_> {
    fn is_rsa(&self) -> bool {
        self.algorithm.oid == rfc5912::RSA_ENCRYPTION
    }

    fn is_ecc(&self) -> bool {
        self.algorithm.oid == rfc5912::ID_EC_PUBLIC_KEY
    }
}
