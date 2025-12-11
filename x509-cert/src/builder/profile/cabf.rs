//! CA/Browser forum specific profiles
//!
//! <https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-v2.0.1.pdf>

use alloc::{collections::BTreeSet, vec};

use crate::{
    builder::{BuilderProfile, Error, Result},
    certificate::TbsCertificate,
    ext::{
        Extension, ToExtension,
        pkix::{
            AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier,
        },
    },
    name::Name,
};
use const_oid::db::{rfc2256, rfc4519};
use spki::SubjectPublicKeyInfoRef;

/// Check Name encoding
///
/// BR 7.1.4.1 Name Encoding
///
/// See <https://cabforum.org/working-groups/server/baseline-requirements/requirements/#7141-name-encoding>
pub fn check_names_encoding(name: &Name, multiple_allowed: bool) -> Result<()> {
    // NOTE: RDNSequence may be empty (at least with tls Subscribers).

    let enforce_ordering = vec![
        rfc4519::DOMAIN_COMPONENT,
        rfc4519::COUNTRY_NAME,
        rfc2256::STATE_OR_PROVINCE_NAME,
        rfc4519::LOCALITY_NAME,
        rfc4519::POSTAL_CODE,
        rfc2256::STREET_ADDRESS,
        rfc4519::ORGANIZATION_NAME,
        rfc4519::SURNAME,
        rfc4519::GIVEN_NAME,
        rfc4519::ORGANIZATIONAL_UNIT_NAME,
        rfc4519::COMMON_NAME,
    ];
    let mut ordering = enforce_ordering.iter();

    let mut seen = BTreeSet::new();

    for rdn in name.iter_rdn() {
        if rdn.len() != 1 {
            return Err(Error::NonUniqueRdn);
        }

        for atv in rdn.iter() {
            if !multiple_allowed && !seen.insert(atv.oid) {
                return Err(Error::NonUniqueATV);
            }

            // If the type is in the list we should enforce ordering of
            if enforce_ordering.iter().any(|attr| attr == &atv.oid) {
                // then advance the iterator in that list, and make sure we respected it
                if !ordering.any(|attr| attr == &atv.oid) {
                    return Err(Error::InvalidAttribute { oid: atv.oid });
                }
            }
        }
    }

    Ok(())
}

/// Check CA subject naming
///
/// BR 7.1.2.10.2 CA Certificate Naming
pub fn ca_certificate_naming(subject: &Name) -> Result<()> {
    let mut required = BTreeSet::from([
        rfc4519::COUNTRY_NAME,
        rfc4519::ORGANIZATION_NAME,
        rfc4519::COMMON_NAME,
    ]);
    let mut allowed = BTreeSet::from([
        rfc4519::COUNTRY_NAME,
        rfc2256::STATE_OR_PROVINCE_NAME,
        rfc4519::LOCALITY_NAME,
        rfc4519::POSTAL_CODE,
        rfc2256::STREET_ADDRESS,
        rfc4519::ORGANIZATION_NAME,
        rfc4519::COMMON_NAME,
    ]);

    check_names_encoding(subject, false)?;

    for atv in subject.iter() {
        if !allowed.remove(&atv.oid) {
            return Err(Error::InvalidAttribute { oid: atv.oid });
        }
        required.remove(&atv.oid);
    }

    if !required.is_empty() {
        return Err(Error::MissingAttributes);
    }

    Ok(())
}

/// Root CA certificate profile
///
/// Certificate profile conforming - to the extent possible - to the CABF BR for Root CAs.
pub struct Root {
    /// Whether the root CA will emit OCSP responses.
    /// This adds the [`KeyUsages::DigitalSignature`] bit to the [`KeyUsage`] extension.
    pub emits_ocsp_response: bool,
    subject: Name,
}

impl Root {
    /// Create a new root profile.
    pub fn new(emits_ocsp_response: bool, subject: Name) -> Result<Self> {
        ca_certificate_naming(&subject)?;

        Ok(Self {
            emits_ocsp_response,
            subject,
        })
    }
}

impl BuilderProfile for Root {
    fn get_issuer(&self, subject: &Name) -> Name {
        subject.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> Result<vec::Vec<Extension>> {
        let mut extensions: vec::Vec<Extension> = vec::Vec::new();

        // 7.1.2.1.2 Root CA Extensions

        let ski = SubjectKeyIdentifier::try_from(spk)?;

        // ## authorityKeyIdentifier RECOMMENDED
        // 7.1.2.1.3 Root CA Authority Key Identifier
        extensions.push(
            AuthorityKeyIdentifier {
                // KeyIdentifier must be the same as subjectKeyIdentifier
                key_identifier: Some(ski.0.clone()),
                // other fields must not be present.
                ..Default::default()
            }
            .to_extension(&tbs.subject, &extensions)?,
        );

        // ## basicConstraints MUST
        // Spec: 7.1.2.1.4 Root CA Basic Constraints
        extensions.push(
            BasicConstraints {
                ca: true,
                path_len_constraint: None,
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
        //
        // TODO: from 7.1.2.11.4 Subject Key Identifier
        // The CA MUST generate a subjectKeyIdentifier that is unique within the scope of all
        // Certificates it has issued for each unique public key (the subjectPublicKeyInfo field of the
        // tbsCertificate). For example, CAs may generate the subject key identifier using an algorithm
        // derived from the public key, or may generate a sufficiently‐large unique number, such by using a
        // CSPRNG.
        extensions.push(ski.to_extension(&tbs.subject, &extensions)?);

        // ## extKeyUsage MUST NOT

        // ## certificatePolicies NOT RECOMMENDED

        // ## Signed Certificate Timestamp List MAY

        // ## Any other extension NOT RECOMMENDED

        Ok(extensions)
    }

    // 7.1.2.1 Root CA Certificate Profile
    // TODO:
    //   - issuerUniqueID MUST NOT be present
    //   - subjectUniqueID MUST NOT be present
    // NOTE(baloo): we never build those?
    //
    // 7.1.2.1.1 Root CA Validity
    // TODO:
    //   - Minimum 2922 days (approx. 8 years)
    //   - Max 9132 days (approx. 25 years)
    //
    //
}

pub mod tls;

pub mod codesigning {
    //! <https://cabforum.org/uploads/Baseline-Requirements-for-the-Issuance-and-Management-of-Code-Signing.v3.9.pdf>
    // TODO
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;

    #[test]
    fn test_check_names() {
        assert!(
            check_names_encoding(&Name::from_str("C=US,ST=CA").expect("parse name"), false)
                .is_err()
        );
        assert!(
            check_names_encoding(&Name::from_str("ST=CA,C=US").expect("parse name"), false).is_ok()
        );
        assert!(
            check_names_encoding(
                &Name::from_str("serialNumber=1234,ST=CA,C=US").expect("parse name"),
                false
            )
            .is_ok()
        );
    }
}
