//! Profile for 802.1AR // Secure Device Identity certificates
//!
//! Specification can be found here:
//! <https://ieeexplore.ieee.org/document/8423794>

// NOTE(baloo): due to copyright issues, I am not going to
// copy paste parts of spec relevant to the implementation.
// Unlike other organizations, IEEE does not appear to grant a license for
// reproduction in implementations.
// There is a fair use exclusion to copyright, but I am not willing to
// go to court to test waters.
//
// You, as a reader/reviewer, are expected to download a copy of the spec
// yourself.

use alloc::vec;

use crate::{
    builder::{BuilderProfile, Result},
    certificate::TbsCertificate,
    ext::{
        Extension, ToExtension,
        pkix::{
            AuthorityKeyIdentifier, KeyUsage, KeyUsages, SubjectAltName,
            name::{GeneralName, GeneralNames, HardwareModuleName, OtherName},
        },
    },
    name::Name,
};
use der::{ErrorKind, asn1::OctetString};
use spki::{ObjectIdentifier, SubjectPublicKeyInfoRef};

// TODO(tarcieri): use this when `const-oid` has been bumped to v0.10.0-rc.0
//use const_oid::db::tcgtpm;
#[allow(missing_docs)]
pub mod tcgtpm {
    use const_oid::ObjectIdentifier;
    pub const TCG_SV_TPM_12: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.1.0");
    pub const TCG_SV_TPM_20: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.1.2");
}

/// DevID Certificate
///
/// See: section 8 DevID certificate fields and extensions
pub struct DevId {
    /// issuer   Name,
    /// represents the name signing the certificate
    pub issuer: Name,

    subject: Name,

    subject_alt_name: Option<GeneralNames>,
}

impl DevId {
    /// Create a new DevID
    ///
    /// Spec: 802.1AR Section 8.10.4 subjectAltName
    /// Also documented in
    /// <https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf#page=58>
    pub fn new(issuer: Name, subject: Name, alt_names: Option<GeneralNames>) -> Result<Self> {
        // If alt_name is present it is required to include `HardwareModuleName`
        // HardwareModuleName is der-encoded in an OtherName field of GeneralNames.
        if let Some(ref alt_names) = alt_names {
            // TODO: do we need to validate the SAN more than that? check for duplicates?
            let mut found = false;
            for gn in alt_names {
                match gn {
                    GeneralName::OtherName(on)
                        if HardwareModuleName::from_other_name(on)?.is_some() =>
                    {
                        found = true;
                        break;
                    }
                    _ => {}
                }
            }

            if !found {
                return Err(der::Error::from(ErrorKind::Failed).into());
            }
        }

        Ok(Self {
            issuer,
            subject,
            subject_alt_name: alt_names,
        })
    }

    /// Create a new IDevID for a TPM-based key.
    pub fn idevid_tpm(
        issuer: Name,
        subject: Name,
        hw_type: TpmVersion,
        serial_number: OctetString,
    ) -> Result<Self> {
        let hardware_module_name = HardwareModuleName {
            hw_type: hw_type.to_oid(),
            hw_serial_num: serial_number,
        };

        let alt_names = vec![GeneralName::OtherName(OtherName::try_from(
            &hardware_module_name,
        )?)];

        Ok(Self {
            issuer,
            subject,
            subject_alt_name: Some(alt_names),
        })
    }
}

impl BuilderProfile for DevId {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        _spk: SubjectPublicKeyInfoRef<'_>,
        issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> Result<vec::Vec<Extension>> {
        let mut extensions: vec::Vec<Extension> = vec::Vec::new();

        // # Table 8-2 - DevID certificate and intermediate certificate extensions

        // ## authorityKeyIdentifier MUST
        // Section 8.10.1
        extensions.push(
            AuthorityKeyIdentifier::try_from(issuer_spk.clone())?
                .to_extension(&tbs.subject, &extensions)?,
        );

        // ## subjectKeyIdentifier NOT RECOMMENDED

        // ## keyUsage SHOULD
        // Section 8.10.3
        //
        // NOTE(baloo):
        //   IEEE spec allows for keyEncipherment but that would be used for TLS1.2 RSA and RSA_PSK
        //   (IE: non-DH) session scheme.
        //   In the mean time, when used with TPMs, the [TCG] will only allow for `digitalSignature`:
        //   Use of digitalSignature (only) is RECOMMENDED. Refer to section 3.8.
        //
        // [TCG]: https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf#page=57
        let key_usage = KeyUsages::DigitalSignature.into();
        extensions.push(KeyUsage(key_usage).to_extension(&tbs.subject, &extensions)?);

        // ## subjectAltName SHOULD
        // 8.10.4
        if let Some(san) = &self.subject_alt_name {
            extensions.push(SubjectAltName(san.clone()).to_extension(&tbs.subject, &extensions)?);
        }

        Ok(extensions)
    }
}

/// Version of the TPM used for DevID
#[derive(Debug, Clone, PartialEq)]
pub enum TpmVersion {
    /// TPM version 1.2
    Tpm12,
    /// TPM version 2.0
    Tpm20,
    /// Other TPM version
    #[cfg(feature = "hazmat")]
    Other(ObjectIdentifier),
}

impl TpmVersion {
    fn to_oid(&self) -> ObjectIdentifier {
        match self {
            Self::Tpm12 => tcgtpm::TCG_SV_TPM_12,
            Self::Tpm20 => tcgtpm::TCG_SV_TPM_20,
            #[cfg(feature = "hazmat")]
            Self::Other(o) => *o,
        }
    }
}

// Notes:
// Example of a certificate can be found in A.2
// https://trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf#page=37
//
// OID 2.23.133.1.0 for TPM version 1.2
// OID 2.23.133.1.2 for TPM version 2.0
//
//
// https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf#page=60
// An IDevID/IAK complying with this specification SHOULD include tcg-cap-verifiedTPMResidency to indicate
// compliance with section 4 and also one of tcg-cap-verifiedTPMFixed (IDevID) or tcg-cap-verifiedTPMRestricted
// (IAK).
//
// tcg-cap-verifiedTPMResidency 2.23.133.11.1.1
// tcg-cap-verifiedTPMFixed 2.23.133.11.1.2
// tcg-cap-verifiedTPMRestricted 2.23.133.11.1.3
