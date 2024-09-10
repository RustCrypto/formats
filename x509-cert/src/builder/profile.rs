//! Certificate profiles
//!
//! Profiles need implement by the [`BuildProfile`] trait.
//! They may then be consumed by a [`builder::CertificateBuilder`].
//!
//!
//! Multiple profiles are provided and you may select one depending on your use-case:
//!  - [`cabf`] implements the Baseline Requirement from the CA Browser Forum as close as it can be
//!    done.
//!  - [`devid`] implements the specification for IEEE 802.1 AR. Certificates for Secure
//!    Device Identity.
//!
//! Please follow each sub-module documentation and select a profile that may suit your needs, or
//! you may implement your own profile, if need be.

#[cfg(doc)]
use crate::builder;

use crate::{builder::Result, certificate::TbsCertificate, ext::Extension, name::Name};
use alloc::vec;
use spki::SubjectPublicKeyInfoRef;

pub mod cabf;
pub mod devid;

/// Profile for certificates
///
/// The profile will define the various extensions to add to a certificate, this may be used to
/// generate a [`cabf::Root`], or a TLS [`cabf::tls::Subscriber`] certificate.
///
/// See [implementors](#implementors) for a full list of existing profiles.
pub trait BuildProfile {
    /// Issuer to be used for issued certificates
    fn get_issuer(&self, subject: &Name) -> Name;

    /// Subject for the certificate to be used.
    fn get_subject(&self) -> Name;

    /// X509v3 extensions to be added in the certificates.
    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> Result<vec::Vec<Extension>>;
}
