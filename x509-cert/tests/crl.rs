use const_oid::{
    AssociatedOid,
    db::rfc5280::{ID_CE_ISSUING_DISTRIBUTION_POINT, ID_PE_SUBJECT_INFO_ACCESS},
};
use der::{Decode, Encode, asn1::OctetString};
use x509_cert::{
    certificate::Rfc5280,
    crl::CertificateList,
    ext::{
        Extension,
        pkix::{IssuingDistributionPoint, SubjectInfoAccessSyntax},
    },
};

#[test]
fn decode_crl() {
    // vanilla CRL from PKITS
    let der_encoded_cert = include_bytes!("examples/GoodCACRL.crl");
    let crl = CertificateList::<Rfc5280>::from_der(der_encoded_cert).unwrap();
    assert_eq!(2, crl.tbs_cert_list.crl_extensions.unwrap().len());
    assert_eq!(2, crl.tbs_cert_list.revoked_certificates.unwrap().len());

    // CRL with an entry with no entry extensions
    let der_encoded_cert = include_bytes!("examples/tscpbcasha256.crl");
    let crl = CertificateList::<Rfc5280>::from_der(der_encoded_cert).unwrap();
    assert_eq!(2, crl.tbs_cert_list.crl_extensions.unwrap().len());
    assert_eq!(4, crl.tbs_cert_list.revoked_certificates.unwrap().len());
}

/// `issuingDistributionPoint` is `id-ce-issuingDistributionPoint` (2.5.29.28,
/// RFC 5280 §5.2.5), not `id-pe-subjectInfoAccess` (1.3.6.1.5.5.7.1.11, §4.2.2.2),
/// which is a certificate extension and belongs to [`SubjectInfoAccessSyntax`].
///
/// Binding the two types to the same OID makes an `extn_id`-driven lookup for an
/// `IssuingDistributionPoint` miss every real one, so `indirectCRL` reads as absent
/// on a CRL that sets it — a silent failure in the permissive direction.
#[test]
fn issuing_distribution_point_has_its_own_oid() {
    assert_eq!(
        IssuingDistributionPoint::OID,
        ID_CE_ISSUING_DISTRIBUTION_POINT
    );
    assert_eq!(SubjectInfoAccessSyntax::OID, ID_PE_SUBJECT_INFO_ACCESS);
    assert_ne!(
        IssuingDistributionPoint::OID,
        SubjectInfoAccessSyntax::OID,
        "a CRL extension and a certificate extension must not share an OID"
    );
}

/// Locating the extension by its associated OID finds a real one on the wire.
#[test]
fn issuing_distribution_point_is_found_by_its_associated_oid() {
    let idp = IssuingDistributionPoint {
        distribution_point: None,
        only_contains_user_certs: false,
        only_contains_ca_certs: false,
        only_some_reasons: None,
        indirect_crl: true,
        only_contains_attribute_certs: false,
    };
    let ext = Extension {
        extn_id: ID_CE_ISSUING_DISTRIBUTION_POINT,
        critical: true,
        extn_value: OctetString::new(idp.to_der().unwrap()).unwrap(),
    };

    let extensions = vec![ext];
    let found = extensions
        .iter()
        .find(|e| e.extn_id == IssuingDistributionPoint::OID)
        .expect("IDP extension located by IssuingDistributionPoint::OID");
    let decoded = IssuingDistributionPoint::from_der(found.extn_value.as_bytes()).unwrap();
    assert!(decoded.indirect_crl);
}
