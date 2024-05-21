use crate::ext::pkix::name::OtherName;
use const_oid::db::rfc5911::ID_ON_HARDWARE_MODULE_NAME;
use der::{
    asn1::{ObjectIdentifier, OctetString},
    Any, Sequence, ValueOrd,
};

/// HardwareModuleName as defined in [RFC 4108 Section 5].
///
/// ```text
/// HardwareModuleName ::= SEQUENCE {
///     hwType OBJECT IDENTIFIER,
///     hwSerialNum OCTET STRING
/// }
/// ```
///
/// [RFC 4108 Section 5]: https://www.rfc-editor.org/rfc/rfc4108#section-5
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct HardwareModuleName {
    pub hw_type: ObjectIdentifier,

    pub hw_serial_num: OctetString,
}

impl HardwareModuleName {
    /// Convert from an [`OtherName`] if the other name is of the correct type.
    ///
    /// It will return `Ok(None)` if the [`OtherName`] contains another type.
    pub fn from_other_name(other_name: &OtherName) -> der::Result<Option<Self>> {
        if ID_ON_HARDWARE_MODULE_NAME.eq(&other_name.type_id) {
            other_name.value.decode_as().map(Some)
        } else {
            Ok(None)
        }
    }
}

impl TryFrom<&HardwareModuleName> for OtherName {
    type Error = der::Error;

    fn try_from(hmn: &HardwareModuleName) -> der::Result<Self> {
        Ok(Self {
            type_id: ID_ON_HARDWARE_MODULE_NAME.try_into().unwrap(),
            value: Any::encode_from(hmn)?,
        })
    }
}
