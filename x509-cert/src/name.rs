//! Name-related definitions as defined in X.501 (and updated by RFC 5280).

use crate::{attr::AttributeTypeAndValue, ext::pkix::name::DirectoryString};
use alloc::vec::Vec;
use const_oid::{
    ObjectIdentifier,
    db::{rfc3280, rfc4519},
};
use core::{cmp::Ordering, fmt, str::FromStr};
use der::{
    DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Tag, ValueOrd, Writer,
    asn1::{Any, Ia5StringRef, PrintableStringRef, SetOfVec},
};

/// X.501 Name as defined in [RFC 5280 Section 4.1.2.4]. X.501 Name is used to represent distinguished names.
///
/// ```text
/// Name ::= CHOICE { rdnSequence  RDNSequence }
/// ```
///
/// To build name, the syntax described in [RFC 4514 Section 3] is expected.
///
/// The following attribute names are recognized:
/// ```text
///      String  X.500 AttributeType
///      ------  --------------------------------------------
///      CN      commonName (2.5.4.3)
///      L       localityName (2.5.4.7)
///      ST      stateOrProvinceName (2.5.4.8)
///      O       organizationName (2.5.4.10)
///      OU      organizationalUnitName (2.5.4.11)
///      C       countryName (2.5.4.6)
///      STREET  streetAddress (2.5.4.9)
///      DC      domainComponent (0.9.2342.19200300.100.1.25)
///      UID     userId (0.9.2342.19200300.100.1.1)
///
/// ```
///
/// # Example
///
/// ```
/// use std::str::FromStr;
/// use x509_cert::name::Name;
///
/// // Multiple syntaxes are supported by `from_str`:
/// let subject = Name::from_str("CN=example.com").unwrap();
/// let subject = Name::from_str("C=US; ST=California; L=Los Angeles; O=InternetCorporationforAssignedNamesandNumbers; CN=www.example.org").unwrap();
/// let subject = Name::from_str("C=US,ST=California,L=Los Angeles,O=InternetCorporationforAssignedNamesandNumbers,CN=www.example.org").unwrap();
/// let subject = Name::from_str("C=US/ST=California/L=Los Angeles/O=InternetCorporationforAssignedNamesandNumbers/CN=www.example.org").unwrap();
/// let subject = Name::from_str("UID=jsmith,DC=example,DC=net").unwrap();
/// let subject = Name::from_str("OU=Sales+CN=J.  Smith,DC=example,DC=net").unwrap();
/// let subject = Name::from_str(r#"CN=James \"Jim\" Smith\, III,DC=example,DC=net"#).unwrap();
/// let subject = Name::from_str(r#"CN=Before\0dAfter,DC=example,DC=net"#).unwrap();
/// let subject = Name::from_str("1.3.6.1.4.1.1466.0=#04024869").unwrap();
/// ```
///
/// [RFC 4514 Section 3]: https://www.rfc-editor.org/rfc/rfc4514#section-3
/// [RFC 5280 Section 4.1.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Name(pub(crate) RdnSequence);

impl Name {
    /// Build a name from an [`RdnSequence`].
    ///
    ///
    /// This is provided as an escape hatch (see [RFC 5280 Section 4.1.2.4]) to build
    /// names from `bmpString`, `TeletexString`, or `UniversalString`:
    /// ```text
    /// When CAs have previously issued certificates with issuer fields with
    /// attributes encoded using TeletexString, BMPString, or
    /// UniversalString, then the CA MAY continue to use these encodings of
    /// the DirectoryString to preserve backward compatibility.
    /// ```
    ///
    /// # Safety
    ///
    /// As the name implies, this is a dangerous helper. You are responsible for ensuring the
    /// [`RdnSequence`] complies with the RFC.
    ///
    /// [RFC 5280 Section 4.1.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
    #[cfg(feature = "hazmat")]
    pub fn hazmat_from_rdn_sequence(value: RdnSequence) -> Self {
        Self(value)
    }
}

impl From<Name> for RdnSequence {
    #[inline]
    fn from(value: Name) -> Self {
        value.0
    }
}

impl AsRef<RdnSequence> for Name {
    #[inline]
    fn as_ref(&self) -> &RdnSequence {
        &self.0
    }
}

impl FixedTag for Name {
    const TAG: Tag = <RdnSequence as FixedTag>::TAG;
}

impl<'a> DecodeValue<'a> for Name {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(decoder: &mut R, header: Header) -> der::Result<Self> {
        Ok(Self(RdnSequence::decode_value(decoder, header)?))
    }
}

impl EncodeValue for Name {
    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.0.encode_value(encoder)
    }

    fn value_len(&self) -> der::Result<Length> {
        self.0.value_len()
    }
}

impl ValueOrd for Name {
    fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
        self.0.value_cmp(&other.0)
    }
}

impl Name {
    /// Is this [`Name`] empty?
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of [`RelativeDistinguishedName`] elements in this [`Name`].
    pub fn len(&self) -> usize {
        self.0.0.len()
    }

    /// Returns an iterator over the inner [`AttributeTypeAndValue`]s.
    ///
    /// This iterator does not expose which attributes are grouped together as
    /// [`RelativeDistinguishedName`]s. If you need this, use [`Self::iter_rdn`].
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &'_ AttributeTypeAndValue> + '_ {
        self.0.0.iter().flat_map(move |rdn| rdn.0.as_slice())
    }

    /// Returns an iterator over the inner [`RelativeDistinguishedName`]s.
    #[inline]
    pub fn iter_rdn(&self) -> impl Iterator<Item = &'_ RelativeDistinguishedName> + '_ {
        self.0.0.iter()
    }
}

impl Name {
    /// Returns the element found in the name identified by `oid`
    ///
    /// This will return `Ok(None)` if no such element is present.
    ///
    /// If more than one attribute is present with the specified OID, only the first attribute is
    /// returned. Later elements should be fetched using [`Name::iter`].
    ///
    /// # Errors
    ///
    /// This will return [`der::Error`] if the content is not serialized as expected
    pub fn by_oid<'a, T>(&'a self, oid: ObjectIdentifier) -> der::Result<Option<T>>
    where
        T: TryFrom<&'a Any, Error = der::Error>,
        T: fmt::Debug,
    {
        self.iter()
            .filter(|atav| atav.oid == oid)
            .map(|atav| T::try_from(&atav.value))
            .next()
            .transpose()
    }

    /// Returns the Common Name (CN) found in the name.
    ///
    /// This will return `Ok(None)` if no CN is found.
    ///
    /// If more than one value is present, only the first is returned.
    /// Later elements should be fetched using [`Name::iter`].
    ///
    /// # Errors
    ///
    /// This will return [`der::Error`] if the content is not serialized as a string.
    pub fn common_name(&self) -> der::Result<Option<DirectoryString>> {
        self.by_oid(rfc4519::COMMON_NAME)
    }

    /// Returns the Country (C) found in the name.
    ///
    /// This will return `Ok(None)` if no Country is found.
    ///
    /// If more than one value is present, only the first is returned.
    /// Later elements should be fetched using [`Name::iter`].
    ///
    /// # Errors
    ///
    /// This will return [`der::Error`] if the content is not serialized as a printableString.
    pub fn country(&self) -> der::Result<Option<PrintableStringRef<'_>>> {
        self.by_oid(rfc4519::COUNTRY_NAME)
    }

    /// Returns the State or Province (ST) found in the name.
    ///
    /// This will return `Ok(None)` if no State or Province is found.
    ///
    /// If more than one value is present, only the first is returned.
    /// Later elements should be fetched using [`Name::iter`].
    ///
    /// # Errors
    ///
    /// This will return [`der::Error`] if the content is not serialized as a string.
    pub fn state_or_province(&self) -> der::Result<Option<DirectoryString>> {
        self.by_oid(rfc4519::ST)
    }

    /// Returns the Locality (L) found in the name.
    ///
    /// This will return `Ok(None)` if no Locality is found.
    ///
    /// If more than one value is present, only the first is returned.
    /// Later elements should be fetched using [`Name::iter`].
    ///
    /// # Errors
    ///
    /// This will return [`der::Error`] if the content is not serialized as a string.
    pub fn locality(&self) -> der::Result<Option<DirectoryString>> {
        self.by_oid(rfc4519::LOCALITY_NAME)
    }

    /// Returns the Organization (O) found in the name.
    ///
    /// This will return `Ok(None)` if no Organization is found.
    ///
    /// If more than one value is present, only the first is returned.
    /// Later elements should be fetched using [`Name::iter`].
    ///
    /// # Errors
    ///
    /// This will return [`der::Error`] if the content is not serialized as a string.
    pub fn organization(&self) -> der::Result<Option<DirectoryString>> {
        self.by_oid(rfc4519::ORGANIZATION_NAME)
    }

    /// Returns the Organization Unit (OU) found in the name.
    ///
    /// This will return `Ok(None)` if no Organization Unit is found.
    ///
    /// If more than one value is present, only the first is returned.
    /// Later elements should be fetched using [`Name::iter`].
    ///
    /// # Errors
    ///
    /// This will return [`der::Error`] if the content is not serialized as a string.
    pub fn organization_unit(&self) -> der::Result<Option<DirectoryString>> {
        self.by_oid(rfc4519::ORGANIZATIONAL_UNIT_NAME)
    }

    /// Returns the Email Address (emailAddress) found in the name.
    ///
    /// This will return `Ok(None)` if no email address is found.
    ///
    /// If more than one value is present, only the first is returned.
    /// Later elements should be fetched using [`Name::iter`].
    ///
    /// # Errors
    ///
    /// This will return [`der::Error`] if the content is not serialized as an ia5String.
    pub fn email_address(&self) -> der::Result<Option<Ia5StringRef<'_>>> {
        self.by_oid(rfc3280::EMAIL_ADDRESS)
    }
}

/// Parse a [`Name`] string.
///
/// Follows the rules in [RFC 4514].
///
/// [RFC 4514]: https://datatracker.ietf.org/doc/html/rfc4514
impl FromStr for Name {
    type Err = der::Error;

    fn from_str(s: &str) -> der::Result<Self> {
        Ok(Self(RdnSequence::from_str(s)?))
    }
}

/// Serializes the name according to the rules in [RFC 4514].
///
/// [RFC 4514]: https://datatracker.ietf.org/doc/html/rfc4514
impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// X.501 RDNSequence as defined in [RFC 5280 Section 4.1.2.4].
///
/// ```text
/// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
/// ```
///
/// [RFC 5280 Section 4.1.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct RdnSequence(Vec<RelativeDistinguishedName>);

impl RdnSequence {
    /// Converts an `RDNSequence` string into an encoded `RDNSequence`.
    #[deprecated(since = "0.2.1", note = "use RdnSequence::from_str(...)?.to_der()")]
    pub fn encode_from_string(s: &str) -> Result<Vec<u8>, der::Error> {
        Self::from_str(s)?.to_der()
    }

    /// Is this [`RdnSequence`] empty?
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate over this [`RdnSequence`].
    pub fn iter(&self) -> impl Iterator<Item = &RelativeDistinguishedName> {
        self.0.iter()
    }

    /// Length of this [`RdnSequence`].
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Push a [`RelativeDistinguishedName`] onto this [`RdnSequence`].
    pub fn push(&mut self, name: RelativeDistinguishedName) {
        self.0.push(name)
    }
}

/// Parse an [`RdnSequence`] string.
///
/// Follows the rules in [RFC 4514].
///
/// [RFC 4514]: https://datatracker.ietf.org/doc/html/rfc4514
impl FromStr for RdnSequence {
    type Err = der::Error;

    fn from_str(s: &str) -> der::Result<Self> {
        let mut parts = split(s, b',')
            .map(RelativeDistinguishedName::from_str)
            .collect::<der::Result<Vec<_>>>()?;
        parts.reverse();
        Ok(Self(parts))
    }
}

/// Serializes the structure according to the rules in [RFC 4514].
///
/// [RFC 4514]: https://datatracker.ietf.org/doc/html/rfc4514
impl fmt::Display for RdnSequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // As per RFC 4514 Section 2.1, the elements are reversed
        for (i, atv) in self.0.iter().rev().enumerate() {
            match i {
                0 => write!(f, "{atv}")?,
                _ => write!(f, ",{atv}")?,
            }
        }

        Ok(())
    }
}

impl_newtype!(RdnSequence, Vec<RelativeDistinguishedName>);

/// Find the indices of all non-escaped separators.
fn find(s: &str, b: u8) -> impl '_ + Iterator<Item = usize> {
    (0..s.len())
        .filter(move |i| s.as_bytes()[*i] == b)
        .filter(|i| {
            let x = i
                .checked_sub(2)
                .map(|i| s.as_bytes()[i])
                .unwrap_or_default();

            let y = i
                .checked_sub(1)
                .map(|i| s.as_bytes()[i])
                .unwrap_or_default();

            y != b'\\' || x == b'\\'
        })
}

/// Split a string at all non-escaped separators.
fn split(s: &str, b: u8) -> impl '_ + Iterator<Item = &'_ str> {
    let mut prev = 0;
    find(s, b).chain([s.len()]).map(move |i| {
        let x = &s[prev..i];
        prev = i + 1;
        x
    })
}

/// X.501 DistinguishedName as defined in [RFC 5280 Section 4.1.2.4].
///
/// ```text
/// DistinguishedName ::=   RDNSequence
/// ```
///
/// [RFC 5280 Section 4.1.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
pub type DistinguishedName = RdnSequence;

/// RelativeDistinguishedName as defined in [RFC 5280 Section 4.1.2.4].
///
/// ```text
/// RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
/// ```
///
/// Note that we follow the more common definition above. This technically
/// differs from the definition in X.501, which is:
///
/// ```text
/// RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndDistinguishedValue
///
/// AttributeTypeAndDistinguishedValue ::= SEQUENCE {
///     type ATTRIBUTE.&id ({SupportedAttributes}),
///     value ATTRIBUTE.&Type({SupportedAttributes}{@type}),
///     primaryDistinguished BOOLEAN DEFAULT TRUE,
///     valuesWithContext SET SIZE (1..MAX) OF SEQUENCE {
///         distingAttrValue [0] ATTRIBUTE.&Type ({SupportedAttributes}{@type}) OPTIONAL,
///         contextList SET SIZE (1..MAX) OF Context
///     } OPTIONAL
/// }
/// ```
///
/// [RFC 5280 Section 4.1.2.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct RelativeDistinguishedName(pub(crate) SetOfVec<AttributeTypeAndValue>);

impl RelativeDistinguishedName {
    /// Is this [`RelativeDistinguishedName`] empty?
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate over this [`RelativeDistinguishedName`].
    pub fn iter(&self) -> impl Iterator<Item = &AttributeTypeAndValue> {
        self.0.iter()
    }

    /// Length of this [`RelativeDistinguishedName`].
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Insert an [`AttributeTypeAndValue`] into this [`RelativeDistinguishedName`]. Must be unique.
    pub fn insert(&mut self, item: AttributeTypeAndValue) -> Result<(), der::Error> {
        self.0.insert(item)
    }
}

/// Parse a [`RelativeDistinguishedName`] string.
///
/// This function follows the rules in [RFC 4514].
///
/// [RFC 4514]: https://datatracker.ietf.org/doc/html/rfc4514
impl FromStr for RelativeDistinguishedName {
    type Err = der::Error;

    fn from_str(s: &str) -> der::Result<Self> {
        split(s, b'+')
            .map(AttributeTypeAndValue::from_str)
            .collect::<der::Result<Vec<_>>>()?
            .try_into()
            .map(Self)
    }
}

impl TryFrom<Vec<AttributeTypeAndValue>> for RelativeDistinguishedName {
    type Error = der::Error;

    fn try_from(vec: Vec<AttributeTypeAndValue>) -> der::Result<RelativeDistinguishedName> {
        Ok(RelativeDistinguishedName(SetOfVec::try_from(vec)?))
    }
}

/// Serializes the structure according to the rules in [RFC 4514].
///
/// [RFC 4514]: https://datatracker.ietf.org/doc/html/rfc4514
impl fmt::Display for RelativeDistinguishedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, atv) in self.0.iter().enumerate() {
            match i {
                0 => write!(f, "{atv}")?,
                _ => write!(f, "+{atv}")?,
            }
        }

        Ok(())
    }
}

impl_newtype!(RelativeDistinguishedName, SetOfVec<AttributeTypeAndValue>);
