/// ASN.1 encoding rules.
///
/// This enum identifies the specific encoding rules which are applied at the time a given document
/// is decoded from a byte/octet serialization.
///
/// In addition to the Distinguished Encoding Rules (DER), this crate also supports a strict subset
/// of the Basic Encoding Rules (BER) which supports the minimum amount of additional productions
/// beyond DER needed to interoperate with other implementations of cryptography-oriented formats
/// which utilize BER, e.g. CMS, PKCS#8.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub enum EncodingRules {
    /// Basic Encoding Rules.
    Ber,

    /// Distinguished Encoding Rules.
    #[default]
    Der,
}
