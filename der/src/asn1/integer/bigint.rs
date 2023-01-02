//! "Big" ASN.1 `INTEGER` types.

use super::{int, uint};
use crate::{
    asn1::AnyRef, ord::OrdIsValueOrd, BytesRef, DecodeValue, EncodeValue, Error, ErrorKind,
    FixedTag, Header, Length, Reader, Result, Tag, Writer,
};

/// A "big" ASN.1 `INTEGER` type that can hold both positive and negative
/// values.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum IntRef<'a> {
    /// Unsigned integers.
    Unsigned(UintRef<'a>),

    /// Signed integers. These are functionally always negative,
    /// since we represent positive signed integers using the unsigned variant.
    Signed(SintRef<'a>),
}

impl<'a> From<UintRef<'a>> for IntRef<'a> {
    fn from(value: UintRef<'a>) -> Self {
        Self::Unsigned(value)
    }
}

impl<'a> From<SintRef<'a>> for IntRef<'a> {
    fn from(value: SintRef<'a>) -> Self {
        Self::Signed(value)
    }
}

impl<'a> IntRef<'a> {
    /// Borrow the inner byte slice which contains the least significant bytes
    /// of a big endian integer value with all leading ones stripped.
    pub fn as_bytes(&self) -> &'a [u8] {
        match self {
            IntRef::Unsigned(i) => i.inner.as_slice(),
            IntRef::Signed(i) => i.inner.as_slice(),
        }
    }

    /// Get the length of this [`IntRef`] in bytes.
    pub fn len(&self) -> Length {
        match self {
            IntRef::Unsigned(i) => i.len(),
            IntRef::Signed(i) => i.len(),
        }
    }

    /// Is the inner byte slice empty?
    pub fn is_empty(self) -> bool {
        match self {
            IntRef::Unsigned(i) => i.is_empty(),
            IntRef::Signed(i) => i.is_empty(),
        }
    }
}

impl<'a> DecodeValue<'a> for IntRef<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        let bytes = BytesRef::decode_value(reader, header)?.as_slice();

        // Try to decode as unsigned first, then signed.
        let result: Self = match uint::decode_to_slice(bytes) {
            Ok(result) => Ok(UintRef::new(result)?.into()),
            Err(Error {
                kind: ErrorKind::Value { .. },
                ..
            }) => Ok(SintRef::new(int::decode_to_slice(bytes)?)?.into()),
            Err(e) => Err(e),
        }?;

        // Ensure we compute the same encoded length as the original any value.
        if result.value_len()? != header.length {
            return Err(Self::TAG.non_canonical_error());
        }

        Ok(result)
    }
}

impl<'a> EncodeValue for IntRef<'a> {
    fn value_len(&self) -> Result<Length> {
        match self {
            IntRef::Unsigned(i) => i.value_len(),
            IntRef::Signed(i) => i.value_len(),
        }
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        match self {
            IntRef::Unsigned(i) => i.encode_value(writer),
            IntRef::Signed(i) => i.encode_value(writer),
        }
    }
}

impl<'a> From<&IntRef<'a>> for IntRef<'a> {
    fn from(value: &IntRef<'a>) -> IntRef<'a> {
        *value
    }
}

impl<'a> TryFrom<AnyRef<'a>> for IntRef<'a> {
    type Error = Error;

    fn try_from(any: AnyRef<'a>) -> Result<IntRef<'a>> {
        any.decode_as()
    }
}

impl<'a> FixedTag for IntRef<'a> {
    const TAG: Tag = Tag::Integer;
}

impl<'a> OrdIsValueOrd for IntRef<'a> {}

/// "Big" negative ASN.1 `INTEGER` type.
///
/// Provides direct access to the underlying big endian bytes which comprise
/// an negative integer value.
///
/// Intended for use cases like very large integers that are used in
/// cryptographic applications (e.g. keys, signatures).
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct SintRef<'a> {
    /// Inner value
    inner: BytesRef<'a>,
}

impl<'a> SintRef<'a> {
    /// Create a new [`SintRef`] from a byte slice.
    pub fn new(bytes: &'a [u8]) -> Result<Self> {
        let inner = BytesRef::new(int::strip_leading_ones(bytes))
            .map_err(|_| ErrorKind::Length { tag: Self::TAG })?;

        Ok(Self { inner })
    }

    /// Borrow the inner byte slice which contains the least significant bytes
    /// of a big endian integer value with all leading ones stripped.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.inner.as_slice()
    }

    /// Get the length of this [`SintRef`] in bytes.
    pub fn len(&self) -> Length {
        self.inner.len()
    }

    /// Is the inner byte slice empty?
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl<'a> DecodeValue<'a> for SintRef<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        let bytes = BytesRef::decode_value(reader, header)?.as_slice();
        let result = Self::new(int::decode_to_slice(bytes)?)?;

        // Ensure we compute the same encoded length as the original any value.
        if result.value_len()? != header.length {
            return Err(Self::TAG.non_canonical_error());
        }

        Ok(result)
    }
}

impl<'a> EncodeValue for SintRef<'a> {
    fn value_len(&self) -> Result<Length> {
        int::encoded_len(self.inner.as_slice())
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        // Add leading `0xFF` byte if required
        if self.value_len()? > self.len() {
            writer.write_byte(0xFF)?;
        }

        writer.write(self.as_bytes())
    }
}

impl<'a> From<&SintRef<'a>> for SintRef<'a> {
    fn from(value: &SintRef<'a>) -> SintRef<'a> {
        *value
    }
}

impl<'a> TryFrom<AnyRef<'a>> for SintRef<'a> {
    type Error = Error;

    fn try_from(any: AnyRef<'a>) -> Result<SintRef<'a>> {
        any.decode_as()
    }
}

impl<'a> FixedTag for SintRef<'a> {
    const TAG: Tag = Tag::Integer;
}

impl<'a> OrdIsValueOrd for SintRef<'a> {}

/// "Big" unsigned ASN.1 `INTEGER` type.
///
/// Provides direct access to the underlying big endian bytes which comprise an
/// unsigned integer value.
///
/// Intended for use cases like very large integers that are used in
/// cryptographic applications (e.g. keys, signatures).
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct UintRef<'a> {
    /// Inner value
    inner: BytesRef<'a>,
}

impl<'a> UintRef<'a> {
    /// Create a new [`UintRef`] from a byte slice.
    pub fn new(bytes: &'a [u8]) -> Result<Self> {
        let inner = BytesRef::new(uint::strip_leading_zeroes(bytes))
            .map_err(|_| ErrorKind::Length { tag: Self::TAG })?;

        Ok(Self { inner })
    }

    /// Borrow the inner byte slice which contains the least significant bytes
    /// of a big endian integer value with all leading zeros stripped.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.inner.as_slice()
    }

    /// Get the length of this [`UintRef`] in bytes.
    pub fn len(&self) -> Length {
        self.inner.len()
    }

    /// Is the inner byte slice empty?
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl<'a> DecodeValue<'a> for UintRef<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        let bytes = BytesRef::decode_value(reader, header)?.as_slice();
        let result = Self::new(uint::decode_to_slice(bytes)?)?;

        // Ensure we compute the same encoded length as the original any value.
        if result.value_len()? != header.length {
            return Err(Self::TAG.non_canonical_error());
        }

        Ok(result)
    }
}

impl<'a> EncodeValue for UintRef<'a> {
    fn value_len(&self) -> Result<Length> {
        uint::encoded_len(self.inner.as_slice())
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        // Add leading `0x00` byte if required
        if self.value_len()? > self.len() {
            writer.write_byte(0)?;
        }

        writer.write(self.as_bytes())
    }
}

impl<'a> From<&UintRef<'a>> for UintRef<'a> {
    fn from(value: &UintRef<'a>) -> UintRef<'a> {
        *value
    }
}

impl<'a> TryFrom<AnyRef<'a>> for UintRef<'a> {
    type Error = Error;

    fn try_from(any: AnyRef<'a>) -> Result<UintRef<'a>> {
        any.decode_as()
    }
}

impl<'a> FixedTag for UintRef<'a> {
    const TAG: Tag = Tag::Integer;
}

impl<'a> OrdIsValueOrd for UintRef<'a> {}

#[cfg(feature = "alloc")]
pub use self::allocating::{Int, Sint, Uint};

#[cfg(feature = "alloc")]
mod allocating {
    use super::{super::int, super::uint, IntRef, SintRef, UintRef};
    use crate::{
        asn1::AnyRef,
        ord::OrdIsValueOrd,
        referenced::{OwnedToRef, RefToOwned},
        BytesOwned, DecodeValue, EncodeValue, Error, ErrorKind, FixedTag, Header, Length, Reader,
        Result, Tag, Writer,
    };

    /// "Big" ASN.1 `INTEGER` type that can hold both positive and negative
    /// values.
    #[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
    pub enum Int {
        /// Unsigned integers.
        Unsigned(Uint),

        /// Signed integers. These are functionally always negative,
        /// since we represent positive signed integers using the unsigned variant.
        Signed(Sint),
    }

    impl From<Sint> for Int {
        fn from(value: Sint) -> Self {
            Int::Signed(value)
        }
    }

    impl From<Uint> for Int {
        fn from(value: Uint) -> Self {
            Int::Unsigned(value)
        }
    }

    impl Int {
        /// Borrow the inner byte slice which contains the least significant bytes
        /// of a big endian integer value with all leading ones stripped.
        pub fn as_bytes(&self) -> &[u8] {
            match self {
                Int::Unsigned(i) => i.inner.as_slice(),
                Int::Signed(i) => i.inner.as_slice(),
            }
        }

        /// Get the length of this [`Int`] in bytes.
        pub fn len(&self) -> Length {
            match self {
                Int::Unsigned(i) => i.inner.len(),
                Int::Signed(i) => i.inner.len(),
            }
        }

        /// Is the inner byte slice empty?
        pub fn is_empty(&self) -> bool {
            match self {
                Int::Unsigned(i) => i.inner.is_empty(),
                Int::Signed(i) => i.inner.is_empty(),
            }
        }
    }

    impl<'a> DecodeValue<'a> for Int {
        fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
            let bytes = BytesOwned::decode_value(reader, header)?;

            // Try to decode as unsigned first, then signed.
            let result: Self = match uint::decode_to_slice(bytes.as_slice()) {
                Ok(result) => Ok(Uint::new(result)?.into()),
                Err(Error {
                    kind: ErrorKind::Value { .. },
                    ..
                }) => Ok(Sint::new(int::decode_to_slice(bytes.as_slice())?)?.into()),
                Err(e) => Err(e),
            }?;

            // Ensure we compute the same encoded length as the original any value.
            if result.value_len()? != header.length {
                return Err(Self::TAG.non_canonical_error());
            }

            Ok(result)
        }
    }

    impl EncodeValue for Int {
        fn value_len(&self) -> Result<Length> {
            match self {
                Int::Unsigned(i) => i.value_len(),
                Int::Signed(i) => i.value_len(),
            }
        }

        fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
            match self {
                Int::Unsigned(i) => i.encode_value(writer),
                Int::Signed(i) => i.encode_value(writer),
            }
        }
    }

    impl<'a> From<&IntRef<'a>> for Int {
        fn from(value: &IntRef<'a>) -> Int {
            match value {
                IntRef::Unsigned(i) => Int::Unsigned(i.into()),
                IntRef::Signed(i) => Int::Signed(i.into()),
            }
        }
    }

    impl<'a> TryFrom<AnyRef<'a>> for Int {
        type Error = Error;

        fn try_from(any: AnyRef<'a>) -> Result<Int> {
            any.decode_as()
        }
    }

    impl FixedTag for Int {
        const TAG: Tag = Tag::Integer;
    }

    impl OrdIsValueOrd for Int {}

    /// "Big" negative ASN.1 `INTEGER` type.
    ///
    /// Provides direct storage for the big endian bytes which comprise a
    /// negative integer value.
    ///
    /// Intended for use cases like very large integers that are used in
    /// cryptographic applications (e.g. keys, signatures).
    #[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
    pub struct Sint {
        /// Inner value
        inner: BytesOwned,
    }

    impl Sint {
        /// Create a new [`Int`] from a byte slice.
        pub fn new(bytes: &[u8]) -> Result<Self> {
            let inner = BytesOwned::new(int::strip_leading_ones(bytes))
                .map_err(|_| ErrorKind::Length { tag: Self::TAG })?;

            Ok(Self { inner })
        }

        /// Borrow the inner byte slice which contains the least significant bytes
        /// of a big endian integer value with all leading ones stripped.
        pub fn as_bytes(&self) -> &[u8] {
            self.inner.as_slice()
        }

        /// Get the length of this [`Int`] in bytes.
        pub fn len(&self) -> Length {
            self.inner.len()
        }

        /// Is the inner byte slice empty?
        pub fn is_empty(&self) -> bool {
            self.inner.is_empty()
        }
    }

    impl<'a> DecodeValue<'a> for Sint {
        fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
            let bytes = BytesOwned::decode_value(reader, header)?;
            let result = Self::new(int::decode_to_slice(bytes.as_slice())?)?;

            // Ensure we compute the same encoded length as the original any value.
            if result.value_len()? != header.length {
                return Err(Self::TAG.non_canonical_error());
            }

            Ok(result)
        }
    }

    impl EncodeValue for Sint {
        fn value_len(&self) -> Result<Length> {
            int::encoded_len(self.inner.as_slice())
        }

        fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
            // Add leading `0xFF` byte if required
            if self.value_len()? > self.len() {
                writer.write_byte(0xFF)?;
            }

            writer.write(self.as_bytes())
        }
    }

    impl<'a> From<&SintRef<'a>> for Sint {
        fn from(value: &SintRef<'a>) -> Sint {
            let inner = BytesOwned::new(value.as_bytes()).expect("Invalid Int");
            Sint { inner }
        }
    }

    impl<'a> TryFrom<AnyRef<'a>> for Sint {
        type Error = Error;

        fn try_from(any: AnyRef<'a>) -> Result<Sint> {
            any.decode_as()
        }
    }

    impl FixedTag for Sint {
        const TAG: Tag = Tag::Integer;
    }

    impl OrdIsValueOrd for Sint {}

    impl<'a> RefToOwned<'a> for SintRef<'a> {
        type Owned = Sint;
        fn to_owned(&self) -> Self::Owned {
            let inner = self.inner.to_owned();

            Sint { inner }
        }
    }

    impl OwnedToRef for Sint {
        type Borrowed<'a> = SintRef<'a>;
        fn to_ref(&self) -> Self::Borrowed<'_> {
            let inner = self.inner.to_ref();

            SintRef { inner }
        }
    }

    /// "Big" unsigned ASN.1 `INTEGER` type.
    ///
    /// Provides direct storage for the big endian bytes which comprise an
    /// unsigned integer value.
    ///
    /// Intended for use cases like very large integers that are used in
    /// cryptographic applications (e.g. keys, signatures).
    #[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
    pub struct Uint {
        /// Inner value
        inner: BytesOwned,
    }

    impl Uint {
        /// Create a new [`Uint`] from a byte slice.
        pub fn new(bytes: &[u8]) -> Result<Self> {
            let inner = BytesOwned::new(uint::strip_leading_zeroes(bytes))
                .map_err(|_| ErrorKind::Length { tag: Self::TAG })?;

            Ok(Self { inner })
        }

        /// Borrow the inner byte slice which contains the least significant bytes
        /// of a big endian integer value with all leading zeros stripped.
        pub fn as_bytes(&self) -> &[u8] {
            self.inner.as_slice()
        }

        /// Get the length of this [`Uint`] in bytes.
        pub fn len(&self) -> Length {
            self.inner.len()
        }

        /// Is the inner byte slice empty?
        pub fn is_empty(&self) -> bool {
            self.inner.is_empty()
        }
    }

    impl<'a> DecodeValue<'a> for Uint {
        fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
            let bytes = BytesOwned::decode_value(reader, header)?;
            let result = Self::new(uint::decode_to_slice(bytes.as_slice())?)?;

            // Ensure we compute the same encoded length as the original any value.
            if result.value_len()? != header.length {
                return Err(Self::TAG.non_canonical_error());
            }

            Ok(result)
        }
    }

    impl EncodeValue for Uint {
        fn value_len(&self) -> Result<Length> {
            uint::encoded_len(self.inner.as_slice())
        }

        fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
            // Add leading `0x00` byte if required
            if self.value_len()? > self.len() {
                writer.write_byte(0)?;
            }

            writer.write(self.as_bytes())
        }
    }

    impl<'a> From<&UintRef<'a>> for Uint {
        fn from(value: &UintRef<'a>) -> Uint {
            let inner = BytesOwned::new(value.as_bytes()).expect("Invalid Uint");
            Uint { inner }
        }
    }

    impl<'a> TryFrom<AnyRef<'a>> for Uint {
        type Error = Error;

        fn try_from(any: AnyRef<'a>) -> Result<Uint> {
            any.decode_as()
        }
    }

    impl FixedTag for Uint {
        const TAG: Tag = Tag::Integer;
    }

    impl OrdIsValueOrd for Uint {}

    impl<'a> RefToOwned<'a> for UintRef<'a> {
        type Owned = Uint;
        fn to_owned(&self) -> Self::Owned {
            let inner = self.inner.to_owned();

            Uint { inner }
        }
    }

    impl OwnedToRef for Uint {
        type Borrowed<'a> = UintRef<'a>;
        fn to_ref(&self) -> Self::Borrowed<'_> {
            let inner = self.inner.to_ref();

            UintRef { inner }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{IntRef, UintRef};
    use crate::{
        asn1::{integer::tests::*, AnyRef, SintRef},
        Decode, Encode, ErrorKind, SliceWriter, Tag,
    };

    #[test]
    fn decode_int_bytes() {
        for &example in &[
            I0_BYTES,
            I127_BYTES,
            I128_BYTES,
            I255_BYTES,
            I256_BYTES,
            I32767_BYTES,
        ] {
            let int = IntRef::from_der(example).unwrap();
            assert!(matches!(int, IntRef::Unsigned(_)));
            assert_eq!(
                UintRef::from_der(example).unwrap().as_bytes(),
                int.as_bytes()
            );
        }

        for &example in &[INEG128_BYTES, INEG129_BYTES, INEG32768_BYTES] {
            let int = IntRef::from_der(example).unwrap();
            assert!(matches!(int, IntRef::Signed(_)));
            assert_eq!(
                SintRef::from_der(example).unwrap().as_bytes(),
                int.as_bytes()
            );
        }
    }

    #[test]
    fn encode_int_bytes() {
        for &example in &[
            I0_BYTES,
            I127_BYTES,
            I128_BYTES,
            I255_BYTES,
            I256_BYTES,
            I32767_BYTES,
            I65535_BYTES,
            INEG128_BYTES,
            INEG129_BYTES,
            INEG32768_BYTES,
        ] {
            let uint = IntRef::from_der(example).unwrap();

            let mut buf = [0u8; 128];
            let mut encoder = SliceWriter::new(&mut buf);
            uint.encode(&mut encoder).unwrap();

            let result = encoder.finish().unwrap();
            assert_eq!(example, result);
        }
    }

    #[test]
    fn decode_sint_bytes() {
        // Positive numbers do not decode.
        assert!(SintRef::from_der(I127_BYTES).is_err());
        assert!(SintRef::from_der(I128_BYTES).is_err());
        assert!(SintRef::from_der(I255_BYTES).is_err());

        assert!(SintRef::from_der(I256_BYTES).is_err());

        assert!(SintRef::from_der(I32767_BYTES).is_err());

        // Negative integers (and zero) decode.
        assert_eq!(&[0], SintRef::from_der(I0_BYTES).unwrap().as_bytes());
        assert_eq!(&[128], SintRef::from_der(INEG128_BYTES).unwrap().as_bytes());
        assert_eq!(&[127], SintRef::from_der(INEG129_BYTES).unwrap().as_bytes());
        assert_eq!(
            &[128, 0],
            SintRef::from_der(INEG32768_BYTES).unwrap().as_bytes()
        );
    }

    #[test]
    fn encode_sint_bytes() {
        for &example in &[INEG128_BYTES, INEG129_BYTES, INEG32768_BYTES] {
            let uint = SintRef::from_der(example).unwrap();

            let mut buf = [0u8; 128];
            let mut encoder = SliceWriter::new(&mut buf);
            uint.encode(&mut encoder).unwrap();

            let result = encoder.finish().unwrap();
            assert_eq!(example, result);
        }
    }

    #[test]
    fn decode_uint_bytes() {
        assert_eq!(&[0], UintRef::from_der(I0_BYTES).unwrap().as_bytes());
        assert_eq!(&[127], UintRef::from_der(I127_BYTES).unwrap().as_bytes());
        assert_eq!(&[128], UintRef::from_der(I128_BYTES).unwrap().as_bytes());
        assert_eq!(&[255], UintRef::from_der(I255_BYTES).unwrap().as_bytes());

        assert_eq!(
            &[0x01, 0x00],
            UintRef::from_der(I256_BYTES).unwrap().as_bytes()
        );

        assert_eq!(
            &[0x7F, 0xFF],
            UintRef::from_der(I32767_BYTES).unwrap().as_bytes()
        );
    }

    #[test]
    fn encode_uint_bytes() {
        for &example in &[
            I0_BYTES,
            I127_BYTES,
            I128_BYTES,
            I255_BYTES,
            I256_BYTES,
            I32767_BYTES,
        ] {
            let uint = UintRef::from_der(example).unwrap();

            let mut buf = [0u8; 128];
            let mut encoder = SliceWriter::new(&mut buf);
            uint.encode(&mut encoder).unwrap();

            let result = encoder.finish().unwrap();
            assert_eq!(example, result);
        }
    }

    #[test]
    fn reject_oversize_without_extra_zero() {
        let err = UintRef::try_from(AnyRef::new(Tag::Integer, &[0x81]).unwrap())
            .err()
            .unwrap();

        assert_eq!(err.kind(), ErrorKind::Value { tag: Tag::Integer });
    }
}
