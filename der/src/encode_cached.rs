use crate::{DecodeValue, EncodeValue, FixedTag, Header, Length, Result, Tag, ValueOrd, Writer};
use core::{cell::Cell, cmp::Ordering, fmt};

/// Caches once-computed length of the object, when encoding big data structures.
///
/// For example `Vec<EncodeValueLenCached<Vec<()>>>` won't need to calculate inner `Vec`'s length twice.
///
/// ```rust
/// use der::{asn1::SequenceOf, Encode, EncodeValueLenCached};
/// let mut big_vec = SequenceOf::<EncodeValueLenCached<SequenceOf<(), 128>>, 1>::new();
/// let mut inner_vec = SequenceOf::new();
/// for _ in 0..128 {
///     inner_vec.add(());
/// }
/// big_vec.add(inner_vec.into());
///
/// let mut buf = [0u8; 300];
///
/// // Here, inner SequenceOf calculates it's value length once
/// big_vec.encode_to_slice(&mut buf).unwrap();
/// ```
pub struct EncodeValueLenCached<T> {
    cached_len: Cell<Option<Length>>,

    /// Object, that might implement [`EncodeValue`], [`DecodeValue`] or both.
    pub value: T,
}

impl<T> EncodeValueLenCached<T> {
    /// Clears cache, in cases when [`EncodeValue::value_len`] was called by accident,
    ///
    /// without subsequent [`EncodeValue::encode_value`].
    pub fn clear_cache(&self) {
        self.cached_len.set(None)
    }
}

impl<T: Clone> Clone for EncodeValueLenCached<T> {
    fn clone(&self) -> Self {
        Self {
            cached_len: Cell::new(None),
            value: self.value.clone(),
        }
    }
}

impl<T: Default> Default for EncodeValueLenCached<T> {
    fn default() -> Self {
        Self {
            cached_len: Cell::new(None),
            value: Default::default(),
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for EncodeValueLenCached<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt(f)
    }
}

impl<T: fmt::Display> fmt::Display for EncodeValueLenCached<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt(f)
    }
}

impl<T> AsRef<T> for EncodeValueLenCached<T> {
    fn as_ref(&self) -> &T {
        &self.value
    }
}

impl<T> EncodeValue for EncodeValueLenCached<T>
where
    T: EncodeValue,
{
    fn value_len(&self) -> Result<Length> {
        // Prevent calculating the same length twice
        if let Some(len) = self.cached_len.get() {
            return Ok(len);
        }
        let len = self.value.value_len()?;
        self.cached_len.set(Some(len));
        Ok(len)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        // Cached length won't be needed in this encoding pass again, so clear it.
        // Also, this prevents bugs where internal data changes but the length does not.
        self.cached_len.set(None);
        self.value.encode_value(writer)
    }
}

impl<'a, T> DecodeValue<'a> for EncodeValueLenCached<T>
where
    T: DecodeValue<'a>,
{
    type Error = T::Error;

    fn decode_value<R: crate::Reader<'a>>(
        reader: &mut R,
        header: Header,
    ) -> core::result::Result<Self, Self::Error> {
        Ok(EncodeValueLenCached {
            cached_len: Cell::new(None),
            value: T::decode_value(reader, header)?,
        })
    }
}

impl<T> ValueOrd for EncodeValueLenCached<T>
where
    T: ValueOrd,
{
    fn value_cmp(&self, other: &Self) -> Result<Ordering> {
        self.value.value_cmp(&other.value)
    }
}

// FixedTag is more important than Tagged, because FixedTag is used by Choice macro
impl<T: FixedTag> FixedTag for EncodeValueLenCached<T> {
    const TAG: Tag = T::TAG;
}

impl<T> From<T> for EncodeValueLenCached<T> {
    fn from(value: T) -> Self {
        Self {
            cached_len: Cell::new(None),
            value,
        }
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod test {
    use core::cell::Cell;
    use std::vec::Vec;

    use crate::{Encode, EncodeValue, EncodeValueLenCached, FixedTag, Length, Result, Tag, Writer};

    #[derive(Clone, Default)]
    struct SusString {
        len_query_counter: Cell<u8>,
    }

    impl EncodeValue for SusString {
        #[allow(clippy::panic, clippy::panic_in_result_fn)]
        fn value_len(&self) -> Result<Length> {
            let counter = self.len_query_counter.get();
            if counter >= 2 {
                panic!("value_len called more than twice");
            }
            self.len_query_counter.set(counter + 1);
            Ok(Length::new(1))
        }

        fn encode_value(&self, encoder: &mut impl Writer) -> Result<()> {
            encoder.write_byte(0xAA)?;
            Ok(())
        }
    }
    impl FixedTag for SusString {
        const TAG: Tag = Tag::Utf8String;
    }

    /// Inner `SusString` objects should calculate it's length only twice.
    ///
    /// Once when encoding outer SEQUENCE, second time for itself.
    #[test]
    fn value_len_called_2_times() {
        let big_vec: Vec<EncodeValueLenCached<Vec<SusString>>> =
            vec![vec![SusString::default(); 1000].into()];

        let bigger_vec = vec![big_vec];
        bigger_vec.to_der().expect("to_der");

        assert_eq!(2, bigger_vec[0][0].as_ref()[0].len_query_counter.get());
    }
}
