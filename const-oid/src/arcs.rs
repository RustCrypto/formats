//! Arcs are integer values which exist within an OID's hierarchy.

use crate::{Error, Result};

#[cfg(doc)]
use crate::ObjectIdentifier;

/// Type alias used to represent an "arc", i.e. integer identifier value, where an OID comprises a
/// sequence of arcs.
///
/// X.660 does not define a maximum size of an arc. We instead follow Mozilla* conventions for
/// maximum values of an arc, with a maximum value of 2^32-1 (4294967295), a.k.a. [`u32::MAX`]
/// with [`Arc`] being a type alias for [`u32`].
///
/// Note that this means we deliberately do *NOT* support UUIDs used as OIDs.
///
/// *NOTE: please see this study for a survey of how various OID libraries handle maximum arcs:
/// <https://misc.daniel-marschall.de/asn.1/oid_facts.html>
pub type Arc = u32;

/// Maximum value of the first arc in an OID.
pub(crate) const ARC_MAX_FIRST: Arc = 2;

/// Maximum value of the second arc in an OID.
pub(crate) const ARC_MAX_SECOND: Arc = 39;

/// [`Iterator`] over [`Arc`] values (a.k.a. nodes) in an [`ObjectIdentifier`].
///
/// This iterates over all arcs in an OID, including the root.
pub struct Arcs<'a> {
    /// OID bytes we're iterating over.
    bytes: &'a [u8],

    /// Current position within the serialized BER bytes of this OID.
    cursor: Option<usize>,
}

impl<'a> Arcs<'a> {
    /// Create a new iterator over an OID encoded as BER bytes.
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            cursor: None,
        }
    }

    /// Try to parse the next arc in this OID.
    ///
    /// This method is fallible so it can be used as a first pass to determine
    /// that the arcs in the OID are well-formed.
    pub(crate) fn try_next(&mut self) -> Result<Option<Arc>> {
        match self.cursor {
            // Indicates we're on the root arc
            None => {
                let root_byte = *self.bytes.first().ok_or(Error::Empty)?;
                let root = RootArcs::try_from(root_byte)?;
                self.cursor = Some(0);
                Ok(Some(root.first_arc()))
            }
            Some(0) => {
                let root = RootArcs::try_from(self.bytes[0])?;
                self.cursor = Some(1);
                Ok(Some(root.second_arc()))
            }
            Some(offset) => {
                let mut result: Arc = 0;
                let mut arc_bytes = 0;

                loop {
                    let len = checked_add!(offset, arc_bytes);

                    match self.bytes.get(len).cloned() {
                        Some(byte) => {
                            arc_bytes = checked_add!(arc_bytes, 1);

                            // A five byte arc can still exceed `Arc`, so the digits are
                            // accumulated with overflow checking rather than by counting
                            // bytes.
                            result = match result
                                .checked_mul(0x80)
                                .and_then(|result| result.checked_add((byte & 0b0111_1111) as Arc))
                            {
                                Some(result) => result,
                                None => return Err(Error::ArcTooBig),
                            };

                            if byte & 0b1000_0000 == 0 {
                                self.cursor = Some(checked_add!(offset, arc_bytes));
                                return Ok(Some(result));
                            }
                        }
                        None => {
                            if arc_bytes == 0 {
                                return Ok(None);
                            } else {
                                return Err(Error::Base128);
                            }
                        }
                    }
                }
            }
        }
    }
}

impl Iterator for Arcs<'_> {
    type Item = Arc;

    fn next(&mut self) -> Option<Arc> {
        // ObjectIdentifier constructors should ensure the OID is well-formed
        self.try_next().expect("OID malformed")
    }
}

/// Byte containing the first and second arcs of an OID.
///
/// This is represented this way in order to reduce the overall size of the
/// [`ObjectIdentifier`] struct.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct RootArcs(u8);

impl RootArcs {
    /// Create [`RootArcs`] from the first and second arc values represented
    /// as `Arc` integers.
    pub(crate) const fn new(first_arc: Arc, second_arc: Arc) -> Result<Self> {
        if first_arc > ARC_MAX_FIRST {
            return Err(Error::ArcInvalid { arc: first_arc });
        }

        if second_arc > ARC_MAX_SECOND {
            return Err(Error::ArcInvalid { arc: second_arc });
        }

        // The checks above ensure this operation will not overflow
        #[allow(clippy::arithmetic_side_effects)]
        let byte = (first_arc * (ARC_MAX_SECOND + 1)) as u8 + second_arc as u8;

        Ok(Self(byte))
    }

    /// Get the value of the first arc
    #[allow(clippy::arithmetic_side_effects)]
    pub(crate) const fn first_arc(self) -> Arc {
        self.0 as Arc / (ARC_MAX_SECOND + 1)
    }

    /// Get the value of the second arc
    #[allow(clippy::arithmetic_side_effects)]
    pub(crate) const fn second_arc(self) -> Arc {
        self.0 as Arc % (ARC_MAX_SECOND + 1)
    }
}

impl TryFrom<u8> for RootArcs {
    type Error = Error;

    // Ensured not to overflow by constructor invariants
    #[allow(clippy::arithmetic_side_effects)]
    fn try_from(octet: u8) -> Result<Self> {
        let first = octet as Arc / (ARC_MAX_SECOND + 1);
        let second = octet as Arc % (ARC_MAX_SECOND + 1);
        let result = Self::new(first, second)?;
        debug_assert_eq!(octet, result.0);
        Ok(result)
    }
}

impl From<RootArcs> for u8 {
    fn from(root_arcs: RootArcs) -> u8 {
        root_arcs.0
    }
}
