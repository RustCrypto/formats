//! # Variable length vectors
//!
//! While the TLS RFC 8446 only specifies vectors with fixed length length fields
//! the QUIC RFC 9000 defines a variable length integer encoding.
//!
//! Note that we require, as the MLS specification does, that vectors have to
//! use the minimum number of bytes necessary for the encoding.
//! This ensures that encodings are unique.

use alloc::vec::Vec;

use crate::{Deserialize, Error, Serialize, Size};

const MAX_LEN: u64 = 0x3fff_ffff_ffff_ffff; // <= (1<<62)-1

/// Read the length of a variable-length vector.
///
/// This function assumes that the reader is at the start of a variable length
/// vector and returns an error if there's not a single byte to read.
///
/// The length and number of bytes read are returned.
#[inline]
fn read_variable_length<R: std::io::Read>(bytes: &mut R) -> Result<(usize, usize), Error> {
    // The length is encoded in the first two bits of the first byte.
    let mut len_len_byte = [0u8; 1];
    if bytes.read(&mut len_len_byte)? == 0 {
        // Return in case there's nothing to read and this is just an
        // empty vector.
        return Ok((0, 0));
    }

    let mut length: usize = (len_len_byte[0] & 0x3F).into();
    let len_len = (len_len_byte[0] >> 6).into();
    debug_assert!(len_len <= 3);
    if len_len > 3 {
        return Err(Error::InvalidVectorLength);
    }
    for _ in 0..len_len {
        let mut next = [0u8; 1];
        bytes.read(&mut next)?;
        length = (length << 8) + usize::from(next[0]);
    }

    Ok((length, len_len))
}

#[inline]
fn length_encoding_bytes(length: u64) -> usize {
    debug_assert!(length <= MAX_LEN);
    if length < 0x40 {
        1
    } else if length < 0x3fff {
        2
    } else if length < 0x3fff_ffff {
        4
    } else {
        8
    }
}

// === (De)Serialize for `Vec<T>` and &[T].

impl<T: Serialize + std::fmt::Debug> Serialize for Vec<T> {
    #[cfg(feature = "std")]
    #[inline(always)]
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.as_slice().tls_serialize(writer)
    }
}

impl<T: Size> Size for Vec<T> {
    #[cfg(feature = "std")]
    #[inline(always)]
    fn tls_serialized_len(&self) -> usize {
        self.as_slice().tls_serialized_len()
    }
}

impl<T: Deserialize> Deserialize for Vec<T> {
    #[cfg(feature = "std")]
    #[inline(always)]
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, Error> {
        let (length, len_len) = read_variable_length(bytes)?;
        if length == 0 {
            // An empty vector.
            return Ok(Vec::new());
        }

        let mut result = Vec::new();
        let mut read = len_len;
        while (read - len_len) < length as usize {
            let element = T::tls_deserialize(bytes)?;
            read += element.tls_serialized_len();
            result.push(element);
        }
        Ok(result)
    }
}

#[inline(always)]
fn write_length<W: std::io::Write>(writer: &mut W, content_length: usize) -> Result<usize, Error> {
    let len_len = length_encoding_bytes(content_length.try_into()?);
    debug_assert!(len_len <= 8, "Invalid vector len_len {}", len_len);
    if len_len > 8 {
        return Err(Error::InvalidVectorLength);
    }
    let mut length_bytes = vec![0u8; len_len];
    match len_len {
        1 => length_bytes[0] = 0x00,
        2 => length_bytes[0] = 0x40,
        4 => length_bytes[0] = 0xc0,
        8 => length_bytes[0] = 0x80,
        _ => {
            debug_assert!(false, "Invalid vector len_len {}", len_len);
            return Err(Error::InvalidVectorLength);
        }
    }
    let mut len = content_length;
    for b in length_bytes.iter_mut().rev() {
        *b |= (len & 0xFF) as u8;
        len >>= 8;
    }
    writer.write_all(&mut length_bytes)?;
    Ok(len_len)
}

impl<T: Serialize + std::fmt::Debug> Serialize for &[T] {
    #[cfg(feature = "std")]
    #[inline(always)]
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        // We need to pre-compute the length of the content.
        // This requires more computations but the other option would be to buffer
        // the entire content, which can end up requiring a lot of memory.
        let content_length = self.iter().fold(0, |acc, e| acc + e.tls_serialized_len());
        let len_len = write_length(writer, content_length)?;

        // Serialize the elements
        #[cfg(debug_assertions)]
        let mut written = 0;
        for e in self.iter() {
            #[cfg(debug_assertions)]
            {
                written += e.tls_serialize(writer)?;
            }
            // We don't care about the length here. We pre-computed it.
            #[cfg(not(debug_assertions))]
            e.tls_serialize(writer)?;
        }
        #[cfg(debug_assertions)]
        debug_assert_eq!(written, content_length);

        Ok(content_length + len_len)
    }
}

impl<T: Size> Size for &[T] {
    #[cfg(feature = "std")]
    #[inline(always)]
    fn tls_serialized_len(&self) -> usize {
        let content_length = self.iter().fold(0, |acc, e| acc + e.tls_serialized_len());
        let len_len = length_encoding_bytes(content_length as u64);
        content_length + len_len
    }
}

// === Vec<u8> and &[u8]

/// Variable-length encoded byte vectors.
/// Use this struct if bytes are encoded.
/// This is faster than the generic version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VLBytes {
    vec: Vec<u8>,
}

impl VLBytes {
    /// Generate a new variable-length byte vector.
    pub fn new(vec: Vec<u8>) -> Self {
        Self { vec }
    }

    /// Get a reference to the vlbytes's vec.
    pub fn as_slice(&self) -> &[u8] {
        self.vec.as_ref()
    }
}

#[inline(always)]
fn tls_serialize_bytes<W: std::io::Write>(writer: &mut W, bytes: &[u8]) -> Result<usize, Error> {
    // Get the byte length of the content, make sure it's not too
    // large and write it out.
    let content_length = bytes.len();

    debug_assert!(
        content_length as u64 <= MAX_LEN,
        "Vector can't be encoded. It's too large. {} >= {}",
        content_length,
        MAX_LEN
    );
    if content_length as u64 > MAX_LEN {
        return Err(Error::InvalidVectorLength);
    }

    let len_len = write_length(writer, content_length)?;

    // Now serialize the elements
    let mut written = 0;
    written += writer.write(bytes)?;

    debug_assert_eq!(
        written, content_length,
        "{} bytes should have been serialized but {} were written",
        content_length, written
    );
    if written != content_length {
        return Err(Error::EncodingError(format!(
            "{} bytes should have been serialized but {} were written",
            content_length, written
        )));
    }
    Ok(written + len_len)
}

#[inline(always)]
fn tls_serialize_bytes_len(bytes: &[u8]) -> usize {
    let content_length = bytes.len();
    let len_len = length_encoding_bytes(content_length as u64);
    content_length + len_len
}

impl Serialize for VLBytes {
    #[cfg(feature = "std")]
    #[inline(always)]
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        tls_serialize_bytes(writer, self.as_slice())
    }
}

impl Size for VLBytes {
    #[cfg(feature = "std")]
    #[inline(always)]
    fn tls_serialized_len(&self) -> usize {
        tls_serialize_bytes_len(self.as_slice())
    }
}

impl Deserialize for VLBytes {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, Error> {
        let (length, _) = read_variable_length(bytes)?;
        if length == 0 {
            return Ok(Self::new(vec![]));
        }

        debug_assert!(
            length <= u16::MAX as usize,
            "Trying to allocate {} bytes. Only {} allowed.",
            length,
            u16::MAX
        );
        if length > u16::MAX as usize {
            return Err(Error::DecodingError(format!(
                "Trying to allocate {} bytes. Only {} allowed.",
                length,
                u16::MAX
            )));
        }
        let mut result = Self {
            vec: vec![0u8; length],
        };
        let read = bytes.read(result.vec.as_mut_slice())?;
        if read == length {
            return Ok(result);
        }

        debug_assert_eq!(
            read, length,
            "Expected to read {} bytes but {} were read.",
            length, read
        );
        Err(Error::DecodingError(format!(
            "{} bytes were read but {} were expected",
            read, length
        )))
    }
}

impl Serialize for &VLBytes {
    #[cfg(feature = "std")]
    #[inline(always)]
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        (*self).tls_serialize(writer)
    }
}

impl Size for &VLBytes {
    #[cfg(feature = "std")]
    #[inline(always)]
    fn tls_serialized_len(&self) -> usize {
        (*self).tls_serialized_len()
    }
}

pub struct VLByteSlice<'a>(pub &'a [u8]);

impl<'a> VLByteSlice<'a> {
    /// Get the raw slice.
    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        self.0
    }
}

impl<'a> Serialize for &VLByteSlice<'a> {
    #[cfg(feature = "std")]
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        tls_serialize_bytes(writer, self.0)
    }
}

impl<'a> Serialize for VLByteSlice<'a> {
    #[cfg(feature = "std")]
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        tls_serialize_bytes(writer, self.0)
    }
}

impl<'a> Size for &VLByteSlice<'a> {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        tls_serialize_bytes_len(self.0)
    }
}

impl<'a> Size for VLByteSlice<'a> {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        tls_serialize_bytes_len(self.0)
    }
}
