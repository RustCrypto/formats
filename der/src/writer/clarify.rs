pub(crate) mod commentwriter;
pub(crate) mod hexdisplaylines;

use crate::std::io::Write;
use crate::{Encode, Error, SliceWriter};
use crate::{Length, Result, Tag};
use commentwriter::{CommentWriter, JavaCommentWriter, XmlCommentWriter};
use hexdisplaylines::HexDisplayLines;
use std::borrow::Cow;
use std::println;
use std::string::String;
use std::{boxed::Box, vec::Vec};

use super::Writer;

pub trait EncodeClarifyExt: Encode {
    /// Encode this type as pretty-printed hex DER, with comments.
    fn to_der_clarify(&self, flavor: ClarifyFlavor) -> Result<String> {
        let outputs = self.to_der_clarify_ignorant(flavor);
        // Propagate encode and finish errors
        outputs.raw?;
        Ok(String::from_utf8(outputs.clarify_buf).expect("clarified output to be utf-8"))
    }

    /// Encode this type as pretty-printed hex DER, with comments.
    /// Ignores any errors that occur during [`Encode::encode`].
    fn to_der_clarify_ignorant(&self, flavor: ClarifyFlavor) -> ClarifyOutputs<'static> {
        let len = match self.encoded_len() {
            Ok(len) => len,
            Err(err) => return ClarifyOutputs::from_err(err),
        };

        let mut buf = Vec::with_capacity(u32::from(len) as usize);
        let mut writer = ClarifySliceWriter::new(&mut buf, Vec::new(), flavor);
        let result = self.encode(&mut writer);

        let outputs = writer.finish();
        let outputs = ClarifyOutputs {
            // prioritize Encode::encode errors
            raw: result.and(outputs.raw),
            // but use buffer from finish() (even if encode failed)
            clarify_buf: outputs.clarify_buf,
        };

        outputs.into_owned()
    }
}

impl<T> EncodeClarifyExt for T where T: Encode {}

static INDENT_STR: &str =
    "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

/// [`Writer`] which encodes DER as hex with comments.
pub struct ClarifySliceWriter<'a> {
    writer: SliceWriter<'a>,

    clarifier: Clarifier,
}

/// Clarifier that creates HEX with comments
pub struct Clarifier {
    // Buffer into which debug HEX and comments are written
    clarify_buf: Vec<u8>,

    // Position in the buffer is used to track how long is the current sub-message
    last_position: u32,

    /// Used for debug indentation
    ///
    /// Pushes writer positions on the stack
    depth: Vec<Option<u32>>,

    indent_enabled: bool,
    comment_writer: Box<dyn CommentWriter>,
}

/// Returned by .finish()
pub struct ClarifyOutputs<'a> {
    pub raw: Result<Cow<'a, [u8]>>,
    pub clarify_buf: Vec<u8>,
}

impl<'a> ClarifyOutputs<'a> {
    pub fn from_err(err: Error) -> ClarifyOutputs<'static> {
        ClarifyOutputs {
            raw: Err(err),
            clarify_buf: Vec::new(),
        }
    }

    pub fn into_owned(self) -> ClarifyOutputs<'static> {
        ClarifyOutputs {
            raw: self.raw.map(|raw| Cow::Owned(raw.into_owned())),
            clarify_buf: self.clarify_buf,
        }
    }
    // pub fn and(result: Result<Cow<'a, [u8]>>) {
    //     ClarifyOutputs {
    //         // prioritize Encode::encode errors
    //         raw: result.and(outputs.raw),
    //         clarify_buf: outputs.clarify_buf,
    //     };
    // }
}

#[derive(Copy, Clone, Debug)]
pub enum ClarifyFlavor {
    XmlComments,
    JavaComments,
    RustHex,
}

impl Clarifier {
    pub fn new(clarify_buf: Vec<u8>, flavor: ClarifyFlavor) -> Self {
        Self {
            clarify_buf,

            last_position: 0,
            depth: Vec::new(),

            indent_enabled: true,
            comment_writer: match flavor {
                ClarifyFlavor::XmlComments => Box::new(XmlCommentWriter::default()),
                ClarifyFlavor::JavaComments => Box::new(JavaCommentWriter::default()),
                ClarifyFlavor::RustHex => todo!(),
            },
        }
    }
}

impl<'a> ClarifySliceWriter<'a> {
    /// Create a new encoder with the given byte slice as a backing buffer.
    pub fn new(bytes: &'a mut [u8], clarify_buf: Vec<u8>, flavor: ClarifyFlavor) -> Self {
        Self {
            writer: SliceWriter::new(bytes),
            clarifier: Clarifier::new(clarify_buf, flavor),
        }
    }

    // /// Encode a value which impls the [`Encode`] trait.
    // pub fn encode<T: Encode>(&mut self, encodable: &T) -> Result<()> {
    //     self.writer.encode(encodable)
    // }

    // /// Return an error with the given [`ErrorKind`], annotating it with
    // /// context about where the error occurred.
    // pub fn error<T>(&mut self, kind: ErrorKind) -> Result<T> {
    //     self.writer.error(kind)
    // }

    // /// Did the decoding operation fail due to an error?
    // pub fn is_failed(&self) -> bool {
    //     self.writer.is_failed()
    // }

    // /// Finish encoding to the buffer, returning a slice containing the data
    // /// written to the buffer.
    // pub fn finish_internal(&self) -> Result<&'a [u8]> {
    //     self.writer.finish()
    // }

    /// Finish encoding to the buffer, returning a slice containing the data
    /// written to the buffer.
    pub fn finish(self) -> ClarifyOutputs<'a> {
        ClarifyOutputs {
            raw: self.writer.finish().map(|raw| Cow::Borrowed(raw)),
            clarify_buf: self.clarifier.clarify_buf,
        }
    }

    // /// Encode a `CONTEXT-SPECIFIC` field with the provided tag number and mode.
    // pub fn context_specific<T>(
    //     &mut self,
    //     tag_number: TagNumber,
    //     tag_mode: TagMode,
    //     value: &T,
    // ) -> Result<()>
    // where
    //     T: EncodeValue + Tagged,
    // {
    //     self.writer.context_specific(tag_number, tag_mode, value)
    // }

    // /// Encode an ASN.1 `SEQUENCE` of the given length.
    // ///
    // /// Spawns a nested slice writer which is expected to be exactly the
    // /// specified length upon completion.
    // pub fn sequence<F>(&mut self, length: Length, f: F) -> Result<()>
    // where
    //     F: FnOnce(&mut DebugSliceWriter<'_>) -> Result<()>,
    // {
    //     Header::new(Tag::Sequence, length).and_then(|header| header.encode(self))?;

    //     let debug_ref = self.debug_ref.clone();
    //     let mut nested_encoder = DebugSliceWriter::new(self.reserve(length)?, debug_ref, true);
    //     f(&mut nested_encoder)?;

    //     let nresult: FinishOutputs<'_> = nested_encoder.finish();
    //     if nresult.raw?.len() == usize::try_from(length)? {
    //         Ok(())
    //     } else {
    //         self.error(ErrorKind::Length { tag: Tag::Sequence })
    //     }
    // }

    /// Reserve a portion of the internal buffer, updating the internal cursor
    /// position and returning a mutable slice.
    fn reserve(&mut self, len: impl TryInto<Length>) -> Result<&mut [u8]> {
        self.writer.reserve(len)
    }
}

impl Clarifier {
    /// Returns indentation, for example "\n\t" for depth == 1
    pub fn indent_str(&self) -> &'static str {
        let ilen = self.depth.len() * 1;
        let ilen = ilen.min(INDENT_STR.len());
        &INDENT_STR[..ilen]
    }

    pub fn write_clarify_indent_if_enabled(&mut self) {
        if self.indent_enabled {
            self.write_clarify_indent();
        }
    }

    /// Writes indentation to debug output, for example "\n\t" for depth == 1
    pub fn write_clarify_indent(&mut self) {
        let indent = self.indent_str();
        {
            self.comment_writer.before_new_line(&mut self.clarify_buf);
            write!(&mut self.clarify_buf, "\n{}", indent).unwrap();
        }
    }

    /// Writes hex bytes to debug output, for example "30 04 "
    pub fn write_clarify_hex(&mut self, slice: &[u8]) {
        let indent = self.indent_str();
        {
            write!(&mut self.clarify_buf, "{}", HexDisplayLines(&slice, indent)).unwrap();
        }
    }

    /// Writes string to debug output, for example a comment "// SEQUENCE"
    pub fn write_clarify_str(&mut self, s: &str) {
        {
            write!(&mut self.clarify_buf, "{}", s).unwrap();
        }
    }
    /// Writes string to debug output, for example a comment: `// SEQUENCE: name`
    pub fn write_clarify_type_str(&mut self, start_end: &str, type_name: &str) {
        //let mut debugbuf = self.debug_ref.borrow_mut();

        let comment = format!("{}: {} ", start_end, type_name);
        self.comment_writer.comment(&comment);
    }

    /// Writes string to debug output, for example a comment: `// "abc"`
    pub fn write_clarify_value_quote(&mut self, type_name: &str, value: &[u8]) {
        //let mut debugbuf = self.debug_ref.borrow_mut();

        let contains_control = value.iter().any(|&c| c == 0x7F || (c < 0x20 && c != b'\n'));
        if value.len() > 2 && !contains_control {
            let type_name = strip_transparent_types(type_name);
            let comment = format!("{} {:?} ", type_name, String::from_utf8_lossy(value));
            self.comment_writer.comment(&comment);
        }
    }

    /// Writes int to debug output, for example a comment: `// integer: 16dec`
    pub fn write_clarify_int(&mut self, value: i64) {
        if value >= 10 || value < 0 {
            let comment = format!("integer: {value}dec ");
            self.comment_writer.comment(&comment);
        }
    }

    /// input: u32::from(self.writer.position())
    pub fn clarify_start_value_type_str(&mut self, writer_pos: Option<u32>, type_name: &str) {
        self.indent_enabled = true;
        self.depth.push(writer_pos);

        let type_name = strip_transparent_types(type_name);
        self.write_clarify_type_str("type", &type_name);
    }

    fn clarify_end_value_type_str(&mut self, writer_pos: Option<u32>, type_name: &str) {
        let last_pos = self.depth.pop().unwrap_or(writer_pos);

        match (writer_pos, last_pos) {
            (Some(writer_pos), Some(last_pos)) => {
                let diff = writer_pos - last_pos;
                if diff < 16 {
                    // ignore short runs
                    return;
                }
            }
            _ => {}
        }

        let type_name = strip_transparent_types(type_name);
        self.write_clarify_indent();
        self.write_clarify_type_str("end", type_name.as_ref());
    }

    /// for better tag-length pretty-printing inline
    pub fn clarify_end_tag(&mut self, _tag: &Tag) {
        // just to print a single length byte without indent
        self.indent_enabled = false;
    }

    // fn debug_set_indent_enabled(&mut self, enabled: bool) {
    //     if !enabled {
    //         // Write tabs before we switch to in-line mode
    //         self.write_debug_indent();
    //     }
    //     self.indent_enabled = enabled;
    // }

    pub fn clarify_field_name(&mut self, field_name: &str) {
        self.write_clarify_indent();
        self.write_clarify_type_str("field", field_name);
    }

    pub fn clarify_start_value_type<T>(&mut self) {
        self.clarify_start_value_type_str(Some(self.last_position), &tynm::type_name::<T>());
    }
    pub fn clarify_end_value_type<T>(&mut self) {
        self.clarify_end_value_type_str(Some(self.last_position), &tynm::type_name::<T>());
    }

    // fn clarify_end_length(&mut self, tag: Option<&Tag>, length: Length) {
    //     self.indent_enabled = true;
    //     if let Some(tag) = tag {
    //         self.write_debug_type_str("tag", &format!("{}", tag));
    //     }
    //     if u32::from(length) >= 10 {
    //         self.write_debug_type_str("len", &format!("{}", length));
    //     }
    // }

    // fn clarify_value_quote(&mut self, _type_name: &str, tag_name: &[u8]) {
    //     //self.write_debug_value_quote(type_name, tag_name);
    //     self.write_debug_value_quote("", tag_name);
    // }

    // fn debug_int(&mut self, value: i64) {
    //     self.write_debug_int(value);
    // }

    pub fn clarify_choice(&mut self, choice_name: &[u8]) {
        self.write_clarify_indent();
        if let Ok(choice_name) = std::str::from_utf8(choice_name) {
            self.write_clarify_type_str("CHOICE", choice_name);
        }
    }
}

impl<'a> Writer for ClarifySliceWriter<'a> {
    fn write(&mut self, slice: &[u8]) -> Result<()> {
        println!("writing {slice:?}");
        self.reserve(slice.len())?.copy_from_slice(slice);
        self.clarifier.last_position += slice.len() as u32;

        self.clarifier.write_clarify_indent_if_enabled();
        self.clarifier.write_clarify_hex(slice);

        Ok(())
    }
}

/// Strips wrappers, such as `EncodeValueRef`, which is commonly used and is completely transparent
fn strip_transparent_types(mut type_name: &str) -> Cow<'_, str> {
    let prefixes = [
        "EncodeValueRef<",
        "ApplicationRef<",
        "ContextSpecificRef<",
        "PrivateRef<",
    ];

    for prefix in prefixes {
        type_name = if let Some(stripped) = type_name.strip_prefix(prefix) {
            let stripped = stripped.strip_suffix(">").unwrap_or(stripped);
            stripped
        } else {
            type_name
        };
    }

    Cow::Borrowed(type_name)
}

#[cfg(test)]
pub mod test {
    use std::{println, vec::Vec};

    use crate::{
        asn1::OctetString,
        writer::clarify::{ClarifyFlavor, EncodeClarifyExt},
    };

    #[test]
    fn clarify_simple_octetstring() {
        let obj = OctetString::new(&[0xAA, 0xBB, 0xCC]).unwrap();

        let clarified = obj
            .to_der_clarify(ClarifyFlavor::XmlComments)
            .expect("encoded DER");

        println!("clarified: {clarified}");
    }
}
