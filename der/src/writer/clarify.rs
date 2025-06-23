pub(crate) mod commentwriter;
pub(crate) mod hexdisplaylines;

use crate::SliceWriter;
use crate::std::io::Write;
use crate::{Length, Result, Tag};
use commentwriter::{CommentWriter, JavaCommentWriter, XmlCommentWriter};
use core::cell::RefCell;
use core::ops::DerefMut;
use hexdisplaylines::HexDisplayLines;
use std::borrow::Cow;
use std::string::String;
use std::{boxed::Box, rc::Rc, vec::Vec};

use super::Writer;

static INDENT_STR: &str =
    "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

/// [`Writer`] which encodes DER as hex with comments.
pub struct ClarifySliceWriter<'a> {
    writer: SliceWriter<'a>,

    // Buffer into which debug HEX and comments are written
    debug_ref: Rc<RefCell<Vec<u8>>>,

    /// Used for debug indentation
    depth: Vec<u32>,

    indent_enabled: bool,
    comment_writer: Box<dyn CommentWriter>,
}

/// Returned by .finish()
pub struct FinishOutputs<'a> {
    pub raw: Result<&'a [u8]>,
    //pub debug_ref: Vec<u8>,
}

impl<'a> ClarifySliceWriter<'a> {
    /// Create a new encoder with the given byte slice as a backing buffer.
    pub fn new(bytes: &'a mut [u8], debug_ref: Rc<RefCell<Vec<u8>>>, comment_xml: bool) -> Self {
        Self {
            writer: SliceWriter::new(bytes),
            debug_ref,
            depth: Vec::new(),
            indent_enabled: true,
            comment_writer: if comment_xml {
                Box::new(XmlCommentWriter::default())
            } else {
                Box::new(JavaCommentWriter::default())
            },
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
    pub fn finish(self) -> FinishOutputs<'a> {
        FinishOutputs {
            raw: self.writer.finish(),
            //debug_buf: self.debug.expect("debug buf not taken"),
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
    /// Returns indentation, for example "\n\t" for depth == 1
    pub fn indent_str(&self) -> &'static str {
        let ilen = self.depth.len() * 1;
        let ilen = ilen.min(INDENT_STR.len());
        &INDENT_STR[..ilen]
    }

    /// Writes indentation to debug output, for example "\n\t" for depth == 1
    pub fn write_clarify_indent(&mut self) {
        let indent = self.indent_str();
        let mut debugbuf = self.debug_ref.borrow_mut();
        {
            self.comment_writer
                .before_new_line(&mut debugbuf.deref_mut());
            write!(debugbuf, "\n{}", indent).unwrap();
        }
    }

    /// Writes hex bytes to debug output, for example "30 04 "
    pub fn write_clarify_hex(&mut self, slice: &[u8]) {
        let indent = self.indent_str();
        let mut debugbuf = self.debug_ref.borrow_mut();
        {
            write!(debugbuf, "{}", HexDisplayLines(&slice, indent)).unwrap();
        }
    }

    /// Writes string to debug output, for example a comment "// SEQUENCE"
    pub fn write_clarify_str(&mut self, s: &str) {
        let mut debugbuf = self.debug_ref.borrow_mut();
        {
            write!(debugbuf, "{}", s).unwrap();
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

    /// Reserve a portion of the internal buffer, updating the internal cursor
    /// position and returning a mutable slice.
    fn reserve(&mut self, len: impl TryInto<Length>) -> Result<&mut [u8]> {
        self.writer.reserve(len)
    }

    fn clarify_start_value_type_str(&mut self, type_name: &str) {
        self.indent_enabled = true;
        self.depth.push(u32::from(self.writer.position()));

        let type_name = strip_transparent_types(type_name);
        self.write_clarify_type_str("type", &type_name);
    }

    fn clarify_end_value_type_str(&mut self, type_name: &str) {
        let current = u32::from(self.writer.position());
        let last_pos = self.depth.pop().unwrap_or(current);
        let diff = current - last_pos;

        if diff > 16 {
            let type_name = strip_transparent_types(type_name);
            self.write_clarify_indent();
            self.write_clarify_type_str("end", type_name.as_ref());
        }
    }
}

impl<'a> Writer for ClarifySliceWriter<'a> {
    fn write(&mut self, slice: &[u8]) -> Result<()> {
        self.reserve(slice.len())?.copy_from_slice(slice);

        if self.indent_enabled {
            self.write_clarify_indent();
        }

        self.write_clarify_hex(slice);
        Ok(())
    }

    fn clarify_start_value_type<T>(&mut self) {
        self.clarify_start_value_type_str(&tynm::type_name::<T>());
    }
    fn clarify_end_value_type<T>(&mut self) {
        self.clarify_end_value_type_str(&tynm::type_name::<T>());
    }

    /// for better tag-length pretty-printing inline
    fn clarify_end_tag(&mut self, _tag: &Tag) {
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

    fn clarify_field_name(&mut self, field_name: &str) {
        self.write_clarify_indent();
        self.write_clarify_type_str("field", field_name);
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

    fn clarify_choice(&mut self, choice_name: &[u8]) {
        self.write_clarify_indent();
        if let Ok(choice_name) = std::str::from_utf8(choice_name) {
            self.write_clarify_type_str("CHOICE", choice_name);
        }
    }

    fn is_clarify(&self) -> bool {
        true
    }
}

fn strip_transparent_types(type_name: &str) -> Cow<'_, str> {
    // EncodeValueRef is commonly used and it is completely transparent
    let type_name = if let Some(stripped) = type_name.strip_prefix("EncodeValueRef<") {
        let stripped = stripped.strip_suffix(">").unwrap_or(stripped);
        stripped
    } else {
        type_name
    };

    let type_name = if let Some(stripped) = type_name.strip_prefix("ApplicationRef<") {
        let stripped = stripped.strip_suffix(">").unwrap_or(stripped);
        stripped
    } else {
        type_name
    };

    let type_name = if let Some(stripped) = type_name.strip_prefix("ContextSpecificRef<") {
        let stripped = stripped.strip_suffix(">").unwrap_or(stripped);
        stripped
    } else {
        type_name
    };

    Cow::Borrowed(type_name)
}
