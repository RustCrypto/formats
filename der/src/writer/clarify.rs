pub(crate) mod commentwriter;
pub(crate) mod hexdisplaylines;

use crate::std::io::Write;
use crate::writer::clarify::commentwriter::RustHexWriter;
use crate::{Encode, Error, SliceWriter};
use crate::{Length, Result, Tag};
use commentwriter::{CommentWriter, JavaCommentWriter, XmlCommentWriter};
use hexdisplaylines::HexDisplayLines;
use std::borrow::Cow;
use std::string::String;
use std::{boxed::Box, vec::Vec};

use super::Writer;

/// Extension trait, auto-implemented on [`Encode`]
pub trait EncodeClarifyExt: Encode {
    /// Encode this type as pretty-printed hex DER, with comments.
    fn to_der_clarify(&self, flavor: ClarifyFlavor) -> Result<String> {
        let outputs = self.to_der_clarify_err_ignorant(ClarifyOptions {
            flavor,
            ..Default::default()
        });
        // Propagate encode and finish errors
        outputs.raw?;
        Ok(String::from_utf8(outputs.clarify_buf).expect("clarified output to be utf-8"))
    }

    /// Encode this type as pretty-printed hex DER, with comments.
    /// Ignores any errors that occur during [`Encode::encode`].
    fn to_der_clarify_err_ignorant(&self, options: ClarifyOptions) -> ClarifyOutputs<'static> {
        let len = match self.encoded_len() {
            Ok(len) => len,
            Err(err) => return ClarifyOutputs::from_err(err),
        };

        let mut buf = vec![0u8; u32::from(len) as usize];

        let mut writer = ClarifySliceWriter::new(&mut buf, Vec::new(), options);
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

/// Options to customize pretty-printing.
#[derive(Clone)]
pub struct ClarifyOptions {
    /// How should comments look like?
    pub flavor: ClarifyFlavor,

    /// Write types? E.g `type: OctetStringRef`
    pub print_types: bool,
}

impl Default for ClarifyOptions {
    fn default() -> Self {
        Self {
            flavor: Default::default(),
            print_types: true,
        }
    }
}

static INDENT_STR: &str =
    "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

/// [`Writer`] which encodes DER as hex with comments.
pub struct ClarifySliceWriter<'a> {
    writer: SliceWriter<'a>,

    clarifier: Clarifier,
}

/// Clarifier that creates HEX with comments
pub struct Clarifier {
    /// Buffer into which debug HEX and comments are written
    clarify_buf: Vec<u8>,

    /// Position in the buffer is used to track how long is the current sub-message
    last_position: u32,

    /// Used for debug indentation
    ///
    /// Pushes writer positions on the stack
    depth: Vec<Option<u32>>,

    /// Determines if newlines and indent are currently enabled
    indent_enabled: bool,

    print_types: bool,

    /// Sans-io buffer for comments
    comment_writer: Box<dyn CommentWriter>,
}

/// Returned by .finish()
pub struct ClarifyOutputs<'a> {
    /// Raw DER/BER buffer
    pub raw: Result<Cow<'a, [u8]>>,

    /// Hex-encoded DER/BER with comments
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
}

/// Determines how comments will look like
#[derive(Copy, Clone, Debug, Default)]
pub enum ClarifyFlavor {
    /// `01 02 <!-- comment -->`
    XmlComments,
    /// `01 02 // comment`
    #[default]
    JavaComments,
    /// `"01 02" // comment`
    RustHex,
}

impl Clarifier {
    /// Creates new Clarifier with buffer, that accumulates comments and hex bytes.
    pub fn new(clarify_buf: Vec<u8>, options: ClarifyOptions) -> Self {
        Self {
            clarify_buf,

            last_position: 0,
            depth: Vec::new(),

            indent_enabled: true,

            print_types: options.print_types,

            comment_writer: match options.flavor {
                ClarifyFlavor::XmlComments => Box::new(XmlCommentWriter::default()),
                ClarifyFlavor::JavaComments => Box::new(JavaCommentWriter::default()),
                ClarifyFlavor::RustHex => Box::new(RustHexWriter::default()),
            },
        }
    }
}

impl<'a> ClarifySliceWriter<'a> {
    /// Create a new encoder with the given byte slice as a backing buffer.
    pub fn new(bytes: &'a mut [u8], clarify_buf: Vec<u8>, options: ClarifyOptions) -> Self {
        Self {
            writer: SliceWriter::new(bytes),
            clarifier: Clarifier::new(clarify_buf, options),
        }
    }

    /// Finish encoding to the buffer, returning a slice containing the data
    /// written to the buffer.
    pub fn finish(mut self) -> ClarifyOutputs<'a> {
        self.clarifier.flush_line();

        ClarifyOutputs {
            raw: self.writer.finish().map(Cow::Borrowed),
            clarify_buf: self.clarifier.clarify_buf,
        }
    }

    /// Reserve a portion of the internal buffer, updating the internal cursor
    /// position and returning a mutable slice.
    fn reserve(&mut self, len: impl TryInto<Length>) -> Result<&mut [u8]> {
        self.writer.reserve(len)
    }
}

impl Clarifier {
    /// Returns indentation, for example "\n\t" for depth == 1
    pub fn indent_str(&self) -> &'static str {
        let ilen = self.depth.len();
        let ilen = ilen.min(INDENT_STR.len());
        &INDENT_STR[..ilen]
    }

    /// Writes indent if it is currently enabled
    pub fn write_clarify_indent_if_enabled(&mut self) {
        if self.indent_enabled {
            self.write_clarify_indent();
        }
    }

    fn flush_line(&mut self) {
        // if current line ends in space
        if self
            .clarify_buf
            .last()
            .map(|last| *last == b' ')
            .unwrap_or_default()
        {
            // remove space
            self.clarify_buf.pop();
        }
        // write comment after hex
        self.comment_writer.before_new_line(&mut self.clarify_buf);
    }

    /// Writes indentation to debug output, for example "\n\t" for depth == 1
    pub fn write_clarify_indent(&mut self) {
        self.flush_line();

        let indent = self.indent_str();
        write!(&mut self.clarify_buf, "\n{indent}").ok();

        // write e.g. '"' before hex
        self.comment_writer.start_new_line(&mut self.clarify_buf);
    }

    /// Writes hex bytes to debug output, for example "30 04 "
    pub fn write_clarify_hex(&mut self, bytes: &[u8]) {
        let indent = self.indent_str();
        write!(
            &mut self.clarify_buf,
            "{}",
            HexDisplayLines {
                bytes,
                indent,
                space: self.comment_writer.needs_newline_space()
            }
        )
        .ok();
    }

    /// Writes string to debug output, for example a comment "// SEQUENCE"
    pub fn write_clarify_str(&mut self, s: &str) {
        write!(&mut self.clarify_buf, "{s}").ok();
    }
    /// Writes string to debug output, for example a comment: `// SEQUENCE: name`
    pub fn write_clarify_type_str(&mut self, start_end: &str, type_name: &str) {
        let comment = format!("{start_end}: {type_name} ");
        self.comment_writer.comment(&comment);
    }

    /// Writes string to debug output, for example a comment: `// "abc"`
    pub fn write_clarify_value_quote(&mut self, type_name: &str, value: &[u8]) {
        let contains_control = value.iter().any(|&c| c == 0x7F || (c < 0x20 && c != b'\n'));

        if value.len() > 2 && !contains_control {
            let type_name = strip_transparent_types(type_name);
            let comment = format!("{} {:?} ", type_name, String::from_utf8_lossy(value));
            self.comment_writer.comment(&comment);
        }
    }

    /// Writes int to debug output, for example a comment: `// integer: 16dec`
    pub fn write_clarify_int(&mut self, value: i64) {
        if !(0..10).contains(&value) {
            let comment = format!("integer: {value}dec ");
            self.comment_writer.comment(&comment);
        }
    }

    /// Writes e.g. `type: OctetString`
    ///
    /// Expected `writer_pos` input: `u32::from(self.writer.position())`
    pub fn clarify_start_value_type_str(&mut self, writer_pos: Option<u32>, type_name: &str) {
        self.indent_enabled = true;
        self.depth.push(writer_pos);

        if self.print_types {
            let type_name = strip_transparent_types(type_name);
            self.write_clarify_type_str("type", &type_name);
        }
    }

    fn clarify_end_value_type_str(&mut self, writer_pos: Option<u32>, type_name: &str) {
        let last_pos = self.depth.pop().unwrap_or(writer_pos);

        if let (Some(writer_pos), Some(last_pos)) = (writer_pos, last_pos) {
            let diff = writer_pos - last_pos;
            if diff < 16 {
                // ignore short runs
                return;
            }
        }

        if self.print_types {
            let type_name = strip_transparent_types(type_name);
            self.write_clarify_indent();
            self.write_clarify_type_str("end", type_name.as_ref());
        }
    }

    /// for better tag-length pretty-printing inline
    pub fn clarify_header_start_tag(&mut self, _tag: &Tag) {
        self.write_clarify_indent();
        // just to print header bytes without indent
        self.indent_enabled = false;
    }

    /// Writes field name, i.e. field: `public_key`
    ///
    /// when used on Sequence field:
    /// ```text
    /// public_key: Option<&'a [u8]>
    /// ```
    pub fn clarify_field_name(&mut self, field_name: &str) {
        self.write_clarify_indent();
        self.write_clarify_type_str("field", field_name);
    }

    /// Writes e.g. `// type: OctetString`
    pub fn clarify_start_value_type<T: ?Sized>(&mut self) {
        self.clarify_start_value_type_str(Some(self.last_position), &tynm::type_name::<T>());
    }
    /// Writes e.g. `// end: OctetString`
    pub fn clarify_end_value_type<T: ?Sized>(&mut self) {
        self.clarify_end_value_type_str(Some(self.last_position), &tynm::type_name::<T>());
    }

    /// Writes e.g. `// tag: OCTET STRING len: 17`
    pub fn clarify_header_end_length(&mut self, tag: Option<&Tag>, length: Length) {
        self.indent_enabled = true;
        if let Some(tag) = tag {
            self.write_clarify_type_str("tag", &format!("{tag}"));
        }
        if u32::from(length) >= 10 {
            self.write_clarify_type_str("len", &format!("{length}"));
        }
    }

    /// Writes pretty-printed `CHOICE name`
    pub fn clarify_choice(&mut self, choice_name: &[u8]) {
        self.write_clarify_indent();
        if let Ok(choice_name) = std::str::from_utf8(choice_name) {
            self.write_clarify_type_str("CHOICE", choice_name);
        }
    }
}

impl<'a> Writer for ClarifySliceWriter<'a> {
    #[allow(clippy::cast_possible_truncation)]
    fn write(&mut self, slice: &[u8]) -> Result<()> {
        self.reserve(slice.len())?.copy_from_slice(slice);
        self.clarifier.last_position += slice.len() as u32;

        self.clarifier.write_clarify_indent_if_enabled();
        self.clarifier.write_clarify_hex(slice);

        Ok(())
    }

    fn clarifier(&mut self) -> Option<&mut Clarifier> {
        Some(&mut self.clarifier)
    }
}

/// Strips wrappers, such as `EncodeValueRef`, which is commonly used and is completely transparent
fn strip_transparent_types(mut type_name: &str) -> Cow<'_, str> {
    let prefixes = [
        "EncodeValueRef<",
        // "ApplicationRef<",
        // "ContextSpecificRef<",
        // "PrivateRef<",
    ];

    for prefix in prefixes {
        type_name = if let Some(stripped) = type_name.strip_prefix(prefix) {
            stripped.strip_suffix(">").unwrap_or(stripped)
        } else {
            type_name
        };
    }

    Cow::Borrowed(type_name)
}
