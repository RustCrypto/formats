use std::{io::Write, vec::Vec};

pub trait CommentWriter {
    fn comment(&mut self, s: &str);

    fn before_new_line(&mut self, w: &mut dyn Write);

    fn start_new_line(&mut self, _w: &mut dyn Write) {}

    fn needs_newline_space(&self) -> bool {
        false
    }
}

#[derive(Default)]
pub struct JavaCommentWriter {
    pub buf: Vec<u8>,
}

impl CommentWriter for JavaCommentWriter {
    fn comment(&mut self, s: &str) {
        self.buf.extend_from_slice(s.as_bytes());
    }

    fn before_new_line(&mut self, w: &mut dyn Write) {
        if self.buf.is_empty() {
            return;
        }
        let _ = w.write_all(b" // ");
        let _ = w.write_all(&self.buf);
        self.buf.clear();
    }
}

#[derive(Default)]
pub struct XmlCommentWriter {
    pub buf: Vec<u8>,
}

impl CommentWriter for XmlCommentWriter {
    fn comment(&mut self, s: &str) {
        self.buf.extend_from_slice(s.as_bytes());
    }

    fn before_new_line(&mut self, w: &mut dyn Write) {
        if self.buf.is_empty() {
            return;
        }
        let _ = w.write_all(b" <!-- ");
        let _ = w.write_all(&self.buf);
        let _ = w.write_all(b"-->");
        self.buf.clear();
    }
}

#[derive(Default)]
pub struct RustHexWriter {
    pub started_newline: bool,
    pub buf: Vec<u8>,
}

impl CommentWriter for RustHexWriter {
    fn comment(&mut self, s: &str) {
        self.buf.extend_from_slice(s.as_bytes());
    }

    fn before_new_line(&mut self, w: &mut dyn Write) {
        if self.started_newline {
            w.write_all(b"\"").ok();
        }
        if self.buf.is_empty() {
            return;
        }
        w.write_all(b" // ").ok();
        w.write_all(&self.buf).ok();
        self.buf.clear();
        self.started_newline = false;
    }

    fn start_new_line(&mut self, w: &mut dyn Write) {
        self.started_newline = true;
        w.write_all(b"\"").ok();
    }

    fn needs_newline_space(&self) -> bool {
        // because '"' is in first line, next lines need to be moved by 1 character
        true
    }
}
