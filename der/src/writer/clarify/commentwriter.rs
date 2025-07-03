use std::{io::Write, vec::Vec};

pub trait CommentWriter {
    fn comment(&mut self, s: &str);

    fn before_new_line(&mut self, w: &mut dyn Write);
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
        if self.buf.len() == 0 {
            return;
        }
        let _ = w.write_all(b"// ");
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
        if self.buf.len() == 0 {
            return;
        }
        let _ = w.write_all(b"<!-- ");
        let _ = w.write_all(&self.buf);
        let _ = w.write_all(b"-->");
        self.buf.clear();
    }
}
