use alloc::vec::Vec;
use core::mem;

use crate::{
    Decode as _, Encode as _, ErrorKind, Header, IndefiniteLength, Length, Reader, Result,
    SliceReader, Tag,
};

type Chunk = Vec<u8>;
type Stack<T> = Vec<T>;

#[derive(Clone)]
struct ChunkStack {
    vec: Vec<Chunk>,
    size: usize,
}

impl ChunkStack {
    fn new() -> Self {
        Self {
            vec: Vec::new(),
            size: 0,
        }
    }

    fn push(&mut self, chunk: Chunk) {
        self.size += chunk.len();
        self.vec.push(chunk)
    }

    fn extend(&mut self, chunks: Self) {
        self.size += chunks.size;
        self.vec.extend(chunks.vec)
    }

    fn size(&self) -> usize {
        self.size
    }

    fn chunks(self) -> Vec<Chunk> {
        self.vec
    }
}

fn push_header(s: &mut ChunkStack, header: Header) -> Result<()> {
    let header_len = header.encoded_len()?;
    let mut header_bytes = Vec::with_capacity(usize::try_from(header_len)?);
    header.encode_to_vec(&mut header_bytes)?;
    s.push(header_bytes);
    Ok(())
}
fn push_tag_and_len(s: &mut ChunkStack, tag: Tag, length: Length) -> Result<()> {
    push_header(s, Header::new(tag, length)?)
}
fn push_tag_empty(s: &mut ChunkStack, tag: Tag) -> Result<()> {
    push_tag_and_len(s, tag, Length::ZERO)
}

/// Length of end-of-content (eoc) markers
const EOC_LENGTH: Length = Length::new(2);
/// end-of-content (eoc) marker
const EOC_MARKER: &[u8; 2] = &[0u8; 2];

fn read_eoc<'i, 'r, R: Reader<'r>>(r: &'i mut R) -> Result<()> {
    // consume the last two bytes
    if r.peek_byte() == Some(0) {
        let eoc = r.read_slice(EOC_LENGTH)?;
        if eoc.ne(EOC_MARKER) {
            Err(ErrorKind::Failed.at(r.position().saturating_sub(Length::ONE)))
        } else {
            Ok(())
        }
    } else {
        // first of reserved two bytes are non zero
        Err(ErrorKind::Failed.at(r.position()))
    }
}

enum RecurStage {
    Start,
    ResumeDefSeqSet {
        header: Header,
        accum: Stack<ChunkStack>,
        limit: Length,
    },
    ResumeDefTagging {
        header: Header,
    },
    ResumeIndefSeqSet {
        tag: Tag,
        accum: Stack<ChunkStack>,
    },
    ResumeIndefTagging {
        tag: Tag,
    },
}

struct Recur {
    // return value of recursion
    sub_result: ChunkStack,
    stage: RecurStage,
}

impl Recur {
    fn start_stage() -> Self {
        Self {
            sub_result: ChunkStack::new(),
            stage: RecurStage::Start,
        }
    }
    fn savepoint_def_seqset(header: Header, accum: Vec<ChunkStack>, limit: Length) -> Self {
        Self {
            sub_result: ChunkStack::new(),
            stage: RecurStage::ResumeDefSeqSet {
                header,
                accum,
                limit,
            },
        }
    }
    fn first_savepoint_def_seqset(header: Header, limit: Length) -> Self {
        Self::savepoint_def_seqset(header, Vec::new(), limit)
    }
    fn savepoint_def_tagging(header: Header) -> Self {
        Self {
            sub_result: ChunkStack::new(),
            stage: RecurStage::ResumeDefTagging { header },
        }
    }
    fn savepoint_indef_seqset(tag: Tag, accum: Vec<ChunkStack>) -> Self {
        Self {
            sub_result: ChunkStack::new(),
            stage: RecurStage::ResumeIndefSeqSet { tag, accum },
        }
    }
    fn first_savepoint_indef_seqset(tag: Tag) -> Self {
        Self::savepoint_indef_seqset(tag, Vec::new())
    }
    fn savepoint_indef_tagging(tag: Tag) -> Self {
        Self {
            sub_result: ChunkStack::new(),
            stage: RecurStage::ResumeIndefTagging { tag },
        }
    }
}

fn berder_loop<'i, 'r, R: Reader<'r>>(r: &'i mut R) -> Result<ChunkStack> {
    let mut result = ChunkStack::new();

    let mut recur_stack: Stack<Recur> = Vec::new();

    // initial state
    recur_stack.push(Recur::start_stage());

    // NOTE:
    //  In the following large loop, there are multiple occurrences of `continue;`.
    //  These statements are superfluous as there are no remaining reachable code paths in the loop
    //  beyond that immediate lexical scope; however, the `continue;` is kept to make it clear
    //  to the reader that the loop _must_ restart at that point as the prior pushes to the stack
    //  are simulating recursion.
    //  Moreover, the statement
    //    ```rs
    //    mem::swap(&mut result, &mut recur.sub_result);
    //    ```
    //  appears at the end of all other ‘sub loop’ code paths (except for `return Err`).
    //  It is an intentional choice to keep this duplication, over loss of ‘locality’ by
    //  refactoring to a single occurrence at the very end of the loop body.

    while let Some(mut recur) = recur_stack.pop() {
        match recur.stage {
            RecurStage::Start => {
                let tag = Tag::decode(r)
                    .map_err(|e| e.kind().at(r.position().saturating_sub(Length::ONE)))?;

                // NOTE: as `IndefiniteLength` is defined in terms of `Length`,
                //   this will not allow non-canonical encoding of lengths (which are allowed under BER)
                //   so while this function can transform ‘constructed, indefinite-length’ encodings
                //   to ‘constructed, definite-length’ encodings, it will still error on lengths
                //   that are not encoded ‘minimally’.
                let length = IndefiniteLength::decode(r)?;

                if let Some(length) = length.into() {
                    let header = Header::new(tag, length)?;

                    match tag {
                        Tag::Sequence | Tag::Set => {
                            let limit = (r.position() + length)?;

                            if r.position() < limit {
                                recur_stack.push(Recur::first_savepoint_def_seqset(header, limit));
                                recur_stack.push(Recur::start_stage());
                                continue;
                            } else {
                                // empty seq/set
                                push_header(&mut recur.sub_result, header)?;
                                mem::swap(&mut result, &mut recur.sub_result);
                            }
                        }
                        Tag::ContextSpecific {
                            constructed: true, ..
                        }
                        | Tag::Application {
                            constructed: true, ..
                        }
                        | Tag::Private {
                            constructed: true, ..
                        } => {
                            if length > Length::ZERO {
                                recur_stack.push(Recur::savepoint_def_tagging(header));
                                recur_stack.push(Recur::start_stage());
                                continue;
                            } else {
                                // empty tag
                                push_header(&mut recur.sub_result, header)?;
                                mem::swap(&mut result, &mut recur.sub_result);
                            }
                        }
                        _ => {
                            recur.sub_result.push(r.read_slice(length)?.to_vec());
                            push_header(&mut recur.sub_result, header)?;
                            mem::swap(&mut result, &mut recur.sub_result);
                        }
                    }
                } else {
                    match tag {
                        Tag::Sequence | Tag::Set => {
                            if r.peek_byte() != Some(0) {
                                recur_stack.push(Recur::first_savepoint_indef_seqset(tag));
                                recur_stack.push(Recur::start_stage());
                                continue;
                            } else {
                                // empty seq/set
                                read_eoc(r)?;
                                push_tag_empty(&mut recur.sub_result, tag)?;
                                mem::swap(&mut result, &mut recur.sub_result);
                            }
                        }
                        Tag::ContextSpecific {
                            constructed: true, ..
                        }
                        | Tag::Application {
                            constructed: true, ..
                        }
                        | Tag::Private {
                            constructed: true, ..
                        } => {
                            if r.peek_byte() != Some(0) {
                                recur_stack.push(Recur::savepoint_indef_tagging(tag));
                                recur_stack.push(Recur::start_stage());
                                continue;
                            } else {
                                // empty tag
                                read_eoc(r)?;
                                push_tag_empty(&mut recur.sub_result, tag)?;
                                mem::swap(&mut result, &mut recur.sub_result);
                            }
                        }
                        _ => {
                            return Err(ErrorKind::IndefiniteLength.at(r.position()));
                        }
                    }
                }
            }
            RecurStage::ResumeDefSeqSet {
                header,
                mut accum,
                limit,
            } => {
                // resume branch of definite-length seq/set
                accum.push(mem::replace(&mut result, ChunkStack::new()));

                if r.position() < limit {
                    recur_stack.push(Recur::savepoint_def_seqset(header, accum, limit));
                    recur_stack.push(Recur::start_stage());
                    continue;
                } else {
                    for chunks in accum.into_iter().rev() {
                        recur.sub_result.extend(chunks);
                    }

                    push_header(&mut recur.sub_result, header)?;
                    mem::swap(&mut result, &mut recur.sub_result);
                }
            }
            RecurStage::ResumeDefTagging { header } => {
                // resume branch of constructed, definite-length Application/ContextSpecific/Private
                recur
                    .sub_result
                    .extend(mem::replace(&mut result, ChunkStack::new()));

                push_header(&mut recur.sub_result, header)?;
                mem::swap(&mut result, &mut recur.sub_result);
            }
            RecurStage::ResumeIndefSeqSet { tag, mut accum } => {
                // resume branch of indefinite-length seq/set
                accum.push(mem::replace(&mut result, ChunkStack::new()));

                if r.peek_byte() != Some(0) {
                    recur_stack.push(Recur::savepoint_indef_seqset(tag, accum));
                    recur_stack.push(Recur::start_stage());
                    continue;
                } else {
                    read_eoc(r)?;

                    for chunks in accum.into_iter().rev() {
                        recur.sub_result.extend(chunks);
                    }

                    let length = Length::try_from(recur.sub_result.size())?;
                    push_tag_and_len(&mut recur.sub_result, tag, length)?;
                    mem::swap(&mut result, &mut recur.sub_result);
                }
            }
            RecurStage::ResumeIndefTagging { tag } => {
                // resume branch of indefinite length constructed Application/ContextSpecific/Private
                recur
                    .sub_result
                    .extend(mem::replace(&mut result, ChunkStack::new()));

                read_eoc(r)?;

                let length = Length::try_from(recur.sub_result.size())?;
                push_tag_and_len(&mut recur.sub_result, tag, length)?;
                mem::swap(&mut result, &mut recur.sub_result);
            }
        }
    }

    Ok(result)
}

/// Convert from Basic Encoding Rules (BER) to Distinguished Encoding Rules (DER)
///
/// This function transforms an ASN.1 encoding that has occurrences of using the
/// constructed, indefinite-length method. The result has only the
/// definite-length method, thus complying with DER.
/// This function does not handle all possible encodings that would comply with
/// BER but not DER; an example is non-canonical encodings of lengths. In this
/// particular case, the existing decoding features of this crate do not support this.
///
/// The primary motivation of this function is to handle ASN.1 messages in the
/// wild that have been produced by system that have taken advantage of the
/// stream-like modality that the constructed, indefinite-length method affords.
pub fn ber_to_der(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut r = SliceReader::new(bytes)?;
    let chunk_stack = berder_loop(&mut r)?;

    let mut result = Vec::with_capacity(chunk_stack.size());
    for chunk in chunk_stack.chunks().into_iter().rev() {
        result.extend(chunk);
    }
    r.finish(result)
}

#[cfg(all(test, feature = "alloc"))]
#[allow(clippy::panic, clippy::panic_in_result_fn, clippy::unwrap_used)]
mod tests {
    use super::*;

    const EMPTY_SEQ_BER: &[u8; 4] = &[0x30, 0x80, 0x00, 0x00];
    const EMPTY_SEQ_DER: &[u8; 2] = &[0x30, 0x00];
    const EMPTY_SET_BER: &[u8; 4] = &[0x31, 0x80, 0x00, 0x00];
    const EMPTY_SET_DER: &[u8; 2] = &[0x31, 0x00];

    const EMPTY_CONTEXT_SPECIFIC_BER: &[u8; 4] = &[0xA0, 0x80, 0x00, 0x00];
    const EMPTY_CONTEXT_SPECIFIC_DER: &[u8; 2] = &[0xA0, 0x00];
    const EMPTY_APPLICATION_BER: &[u8; 4] = &[0x60, 0x80, 0x00, 0x00];
    const EMPTY_APPLICATION_DER: &[u8; 2] = &[0x60, 0x00];
    const EMPTY_PRIVATE_BER: &[u8; 4] = &[0xE0, 0x80, 0x00, 0x00];
    const EMPTY_PRIVATE_DER: &[u8; 2] = &[0xE0, 0x00];

    const EMPTY_OCTET_STR: &[u8; 2] = &[0x04, 0x00];
    // NOTE: primitive, indefinite-length disallowed in BER/DER

    #[test]
    fn empty_cases_der() -> Result<()> {
        assert_eq!(EMPTY_SEQ_DER, &ber_to_der(EMPTY_SEQ_DER)?[..]);
        assert_eq!(EMPTY_SET_DER, &ber_to_der(EMPTY_SET_DER)?[..]);
        assert_eq!(
            EMPTY_CONTEXT_SPECIFIC_DER,
            &ber_to_der(EMPTY_CONTEXT_SPECIFIC_DER)?[..]
        );
        assert_eq!(
            EMPTY_APPLICATION_DER,
            &ber_to_der(EMPTY_APPLICATION_DER)?[..]
        );
        assert_eq!(EMPTY_PRIVATE_DER, &ber_to_der(EMPTY_PRIVATE_DER)?[..]);
        assert_eq!(EMPTY_OCTET_STR, &ber_to_der(EMPTY_OCTET_STR)?[..]);
        Ok(())
    }

    #[test]
    fn empty_cases_ber() -> Result<()> {
        assert_eq!(EMPTY_SEQ_DER, &ber_to_der(EMPTY_SEQ_BER)?[..]);
        assert_eq!(EMPTY_SET_DER, &ber_to_der(EMPTY_SET_BER)?[..]);
        assert_eq!(
            EMPTY_CONTEXT_SPECIFIC_DER,
            &ber_to_der(EMPTY_CONTEXT_SPECIFIC_BER)?[..]
        );
        assert_eq!(
            EMPTY_APPLICATION_DER,
            &ber_to_der(EMPTY_APPLICATION_BER)?[..]
        );
        assert_eq!(EMPTY_PRIVATE_DER, &ber_to_der(EMPTY_PRIVATE_BER)?[..]);
        Ok(())
    }

    #[test]
    fn primitive_indef_len_err() {
        if let Err(err) = ber_to_der(&[0x04, 0x80, 0x01, 0x00, 0x00]) {
            assert_eq!(ErrorKind::IndefiniteLength, err.kind());
            assert_eq!(Some(Length::from(2u8)), err.position());
        } else {
            panic!("Expected error!")
        }
    }

    const DEGEN_NESTED_SEQ_BER: &[u8; 8] = &[0x30, 0x80, 0x30, 0x80, 0x00, 0x00, 0x00, 0x00];
    const DEGEN_NESTED_SEQ_DER: &[u8; 4] = &[0x30, 0x02, 0x30, 0x00];
    const DEGEN_NESTED_CONTEXT_SPECIFIC_BER: &[u8; 8] =
        &[0xA0, 0x80, 0x30, 0x80, 0x00, 0x00, 0x00, 0x00];
    const DEGEN_NESTED_CONTEXT_SPECIFIC_DER: &[u8; 4] = &[0xA0, 0x02, 0x30, 0x00];

    #[test]
    fn degenerate_nested_cases_der() -> Result<()> {
        assert_eq!(DEGEN_NESTED_SEQ_DER, &ber_to_der(DEGEN_NESTED_SEQ_DER)?[..]);
        assert_eq!(
            DEGEN_NESTED_CONTEXT_SPECIFIC_DER,
            &ber_to_der(DEGEN_NESTED_CONTEXT_SPECIFIC_DER)?[..]
        );
        Ok(())
    }

    #[test]
    fn degenerate_nested_cases_ber() -> Result<()> {
        assert_eq!(DEGEN_NESTED_SEQ_DER, &ber_to_der(DEGEN_NESTED_SEQ_BER)?[..]);
        assert_eq!(
            DEGEN_NESTED_CONTEXT_SPECIFIC_DER,
            &ber_to_der(DEGEN_NESTED_CONTEXT_SPECIFIC_BER)?[..]
        );
        Ok(())
    }

    // [0, 1]
    const TWO_ELEM_SEQ_BER: &[u8; 10] =
        &[0x30, 0x80, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x00, 0x00];
    const TWO_ELEM_SEQ_DER: &[u8; 8] = &[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01];

    #[test]
    fn basic_seqs() -> Result<()> {
        assert_eq!(TWO_ELEM_SEQ_DER, &ber_to_der(TWO_ELEM_SEQ_DER)?[..]);
        assert_eq!(TWO_ELEM_SEQ_DER, &ber_to_der(TWO_ELEM_SEQ_BER)?[..]);
        Ok(())
    }

    // SEQUENCE [1,]
    const INVALID_EOC2_ONE_ELEM_SEQ_BER: &[u8; 7] = &[0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0xFF];

    // context-specific 1
    const INVALID_EOC1_CONTEXT_SPECIFIC_BER: &[u8; 7] = &[0xA0, 0x80, 0x02, 0x01, 0x01, 0xFF, 0x00];
    const INVALID_EOC2_CONTEXT_SPECIFIC_BER: &[u8; 7] = &[0xA0, 0x80, 0x02, 0x01, 0x01, 0x00, 0xFF];

    #[test]
    fn invalid_eoc() {
        if let Err(err) = ber_to_der(INVALID_EOC2_ONE_ELEM_SEQ_BER) {
            assert_eq!(ErrorKind::Failed, err.kind());
            assert_eq!(Some(Length::from(6u8)), err.position());
        } else {
            panic!("Expected error!")
        }

        if let Err(err) = ber_to_der(INVALID_EOC1_CONTEXT_SPECIFIC_BER) {
            assert_eq!(ErrorKind::Failed, err.kind());
            assert_eq!(Some(Length::from(5u8)), err.position());
        } else {
            panic!("Expected error!")
        }

        if let Err(err) = ber_to_der(INVALID_EOC2_CONTEXT_SPECIFIC_BER) {
            assert_eq!(ErrorKind::Failed, err.kind());
            assert_eq!(Some(Length::from(6u8)), err.position());
        } else {
            panic!("Expected error!")
        }
    }

    #[test]
    fn non_canonical_lengths() {
        assert!(Length::from_der(&[0x81, 0x00]).is_err());
        assert!(Length::from_der(&[0x81, 0x01]).is_err());
        assert!(Length::from_der(&[0x81, 0x7F]).is_err());

        assert!(Length::from_der(&[0x82, 0x00, 0x00]).is_err());
        assert!(Length::from_der(&[0x82, 0x00, 0x01]).is_err());
        assert!(Length::from_der(&[0x82, 0x00, 0x7F]).is_err());

        assert!(IndefiniteLength::from_der(&[0x81, 0x00]).is_err());
        assert!(IndefiniteLength::from_der(&[0x81, 0x01]).is_err());
        assert!(IndefiniteLength::from_der(&[0x81, 0x7F]).is_err());

        assert!(IndefiniteLength::from_der(&[0x82, 0x00, 0x00]).is_err());
        assert!(IndefiniteLength::from_der(&[0x82, 0x00, 0x01]).is_err());
        assert!(IndefiniteLength::from_der(&[0x82, 0x00, 0x7F]).is_err());
    }
}
