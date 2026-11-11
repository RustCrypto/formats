# Proof targets: tls-codec (trait-level specs)

Obligations of `TlsCodec/Extraction/ProofObligations.lean` (aeneas trait-level specs,
281 function specs `X.spec.proof` and 656 per-impl `I.Lawful`.

## Where to work

- Function spec `X.spec.proof`: `X.spec.panic_freedom` in `Verification/PanicFreedom.lean`
  (total triple, post `True`) and `X.spec.functional_correctness` in
  `Verification/FunctionalCorrectness.lean` (partial triple, generated post).
- Per-impl `I.Lawful : Trait.Lawful T I`: one PF theorem `I.m_spec.panic_freedom` and one FC
  theorem `I.m_spec.functional_correctness` per method field `m_spec` of the structure (the
  field instantiated with the impl; `Inst.m` written as the impl's method). Fields with a
  `true` post (`Size.tls_serialized_len_spec`) and `Clone.clone_spec` have PF only. Parent
  fields and field-less structures need nothing.
- `Verification/ProofObligations.lean` rebuilds every obligation from these (generated).
- Classes are recomputed by `scripts/classify_targets.py` (the list below);
  `scripts/gen_verification.py` reads them. A row's `-- note` is copied above its theorems.

Formerly "false as generated" (the PF of the `TlsByteVecU24` / `TlsByteVecU32` serializer,
`byte_vec_u24/u32_encode_decode`, the U24 conversions and the `&[T]`/`Vec` serializer `Lawful`): all
proved, the 64-bit ones under the assumed `numBits_eq_64`; see `scripts/audit_*_clean.txt`.

<!-- BEGIN TARGETS -->

## 1a. Function specs, monomorphic (191)

#### `tls_vec`: TlsByteVecU* (60)

- `tls_vec.TlsByteVecU8.new.spec.proof`
- `tls_vec.TlsByteVecU8.len.spec.proof`
- `tls_vec.TlsByteVecU8.is_empty.spec.proof`
- `tls_vec.TlsByteVecU8.into_vec.spec.proof`
- `tls_vec.TlsByteVecU8.push.spec.proof`
- `tls_vec.TlsByteVecU8.pop.spec.proof`
- `tls_vec.TlsByteVecU8.remove.spec.proof`
- `tls_vec.TlsByteVecU8.get.spec.proof`
- `tls_vec.TlsByteVecU8.len_len.spec.proof`
- `tls_vec.TlsByteVecU8.Insts.CoreOpsIndexIndexUsizeU8.index.spec.proof`
- `tls_vec.TlsByteVecU8.Insts.CoreOpsIndexIndexMutUsizeU8.index_mut.spec.proof`
- `tls_vec.TlsByteVecU8.assert_written_bytes.spec.proof`
- `tls_vec.TlsByteVecU8.serialize_bytes_bytes.spec.proof`
- `tls_vec.TlsByteVecU8.tls_serialized_byte_length.spec.proof`
- `tls_vec.TlsByteVecU8.deserialize_bytes_bytes.spec.proof`
- `tls_vec.TlsByteVecU16.new.spec.proof`
- `tls_vec.TlsByteVecU16.len.spec.proof`
- `tls_vec.TlsByteVecU16.is_empty.spec.proof`
- `tls_vec.TlsByteVecU16.into_vec.spec.proof`
- `tls_vec.TlsByteVecU16.push.spec.proof`
- `tls_vec.TlsByteVecU16.pop.spec.proof`
- `tls_vec.TlsByteVecU16.remove.spec.proof`
- `tls_vec.TlsByteVecU16.get.spec.proof`
- `tls_vec.TlsByteVecU16.len_len.spec.proof`
- `tls_vec.TlsByteVecU16.Insts.CoreOpsIndexIndexUsizeU8.index.spec.proof`
- `tls_vec.TlsByteVecU16.Insts.CoreOpsIndexIndexMutUsizeU8.index_mut.spec.proof`
- `tls_vec.TlsByteVecU16.assert_written_bytes.spec.proof`
- `tls_vec.TlsByteVecU16.serialize_bytes_bytes.spec.proof`
- `tls_vec.TlsByteVecU16.tls_serialized_byte_length.spec.proof`
- `tls_vec.TlsByteVecU16.deserialize_bytes_bytes.spec.proof`
- `tls_vec.TlsByteVecU24.new.spec.proof`
- `tls_vec.TlsByteVecU24.len.spec.proof`
- `tls_vec.TlsByteVecU24.is_empty.spec.proof`
- `tls_vec.TlsByteVecU24.into_vec.spec.proof`
- `tls_vec.TlsByteVecU24.push.spec.proof`
- `tls_vec.TlsByteVecU24.pop.spec.proof`
- `tls_vec.TlsByteVecU24.remove.spec.proof`
- `tls_vec.TlsByteVecU24.get.spec.proof`
- `tls_vec.TlsByteVecU24.len_len.spec.proof`
- `tls_vec.TlsByteVecU24.Insts.CoreOpsIndexIndexUsizeU8.index.spec.proof`
- `tls_vec.TlsByteVecU24.Insts.CoreOpsIndexIndexMutUsizeU8.index_mut.spec.proof`
- `tls_vec.TlsByteVecU24.assert_written_bytes.spec.proof`
- `tls_vec.TlsByteVecU24.serialize_bytes_bytes.spec.proof`
- `tls_vec.TlsByteVecU24.tls_serialized_byte_length.spec.proof`
- `tls_vec.TlsByteVecU24.deserialize_bytes_bytes.spec.proof`
- `tls_vec.TlsByteVecU32.new.spec.proof`
- `tls_vec.TlsByteVecU32.len.spec.proof`
- `tls_vec.TlsByteVecU32.is_empty.spec.proof`
- `tls_vec.TlsByteVecU32.into_vec.spec.proof`
- `tls_vec.TlsByteVecU32.push.spec.proof`
- `tls_vec.TlsByteVecU32.pop.spec.proof`
- `tls_vec.TlsByteVecU32.remove.spec.proof`
- `tls_vec.TlsByteVecU32.get.spec.proof`
- `tls_vec.TlsByteVecU32.len_len.spec.proof`
- `tls_vec.TlsByteVecU32.Insts.CoreOpsIndexIndexUsizeU8.index.spec.proof`
- `tls_vec.TlsByteVecU32.Insts.CoreOpsIndexIndexMutUsizeU8.index_mut.spec.proof`
- `tls_vec.TlsByteVecU32.assert_written_bytes.spec.proof`
- `tls_vec.TlsByteVecU32.serialize_bytes_bytes.spec.proof`
- `tls_vec.TlsByteVecU32.tls_serialized_byte_length.spec.proof`
- `tls_vec.TlsByteVecU32.deserialize_bytes_bytes.spec.proof`

#### `tls_vec`: TlsVecU* (44)

- `tls_vec.TlsVecU8.new.spec.proof`
- `tls_vec.TlsVecU8.len.spec.proof`
- `tls_vec.TlsVecU8.is_empty.spec.proof`
- `tls_vec.TlsVecU8.into_vec.spec.proof`
- `tls_vec.TlsVecU8.push.spec.proof`
- `tls_vec.TlsVecU8.pop.spec.proof`
- `tls_vec.TlsVecU8.remove.spec.proof`
- `tls_vec.TlsVecU8.get.spec.proof`
- `tls_vec.TlsVecU8.len_len.spec.proof`
- `tls_vec.TlsVecU8.Insts.CoreOpsIndexIndexUsizeT.index.spec.proof`
- `tls_vec.TlsVecU8.Insts.CoreOpsIndexIndexMutUsizeT.index_mut.spec.proof`
- `tls_vec.TlsVecU16.new.spec.proof`
- `tls_vec.TlsVecU16.len.spec.proof`
- `tls_vec.TlsVecU16.is_empty.spec.proof`
- `tls_vec.TlsVecU16.into_vec.spec.proof`
- `tls_vec.TlsVecU16.push.spec.proof`
- `tls_vec.TlsVecU16.pop.spec.proof`
- `tls_vec.TlsVecU16.remove.spec.proof`
- `tls_vec.TlsVecU16.get.spec.proof`
- `tls_vec.TlsVecU16.len_len.spec.proof`
- `tls_vec.TlsVecU16.Insts.CoreOpsIndexIndexUsizeT.index.spec.proof`
- `tls_vec.TlsVecU16.Insts.CoreOpsIndexIndexMutUsizeT.index_mut.spec.proof`
- `tls_vec.TlsVecU24.new.spec.proof`
- `tls_vec.TlsVecU24.len.spec.proof`
- `tls_vec.TlsVecU24.is_empty.spec.proof`
- `tls_vec.TlsVecU24.into_vec.spec.proof`
- `tls_vec.TlsVecU24.push.spec.proof`
- `tls_vec.TlsVecU24.pop.spec.proof`
- `tls_vec.TlsVecU24.remove.spec.proof`
- `tls_vec.TlsVecU24.get.spec.proof`
- `tls_vec.TlsVecU24.len_len.spec.proof`
- `tls_vec.TlsVecU24.Insts.CoreOpsIndexIndexUsizeT.index.spec.proof`
- `tls_vec.TlsVecU24.Insts.CoreOpsIndexIndexMutUsizeT.index_mut.spec.proof`
- `tls_vec.TlsVecU32.new.spec.proof`
- `tls_vec.TlsVecU32.len.spec.proof`
- `tls_vec.TlsVecU32.is_empty.spec.proof`
- `tls_vec.TlsVecU32.into_vec.spec.proof`
- `tls_vec.TlsVecU32.push.spec.proof`
- `tls_vec.TlsVecU32.pop.spec.proof`
- `tls_vec.TlsVecU32.remove.spec.proof`
- `tls_vec.TlsVecU32.get.spec.proof`
- `tls_vec.TlsVecU32.len_len.spec.proof`
- `tls_vec.TlsVecU32.Insts.CoreOpsIndexIndexUsizeT.index.spec.proof`
- `tls_vec.TlsVecU32.Insts.CoreOpsIndexIndexMutUsizeT.index_mut.spec.proof`

#### Round-trip lemmas (`spec.rs`) (30)

- `spec.u8_encode_decode.spec.proof`
- `spec.u8_decode_encode.spec.proof`
- `spec.u16_encode_decode.spec.proof`
- `spec.u16_decode_encode.spec.proof`
- `spec.u32_encode_decode.spec.proof`
- `spec.u32_decode_encode.spec.proof`
- `spec.u64_encode_decode.spec.proof`
- `spec.u64_decode_encode.spec.proof`
- `spec.u24_encode_decode.spec.proof`
- `spec.u24_decode_encode.spec.proof`
- `spec.array4_encode_decode.spec.proof`
- `spec.array4_decode_encode.spec.proof`
- `spec.option_u16_encode_decode.spec.proof`
- `spec.option_u16_decode_encode.spec.proof`
- `spec.varint_encode_decode.spec.proof`
- `spec.varint_decode_encode.spec.proof`
- `spec.vlbytes_encode_decode.spec.proof`
- `spec.vlbytes_decode_encode.spec.proof`
- `spec.byte_vec_u8_encode_decode.spec.proof`
- `spec.byte_vec_u8_decode_encode.spec.proof`
- `spec.byte_vec_u16_encode_decode.spec.proof`
- `spec.byte_vec_u16_decode_encode.spec.proof`
- `spec.byte_vec_u24_encode_decode.spec.proof`
- `spec.byte_vec_u24_decode_encode.spec.proof`
- `spec.byte_vec_u32_encode_decode.spec.proof`
- `spec.byte_vec_u32_decode_encode.spec.proof`
- `spec.vec_u16_encode_decode.spec.proof`
- `spec.vec_u16_decode_encode.spec.proof`
- `spec.string_encode_decode.spec.proof`
- `spec.string_decode_encode.spec.proof`

#### `quic_vec` (VLBytes, ContentLength, Vec/Slice/Str/String) (19)

- `quic_vec.tls_serialize_bytes_len.spec.proof`
- `quic_vec.ContentLength.new.spec.proof`
- `quic_vec.ContentLength.from_usize.spec.proof`
- `quic_vec.VLBytes.Insts.Tls_codecSerializeBytes.tls_serialize_bytes.spec.proof`
- `quic_vec.VLBytes.as_slice.spec.proof`
- `quic_vec.VLBytes.push.spec.proof`
- `quic_vec.VLBytes.pop.spec.proof`
- `quic_vec.VLByteVec.as_slice.spec.proof`
- `quic_vec.VLByteVec.push.spec.proof`
- `quic_vec.VLByteVec.pop.spec.proof`
- `quic_vec.VLByteSlice.as_slice.spec.proof`
- `quic_vec.VLByteSlice.Insts.Tls_codecSerializeBytes.tls_serialize_bytes.spec.proof`
- `alloc.string.String.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes.spec.proof`
- `quic_vec.secret_bytes.SecretVLBytes.as_slice.spec.proof`
- `quic_vec.secret_bytes.SecretVLBytes.push.spec.proof`
- `quic_vec.secret_bytes.SecretVLBytes.pop.spec.proof`
- `quic_vec.secret_byte_vec.SecretVLByteVec.as_slice.spec.proof`
- `quic_vec.secret_byte_vec.SecretVLByteVec.push.spec.proof`
- `quic_vec.secret_byte_vec.SecretVLByteVec.pop.spec.proof`

#### `tls_vec`: TlsByteSliceU* (12)

- `tls_vec.TlsByteSliceU8.as_slice.spec.proof`
- `tls_vec.TlsByteSliceU8.assert_written_bytes.spec.proof`
- `tls_vec.TlsByteSliceU8.tls_serialized_byte_length.spec.proof`
- `tls_vec.TlsByteSliceU16.as_slice.spec.proof`
- `tls_vec.TlsByteSliceU16.assert_written_bytes.spec.proof`
- `tls_vec.TlsByteSliceU16.tls_serialized_byte_length.spec.proof`
- `tls_vec.TlsByteSliceU24.as_slice.spec.proof`
- `tls_vec.TlsByteSliceU24.assert_written_bytes.spec.proof`
- `tls_vec.TlsByteSliceU24.tls_serialized_byte_length.spec.proof`
- `tls_vec.TlsByteSliceU32.as_slice.spec.proof`
- `tls_vec.TlsByteSliceU32.assert_written_bytes.spec.proof`
- `tls_vec.TlsByteSliceU32.tls_serialized_byte_length.spec.proof`

#### `varint` (10)

- `varint.check_min_len.spec.proof`
- `varint.calculate_value.spec.proof`
- `varint.TlsVarInt.Insts.Tls_codecSerializeBytes.tls_serialize_bytes.spec.proof`
- `varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes.spec.proof`
- `varint.TlsVarInt.try_new.spec.proof`
- `varint.TlsVarInt.value.spec.proof`
- `varint.TlsVarInt.bytes_len.spec.proof`
- `varint.TlsVarInt.write_bytes.spec.proof`
- `varint.TlsVarInt.Insts.CoreConvertTryFromU64Error.try_from.spec.proof`
- `U64.Insts.CoreConvertFromTlsVarInt.from.spec.proof`

#### Integer primitives (primitives.rs) (5)

- `U8.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes.spec.proof`
- `U16.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes.spec.proof`
- `U24.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes.spec.proof`
- `U32.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes.spec.proof`
- `U64.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes.spec.proof`

#### `U24` (lib.rs) (4)

- `U24.from_be_bytes.spec.proof`
- `U24.to_be_bytes.spec.proof`
- `Usize.Insts.CoreConvertFromU24.from.spec.proof`
- `U24.Insts.CoreConvertTryFromUsizeError.try_from.spec.proof`

#### `tls_vec`: TlsSliceU* (4)

- `tls_vec.TlsSliceU8.as_slice.spec.proof`
- `tls_vec.TlsSliceU16.as_slice.spec.proof`
- `tls_vec.TlsSliceU24.as_slice.spec.proof`
- `tls_vec.TlsSliceU32.as_slice.spec.proof`

#### Length arithmetic (lib.rs) (2)

- `checked_capacity.spec.proof`
- `checked_alloc_len.spec.proof`

#### Arrays (arrays.rs) (1)

- `ArrayU8LEN.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes.spec.proof`

## 1b. Function specs, generic (with `…InstLawful` hypotheses where aeneas emits them) (90)

#### `tls_vec`: SecretTlsVecU* (60)

- `tls_vec.SecretTlsVecU8.new.spec.proof`
- `tls_vec.SecretTlsVecU8.from_slice.spec.proof`
- `tls_vec.SecretTlsVecU8.len.spec.proof`
- `tls_vec.SecretTlsVecU8.is_empty.spec.proof`
- `tls_vec.SecretTlsVecU8.into_vec.spec.proof`
- `tls_vec.SecretTlsVecU8.push.spec.proof`
- `tls_vec.SecretTlsVecU8.pop.spec.proof`
- `tls_vec.SecretTlsVecU8.remove.spec.proof`
- `tls_vec.SecretTlsVecU8.get.spec.proof`
- `tls_vec.SecretTlsVecU8.len_len.spec.proof`
- `tls_vec.SecretTlsVecU8.Insts.CoreOpsIndexIndexUsizeT.index.spec.proof`
- `tls_vec.SecretTlsVecU8.Insts.CoreOpsIndexIndexMutUsizeT.index_mut.spec.proof`
- `tls_vec.SecretTlsVecU8.assert_written_bytes.spec.proof`
- `tls_vec.SecretTlsVecU8.tls_serialized_length.spec.proof`
- `tls_vec.SecretTlsVecU8.deserialize_bytes.spec.proof`
- `tls_vec.SecretTlsVecU16.new.spec.proof`
- `tls_vec.SecretTlsVecU16.from_slice.spec.proof`
- `tls_vec.SecretTlsVecU16.len.spec.proof`
- `tls_vec.SecretTlsVecU16.is_empty.spec.proof`
- `tls_vec.SecretTlsVecU16.into_vec.spec.proof`
- `tls_vec.SecretTlsVecU16.push.spec.proof`
- `tls_vec.SecretTlsVecU16.pop.spec.proof`
- `tls_vec.SecretTlsVecU16.remove.spec.proof`
- `tls_vec.SecretTlsVecU16.get.spec.proof`
- `tls_vec.SecretTlsVecU16.len_len.spec.proof`
- `tls_vec.SecretTlsVecU16.Insts.CoreOpsIndexIndexUsizeT.index.spec.proof`
- `tls_vec.SecretTlsVecU16.Insts.CoreOpsIndexIndexMutUsizeT.index_mut.spec.proof`
- `tls_vec.SecretTlsVecU16.assert_written_bytes.spec.proof`
- `tls_vec.SecretTlsVecU16.tls_serialized_length.spec.proof`
- `tls_vec.SecretTlsVecU16.deserialize_bytes.spec.proof`
- `tls_vec.SecretTlsVecU24.new.spec.proof`
- `tls_vec.SecretTlsVecU24.from_slice.spec.proof`
- `tls_vec.SecretTlsVecU24.len.spec.proof`
- `tls_vec.SecretTlsVecU24.is_empty.spec.proof`
- `tls_vec.SecretTlsVecU24.into_vec.spec.proof`
- `tls_vec.SecretTlsVecU24.push.spec.proof`
- `tls_vec.SecretTlsVecU24.pop.spec.proof`
- `tls_vec.SecretTlsVecU24.remove.spec.proof`
- `tls_vec.SecretTlsVecU24.get.spec.proof`
- `tls_vec.SecretTlsVecU24.len_len.spec.proof`
- `tls_vec.SecretTlsVecU24.Insts.CoreOpsIndexIndexUsizeT.index.spec.proof`
- `tls_vec.SecretTlsVecU24.Insts.CoreOpsIndexIndexMutUsizeT.index_mut.spec.proof`
- `tls_vec.SecretTlsVecU24.assert_written_bytes.spec.proof`
- `tls_vec.SecretTlsVecU24.tls_serialized_length.spec.proof`
- `tls_vec.SecretTlsVecU24.deserialize_bytes.spec.proof`
- `tls_vec.SecretTlsVecU32.new.spec.proof`
- `tls_vec.SecretTlsVecU32.from_slice.spec.proof`
- `tls_vec.SecretTlsVecU32.len.spec.proof`
- `tls_vec.SecretTlsVecU32.is_empty.spec.proof`
- `tls_vec.SecretTlsVecU32.into_vec.spec.proof`
- `tls_vec.SecretTlsVecU32.push.spec.proof`
- `tls_vec.SecretTlsVecU32.pop.spec.proof`
- `tls_vec.SecretTlsVecU32.remove.spec.proof`
- `tls_vec.SecretTlsVecU32.get.spec.proof`
- `tls_vec.SecretTlsVecU32.len_len.spec.proof`
- `tls_vec.SecretTlsVecU32.Insts.CoreOpsIndexIndexUsizeT.index.spec.proof`
- `tls_vec.SecretTlsVecU32.Insts.CoreOpsIndexIndexMutUsizeT.index_mut.spec.proof`
- `tls_vec.SecretTlsVecU32.assert_written_bytes.spec.proof`
- `tls_vec.SecretTlsVecU32.tls_serialized_length.spec.proof`
- `tls_vec.SecretTlsVecU32.deserialize_bytes.spec.proof`

#### `tls_vec`: TlsVecU* (16)

- `tls_vec.TlsVecU8.from_slice.spec.proof`
- `tls_vec.TlsVecU8.assert_written_bytes.spec.proof`
- `tls_vec.TlsVecU8.tls_serialized_length.spec.proof`
- `tls_vec.TlsVecU8.deserialize_bytes.spec.proof`
- `tls_vec.TlsVecU16.from_slice.spec.proof`
- `tls_vec.TlsVecU16.assert_written_bytes.spec.proof`
- `tls_vec.TlsVecU16.tls_serialized_length.spec.proof`
- `tls_vec.TlsVecU16.deserialize_bytes.spec.proof`
- `tls_vec.TlsVecU24.from_slice.spec.proof`
- `tls_vec.TlsVecU24.assert_written_bytes.spec.proof`
- `tls_vec.TlsVecU24.tls_serialized_length.spec.proof`
- `tls_vec.TlsVecU24.deserialize_bytes.spec.proof`
- `tls_vec.TlsVecU32.from_slice.spec.proof`
- `tls_vec.TlsVecU32.assert_written_bytes.spec.proof`
- `tls_vec.TlsVecU32.tls_serialized_length.spec.proof`
- `tls_vec.TlsVecU32.deserialize_bytes.spec.proof`

#### `tls_vec`: TlsSliceU* (8)

- `tls_vec.TlsSliceU8.tls_serialized_length.spec.proof`
- `tls_vec.TlsSliceU8.assert_written_bytes.spec.proof`
- `tls_vec.TlsSliceU16.tls_serialized_length.spec.proof`
- `tls_vec.TlsSliceU16.assert_written_bytes.spec.proof`
- `tls_vec.TlsSliceU24.tls_serialized_length.spec.proof`
- `tls_vec.TlsSliceU24.assert_written_bytes.spec.proof`
- `tls_vec.TlsSliceU32.tls_serialized_length.spec.proof`
- `tls_vec.TlsSliceU32.assert_written_bytes.spec.proof`

#### `tls_vec`: TlsByteVecU* (4)

- `tls_vec.TlsByteVecU8.from_slice.spec.proof`
- `tls_vec.TlsByteVecU16.from_slice.spec.proof`
- `tls_vec.TlsByteVecU24.from_slice.spec.proof`
- `tls_vec.TlsByteVecU32.from_slice.spec.proof`

#### Option / tuples / PhantomData / Box (primitives.rs) (2)

- `core.option.Option.Insts.Tls_codecSerializeBytes.tls_serialize_bytes.spec.proof`
- `core.option.Option.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes.spec.proof`

## 2a. Per-impl `Lawful`: `SerializeBytes` / `DeserializeBytes` (62)

#### `quic_vec` (VLBytes, ContentLength, Vec/Slice/Str/String) (17)

- `quic_vec.ContentLength.Insts.Tls_codecDeserializeBytes.Lawful`
- `alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.Lawful`
- `quic_vec.VLBytes.Insts.Tls_codecSerializeBytes.Lawful`
- `Shared0VLBytes.Insts.Tls_codecSerializeBytes.Lawful`
- `Shared0Slice.Insts.Tls_codecSerializeBytes.Lawful`
- `Shared0Vec.Insts.Tls_codecSerializeBytes.Lawful`
- `alloc.vec.Vec.Insts.Tls_codecSerializeBytes.Lawful`
- `quic_vec.VLBytes.Insts.Tls_codecDeserializeBytes.Lawful`
- `quic_vec.VLByteVec.Insts.Tls_codecDeserializeBytes.Lawful`
- `quic_vec.ContentLength.Insts.Tls_codecSerializeBytes.Lawful`
- `quic_vec.VLByteSlice.Insts.Tls_codecSerializeBytes.Lawful`
- `quic_vec.secret_bytes.SecretVLBytes.Insts.Tls_codecDeserializeBytes.Lawful`
- `quic_vec.secret_byte_vec.SecretVLByteVec.Insts.Tls_codecDeserializeBytes.Lawful`
- `alloc.string.String.Insts.Tls_codecDeserializeBytes.Lawful`
- `alloc.string.String.Insts.Tls_codecSerializeBytes.Lawful`
- `Str.Insts.Tls_codecSerializeBytes.Lawful`
- `Shared0Str.Insts.Tls_codecSerializeBytes.Lawful`

#### Integer primitives (primitives.rs) (15)

- `U8.Insts.Tls_codecDeserializeBytes.Lawful`
- `U16.Insts.Tls_codecDeserializeBytes.Lawful`
- `U24.Insts.Tls_codecDeserializeBytes.Lawful`
- `U32.Insts.Tls_codecDeserializeBytes.Lawful`
- `U64.Insts.Tls_codecDeserializeBytes.Lawful`
- `Shared0U8.Insts.Tls_codecSerializeBytes.Lawful`
- `Shared0U16.Insts.Tls_codecSerializeBytes.Lawful`
- `Shared0U24.Insts.Tls_codecSerializeBytes.Lawful`
- `Shared0U32.Insts.Tls_codecSerializeBytes.Lawful`
- `Shared0U64.Insts.Tls_codecSerializeBytes.Lawful`
- `U8.Insts.Tls_codecSerializeBytes.Lawful`
- `U16.Insts.Tls_codecSerializeBytes.Lawful`
- `U24.Insts.Tls_codecSerializeBytes.Lawful`
- `U32.Insts.Tls_codecSerializeBytes.Lawful`
- `U64.Insts.Tls_codecSerializeBytes.Lawful`

#### Option / tuples / PhantomData / Box (primitives.rs) (10)

- `core.option.Option.Insts.Tls_codecSerializeBytes.Lawful`
- `Shared0Option.Insts.Tls_codecSerializeBytes.Lawful`
- `core.option.Option.Insts.Tls_codecDeserializeBytes.Lawful`
- `Pair.Insts.Tls_codecDeserializeBytes.Lawful`
- `TupleTUV.Insts.Tls_codecDeserializeBytes.Lawful`
- `Tuple.Insts.Tls_codecDeserializeBytes.Lawful`
- `core.marker.PhantomData.Insts.Tls_codecDeserializeBytes.Lawful`
- `core.marker.PhantomData.Insts.Tls_codecSerializeBytes.Lawful`
- `Box.Insts.Tls_codecSerializeBytes.Lawful`
- `Box.Insts.Tls_codecDeserializeBytes.Lawful`

#### `tls_vec`: TlsByteVecU* (8)

- `tls_vec.TlsByteVecU8.Insts.Tls_codecSerializeBytes.Lawful`
- `tls_vec.TlsByteVecU8.Insts.Tls_codecDeserializeBytes.Lawful`
- `tls_vec.TlsByteVecU16.Insts.Tls_codecSerializeBytes.Lawful`
- `tls_vec.TlsByteVecU16.Insts.Tls_codecDeserializeBytes.Lawful`
- `tls_vec.TlsByteVecU24.Insts.Tls_codecSerializeBytes.Lawful`
- `tls_vec.TlsByteVecU24.Insts.Tls_codecDeserializeBytes.Lawful`
- `tls_vec.TlsByteVecU32.Insts.Tls_codecSerializeBytes.Lawful`
- `tls_vec.TlsByteVecU32.Insts.Tls_codecDeserializeBytes.Lawful`

#### `tls_vec`: SecretTlsVecU* (4)

- `tls_vec.SecretTlsVecU8.Insts.Tls_codecDeserializeBytes.Lawful`
- `tls_vec.SecretTlsVecU16.Insts.Tls_codecDeserializeBytes.Lawful`
- `tls_vec.SecretTlsVecU24.Insts.Tls_codecDeserializeBytes.Lawful`
- `tls_vec.SecretTlsVecU32.Insts.Tls_codecDeserializeBytes.Lawful`

#### `tls_vec`: TlsVecU* (4)

- `tls_vec.TlsVecU8.Insts.Tls_codecDeserializeBytes.Lawful`
- `tls_vec.TlsVecU16.Insts.Tls_codecDeserializeBytes.Lawful`
- `tls_vec.TlsVecU24.Insts.Tls_codecDeserializeBytes.Lawful`
- `tls_vec.TlsVecU32.Insts.Tls_codecDeserializeBytes.Lawful`

#### Arrays (arrays.rs) (2)

- `ArrayU8LEN.Insts.Tls_codecDeserializeBytes.Lawful`
- `ArrayU8LEN.Insts.Tls_codecSerializeBytes.Lawful`

#### `varint` (2)

- `varint.TlsVarInt.Insts.Tls_codecSerializeBytes.Lawful`
- `varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.Lawful`

## 2b. Per-impl `Lawful`: `Size` (PF only) (74)

#### `quic_vec` (VLBytes, ContentLength, Vec/Slice/Str/String) (15)

- `quic_vec.ContentLength.Insts.Tls_codecSize.Lawful`
- `alloc.vec.Vec.Insts.Tls_codecSize.Lawful`
- `Shared0Vec.Insts.Tls_codecSize.Lawful`
- `quic_vec.VLBytes.Insts.Tls_codecSize.Lawful`
- `Shared0VLBytes.Insts.Tls_codecSize.Lawful`
- `Shared0Slice.Insts.Tls_codecSize.Lawful`
- `quic_vec.VLByteVec.Insts.Tls_codecSize.Lawful`
- `Shared0VLByteVec.Insts.Tls_codecSize.Lawful`
- `Shared0VLByteSlice.Insts.Tls_codecSize.Lawful`
- `quic_vec.VLByteSlice.Insts.Tls_codecSize.Lawful`
- `quic_vec.secret_bytes.SecretVLBytes.Insts.Tls_codecSize.Lawful`
- `quic_vec.secret_byte_vec.SecretVLByteVec.Insts.Tls_codecSize.Lawful`
- `alloc.string.String.Insts.Tls_codecSize.Lawful`
- `Str.Insts.Tls_codecSize.Lawful`
- `Shared0Str.Insts.Tls_codecSize.Lawful`

#### Integer primitives (primitives.rs) (10)

- `U8.Insts.Tls_codecSize.Lawful`
- `U16.Insts.Tls_codecSize.Lawful`
- `U24.Insts.Tls_codecSize.Lawful`
- `U32.Insts.Tls_codecSize.Lawful`
- `U64.Insts.Tls_codecSize.Lawful`
- `Shared0U8.Insts.Tls_codecSize.Lawful`
- `Shared0U16.Insts.Tls_codecSize.Lawful`
- `Shared0U24.Insts.Tls_codecSize.Lawful`
- `Shared0U32.Insts.Tls_codecSize.Lawful`
- `Shared0U64.Insts.Tls_codecSize.Lawful`

#### `tls_vec`: SecretTlsVecU* (8)

- `tls_vec.SecretTlsVecU8.Insts.Tls_codecSize.Lawful`
- `tls_vec.SecretTlsVecU16.Insts.Tls_codecSize.Lawful`
- `tls_vec.SecretTlsVecU24.Insts.Tls_codecSize.Lawful`
- `tls_vec.SecretTlsVecU32.Insts.Tls_codecSize.Lawful`
- `Shared0SecretTlsVecU8.Insts.Tls_codecSize.Lawful`
- `Shared0SecretTlsVecU16.Insts.Tls_codecSize.Lawful`
- `Shared0SecretTlsVecU24.Insts.Tls_codecSize.Lawful`
- `Shared0SecretTlsVecU32.Insts.Tls_codecSize.Lawful`

#### `tls_vec`: TlsByteSliceU* (8)

- `Shared0TlsByteSliceU8.Insts.Tls_codecSize.Lawful`
- `Shared0TlsByteSliceU16.Insts.Tls_codecSize.Lawful`
- `Shared0TlsByteSliceU24.Insts.Tls_codecSize.Lawful`
- `Shared0TlsByteSliceU32.Insts.Tls_codecSize.Lawful`
- `tls_vec.TlsByteSliceU8.Insts.Tls_codecSize.Lawful`
- `tls_vec.TlsByteSliceU16.Insts.Tls_codecSize.Lawful`
- `tls_vec.TlsByteSliceU24.Insts.Tls_codecSize.Lawful`
- `tls_vec.TlsByteSliceU32.Insts.Tls_codecSize.Lawful`

#### `tls_vec`: TlsByteVecU* (8)

- `tls_vec.TlsByteVecU8.Insts.Tls_codecSize.Lawful`
- `tls_vec.TlsByteVecU16.Insts.Tls_codecSize.Lawful`
- `tls_vec.TlsByteVecU24.Insts.Tls_codecSize.Lawful`
- `tls_vec.TlsByteVecU32.Insts.Tls_codecSize.Lawful`
- `Shared0TlsByteVecU8.Insts.Tls_codecSize.Lawful`
- `Shared0TlsByteVecU16.Insts.Tls_codecSize.Lawful`
- `Shared0TlsByteVecU24.Insts.Tls_codecSize.Lawful`
- `Shared0TlsByteVecU32.Insts.Tls_codecSize.Lawful`

#### `tls_vec`: TlsSliceU* (8)

- `Shared0TlsSliceU8.Insts.Tls_codecSize.Lawful`
- `Shared0TlsSliceU16.Insts.Tls_codecSize.Lawful`
- `Shared0TlsSliceU24.Insts.Tls_codecSize.Lawful`
- `Shared0TlsSliceU32.Insts.Tls_codecSize.Lawful`
- `tls_vec.TlsSliceU8.Insts.Tls_codecSize.Lawful`
- `tls_vec.TlsSliceU16.Insts.Tls_codecSize.Lawful`
- `tls_vec.TlsSliceU24.Insts.Tls_codecSize.Lawful`
- `tls_vec.TlsSliceU32.Insts.Tls_codecSize.Lawful`

#### `tls_vec`: TlsVecU* (8)

- `tls_vec.TlsVecU8.Insts.Tls_codecSize.Lawful`
- `tls_vec.TlsVecU16.Insts.Tls_codecSize.Lawful`
- `tls_vec.TlsVecU24.Insts.Tls_codecSize.Lawful`
- `tls_vec.TlsVecU32.Insts.Tls_codecSize.Lawful`
- `Shared0TlsVecU8.Insts.Tls_codecSize.Lawful`
- `Shared0TlsVecU16.Insts.Tls_codecSize.Lawful`
- `Shared0TlsVecU24.Insts.Tls_codecSize.Lawful`
- `Shared0TlsVecU32.Insts.Tls_codecSize.Lawful`

#### Option / tuples / PhantomData / Box (primitives.rs) (7)

- `core.option.Option.Insts.Tls_codecSize.Lawful`
- `Shared0Option.Insts.Tls_codecSize.Lawful`
- `Pair.Insts.Tls_codecSize.Lawful`
- `TupleTUV.Insts.Tls_codecSize.Lawful`
- `Tuple.Insts.Tls_codecSize.Lawful`
- `core.marker.PhantomData.Insts.Tls_codecSize.Lawful`
- `Box.Insts.Tls_codecSize.Lawful`

#### Arrays (arrays.rs) (1)

- `ArrayU8LEN.Insts.Tls_codecSize.Lawful`

#### `varint` (1)

- `varint.TlsVarInt.Insts.Tls_codecSize.Lawful`

## 2c. Per-impl `Lawful`: `Serialize` / `Deserialize` (parent field only) (105)

#### `quic_vec` (VLBytes, ContentLength, Vec/Slice/Str/String) (21)

- `quic_vec.ContentLength.Insts.Tls_codecDeserialize.Lawful`
- `quic_vec.ContentLength.Insts.Tls_codecSerialize.Lawful`
- `alloc.vec.Vec.Insts.Tls_codecDeserialize.Lawful`
- `alloc.vec.Vec.Insts.Tls_codecSerialize.Lawful`
- `Shared0Slice.Insts.Tls_codecSerialize.Lawful`
- `quic_vec.VLBytes.Insts.Tls_codecSerialize.Lawful`
- `Shared0VLBytes.Insts.Tls_codecSerialize.Lawful`
- `quic_vec.VLBytes.Insts.Tls_codecDeserialize.Lawful`
- `quic_vec.VLByteVec.Insts.Tls_codecSerialize.Lawful`
- `Shared0VLByteVec.Insts.Tls_codecSerialize.Lawful`
- `quic_vec.VLByteVec.Insts.Tls_codecDeserialize.Lawful`
- `Shared0VLByteSlice.Insts.Tls_codecSerialize.Lawful`
- `quic_vec.VLByteSlice.Insts.Tls_codecSerialize.Lawful`
- `quic_vec.secret_bytes.SecretVLBytes.Insts.Tls_codecSerialize.Lawful`
- `quic_vec.secret_bytes.SecretVLBytes.Insts.Tls_codecDeserialize.Lawful`
- `quic_vec.secret_byte_vec.SecretVLByteVec.Insts.Tls_codecSerialize.Lawful`
- `quic_vec.secret_byte_vec.SecretVLByteVec.Insts.Tls_codecDeserialize.Lawful`
- `alloc.string.String.Insts.Tls_codecSerialize.Lawful`
- `Str.Insts.Tls_codecSerialize.Lawful`
- `Shared0Str.Insts.Tls_codecSerialize.Lawful`
- `alloc.string.String.Insts.Tls_codecDeserialize.Lawful`

#### Integer primitives (primitives.rs) (15)

- `U8.Insts.Tls_codecDeserialize.Lawful`
- `U16.Insts.Tls_codecDeserialize.Lawful`
- `U24.Insts.Tls_codecDeserialize.Lawful`
- `U32.Insts.Tls_codecDeserialize.Lawful`
- `U64.Insts.Tls_codecDeserialize.Lawful`
- `U8.Insts.Tls_codecSerialize.Lawful`
- `U16.Insts.Tls_codecSerialize.Lawful`
- `U24.Insts.Tls_codecSerialize.Lawful`
- `U32.Insts.Tls_codecSerialize.Lawful`
- `U64.Insts.Tls_codecSerialize.Lawful`
- `Shared0U8.Insts.Tls_codecSerialize.Lawful`
- `Shared0U16.Insts.Tls_codecSerialize.Lawful`
- `Shared0U24.Insts.Tls_codecSerialize.Lawful`
- `Shared0U32.Insts.Tls_codecSerialize.Lawful`
- `Shared0U64.Insts.Tls_codecSerialize.Lawful`

#### Option / tuples / PhantomData / Box (primitives.rs) (13)

- `core.option.Option.Insts.Tls_codecSerialize.Lawful`
- `Shared0Option.Insts.Tls_codecSerialize.Lawful`
- `core.option.Option.Insts.Tls_codecDeserialize.Lawful`
- `Pair.Insts.Tls_codecDeserialize.Lawful`
- `Pair.Insts.Tls_codecSerialize.Lawful`
- `TupleTUV.Insts.Tls_codecDeserialize.Lawful`
- `TupleTUV.Insts.Tls_codecSerialize.Lawful`
- `Tuple.Insts.Tls_codecDeserialize.Lawful`
- `Tuple.Insts.Tls_codecSerialize.Lawful`
- `core.marker.PhantomData.Insts.Tls_codecDeserialize.Lawful`
- `core.marker.PhantomData.Insts.Tls_codecSerialize.Lawful`
- `Box.Insts.Tls_codecSerialize.Lawful`
- `Box.Insts.Tls_codecDeserialize.Lawful`

#### `tls_vec`: SecretTlsVecU* (12)

- `tls_vec.SecretTlsVecU8.Insts.Tls_codecSerialize.Lawful`
- `tls_vec.SecretTlsVecU16.Insts.Tls_codecSerialize.Lawful`
- `tls_vec.SecretTlsVecU24.Insts.Tls_codecSerialize.Lawful`
- `tls_vec.SecretTlsVecU32.Insts.Tls_codecSerialize.Lawful`
- `Shared0SecretTlsVecU8.Insts.Tls_codecSerialize.Lawful`
- `Shared0SecretTlsVecU16.Insts.Tls_codecSerialize.Lawful`
- `Shared0SecretTlsVecU24.Insts.Tls_codecSerialize.Lawful`
- `Shared0SecretTlsVecU32.Insts.Tls_codecSerialize.Lawful`
- `tls_vec.SecretTlsVecU8.Insts.Tls_codecDeserialize.Lawful`
- `tls_vec.SecretTlsVecU16.Insts.Tls_codecDeserialize.Lawful`
- `tls_vec.SecretTlsVecU24.Insts.Tls_codecDeserialize.Lawful`
- `tls_vec.SecretTlsVecU32.Insts.Tls_codecDeserialize.Lawful`

#### `tls_vec`: TlsByteVecU* (12)

- `tls_vec.TlsByteVecU8.Insts.Tls_codecSerialize.Lawful`
- `tls_vec.TlsByteVecU16.Insts.Tls_codecSerialize.Lawful`
- `tls_vec.TlsByteVecU24.Insts.Tls_codecSerialize.Lawful`
- `tls_vec.TlsByteVecU32.Insts.Tls_codecSerialize.Lawful`
- `Shared0TlsByteVecU8.Insts.Tls_codecSerialize.Lawful`
- `Shared0TlsByteVecU16.Insts.Tls_codecSerialize.Lawful`
- `Shared0TlsByteVecU24.Insts.Tls_codecSerialize.Lawful`
- `Shared0TlsByteVecU32.Insts.Tls_codecSerialize.Lawful`
- `tls_vec.TlsByteVecU8.Insts.Tls_codecDeserialize.Lawful`
- `tls_vec.TlsByteVecU16.Insts.Tls_codecDeserialize.Lawful`
- `tls_vec.TlsByteVecU24.Insts.Tls_codecDeserialize.Lawful`
- `tls_vec.TlsByteVecU32.Insts.Tls_codecDeserialize.Lawful`

#### `tls_vec`: TlsVecU* (12)

- `tls_vec.TlsVecU8.Insts.Tls_codecSerialize.Lawful`
- `tls_vec.TlsVecU16.Insts.Tls_codecSerialize.Lawful`
- `tls_vec.TlsVecU24.Insts.Tls_codecSerialize.Lawful`
- `tls_vec.TlsVecU32.Insts.Tls_codecSerialize.Lawful`
- `Shared0TlsVecU8.Insts.Tls_codecSerialize.Lawful`
- `Shared0TlsVecU16.Insts.Tls_codecSerialize.Lawful`
- `Shared0TlsVecU24.Insts.Tls_codecSerialize.Lawful`
- `Shared0TlsVecU32.Insts.Tls_codecSerialize.Lawful`
- `tls_vec.TlsVecU8.Insts.Tls_codecDeserialize.Lawful`
- `tls_vec.TlsVecU16.Insts.Tls_codecDeserialize.Lawful`
- `tls_vec.TlsVecU24.Insts.Tls_codecDeserialize.Lawful`
- `tls_vec.TlsVecU32.Insts.Tls_codecDeserialize.Lawful`

#### `tls_vec`: TlsByteSliceU* (8)

- `Shared0TlsByteSliceU8.Insts.Tls_codecSerialize.Lawful`
- `Shared0TlsByteSliceU16.Insts.Tls_codecSerialize.Lawful`
- `Shared0TlsByteSliceU24.Insts.Tls_codecSerialize.Lawful`
- `Shared0TlsByteSliceU32.Insts.Tls_codecSerialize.Lawful`
- `tls_vec.TlsByteSliceU8.Insts.Tls_codecSerialize.Lawful`
- `tls_vec.TlsByteSliceU16.Insts.Tls_codecSerialize.Lawful`
- `tls_vec.TlsByteSliceU24.Insts.Tls_codecSerialize.Lawful`
- `tls_vec.TlsByteSliceU32.Insts.Tls_codecSerialize.Lawful`

#### `tls_vec`: TlsSliceU* (8)

- `Shared0TlsSliceU8.Insts.Tls_codecSerialize.Lawful`
- `Shared0TlsSliceU16.Insts.Tls_codecSerialize.Lawful`
- `Shared0TlsSliceU24.Insts.Tls_codecSerialize.Lawful`
- `Shared0TlsSliceU32.Insts.Tls_codecSerialize.Lawful`
- `tls_vec.TlsSliceU8.Insts.Tls_codecSerialize.Lawful`
- `tls_vec.TlsSliceU16.Insts.Tls_codecSerialize.Lawful`
- `tls_vec.TlsSliceU24.Insts.Tls_codecSerialize.Lawful`
- `tls_vec.TlsSliceU32.Insts.Tls_codecSerialize.Lawful`

#### Arrays (arrays.rs) (2)

- `ArrayU8LEN.Insts.Tls_codecSerialize.Lawful`
- `ArrayU8LEN.Insts.Tls_codecDeserialize.Lawful`

#### `varint` (2)

- `varint.TlsVarInt.Insts.Tls_codecDeserialize.Lawful`
- `varint.TlsVarInt.Insts.Tls_codecSerialize.Lawful`

## 2d. Per-impl `Lawful`: core / third-party traits (428)

#### `core.ops.function.FnOnce` (114)

- `arrays.DeserializeBytesArrayU8LEN.tls_deserialize_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairArrayU8LENSharedSliceU8Bool.Lawful`
- `arrays.DeserializeBytesArrayU8LEN.tls_deserialize_bytes.closure.Insts.CoreOpsFunctionFnOnceTupleTryFromSliceErrorError.Lawful`
- `__4.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleUsizeBool.Lawful`
- `__5.ensures.closure.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.Lawful`
- `__5.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.Lawful`
- `__6.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.Lawful`
- `__7.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleSelf_Bool.Lawful`
- `__8.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleSelf_Bool.Lawful`
- `__9.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairSelf_SharedSliceU8Bool.Lawful`
- `__10.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleSelf_Bool.Lawful`
- `primitives.SerializeOption.tls_serialize.closure.Insts.CoreOpsFunctionFnOnceTupleUsizeUsize.Lawful`
- `primitives.SerializeBytesOption.tls_serialize_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.Lawful`
- `primitives.SerializeBytesOption.tls_serialize_bytes._.ensures.closure_1.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.Lawful`
- `primitives.DeserializeBytesOption.tls_deserialize_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairOptionSharedSliceU8Bool.Lawful`
- `primitives.DeserializeBytesU8.tls_deserialize_bytes.closure.Insts.CoreOpsFunctionFnOnceTupleTryFromSliceErrorError.Lawful`
- `primitives.DeserializeBytesU16.tls_deserialize_bytes.closure.Insts.CoreOpsFunctionFnOnceTupleTryFromSliceErrorError.Lawful`
- `primitives.DeserializeBytesU24.tls_deserialize_bytes.closure.Insts.CoreOpsFunctionFnOnceTupleTryFromSliceErrorError.Lawful`
- `primitives.DeserializeBytesU32.tls_deserialize_bytes.closure.Insts.CoreOpsFunctionFnOnceTupleTryFromSliceErrorError.Lawful`
- `primitives.DeserializeBytesU64.tls_deserialize_bytes.closure.Insts.CoreOpsFunctionFnOnceTupleTryFromSliceErrorError.Lawful`
- `primitives.DeserializeBytesU8.tls_deserialize_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairU8SharedSliceU8Bool.Lawful`
- `primitives.DeserializeBytesU16.tls_deserialize_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairU16SharedSliceU8Bool.Lawful`
- `primitives.DeserializeBytesU24.tls_deserialize_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairU24SharedSliceU8Bool.Lawful`
- `primitives.DeserializeBytesU32.tls_deserialize_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairU32SharedSliceU8Bool.Lawful`
- `primitives.DeserializeBytesU64.tls_deserialize_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairU64SharedSliceU8Bool.Lawful`
- `primitives.SerializePair.tls_serialize.closure.Insts.CoreOpsFunctionFnOnceTupleUsizeUsize.Lawful`
- `primitives.SerializeTupleTUV.tls_serialize.closure.Insts.CoreOpsFunctionFnOnceTupleUsizeUsize.Lawful`
- `quic_vec.ContentLength.from_usize._.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleContentLengthBool.Lawful`
- `varint.DeserializeBytesTlsVarInt.tls_deserialize_bytes.closure.Insts.CoreOpsFunctionFnOnceTupleTryFromIntErrorError.Lawful`
- `quic_vec.SizeShared0Slice.tls_serialized_len.closure_1.Insts.CoreOpsFunctionFnOnceTupleContentLengthUsize.Lawful`
- `quic_vec.SizeShared0Slice.tls_serialized_len.closure.Insts.CoreOpsFunctionFnOncePairUsizeSharedTUsize.Lawful`
- `quic_vec.tls_serialize_bytes_len.closure.Insts.CoreOpsFunctionFnOnceTupleContentLengthUsize.Lawful`
- `quic_vec.SerializeBytesVLBytes.tls_serialize_bytes._.ensures.closure_1.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.Lawful`
- `quic_vec.SerializeBytesVLBytes.tls_serialize_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleContentLengthBool.Lawful`
- `quic_vec.SerializeBytesVLByteSlice.tls_serialize_bytes._.ensures.closure_1.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.Lawful`
- `quic_vec.SerializeBytesVLByteSlice.tls_serialize_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleContentLengthBool.Lawful`
- `varint.DeserializeTlsVarInt.tls_deserialize.closure.Insts.CoreOpsFunctionFnOnceTupleTryFromIntErrorError.Lawful`
- `spec.__1.ensures.closure.closure.Insts.CoreOpsFunctionFnOnceTuplePairSelf_VecU8Bool.Lawful`
- `spec.__1.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleOptionPairSelf_VecU8Bool.Lawful`
- `spec.__2.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.Lawful`
- `string.DeserializeBytesString.tls_deserialize_bytes.closure.Insts.CoreOpsFunctionFnOnceTupleFromUtf8ErrorError.Lawful`
- `spec.__3.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairU8UsizeBool.Lawful`
- `spec.__4.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairVecU8UsizeBool.Lawful`
- `spec.__5.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairU16UsizeBool.Lawful`
- `spec.__6.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairVecU8UsizeBool.Lawful`
- `spec.__7.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairU32UsizeBool.Lawful`
- `spec.__8.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairVecU8UsizeBool.Lawful`
- `spec.__9.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairU64UsizeBool.Lawful`
- `spec.__10.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairVecU8UsizeBool.Lawful`
- `spec.__11.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairU24UsizeBool.Lawful`
- `spec.__12.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairVecU8UsizeBool.Lawful`
- `spec.__13.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairArrayU84UsizeBool.Lawful`
- `spec.__14.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairVecU8UsizeBool.Lawful`
- `spec.__15.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairOptionU16UsizeBool.Lawful`
- `spec.__16.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairVecU8UsizeBool.Lawful`
- `spec.__18.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairTlsVarIntUsizeBool.Lawful`
- `spec.__19.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairVecU8UsizeBool.Lawful`
- `spec.__20.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairVLBytesUsizeBool.Lawful`
- `spec.__21.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairVecU8UsizeBool.Lawful`
- `spec.__22.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairTlsByteVecU8UsizeBool.Lawful`
- `spec.__23.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairVecU8UsizeBool.Lawful`
- `spec.__24.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairTlsByteVecU16UsizeBool.Lawful`
- `spec.__25.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairVecU8UsizeBool.Lawful`
- `spec.__26.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairTlsByteVecU24UsizeBool.Lawful`
- `spec.__27.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairVecU8UsizeBool.Lawful`
- `spec.__28.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairTlsByteVecU32UsizeBool.Lawful`
- `spec.__29.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairVecU8UsizeBool.Lawful`
- `spec.__30.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairVecU16UsizeBool.Lawful`
- `spec.__31.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairVecU8UsizeBool.Lawful`
- `spec.__32.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairStringUsizeBool.Lawful`
- `spec.__33.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairVecU8UsizeBool.Lawful`
- `spec.io.__1.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleSelf_Bool.Lawful`
- `spec.io.__2.ensures.closure.closure.Insts.CoreOpsFunctionFnOnceTupleSelf_Bool.Lawful`
- `spec.io._.requires.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.Lawful`
- `spec.io.__2.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.Lawful`
- `spec.io.__3.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.Lawful`
- `spec.io.__4.ensures.closure.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.Lawful`
- `spec.io.__4.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.Lawful`
- `spec.io.__5.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleSelf_Bool.Lawful`
- `spec.io.__7.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairSelf_SharedSliceU8Bool.Lawful`
- `spec.io.__9.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairSelf_SharedSliceU8Bool.Lawful`
- `spec.io.__8.requires.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.Lawful`
- `string.DeserializeBytesString.tls_deserialize_bytes._.ensures.closure.closure.Insts.CoreOpsFunctionFnOnceTuplePairVLByteVecSharedSliceU8Bool.Lawful`
- `string.DeserializeBytesString.tls_deserialize_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairStringSharedSliceU8Bool.Lawful`
- `string.std_only.DeserializeString.tls_deserialize.closure.Insts.CoreOpsFunctionFnOnceTupleFromUtf8ErrorError.Lawful`
- `tls_vec.TlsVecU8.tls_serialized_length.closure.Insts.CoreOpsFunctionFnOncePairUsizeSharedTUsize.Lawful`
- `tls_vec.TlsVecU16.tls_serialized_length.closure.Insts.CoreOpsFunctionFnOncePairUsizeSharedTUsize.Lawful`
- `tls_vec.TlsVecU24.tls_serialized_length.closure.Insts.CoreOpsFunctionFnOncePairUsizeSharedTUsize.Lawful`
- `tls_vec.TlsVecU32.tls_serialized_length.closure.Insts.CoreOpsFunctionFnOncePairUsizeSharedTUsize.Lawful`
- `tls_vec.SecretTlsVecU8.tls_serialized_length.closure.Insts.CoreOpsFunctionFnOncePairUsizeSharedTUsize.Lawful`
- `tls_vec.SecretTlsVecU16.tls_serialized_length.closure.Insts.CoreOpsFunctionFnOncePairUsizeSharedTUsize.Lawful`
- `tls_vec.SecretTlsVecU24.tls_serialized_length.closure.Insts.CoreOpsFunctionFnOncePairUsizeSharedTUsize.Lawful`
- `tls_vec.SecretTlsVecU32.tls_serialized_length.closure.Insts.CoreOpsFunctionFnOncePairUsizeSharedTUsize.Lawful`
- `tls_vec.TlsSliceU8.tls_serialized_length.closure.Insts.CoreOpsFunctionFnOncePairUsizeSharedTUsize.Lawful`
- `tls_vec.TlsSliceU16.tls_serialized_length.closure.Insts.CoreOpsFunctionFnOncePairUsizeSharedTUsize.Lawful`
- `tls_vec.TlsSliceU24.tls_serialized_length.closure.Insts.CoreOpsFunctionFnOncePairUsizeSharedTUsize.Lawful`
- `tls_vec.TlsSliceU32.tls_serialized_length.closure.Insts.CoreOpsFunctionFnOncePairUsizeSharedTUsize.Lawful`
- `tls_vec.TlsByteVecU8.deserialize_bytes_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairTlsByteVecU8SharedSliceU8Bool.Lawful`
- `tls_vec.TlsByteVecU16.deserialize_bytes_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairTlsByteVecU16SharedSliceU8Bool.Lawful`
- `tls_vec.TlsByteVecU24.deserialize_bytes_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairTlsByteVecU24SharedSliceU8Bool.Lawful`
- `tls_vec.TlsByteVecU32.deserialize_bytes_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairTlsByteVecU32SharedSliceU8Bool.Lawful`
- `tls_vec.TlsVecU8.deserialize_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairTlsVecU8SharedSliceU8Bool.Lawful`
- `tls_vec.TlsVecU16.deserialize_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairTlsVecU16SharedSliceU8Bool.Lawful`
- `tls_vec.TlsVecU24.deserialize_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairTlsVecU24SharedSliceU8Bool.Lawful`
- `tls_vec.TlsVecU32.deserialize_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairTlsVecU32SharedSliceU8Bool.Lawful`
- `tls_vec.SecretTlsVecU8.deserialize_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairSecretTlsVecU8SharedSliceU8Bool.Lawful`
- `tls_vec.SecretTlsVecU16.deserialize_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairSecretTlsVecU16SharedSliceU8Bool.Lawful`
- `tls_vec.SecretTlsVecU24.deserialize_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairSecretTlsVecU24SharedSliceU8Bool.Lawful`
- `tls_vec.SecretTlsVecU32.deserialize_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairSecretTlsVecU32SharedSliceU8Bool.Lawful`
- `tls_vec.TlsByteVecU8.serialize_bytes_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.Lawful`
- `tls_vec.TlsByteVecU16.serialize_bytes_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.Lawful`
- `tls_vec.TlsByteVecU24.serialize_bytes_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.Lawful`
- `tls_vec.TlsByteVecU32.serialize_bytes_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.Lawful`
- `varint.DeserializeBytesTlsVarInt.tls_deserialize_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairTlsVarIntSharedSliceU8Bool.Lawful`
- `varint.SerializeBytesTlsVarInt.tls_serialize_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.Lawful`

#### `core.convert.From` (56)

- `Error.Insts.CoreConvertFromError.Lawful`
- `Usize.Insts.CoreConvertFromU24.Lawful`
- `Error.Insts.CoreConvertFromTryFromSliceError.Lawful`
- `Error.Insts.CoreConvertFromTryFromIntError.Lawful`
- `quic_vec.VLBytes.Insts.CoreConvertFromVecU8.Lawful`
- `quic_vec.VLByteVec.Insts.CoreConvertFromVecU8.Lawful`
- `quic_vec.secret_bytes.SecretVLBytes.Insts.CoreConvertFromVecU8.Lawful`
- `quic_vec.secret_byte_vec.SecretVLByteVec.Insts.CoreConvertFromVecU8.Lawful`
- `quic_vec.VLBytes.Insts.CoreConvertFromShared0SliceU8.Lawful`
- `quic_vec.VLByteVec.Insts.CoreConvertFromShared0SliceU8.Lawful`
- `quic_vec.secret_bytes.SecretVLBytes.Insts.CoreConvertFromShared0SliceU8.Lawful`
- `quic_vec.secret_byte_vec.SecretVLByteVec.Insts.CoreConvertFromShared0SliceU8.Lawful`
- `quic_vec.VLBytes.Insts.CoreConvertFromShared0ArrayU8N.Lawful`
- `quic_vec.VLByteVec.Insts.CoreConvertFromShared0ArrayU8N.Lawful`
- `quic_vec.secret_bytes.SecretVLBytes.Insts.CoreConvertFromShared0ArrayU8N.Lawful`
- `quic_vec.secret_byte_vec.SecretVLByteVec.Insts.CoreConvertFromShared0ArrayU8N.Lawful`
- `alloc.vec.VecU8.Insts.CoreConvertFromVLBytes.Lawful`
- `alloc.vec.VecU8.Insts.CoreConvertFromVLByteVec.Lawful`
- `tls_vec.TlsVecU8.Insts.CoreConvertFromVec.Lawful`
- `tls_vec.TlsVecU16.Insts.CoreConvertFromVec.Lawful`
- `tls_vec.TlsVecU24.Insts.CoreConvertFromVec.Lawful`
- `tls_vec.TlsVecU32.Insts.CoreConvertFromVec.Lawful`
- `tls_vec.SecretTlsVecU8.Insts.CoreConvertFromVec.Lawful`
- `tls_vec.SecretTlsVecU16.Insts.CoreConvertFromVec.Lawful`
- `tls_vec.SecretTlsVecU24.Insts.CoreConvertFromVec.Lawful`
- `tls_vec.SecretTlsVecU32.Insts.CoreConvertFromVec.Lawful`
- `tls_vec.TlsVecU8.Insts.CoreConvertFromShared0Slice.Lawful`
- `tls_vec.TlsVecU16.Insts.CoreConvertFromShared0Slice.Lawful`
- `tls_vec.TlsVecU24.Insts.CoreConvertFromShared0Slice.Lawful`
- `tls_vec.TlsVecU32.Insts.CoreConvertFromShared0Slice.Lawful`
- `tls_vec.SecretTlsVecU8.Insts.CoreConvertFromShared0Slice.Lawful`
- `tls_vec.SecretTlsVecU16.Insts.CoreConvertFromShared0Slice.Lawful`
- `tls_vec.SecretTlsVecU24.Insts.CoreConvertFromShared0Slice.Lawful`
- `tls_vec.SecretTlsVecU32.Insts.CoreConvertFromShared0Slice.Lawful`
- `alloc.vec.Vec.Insts.CoreConvertFromTlsVecU8.Lawful`
- `alloc.vec.Vec.Insts.CoreConvertFromTlsVecU16.Lawful`
- `alloc.vec.Vec.Insts.CoreConvertFromTlsVecU24.Lawful`
- `alloc.vec.Vec.Insts.CoreConvertFromTlsVecU32.Lawful`
- `alloc.vec.Vec.Insts.CoreConvertFromSecretTlsVecU8.Lawful`
- `alloc.vec.Vec.Insts.CoreConvertFromSecretTlsVecU16.Lawful`
- `alloc.vec.Vec.Insts.CoreConvertFromSecretTlsVecU24.Lawful`
- `alloc.vec.Vec.Insts.CoreConvertFromSecretTlsVecU32.Lawful`
- `tls_vec.TlsByteVecU8.Insts.CoreConvertFromVecU8.Lawful`
- `tls_vec.TlsByteVecU16.Insts.CoreConvertFromVecU8.Lawful`
- `tls_vec.TlsByteVecU24.Insts.CoreConvertFromVecU8.Lawful`
- `tls_vec.TlsByteVecU32.Insts.CoreConvertFromVecU8.Lawful`
- `tls_vec.TlsByteVecU8.Insts.CoreConvertFromShared0SliceU8.Lawful`
- `tls_vec.TlsByteVecU16.Insts.CoreConvertFromShared0SliceU8.Lawful`
- `tls_vec.TlsByteVecU24.Insts.CoreConvertFromShared0SliceU8.Lawful`
- `tls_vec.TlsByteVecU32.Insts.CoreConvertFromShared0SliceU8.Lawful`
- `alloc.vec.VecU8.Insts.CoreConvertFromTlsByteVecU8.Lawful`
- `alloc.vec.VecU8.Insts.CoreConvertFromTlsByteVecU16.Lawful`
- `alloc.vec.VecU8.Insts.CoreConvertFromTlsByteVecU24.Lawful`
- `alloc.vec.VecU8.Insts.CoreConvertFromTlsByteVecU32.Lawful`
- `Error.Insts.CoreConvertFromInfallible.Lawful`
- `U64.Insts.CoreConvertFromTlsVarInt.Lawful`

#### `core.fmt.Debug` (20)

- `Error.Insts.CoreFmtDebug.Lawful`
- `U24.Insts.CoreFmtDebug.Lawful`
- `quic_vec.VLBytes.Insts.CoreFmtDebug.Lawful`
- `quic_vec.VLByteVec.Insts.CoreFmtDebug.Lawful`
- `quic_vec.secret_bytes.SecretVLBytes.Insts.CoreFmtDebug.Lawful`
- `quic_vec.secret_byte_vec.SecretVLByteVec.Insts.CoreFmtDebug.Lawful`
- `quic_vec.VLByteSlice.Insts.CoreFmtDebug.Lawful`
- `tls_vec.TlsVecU8.Insts.CoreFmtDebug.Lawful`
- `tls_vec.TlsVecU16.Insts.CoreFmtDebug.Lawful`
- `tls_vec.TlsVecU24.Insts.CoreFmtDebug.Lawful`
- `tls_vec.TlsVecU32.Insts.CoreFmtDebug.Lawful`
- `tls_vec.SecretTlsVecU8.Insts.CoreFmtDebug.Lawful`
- `tls_vec.SecretTlsVecU16.Insts.CoreFmtDebug.Lawful`
- `tls_vec.SecretTlsVecU24.Insts.CoreFmtDebug.Lawful`
- `tls_vec.SecretTlsVecU32.Insts.CoreFmtDebug.Lawful`
- `tls_vec.TlsByteVecU8.Insts.CoreFmtDebug.Lawful`
- `tls_vec.TlsByteVecU16.Insts.CoreFmtDebug.Lawful`
- `tls_vec.TlsByteVecU24.Insts.CoreFmtDebug.Lawful`
- `tls_vec.TlsByteVecU32.Insts.CoreFmtDebug.Lawful`
- `varint.TlsVarInt.Insts.CoreFmtDebug.Lawful`

#### `core.clone.Clone` (19)

- `Error.Insts.CoreCloneClone.Lawful`
- `U24.Insts.CoreCloneClone.Lawful`
- `quic_vec.VLBytes.Insts.CoreCloneClone.Lawful`
- `quic_vec.VLByteVec.Insts.CoreCloneClone.Lawful`
- `quic_vec.secret_bytes.SecretVLBytes.Insts.CoreCloneClone.Lawful`
- `quic_vec.secret_byte_vec.SecretVLByteVec.Insts.CoreCloneClone.Lawful`
- `tls_vec.TlsVecU8.Insts.CoreCloneClone.Lawful`
- `tls_vec.TlsVecU16.Insts.CoreCloneClone.Lawful`
- `tls_vec.TlsVecU24.Insts.CoreCloneClone.Lawful`
- `tls_vec.TlsVecU32.Insts.CoreCloneClone.Lawful`
- `tls_vec.SecretTlsVecU8.Insts.CoreCloneClone.Lawful`
- `tls_vec.SecretTlsVecU16.Insts.CoreCloneClone.Lawful`
- `tls_vec.SecretTlsVecU24.Insts.CoreCloneClone.Lawful`
- `tls_vec.SecretTlsVecU32.Insts.CoreCloneClone.Lawful`
- `tls_vec.TlsByteVecU8.Insts.CoreCloneClone.Lawful`
- `tls_vec.TlsByteVecU16.Insts.CoreCloneClone.Lawful`
- `tls_vec.TlsByteVecU24.Insts.CoreCloneClone.Lawful`
- `tls_vec.TlsByteVecU32.Insts.CoreCloneClone.Lawful`
- `varint.TlsVarInt.Insts.CoreCloneClone.Lawful`

#### `core.cmp.PartialEq` (19)

- `Error.Insts.CoreCmpPartialEqError.Lawful`
- `U24.Insts.CoreCmpPartialEqU24.Lawful`
- `quic_vec.VLBytes.Insts.CoreCmpPartialEqVLBytes.Lawful`
- `quic_vec.VLByteVec.Insts.CoreCmpPartialEqVLByteVec.Lawful`
- `quic_vec.secret_bytes.SecretVLBytes.Insts.CoreCmpPartialEqSecretVLBytes.Lawful`
- `quic_vec.secret_byte_vec.SecretVLByteVec.Insts.CoreCmpPartialEqSecretVLByteVec.Lawful`
- `varint.TlsVarInt.Insts.CoreCmpPartialEqTlsVarInt.Lawful`
- `tls_vec.TlsByteVecU8.Insts.CoreCmpPartialEqTlsByteVecU8.Lawful`
- `tls_vec.TlsByteVecU16.Insts.CoreCmpPartialEqTlsByteVecU16.Lawful`
- `tls_vec.TlsByteVecU24.Insts.CoreCmpPartialEqTlsByteVecU24.Lawful`
- `tls_vec.TlsByteVecU32.Insts.CoreCmpPartialEqTlsByteVecU32.Lawful`
- `tls_vec.TlsVecU8.Insts.CoreCmpPartialEqTlsVecU8.Lawful`
- `tls_vec.TlsVecU16.Insts.CoreCmpPartialEqTlsVecU16.Lawful`
- `tls_vec.TlsVecU24.Insts.CoreCmpPartialEqTlsVecU24.Lawful`
- `tls_vec.TlsVecU32.Insts.CoreCmpPartialEqTlsVecU32.Lawful`
- `tls_vec.SecretTlsVecU8.Insts.CoreCmpPartialEqSecretTlsVecU8.Lawful`
- `tls_vec.SecretTlsVecU16.Insts.CoreCmpPartialEqSecretTlsVecU16.Lawful`
- `tls_vec.SecretTlsVecU24.Insts.CoreCmpPartialEqSecretTlsVecU24.Lawful`
- `tls_vec.SecretTlsVecU32.Insts.CoreCmpPartialEqSecretTlsVecU32.Lawful`

#### `core.cmp.Eq` (18)

- `Error.Insts.CoreCmpEq.Lawful`
- `quic_vec.VLBytes.Insts.CoreCmpEq.Lawful`
- `quic_vec.VLByteVec.Insts.CoreCmpEq.Lawful`
- `quic_vec.secret_bytes.SecretVLBytes.Insts.CoreCmpEq.Lawful`
- `quic_vec.secret_byte_vec.SecretVLByteVec.Insts.CoreCmpEq.Lawful`
- `tls_vec.TlsVecU8.Insts.CoreCmpEq.Lawful`
- `tls_vec.TlsVecU16.Insts.CoreCmpEq.Lawful`
- `tls_vec.TlsVecU24.Insts.CoreCmpEq.Lawful`
- `tls_vec.TlsVecU32.Insts.CoreCmpEq.Lawful`
- `tls_vec.SecretTlsVecU8.Insts.CoreCmpEq.Lawful`
- `tls_vec.SecretTlsVecU16.Insts.CoreCmpEq.Lawful`
- `tls_vec.SecretTlsVecU24.Insts.CoreCmpEq.Lawful`
- `tls_vec.SecretTlsVecU32.Insts.CoreCmpEq.Lawful`
- `tls_vec.TlsByteVecU8.Insts.CoreCmpEq.Lawful`
- `tls_vec.TlsByteVecU16.Insts.CoreCmpEq.Lawful`
- `tls_vec.TlsByteVecU24.Insts.CoreCmpEq.Lawful`
- `tls_vec.TlsByteVecU32.Insts.CoreCmpEq.Lawful`
- `varint.TlsVarInt.Insts.CoreCmpEq.Lawful`

#### `core.hash.Hash` (17)

- `quic_vec.VLBytes.Insts.CoreHashHash.Lawful`
- `quic_vec.VLByteVec.Insts.CoreHashHash.Lawful`
- `quic_vec.secret_bytes.SecretVLBytes.Insts.CoreHashHash.Lawful`
- `quic_vec.secret_byte_vec.SecretVLByteVec.Insts.CoreHashHash.Lawful`
- `tls_vec.TlsVecU8.Insts.CoreHashHash.Lawful`
- `tls_vec.TlsVecU16.Insts.CoreHashHash.Lawful`
- `tls_vec.TlsVecU24.Insts.CoreHashHash.Lawful`
- `tls_vec.TlsVecU32.Insts.CoreHashHash.Lawful`
- `tls_vec.SecretTlsVecU8.Insts.CoreHashHash.Lawful`
- `tls_vec.SecretTlsVecU16.Insts.CoreHashHash.Lawful`
- `tls_vec.SecretTlsVecU24.Insts.CoreHashHash.Lawful`
- `tls_vec.SecretTlsVecU32.Insts.CoreHashHash.Lawful`
- `tls_vec.TlsByteVecU8.Insts.CoreHashHash.Lawful`
- `tls_vec.TlsByteVecU16.Insts.CoreHashHash.Lawful`
- `tls_vec.TlsByteVecU24.Insts.CoreHashHash.Lawful`
- `tls_vec.TlsByteVecU32.Insts.CoreHashHash.Lawful`
- `varint.TlsVarInt.Insts.CoreHashHash.Lawful`

#### `spec.NonEmpty` (15)

- `U8.Insts.Tls_codecSpecNonEmpty.Lawful`
- `U16.Insts.Tls_codecSpecNonEmpty.Lawful`
- `U32.Insts.Tls_codecSpecNonEmpty.Lawful`
- `U64.Insts.Tls_codecSpecNonEmpty.Lawful`
- `U24.Insts.Tls_codecSpecNonEmpty.Lawful`
- `ArrayU84.Insts.Tls_codecSpecNonEmpty.Lawful`
- `core.option.Option.Insts.Tls_codecSpecNonEmpty.Lawful`
- `varint.TlsVarInt.Insts.Tls_codecSpecNonEmpty.Lawful`
- `quic_vec.VLBytes.Insts.Tls_codecSpecNonEmpty.Lawful`
- `tls_vec.TlsByteVecU8.Insts.Tls_codecSpecNonEmpty.Lawful`
- `tls_vec.TlsByteVecU16.Insts.Tls_codecSpecNonEmpty.Lawful`
- `tls_vec.TlsByteVecU24.Insts.Tls_codecSpecNonEmpty.Lawful`
- `tls_vec.TlsByteVecU32.Insts.Tls_codecSpecNonEmpty.Lawful`
- `alloc.string.String.Insts.Tls_codecSpecNonEmpty.Lawful`
- `alloc.vec.Vec.Insts.Tls_codecSpecNonEmpty.Lawful`

#### `spec.RoundTrip` (15)

- `U8.Insts.Tls_codecSpecRoundTrip.Lawful`
- `U16.Insts.Tls_codecSpecRoundTrip.Lawful`
- `U32.Insts.Tls_codecSpecRoundTrip.Lawful`
- `U64.Insts.Tls_codecSpecRoundTrip.Lawful`
- `U24.Insts.Tls_codecSpecRoundTrip.Lawful`
- `ArrayU84.Insts.Tls_codecSpecRoundTrip.Lawful`
- `core.option.Option.Insts.Tls_codecSpecRoundTrip.Lawful`
- `varint.TlsVarInt.Insts.Tls_codecSpecRoundTrip.Lawful`
- `quic_vec.VLBytes.Insts.Tls_codecSpecRoundTrip.Lawful`
- `tls_vec.TlsByteVecU8.Insts.Tls_codecSpecRoundTrip.Lawful`
- `tls_vec.TlsByteVecU16.Insts.Tls_codecSpecRoundTrip.Lawful`
- `tls_vec.TlsByteVecU24.Insts.Tls_codecSpecRoundTrip.Lawful`
- `tls_vec.TlsByteVecU32.Insts.Tls_codecSpecRoundTrip.Lawful`
- `alloc.string.String.Insts.Tls_codecSpecRoundTrip.Lawful`
- `alloc.vec.Vec.Insts.Tls_codecSpecRoundTrip.Lawful`

#### `core.default.Default` (13)

- `U24.Insts.CoreDefaultDefault.Lawful`
- `tls_vec.TlsVecU8.Insts.CoreDefaultDefault.Lawful`
- `tls_vec.TlsVecU16.Insts.CoreDefaultDefault.Lawful`
- `tls_vec.TlsVecU24.Insts.CoreDefaultDefault.Lawful`
- `tls_vec.TlsVecU32.Insts.CoreDefaultDefault.Lawful`
- `tls_vec.SecretTlsVecU8.Insts.CoreDefaultDefault.Lawful`
- `tls_vec.SecretTlsVecU16.Insts.CoreDefaultDefault.Lawful`
- `tls_vec.SecretTlsVecU24.Insts.CoreDefaultDefault.Lawful`
- `tls_vec.SecretTlsVecU32.Insts.CoreDefaultDefault.Lawful`
- `tls_vec.TlsByteVecU8.Insts.CoreDefaultDefault.Lawful`
- `tls_vec.TlsByteVecU16.Insts.CoreDefaultDefault.Lawful`
- `tls_vec.TlsByteVecU24.Insts.CoreDefaultDefault.Lawful`
- `tls_vec.TlsByteVecU32.Insts.CoreDefaultDefault.Lawful`

#### `core.ops.function.FnMut` (13)

- `quic_vec.SizeShared0Slice.tls_serialized_len.closure.Insts.CoreOpsFunctionFnMutPairUsizeSharedTUsize.Lawful`
- `tls_vec.TlsVecU8.tls_serialized_length.closure.Insts.CoreOpsFunctionFnMutPairUsizeSharedTUsize.Lawful`
- `tls_vec.TlsVecU16.tls_serialized_length.closure.Insts.CoreOpsFunctionFnMutPairUsizeSharedTUsize.Lawful`
- `tls_vec.TlsVecU24.tls_serialized_length.closure.Insts.CoreOpsFunctionFnMutPairUsizeSharedTUsize.Lawful`
- `tls_vec.TlsVecU32.tls_serialized_length.closure.Insts.CoreOpsFunctionFnMutPairUsizeSharedTUsize.Lawful`
- `tls_vec.SecretTlsVecU8.tls_serialized_length.closure.Insts.CoreOpsFunctionFnMutPairUsizeSharedTUsize.Lawful`
- `tls_vec.SecretTlsVecU16.tls_serialized_length.closure.Insts.CoreOpsFunctionFnMutPairUsizeSharedTUsize.Lawful`
- `tls_vec.SecretTlsVecU24.tls_serialized_length.closure.Insts.CoreOpsFunctionFnMutPairUsizeSharedTUsize.Lawful`
- `tls_vec.SecretTlsVecU32.tls_serialized_length.closure.Insts.CoreOpsFunctionFnMutPairUsizeSharedTUsize.Lawful`
- `tls_vec.TlsSliceU8.tls_serialized_length.closure.Insts.CoreOpsFunctionFnMutPairUsizeSharedTUsize.Lawful`
- `tls_vec.TlsSliceU16.tls_serialized_length.closure.Insts.CoreOpsFunctionFnMutPairUsizeSharedTUsize.Lawful`
- `tls_vec.TlsSliceU24.tls_serialized_length.closure.Insts.CoreOpsFunctionFnMutPairUsizeSharedTUsize.Lawful`
- `tls_vec.TlsSliceU32.tls_serialized_length.closure.Insts.CoreOpsFunctionFnMutPairUsizeSharedTUsize.Lawful`

#### `core.borrow.Borrow` (12)

- `tls_vec.TlsVecU8.Insts.CoreBorrowBorrowSlice.Lawful`
- `tls_vec.TlsVecU16.Insts.CoreBorrowBorrowSlice.Lawful`
- `tls_vec.TlsVecU24.Insts.CoreBorrowBorrowSlice.Lawful`
- `tls_vec.TlsVecU32.Insts.CoreBorrowBorrowSlice.Lawful`
- `tls_vec.SecretTlsVecU8.Insts.CoreBorrowBorrowSlice.Lawful`
- `tls_vec.SecretTlsVecU16.Insts.CoreBorrowBorrowSlice.Lawful`
- `tls_vec.SecretTlsVecU24.Insts.CoreBorrowBorrowSlice.Lawful`
- `tls_vec.SecretTlsVecU32.Insts.CoreBorrowBorrowSlice.Lawful`
- `tls_vec.TlsByteVecU8.Insts.CoreBorrowBorrowSliceU8.Lawful`
- `tls_vec.TlsByteVecU16.Insts.CoreBorrowBorrowSliceU8.Lawful`
- `tls_vec.TlsByteVecU24.Insts.CoreBorrowBorrowSliceU8.Lawful`
- `tls_vec.TlsByteVecU32.Insts.CoreBorrowBorrowSliceU8.Lawful`

#### `core.iter.traits.collect.FromIterator` (12)

- `tls_vec.TlsVecU8.Insts.CoreIterTraitsCollectFromIterator.Lawful`
- `tls_vec.TlsVecU16.Insts.CoreIterTraitsCollectFromIterator.Lawful`
- `tls_vec.TlsVecU24.Insts.CoreIterTraitsCollectFromIterator.Lawful`
- `tls_vec.TlsVecU32.Insts.CoreIterTraitsCollectFromIterator.Lawful`
- `tls_vec.SecretTlsVecU8.Insts.CoreIterTraitsCollectFromIterator.Lawful`
- `tls_vec.SecretTlsVecU16.Insts.CoreIterTraitsCollectFromIterator.Lawful`
- `tls_vec.SecretTlsVecU24.Insts.CoreIterTraitsCollectFromIterator.Lawful`
- `tls_vec.SecretTlsVecU32.Insts.CoreIterTraitsCollectFromIterator.Lawful`
- `tls_vec.TlsByteVecU8.Insts.CoreIterTraitsCollectFromIteratorU8.Lawful`
- `tls_vec.TlsByteVecU16.Insts.CoreIterTraitsCollectFromIteratorU8.Lawful`
- `tls_vec.TlsByteVecU24.Insts.CoreIterTraitsCollectFromIteratorU8.Lawful`
- `tls_vec.TlsByteVecU32.Insts.CoreIterTraitsCollectFromIteratorU8.Lawful`

#### `core.ops.index.IndexMut` (12)

- `tls_vec.TlsVecU8.Insts.CoreOpsIndexIndexMutUsizeT.Lawful`
- `tls_vec.TlsVecU16.Insts.CoreOpsIndexIndexMutUsizeT.Lawful`
- `tls_vec.TlsVecU24.Insts.CoreOpsIndexIndexMutUsizeT.Lawful`
- `tls_vec.TlsVecU32.Insts.CoreOpsIndexIndexMutUsizeT.Lawful`
- `tls_vec.SecretTlsVecU8.Insts.CoreOpsIndexIndexMutUsizeT.Lawful`
- `tls_vec.SecretTlsVecU16.Insts.CoreOpsIndexIndexMutUsizeT.Lawful`
- `tls_vec.SecretTlsVecU24.Insts.CoreOpsIndexIndexMutUsizeT.Lawful`
- `tls_vec.SecretTlsVecU32.Insts.CoreOpsIndexIndexMutUsizeT.Lawful`
- `tls_vec.TlsByteVecU8.Insts.CoreOpsIndexIndexMutUsizeU8.Lawful`
- `tls_vec.TlsByteVecU16.Insts.CoreOpsIndexIndexMutUsizeU8.Lawful`
- `tls_vec.TlsByteVecU24.Insts.CoreOpsIndexIndexMutUsizeU8.Lawful`
- `tls_vec.TlsByteVecU32.Insts.CoreOpsIndexIndexMutUsizeU8.Lawful`

#### `core.ops.index.Index` (12)

- `tls_vec.TlsVecU8.Insts.CoreOpsIndexIndexUsizeT.Lawful`
- `tls_vec.TlsVecU16.Insts.CoreOpsIndexIndexUsizeT.Lawful`
- `tls_vec.TlsVecU24.Insts.CoreOpsIndexIndexUsizeT.Lawful`
- `tls_vec.TlsVecU32.Insts.CoreOpsIndexIndexUsizeT.Lawful`
- `tls_vec.SecretTlsVecU8.Insts.CoreOpsIndexIndexUsizeT.Lawful`
- `tls_vec.SecretTlsVecU16.Insts.CoreOpsIndexIndexUsizeT.Lawful`
- `tls_vec.SecretTlsVecU24.Insts.CoreOpsIndexIndexUsizeT.Lawful`
- `tls_vec.SecretTlsVecU32.Insts.CoreOpsIndexIndexUsizeT.Lawful`
- `tls_vec.TlsByteVecU8.Insts.CoreOpsIndexIndexUsizeU8.Lawful`
- `tls_vec.TlsByteVecU16.Insts.CoreOpsIndexIndexUsizeU8.Lawful`
- `tls_vec.TlsByteVecU24.Insts.CoreOpsIndexIndexUsizeU8.Lawful`
- `tls_vec.TlsByteVecU32.Insts.CoreOpsIndexIndexUsizeU8.Lawful`

#### `spec.io.DecodersAgree` (8)

- `U8.Insts.Tls_codecSpecIoDecodersAgree.Lawful`
- `U16.Insts.Tls_codecSpecIoDecodersAgree.Lawful`
- `U32.Insts.Tls_codecSpecIoDecodersAgree.Lawful`
- `U64.Insts.Tls_codecSpecIoDecodersAgree.Lawful`
- `ArrayU8LEN.Insts.Tls_codecSpecIoDecodersAgree.Lawful`
- `quic_vec.VLBytes.Insts.Tls_codecSpecIoDecodersAgree.Lawful`
- `quic_vec.secret_bytes.SecretVLBytes.Insts.Tls_codecSpecIoDecodersAgree.Lawful`
- `alloc.vec.Vec.Insts.Tls_codecSpecIoDecodersAgree.Lawful`

#### `zeroize.Zeroize` (8)

- `quic_vec.VLBytes.Insts.ZeroizeZeroize.Lawful`
- `quic_vec.VLByteVec.Insts.ZeroizeZeroize.Lawful`
- `quic_vec.secret_bytes.SecretVLBytes.Insts.ZeroizeZeroize.Lawful`
- `quic_vec.secret_byte_vec.SecretVLByteVec.Insts.ZeroizeZeroize.Lawful`
- `tls_vec.SecretTlsVecU8.Insts.ZeroizeZeroize.Lawful`
- `tls_vec.SecretTlsVecU16.Insts.ZeroizeZeroize.Lawful`
- `tls_vec.SecretTlsVecU24.Insts.ZeroizeZeroize.Lawful`
- `tls_vec.SecretTlsVecU32.Insts.ZeroizeZeroize.Lawful`

#### `core.marker.StructuralPartialEq` (7)

- `Error.Insts.CoreMarkerStructuralPartialEq.Lawful`
- `U24.Insts.CoreMarkerStructuralPartialEq.Lawful`
- `quic_vec.VLBytes.Insts.CoreMarkerStructuralPartialEq.Lawful`
- `quic_vec.VLByteVec.Insts.CoreMarkerStructuralPartialEq.Lawful`
- `quic_vec.secret_bytes.SecretVLBytes.Insts.CoreMarkerStructuralPartialEq.Lawful`
- `quic_vec.secret_byte_vec.SecretVLByteVec.Insts.CoreMarkerStructuralPartialEq.Lawful`
- `varint.TlsVarInt.Insts.CoreMarkerStructuralPartialEq.Lawful`

#### `core.ops.drop.Drop` (6)

- `quic_vec.secret_bytes.SecretVLBytes.Insts.CoreOpsDropDrop.Lawful`
- `quic_vec.secret_byte_vec.SecretVLByteVec.Insts.CoreOpsDropDrop.Lawful`
- `tls_vec.SecretTlsVecU8.Insts.CoreOpsDropDrop.Lawful`
- `tls_vec.SecretTlsVecU16.Insts.CoreOpsDropDrop.Lawful`
- `tls_vec.SecretTlsVecU24.Insts.CoreOpsDropDrop.Lawful`
- `tls_vec.SecretTlsVecU32.Insts.CoreOpsDropDrop.Lawful`

#### `core.cmp.Ord` (5)

- `quic_vec.VLBytes.Insts.CoreCmpOrd.Lawful`
- `quic_vec.VLByteVec.Insts.CoreCmpOrd.Lawful`
- `quic_vec.secret_bytes.SecretVLBytes.Insts.CoreCmpOrd.Lawful`
- `quic_vec.secret_byte_vec.SecretVLByteVec.Insts.CoreCmpOrd.Lawful`
- `varint.TlsVarInt.Insts.CoreCmpOrd.Lawful`

#### `core.cmp.PartialOrd` (5)

- `quic_vec.VLBytes.Insts.CoreCmpPartialOrdVLBytes.Lawful`
- `quic_vec.VLByteVec.Insts.CoreCmpPartialOrdVLByteVec.Lawful`
- `quic_vec.secret_bytes.SecretVLBytes.Insts.CoreCmpPartialOrdSecretVLBytes.Lawful`
- `quic_vec.secret_byte_vec.SecretVLByteVec.Insts.CoreCmpPartialOrdSecretVLByteVec.Lawful`
- `varint.TlsVarInt.Insts.CoreCmpPartialOrdTlsVarInt.Lawful`

#### `core.convert.AsRef` (4)

- `quic_vec.VLBytes.Insts.CoreConvertAsRefSliceU8.Lawful`
- `quic_vec.VLByteVec.Insts.CoreConvertAsRefSliceU8.Lawful`
- `quic_vec.secret_bytes.SecretVLBytes.Insts.CoreConvertAsRefSliceU8.Lawful`
- `quic_vec.secret_byte_vec.SecretVLByteVec.Insts.CoreConvertAsRefSliceU8.Lawful`

#### `spec.io.NonEmptyStd` (3)

- `U8.Insts.Tls_codecSpecIoNonEmptyStd.Lawful`
- `quic_vec.VLBytes.Insts.Tls_codecSpecIoNonEmptyStd.Lawful`
- `alloc.vec.Vec.Insts.Tls_codecSpecIoNonEmptyStd.Lawful`

#### `spec.io.RoundTripStd` (3)

- `U8.Insts.Tls_codecSpecIoRoundTripStd.Lawful`
- `quic_vec.VLBytes.Insts.Tls_codecSpecIoRoundTripStd.Lawful`
- `alloc.vec.Vec.Insts.Tls_codecSpecIoRoundTripStd.Lawful`

#### `core.convert.TryFrom` (2)

- `U24.Insts.CoreConvertTryFromUsizeError.Lawful`
- `varint.TlsVarInt.Insts.CoreConvertTryFromU64Error.Lawful`

#### `core.marker.Copy` (2)

- `U24.Insts.CoreMarkerCopy.Lawful`
- `varint.TlsVarInt.Insts.CoreMarkerCopy.Lawful`

#### `spec.io.RoundTripMixed` (2)

- `U8.Insts.Tls_codecSpecIoRoundTripMixed.Lawful`
- `quic_vec.VLBytes.Insts.Tls_codecSpecIoRoundTripMixed.Lawful`

#### `spec.io.SameBytes` (2)

- `U8.Insts.Tls_codecSpecIoSameBytes.Lawful`
- `quic_vec.VLBytes.Insts.Tls_codecSpecIoSameBytes.Lawful`

#### `zeroize.ZeroizeOnDrop` (2)

- `quic_vec.secret_bytes.SecretVLBytes.Insts.ZeroizeZeroizeOnDrop.Lawful`
- `quic_vec.secret_byte_vec.SecretVLByteVec.Insts.ZeroizeZeroizeOnDrop.Lawful`

#### `core.error.Error` (1)

- `Error.Insts.CoreErrorError.Lawful`

#### `core.fmt.Display` (1)

- `Error.Insts.CoreFmtDisplay.Lawful`

<!-- END TARGETS -->
