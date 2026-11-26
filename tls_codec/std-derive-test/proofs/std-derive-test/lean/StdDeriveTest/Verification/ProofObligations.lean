/- The per-impl `Lawful` obligations of the test crate's derived impls (a test fixture for the derive tactics),
proved with the derive tactics that now live in TlsCodec (`TlsCodec.Verification.Derive.Bytes`, bytes
path, and `TlsCodec.Verification.Derive.Std`, `std` path). -/
import Aeneas
import CoreModels
import Hax
import StdDeriveTest.Extraction
import TlsCodec.Verification.Derive.Std
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false
set_option maxHeartbeats 4000000
set_option maxRecDepth 2048
set_option mvcgen.warning false

noncomputable section

namespace std_derive_test
open tls_codec.Derive

/-! The field types' `Lawful`s are TlsCodec theorems (`Verification/ProofObligations.lean`); taken
as hypotheses here, so that this test does not rebuild TlsCodec's 18k-line proof files. -/
variable
  (hVLsz : tls_codec.Size.Lawful tls_codec.quic_vec.VLBytes tls_codec.quic_vec.VLBytes.Insts.Tls_codecSize)
  (hU16sz : tls_codec.Size.Lawful U16 tls_codec.U16.Insts.Tls_codecSize)
  (hVLsb : tls_codec.SerializeBytes.Lawful tls_codec.quic_vec.VLBytes tls_codec.quic_vec.VLBytes.Insts.Tls_codecSerializeBytes)
  (hU16sb : tls_codec.SerializeBytes.Lawful U16 tls_codec.U16.Insts.Tls_codecSerializeBytes)
  (hVLdb : tls_codec.DeserializeBytes.Lawful tls_codec.quic_vec.VLBytes tls_codec.quic_vec.VLBytes.Insts.Tls_codecDeserializeBytes)
  (hU16db : tls_codec.DeserializeBytes.Lawful U16 tls_codec.U16.Insts.Tls_codecDeserializeBytes)
  (hVLs : tls_codec.Serialize.Lawful tls_codec.quic_vec.VLBytes tls_codec.quic_vec.VLBytes.Insts.Tls_codecSerialize)
  (hU16s : tls_codec.Serialize.Lawful U16 tls_codec.U16.Insts.Tls_codecSerialize)
  (hU8s : tls_codec.Serialize.Lawful U8 tls_codec.U8.Insts.Tls_codecSerialize)
  (hVLd : tls_codec.Deserialize.Lawful tls_codec.quic_vec.VLBytes tls_codec.quic_vec.VLBytes.Insts.Tls_codecDeserialize)
  (hU16d : tls_codec.Deserialize.Lawful U16 tls_codec.U16.Insts.Tls_codecDeserialize)
  (hU8d : tls_codec.Deserialize.Lawful U8 tls_codec.U8.Insts.Tls_codecDeserialize)
  (hP2sz : tls_codec.Size.Lawful Pair2 Pair2.Insts.Tls_codecSize)
  (hChsz : tls_codec.Size.Lawful Choice Choice.Insts.Tls_codecSize)

/-! ### Bytes path: the derive tactics moved into TlsCodec (`Derive/Bytes.lean`) -/

include hVLsz hU16sz in
theorem Pair2.size_lawful : tls_codec.Size.Lawful Pair2 Pair2.Insts.Tls_codecSize := by
  derive_size_lawful [Pair2.Insts.Tls_codecSize.tls_serialized_len] [hVLsz, hU16sz]

include hP2sz in
theorem Shared0Pair2.size_lawful : tls_codec.Size.Lawful Pair2 Shared0Pair2.Insts.Tls_codecSize := by
  derive_size_lawful [Shared0Pair2.Insts.Tls_codecSize.tls_serialized_len] [hP2sz]

include hP2sz hVLsb hU16sb in
theorem Pair2.serBytes_lawful :
    tls_codec.SerializeBytes.Lawful Pair2 Pair2.Insts.Tls_codecSerializeBytes := by
  derive_ser_lawful hP2sz [Pair2.Insts.Tls_codecSerializeBytes.tls_serialize_bytes, Shared0Pair2.Insts.Tls_codecSize.tls_serialized_len, Pair2.Insts.Tls_codecSize.tls_serialized_len] [hVLsb, hU16sb]

include hP2sz hVLdb hU16db in
theorem Pair2.deserBytes_lawful :
    tls_codec.DeserializeBytes.Lawful Pair2 Pair2.Insts.Tls_codecDeserializeBytes := by
  derive_deser_lawful hP2sz [Pair2.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes, Pair2.Insts.Tls_codecSize.tls_serialized_len] [hVLdb, hU16db]

include hVLsz hU16sz in
theorem Choice.size_lawful : tls_codec.Size.Lawful Choice Choice.Insts.Tls_codecSize := by
  derive_size_lawful [Choice.Insts.Tls_codecSize.tls_serialized_len] [hVLsz, hU16sz]

/-! ### `std` path (`Derive/Std.lean`) -/

include hP2sz hVLs hU16s in
theorem Pair2.serSpec : ∀ x, tls_codec.SerSpec Pair2.Insts.Tls_codecSerialize x := by
  derive_ser_std hP2sz
    [Pair2.Insts.Tls_codecSerialize.tls_serialize, Shared0Pair2.Insts.Tls_codecSize.tls_serialized_len]
    [Pair2.Insts.Tls_codecSize, Pair2.Insts.Tls_codecSize.tls_serialized_len]
    [hVLs, hU16s]

include hChsz hVLs hU16s hU8s in
theorem Choice.serSpec : ∀ x, tls_codec.SerSpec Choice.Insts.Tls_codecSerialize x := by
  derive_ser_std hChsz
    [Choice.Insts.Tls_codecSerialize.tls_serialize, SerializeChoice.tls_serialize.__TLS_CODEC_Empty,
      SerializeChoice.tls_serialize.__TLS_CODEC_Bytes, SerializeChoice.tls_serialize.__TLS_CODEC_Num]
    [Choice.Insts.Tls_codecSize, Choice.Insts.Tls_codecSize.tls_serialized_len]
    [hU8s, hVLs, hU16s]

include hP2sz hVLd hU16d in
theorem Pair2.deSpec : tls_codec.DeSpec Pair2.Insts.Tls_codecDeserialize := by
  derive_de_std hP2sz [Pair2.Insts.Tls_codecDeserialize.tls_deserialize]
    [Pair2.Insts.Tls_codecSize, Pair2.Insts.Tls_codecSize.tls_serialized_len] [hVLd, hU16d]

include hChsz hVLd hU16d hU8d in
theorem Choice.deSpec : tls_codec.DeSpec Choice.Insts.Tls_codecDeserialize := by
  derive_de_std hChsz
    [Choice.Insts.Tls_codecDeserialize.tls_deserialize, DeserializeChoice.tls_deserialize.__TLS_CODEC_Empty,
      DeserializeChoice.tls_deserialize.__TLS_CODEC_Bytes, DeserializeChoice.tls_deserialize.__TLS_CODEC_Num]
    [Choice.Insts.Tls_codecSize, Choice.Insts.Tls_codecSize.tls_serialized_len] [hU8d, hVLd, hU16d]

/-! ### The generated obligations (`Extraction/ProofObligations.lean` statements) -/

include hP2sz hVLs hU16s in
theorem Pair2.Insts.Tls_codecSerialize.Lawful :
    tls_codec.Serialize.Lawful Pair2 Pair2.Insts.Tls_codecSerialize := by
  derive_ser_std_lawful hP2sz
    [Pair2.Insts.Tls_codecSerialize.tls_serialize, Shared0Pair2.Insts.Tls_codecSize.tls_serialized_len]
    [Pair2.Insts.Tls_codecSize, Pair2.Insts.Tls_codecSize.tls_serialized_len] [hVLs, hU16s]

include hP2sz hVLd hU16d in
theorem Pair2.Insts.Tls_codecDeserialize.Lawful :
    tls_codec.Deserialize.Lawful Pair2 Pair2.Insts.Tls_codecDeserialize := by
  derive_de_std_lawful hP2sz [Pair2.Insts.Tls_codecDeserialize.tls_deserialize]
    [Pair2.Insts.Tls_codecSize, Pair2.Insts.Tls_codecSize.tls_serialized_len] [hVLd, hU16d]

include hChsz hVLs hU16s hU8s in
theorem Choice.Insts.Tls_codecSerialize.Lawful :
    tls_codec.Serialize.Lawful Choice Choice.Insts.Tls_codecSerialize := by
  derive_ser_std_lawful hChsz
    [Choice.Insts.Tls_codecSerialize.tls_serialize, SerializeChoice.tls_serialize.__TLS_CODEC_Empty,
      SerializeChoice.tls_serialize.__TLS_CODEC_Bytes, SerializeChoice.tls_serialize.__TLS_CODEC_Num]
    [Choice.Insts.Tls_codecSize, Choice.Insts.Tls_codecSize.tls_serialized_len] [hU8s, hVLs, hU16s]

include hChsz hVLd hU16d hU8d in
theorem Choice.Insts.Tls_codecDeserialize.Lawful :
    tls_codec.Deserialize.Lawful Choice Choice.Insts.Tls_codecDeserialize := by
  derive_de_std_lawful hChsz
    [Choice.Insts.Tls_codecDeserialize.tls_deserialize, DeserializeChoice.tls_deserialize.__TLS_CODEC_Empty,
      DeserializeChoice.tls_deserialize.__TLS_CODEC_Bytes, DeserializeChoice.tls_deserialize.__TLS_CODEC_Num]
    [Choice.Insts.Tls_codecSize, Choice.Insts.Tls_codecSize.tls_serialized_len] [hU8d, hVLd, hU16d]

end std_derive_test
