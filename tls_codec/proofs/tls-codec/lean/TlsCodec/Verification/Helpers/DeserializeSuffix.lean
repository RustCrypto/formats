/- Suffix facts for the `DeserializeBytes` trait-level post: the remainder
returned by `tls_deserialize_bytes` is a suffix of the input, derived from the content lemmas of
`Helpers/` (which give the exact decomposition of the input).

Obligations: none directly; the trait-level FC halves use them through `DeserializeBytes.fc_of_len`.
Axioms reached (`scripts/axiom_whitelist.txt`): ASSUMED
`alloc.string.FromUtf8Error.Insts.CoreFmtDisplay.fmt.ok_spec`, `size_of`, `size_of_U16`,
`size_of_U24`, `size_of_U32`, `size_of_U8`, `size_of_Usize`, `numBits_eq_64`; 3 signature-only stubs
(`alloc.string.FromUtf8Error.Insts.CoreFmtDisplay.fmt`,
`core.convert.Infallible.Insts.CoreFmtDebug.fmt`,
`core.num.error.TryFromIntError.Insts.CoreFmtDebug.fmt`). -/
import TlsCodec.Verification.Helpers
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option mvcgen.warning false

namespace tls_codec

/-- The post of the suffix facts below. -/
abbrev SuffixPost {T : Type} (bytes : Slice Std.U8) (r : core.result.Result (T × Slice Std.U8) Error) :
    Prop :=
  ∀ v rem, r = .Ok (v, rem) → rem.val <:+ bytes.val

theorem quic_vec.VLBytes.deserialize_suffix (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLBytes.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ SuffixPost bytes r ⌝ ⦄ :=
  triple_post_mono (quic_vec.VLBytes.deserialize_content bytes) fun _ h v t hr =>
    suffix_of_map_val (h v t hr).2

theorem quic_vec.VLByteVec.deserialize_suffix (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLByteVec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ SuffixPost bytes r ⌝ ⦄ :=
  triple_post_mono (quic_vec.VLByteVec.deserialize_content bytes) fun _ h v t hr =>
    suffix_of_map_val (h v t hr).2

theorem alloc.string.String.deserialize_suffix (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ alloc.string.String.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ SuffixPost bytes r ⌝ ⦄ :=
  triple_post_mono (alloc.string.String.deserialize_content bytes) fun _ h v t hr =>
    suffix_of_map_val (h v t hr).2

/-- `x ++ (y ++ t)` ends with `t`. -/
theorem suffix_app_app {x y t l : List Std.U8} (h : l = x ++ (y ++ t)) : t <:+ l := by
  rw [h]; exact (List.suffix_append _ _).trans (List.suffix_append _ _)

theorem tls_vec.TlsByteVecU8.deserialize_suffix (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU8.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ SuffixPost bytes r ⌝ ⦄ := by
  unfold tls_vec.TlsByteVecU8.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
  exact triple_post_mono (tls_vec.TlsByteVecU8.deserialize_content bytes) fun _ h v t hr => by
    obtain ⟨n, -, hb⟩ := h v t hr
    exact suffix_app_app (x := [n]) hb

theorem tls_vec.TlsByteVecU16.deserialize_suffix (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU16.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ SuffixPost bytes r ⌝ ⦄ := by
  unfold tls_vec.TlsByteVecU16.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
  exact triple_post_mono (tls_vec.TlsByteVecU16.deserialize_content bytes) fun _ h v t hr => by
    obtain ⟨n, -, hb⟩ := h v t hr
    exact suffix_app_app hb

theorem tls_vec.TlsByteVecU24.deserialize_suffix (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU24.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ SuffixPost bytes r ⌝ ⦄ := by
  unfold tls_vec.TlsByteVecU24.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
  exact triple_post_mono (tls_vec.TlsByteVecU24.deserialize_content bytes) fun _ h v t hr => by
    obtain ⟨b0, b1, b2, -, hb⟩ := h v t hr
    exact suffix_app_app (x := [b0, b1, b2]) hb

theorem tls_vec.TlsByteVecU32.deserialize_suffix (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU32.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ SuffixPost bytes r ⌝ ⦄ := by
  unfold tls_vec.TlsByteVecU32.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
  exact triple_post_mono (tls_vec.TlsByteVecU32.deserialize_content bytes) fun _ h v t hr => by
    obtain ⟨n, -, hb⟩ := h v t hr
    exact suffix_app_app hb

end tls_codec
