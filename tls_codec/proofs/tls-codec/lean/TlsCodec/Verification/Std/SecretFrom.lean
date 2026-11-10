/- `SecretVLBytes::from(Vec<u8>)` keeps the size: the `VLBytes` size of the wrapped vector is the
`Vec<u8>` size (both are the content length plus its varint prefix, when it has one).

Obligations: none in TlsCodec; OpenMLS's `Secret` `std` deserializer (reads a `Vec<u8>` and
converts it) uses it.
Axioms reached (`scripts/axiom_whitelist.txt`): nothing ASSUMED; 1 signature-only stub
(`core.io.error.Error.Insts.CoreFmtDebug.fmt`). -/
import TlsCodec.Verification.Std.String
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-- `tls_serialize_bytes_len` for every length: the length plus the varint prefix when the length
fits (`≤ 2^30 - 1`), the length alone otherwise (`from_usize` fails, the prefix length is 0). -/
theorem quic_vec.tls_serialize_bytes_len_val (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.tls_serialize_bytes_len bytes
    ⦃ ⇓ r => ⌜ r.val = bytes.val.length +
      (if bytes.val.length ≤ 2 ^ 30 - 1 then varint.lenOf bytes.val.length else 0) ⌝ ⦄ := by
  by_cases h : bytes.val.length ≤ 2 ^ 30 - 1
  · simp only [h, if_true]; exact quic_vec.tls_serialize_bytes_len_char bytes h
  · simp only [h, if_false]
    mvcgen [quic_vec.tls_serialize_bytes_len, CoreModels.core.slice.Slice.len_spec]
    · rename_i n hn rc hrc r2 hr2 r1 hr1 r hr
      have hl : n.val = bytes.val.length := by subst hn; simp [Slice.len]
      cases rc with
      | Ok c => simp only at hrc; omega
      | Err e =>
        rw [hr2.2 e rfl] at hr1
        subst hr1
        simp only [hr, Nat.add_zero, hl]; rfl
    · rename_i n hn rc hrc r2 hr2 r1 hr1 hov
      cases rc with
      | Ok c => simp only at hrc; subst hn; simp [Slice.len] at hrc; omega
      | Err e =>
        rw [hr2.2 e rfl] at hr1
        subst hr1
        simp only at hov
        scalar_tac

/-- `SecretVLBytes::from` of a vector `v` succeeds, with the `Vec<u8>` size of `v`. -/
theorem SecretVLBytes.from_size (v : alloc.vec.Vec Std.U8) (n : Std.Usize)
    (h : alloc.vec.Vec.Insts.Tls_codecSize.tls_serialized_len U8.Insts.Tls_codecSize v = ok n) :
    ∃ s, quic_vec.secret_bytes.SecretVLBytes.Insts.CoreConvertFromVecU8.from v = ok s ∧
      quic_vec.secret_bytes.SecretVLBytes.Insts.Tls_codecSize.tls_serialized_len s = ok n := by
  refine ⟨⟨v⟩, rfl, ?_⟩
  obtain ⟨c, -, hc, hsz⟩ := Vec.size_exact U8.lawful v n h (SizeNat.u8 v.val)
  simp only [quic_vec.secret_bytes.SecretVLBytes.Insts.Tls_codecSize.tls_serialized_len,
    quic_vec.VLBytes.Insts.Tls_codecSize.tls_serialized_len, quic_vec.VLBytes.as_slice,
    quic_vec.VLBytes.impl.vec, alloc.vec.Vec.Insts.CoreOpsDerefDerefSlice.deref,
    core.Slice.Insts.CoreConvertAsRefSlice.as_ref]
  have hs : alloc.vec.Vec.as_slice v = ok ⟨v.val, v.property⟩ := rfl
  obtain ⟨r, hr, hrv⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (quic_vec.tls_serialize_bytes_len_val ⟨v.val, v.property⟩)
  simp only [hs, bind_tc_ok, hr]
  congr 1
  apply UScalar.eq_of_val_eq
  have hvl : (v.val).length ≤ Usize.max := by have := v.property; scalar_tac
  rw [hrv, hsz, hc, min_eq_left hvl]
  split <;> scalar_tac

end tls_codec
