/- `TlsByteVecU*::tls_serialize_bytes` (through the hand-translated `get_content_lengths`).

Obligations: none directly; the bytes-path halves of `PanicFreedom.lean` /
`FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): ASSUMED `size_of`, `size_of_Usize`, `numBits_eq_64`;
3 signature-only stubs (`core.convert.Infallible.Insts.CoreFmtDebug.fmt`,
`core.num.error.TryFromIntError.Insts.CoreFmtDebug.fmt`, `Error.Insts.CoreFmtDebug.fmt`). -/
import TlsCodec.Verification.Helpers.HandTranslated
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! ### `TlsByteVecU*::serialize_bytes_bytes` (uses the hand-written `get_content_lengths`)

`_partial`: if it returns `Ok out`, then `out` has the payload plus the prefix and the payload is within the
prefix bound (it panics above, in the model of the `debug_assert!`). `_char`: below the bound it does not panic. -/

/-- `saturating_add` does not saturate when the sum fits. -/
theorem Usize_saturating_add_val_le (x y : Std.Usize) (h : x.val + y.val ≤ Std.Usize.max) :
    (UScalar.saturating_add x y).val = x.val + y.val := by
  have hm : x.val + y.val ≤ UScalar.max UScalarTy.Usize := by
    simp only [UScalar.max, UScalarTy.numBits]
    simpa [Std.Usize.max, UScalar.max, UScalarTy.numBits, Std.Usize.numBits] using h
  have hlt : x.val + y.val < 2 ^ System.Platform.numBits := by
    simp only [UScalar.max, UScalarTy.numBits] at hm
    have := Nat.one_le_two_pow (n := System.Platform.numBits)
    omega
  unfold UScalar.saturating_add
  rw [min_eq_right hm]
  unfold UScalar.val
  simp only [BitVec.toNat_ofNat]
  exact Nat.mod_eq_of_lt hlt

/-- `checked_alloc_len` of operands whose sum fits a `usize`: the sum, or an error. -/
theorem checked_alloc_len_total (a b : Std.Usize) (h : a.val + b.val ≤ Std.Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ checked_alloc_len a b
    ⦃ ⇓ r => ⌜ (∃ n : Std.Usize, r = .Ok n ∧ n.val = a.val + b.val) ∨ ∃ e, r = .Err e ⌝ ⦄ := by
  have hs := Usize_saturating_add_val_le a b h
  mvcgen [checked_alloc_len, checked_capacity, CoreModels.core.num.Usize.saturating_add_spec]
  · exact Or.inr ⟨_, rfl⟩
  · rename_i sat hsat hle
    subst hsat
    exact Or.inl ⟨_, rfl, hs⟩

/-- A successful `checked_alloc_len` is the exact sum. -/
theorem checked_alloc_len_ok (a b : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ checked_alloc_len a b
    ⦃ ⇓ r => ⌜ ∀ n : Std.Usize, r = .Ok n → n.val = a.val + b.val ⌝ ⦄ := by
  mvcgen [checked_alloc_len, checked_capacity, CoreModels.core.num.Usize.saturating_add_spec]
  · simp
  · rename_i sat hsat hle
    intro n hn
    simp only [core.result.Result.Ok.injEq] at hn
    subst hn hsat
    have hm := Usize.hcast_Isize_MAX_val
    have h1 := UScalar.saturating_add_val a b
    scalar_tac

/-- `Vec::<u8>::extend_from_slice` appends the slice, given room. -/
theorem alloc.vec.Vec.extend_from_slice_U8_spec (v : alloc.vec.Vec Std.U8) (s : Slice Std.U8)
    (h : (v : Slice Std.U8).val.length + s.val.length ≤ Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.extend_from_slice core.U8.Insts.CoreCloneClone v s
    ⦃ ⇓ r => ⌜ (r : Slice Std.U8).val = (v : Slice Std.U8).val ++ s.val ⌝ ⦄ := by
  unfold alloc.vec.Vec.extend_from_slice rust_primitives.sequence.seq_extend
  erw [mapM_clone_U8]
  have hh : (v : Slice Std.U8).val.length + s.val.length ≤ Usize.max := h
  mvcgen
  all_goals (exfalso; simp_all +zetaDelta [List.length_append])

/-- `usize -> u8` `TryFrom`: `Ok` of the cast when it fits, an error otherwise. -/
theorem core.U8.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from_char (x : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ core.U8.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from x
    ⦃ ⇓ r => ⌜ (x.val ≤ 255 → ∃ y : Std.U8, r = .Ok y ∧ y.val = x.val) ∧
        (255 < x.val → ∃ e, r = .Err e) ⌝ ⦄ := by
  unfold core.U8.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from
  mvcgen
  all_goals (subst_vars; simp [core.num.U8.MAX, core.num.U8.MIN, U8.rMax] at *; try scalar_tac)

/-- `TlsByteVecU8::assert_written_bytes` never panics (relies on the ASSUMED fmt no-fail axioms). -/
theorem tls_vec.TlsByteVecU8.assert_written_bytes_total (self : tls_vec.TlsByteVecU8)
    (tls_serialized_len written : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU8.assert_written_bytes self tls_serialized_len written
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  mvcgen [tls_vec.TlsByteVecU8.assert_written_bytes]

/-- `usize -> u16` `TryFrom`: `Ok` of the cast when it fits, an error otherwise. -/
theorem core.U16.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from_char (x : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ core.U16.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from x
    ⦃ ⇓ r => ⌜ (x.val ≤ 65535 → ∃ y : Std.U16, r = .Ok y ∧ y.val = x.val) ∧
        (65535 < x.val → ∃ e, r = .Err e) ⌝ ⦄ := by
  unfold core.U16.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from
  mvcgen
  all_goals (subst_vars; simp [core.num.U16.MAX, core.num.U16.MIN, U16.rMax] at *; try scalar_tac)

/-- `TlsByteVecU16::assert_written_bytes` never panics (relies on the ASSUMED fmt no-fail axioms). -/
theorem tls_vec.TlsByteVecU16.assert_written_bytes_total (self : tls_vec.TlsByteVecU16)
    (tls_serialized_len written : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU16.assert_written_bytes self tls_serialized_len written
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  mvcgen [tls_vec.TlsByteVecU16.assert_written_bytes]

/-- `usize -> u32` `TryFrom`: `Ok` of the cast when it fits, an error otherwise. -/
theorem core.U32.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from_char (x : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ core.U32.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from x
    ⦃ ⇓ r => ⌜ (x.val ≤ 4294967295 → ∃ y : Std.U32, r = .Ok y ∧ y.val = x.val) ∧
        (4294967295 < x.val → ∃ e, r = .Err e) ⌝ ⦄ := by
  unfold core.U32.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from
  mvcgen
  all_goals (subst_vars; simp [core.num.U32.MAX, core.num.U32.MIN, U32.rMax] at *; try scalar_tac)

/-- `TlsByteVecU32::assert_written_bytes` never panics (relies on the ASSUMED fmt no-fail axioms). -/
theorem tls_vec.TlsByteVecU32.assert_written_bytes_total (self : tls_vec.TlsByteVecU32)
    (tls_serialized_len written : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU32.assert_written_bytes self tls_serialized_len written
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  mvcgen [tls_vec.TlsByteVecU32.assert_written_bytes]

/-- `TlsByteVecU24::assert_written_bytes` never panics (relies on the ASSUMED fmt no-fail axioms). -/
theorem tls_vec.TlsByteVecU24.assert_written_bytes_total (self : tls_vec.TlsByteVecU24)
    (tls_serialized_len written : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU24.assert_written_bytes self tls_serialized_len written
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  mvcgen [tls_vec.TlsByteVecU24.assert_written_bytes]

/-- Closing script shared by the `TlsByteVecU*.serialize_bytes_bytes_{partial,char,content}` proofs: discharge the VCs left by `mvcgen`. The `first` alternatives are the union over all widths (partial/char arithmetic, content equation for U8, U16/U32 and U24). -/
macro "bytevec_ser_close" : tactic => `(tactic| (
  try_vcs
  all_goals (try simp only [continue_eq_tryCF] at *)
  all_goals (try casesm* (∃ _, _), (_ ∧ _))
  all_goals subst_vars
  all_goals (simp_all [Slice.len, Slice.new])
  all_goals first
    | omega
    | scalar_tac
    | (obtain ⟨y, hy, -⟩ := ‹∃ y, _ = _ ∧ _›; exact ⟨y, hy⟩)
    | (rw [U8_to_be_bytes_val]; exact ⟨_, ‹_›, rfl⟩)
    | exact ⟨_, ‹_›, rfl⟩
    | (obtain ⟨b0, b1, b2, h3, h4⟩ := ‹∃ b0 b1 b2, _ ∧ _›; exact ⟨b0, b1, b2, h4.symm, by rw [h3]; rfl⟩)
    | (intro _ out h; cases h)))

/-- `TlsByteVecU8::serialize_bytes_bytes`, when it returns `Ok`, gives the payload plus the 1-byte prefix, and the payload is within the prefix bound. -/
theorem tls_vec.TlsByteVecU8.serialize_bytes_bytes_partial (self : tls_vec.TlsByteVecU8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU8.serialize_bytes_bytes self
    ⦃ ⇓? r => ⌜ ∀ out : alloc.vec.Vec Std.U8, r = .Ok out →
        out.val.length = self.vec.val.length + 1 ∧ self.vec.val.length ≤ 255 ⌝ ⦄ := by
  mvcgen [tls_vec.TlsByteVecU8.serialize_bytes_bytes,
    tls_vec.TlsByteVecU8.get_content_lengths_char,
    checked_alloc_len_total, alloc.vec.Vec.extend_from_slice_U8_spec,
    core.U8.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from_char,
    alloc.vec.Vec.with_capacity, core.result.Result.unwrap_ok_spec, U8_serialize_char,
    alloc.vec.Vec.len_spec, tls_vec.TlsByteVecU8.as_slice, CoreModels.core.slice.Slice.len_spec,
    tls_vec.TlsByteVecU8.assert_written_bytes_total]
  bytevec_ser_close

/-- `TlsByteVecU8::serialize_bytes_bytes` does not panic (an over-long vector gives `Err`); an `Ok` result has the payload length plus the 1-byte prefix. -/
theorem tls_vec.TlsByteVecU8.serialize_bytes_bytes_char (self : tls_vec.TlsByteVecU8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU8.serialize_bytes_bytes self
    ⦃ ⇓ r => ⌜ ∀ out : alloc.vec.Vec Std.U8, r = .Ok out →
        out.val.length = self.vec.val.length + 1 ⌝ ⦄ := by
  mvcgen [tls_vec.TlsByteVecU8.serialize_bytes_bytes,
    tls_vec.TlsByteVecU8.get_content_lengths_char,
    checked_alloc_len_total, alloc.vec.Vec.extend_from_slice_U8_spec,
    core.U8.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from_char,
    alloc.vec.Vec.with_capacity, core.result.Result.unwrap_ok_spec, U8_serialize_char,
    alloc.vec.Vec.len_spec, tls_vec.TlsByteVecU8.as_slice, CoreModels.core.slice.Slice.len_spec,
    tls_vec.TlsByteVecU8.assert_written_bytes_total]
  bytevec_ser_close

/-- `TlsByteVecU16::serialize_bytes_bytes`, when it returns `Ok`, gives the payload plus the 2-byte prefix, and the payload is within the prefix bound. -/
theorem tls_vec.TlsByteVecU16.serialize_bytes_bytes_partial (self : tls_vec.TlsByteVecU16) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU16.serialize_bytes_bytes self
    ⦃ ⇓? r => ⌜ ∀ out : alloc.vec.Vec Std.U8, r = .Ok out →
        out.val.length = self.vec.val.length + 2 ∧ self.vec.val.length ≤ 65535 ⌝ ⦄ := by
  mvcgen [tls_vec.TlsByteVecU16.serialize_bytes_bytes,
    tls_vec.TlsByteVecU16.get_content_lengths_char,
    checked_alloc_len_total, alloc.vec.Vec.extend_from_slice_U8_spec,
    core.U16.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from_char,
    alloc.vec.Vec.with_capacity, core.result.Result.unwrap_ok_spec, U16_serialize_char,
    alloc.vec.Vec.len_spec, tls_vec.TlsByteVecU16.as_slice, CoreModels.core.slice.Slice.len_spec,
    tls_vec.TlsByteVecU16.assert_written_bytes_total]
  bytevec_ser_close

/-- `TlsByteVecU16::serialize_bytes_bytes` does not panic (an over-long vector gives `Err`); an `Ok` result has the payload length plus the 2-byte prefix. -/
theorem tls_vec.TlsByteVecU16.serialize_bytes_bytes_char (self : tls_vec.TlsByteVecU16) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU16.serialize_bytes_bytes self
    ⦃ ⇓ r => ⌜ ∀ out : alloc.vec.Vec Std.U8, r = .Ok out →
        out.val.length = self.vec.val.length + 2 ⌝ ⦄ := by
  mvcgen [tls_vec.TlsByteVecU16.serialize_bytes_bytes,
    tls_vec.TlsByteVecU16.get_content_lengths_char,
    checked_alloc_len_total, alloc.vec.Vec.extend_from_slice_U8_spec,
    core.U16.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from_char,
    alloc.vec.Vec.with_capacity, core.result.Result.unwrap_ok_spec, U16_serialize_char,
    alloc.vec.Vec.len_spec, tls_vec.TlsByteVecU16.as_slice, CoreModels.core.slice.Slice.len_spec,
    tls_vec.TlsByteVecU16.assert_written_bytes_total]
  bytevec_ser_close

/-- `TlsByteVecU24::serialize_bytes_bytes` does not panic (an over-long vector gives `Err`); an `Ok` result has the payload length plus the 3-byte prefix. -/
theorem tls_vec.TlsByteVecU24.serialize_bytes_bytes_char (self : tls_vec.TlsByteVecU24) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU24.serialize_bytes_bytes self
    ⦃ ⇓ r => ⌜ ∀ out : alloc.vec.Vec Std.U8, r = .Ok out →
        out.val.length = self.vec.val.length + 3 ⌝ ⦄ := by
  mvcgen [tls_vec.TlsByteVecU24.serialize_bytes_bytes,
    tls_vec.TlsByteVecU24.get_content_lengths_char,
    checked_alloc_len_total, alloc.vec.Vec.extend_from_slice_U8_spec,
    U24.Insts.CoreConvertTryFromUsizeU24OverflowError.try_from_char,
    alloc.vec.Vec.with_capacity, core.result.Result.unwrap_ok_spec, U24_serialize_char,
    alloc.vec.Vec.len_spec, tls_vec.TlsByteVecU24.as_slice, CoreModels.core.slice.Slice.len_spec,
    tls_vec.TlsByteVecU24.assert_written_bytes_total]
  bytevec_ser_close

/-- `TlsByteVecU24::serialize_bytes_bytes`, when it returns `Ok`, gives the payload plus the 3-byte prefix. -/
theorem tls_vec.TlsByteVecU24.serialize_bytes_bytes_partial (self : tls_vec.TlsByteVecU24) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU24.serialize_bytes_bytes self
    ⦃ ⇓? r => ⌜ ∀ out : alloc.vec.Vec Std.U8, r = .Ok out →
        out.val.length = self.vec.val.length + 3 ⌝ ⦄ :=
  partial_of_total (tls_vec.TlsByteVecU24.serialize_bytes_bytes_char self)

/-- `TlsByteVecU32::serialize_bytes_bytes`, when it returns `Ok`, gives the payload plus the 4-byte prefix, and the payload is within the prefix bound. -/
theorem tls_vec.TlsByteVecU32.serialize_bytes_bytes_partial (self : tls_vec.TlsByteVecU32) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU32.serialize_bytes_bytes self
    ⦃ ⇓? r => ⌜ ∀ out : alloc.vec.Vec Std.U8, r = .Ok out →
        out.val.length = self.vec.val.length + 4 ∧ self.vec.val.length ≤ 4294967295 ⌝ ⦄ := by
  mvcgen [tls_vec.TlsByteVecU32.serialize_bytes_bytes,
    tls_vec.TlsByteVecU32.get_content_lengths_char,
    checked_alloc_len_total, alloc.vec.Vec.extend_from_slice_U8_spec,
    core.U32.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from_char,
    alloc.vec.Vec.with_capacity, core.result.Result.unwrap_ok_spec, U32_serialize_char,
    alloc.vec.Vec.len_spec, tls_vec.TlsByteVecU32.as_slice, CoreModels.core.slice.Slice.len_spec,
    tls_vec.TlsByteVecU32.assert_written_bytes_total]
  bytevec_ser_close

/-- `TlsByteVecU32::serialize_bytes_bytes` does not panic (an over-long vector gives `Err`); an `Ok` result has the payload length plus the 4-byte prefix. -/
theorem tls_vec.TlsByteVecU32.serialize_bytes_bytes_char (self : tls_vec.TlsByteVecU32) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU32.serialize_bytes_bytes self
    ⦃ ⇓ r => ⌜ ∀ out : alloc.vec.Vec Std.U8, r = .Ok out →
        out.val.length = self.vec.val.length + 4 ⌝ ⦄ := by
  mvcgen [tls_vec.TlsByteVecU32.serialize_bytes_bytes,
    tls_vec.TlsByteVecU32.get_content_lengths_char,
    checked_alloc_len_total, alloc.vec.Vec.extend_from_slice_U8_spec,
    core.U32.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from_char,
    alloc.vec.Vec.with_capacity, core.result.Result.unwrap_ok_spec, U32_serialize_char,
    alloc.vec.Vec.len_spec, tls_vec.TlsByteVecU32.as_slice, CoreModels.core.slice.Slice.len_spec,
    tls_vec.TlsByteVecU32.assert_written_bytes_total]
  bytevec_ser_close

/-- `TlsByteVecU8::serialize_bytes_bytes`, when it returns `Ok`, gives the 1-byte length prefix followed by the payload. -/
theorem tls_vec.TlsByteVecU8.serialize_bytes_bytes_content (self : tls_vec.TlsByteVecU8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU8.serialize_bytes_bytes self
    ⦃ ⇓? r => ⌜ ∀ out : alloc.vec.Vec Std.U8, r = .Ok out →
        ∃ n : Std.U8, n.val = self.vec.val.length ∧ out.val = n :: self.vec.val ⌝ ⦄ := by
  mvcgen [tls_vec.TlsByteVecU8.serialize_bytes_bytes,
    tls_vec.TlsByteVecU8.get_content_lengths_char,
    checked_alloc_len_total, alloc.vec.Vec.extend_from_slice_U8_spec,
    core.U8.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from_char,
    alloc.vec.Vec.with_capacity, core.result.Result.unwrap_ok_spec, U8_serialize_char,
    alloc.vec.Vec.len_spec, tls_vec.TlsByteVecU8.as_slice, CoreModels.core.slice.Slice.len_spec,
    tls_vec.TlsByteVecU8.assert_written_bytes_total]
  bytevec_ser_close

/-- `s.get(start..end)`, content version: if it returns `Some t`, then `t` is the corresponding sublist. -/
theorem core.ops.range.RangeUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get_content_spec
    {T : Type} (r : core.ops.range.Range Std.Usize) (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ core.ops.range.RangeUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get r s
    ⦃ ⇓ o => ⌜ ∀ t, o = some t → r.start.val ≤ r.end.val ∧ r.end.val ≤ s.val.length ∧
        t.val = (s.val.drop r.start.val).take (r.end.val - r.start.val) ⌝ ⦄ := by
  unfold core.ops.range.RangeUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get
    rust_primitives.slice.slice_length rust_primitives.slice.slice_slice Slice.subslice
  mvcgen
  · rename_i h1 h2 h3
    have hl : (s.len).val = s.val.length := by simp
    intro t ht
    have ht' := Option.some.inj ht
    subst ht'
    refine ⟨h3.1, h3.2, ?_⟩
    simp [List.slice]
  · rename_i h1 h2 h3
    have hl : (s.len).val = s.val.length := by simp
    exact absurd ⟨by scalar_tac, by scalar_tac⟩ h3
  · intro t ht; cases ht
  · intro t ht; cases ht

/-- `s.get(start..end)`, exact version: `Some` of the corresponding sublist exactly when the range is
within `s`. -/
theorem core.ops.range.RangeUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get_total_spec
    {T : Type} (r : core.ops.range.Range Std.Usize) (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ core.ops.range.RangeUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get r s
    ⦃ ⇓ o => ⌜ r.start.val ≤ r.end.val → r.end.val ≤ s.val.length →
        ∃ t : Slice T, o = some t ∧ t.val = (s.val.drop r.start.val).take (r.end.val - r.start.val) ⌝ ⦄ := by
  unfold core.ops.range.RangeUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get
    rust_primitives.slice.slice_length rust_primitives.slice.slice_slice Slice.subslice
  mvcgen
  · intro _ _
    exact ⟨_, rfl, by simp [List.slice]⟩
  · rename_i h1 h2 h3
    have hl : (s.len).val = s.val.length := by simp
    exact absurd ⟨by scalar_tac, by scalar_tac⟩ h3
  · rename_i h1 h2
    have hl : (s.len).val = s.val.length := by simp
    intro _ h
    exfalso
    apply h2
    scalar_tac
  · rename_i h1
    intro h
    exfalso
    apply h1
    scalar_tac

/-- `Vec::eq` (element-wise, through a spec of the element `eq`): `decide` of list equality. -/
theorem alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq_spec {T : Type} [DecidableEq T]
    (inst : core.cmp.PartialEq T T) (a b : alloc.vec.Vec T)
    (heq : ∀ x y, ⦃ ⌜ True ⌝ ⦄ inst.eq x y ⦃ ⇓ r => ⌜ r = decide (x = y) ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq inst a b
    ⦃ ⇓ r => ⌜ r = decide (a.val = b.val) ⌝ ⦄ := by
  have hbody : ∀ (it : core.ops.range.Range Std.Usize) (res : Bool),
      it.end.val = a.val.length → a.val.length = b.val.length →
      it.start.val ≤ it.end.val → (res = true ↔ ∀ j, j < it.start.val → a.val[j]? = b.val[j]?) →
      ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq_loop.body inst a b it res
      ⦃ ⇓ r => ⌜ match r with
        | .done y => y = decide (a.val = b.val)
        | .cont (it', res') => (it'.end.val = a.val.length ∧ it'.start.val ≤ it'.end.val ∧
            (res' = true ↔ ∀ j, j < it'.start.val → a.val[j]? = b.val[j]?)) ∧
            it'.end.val - it'.start.val < it.end.val - it.start.val ⌝ ⦄ := by
    intro it res hend hlen hle hres
    unfold alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq_loop.body
    mvcgen [heq, core.ops.range.Range.Insts.CoreIterTraitsIteratorIterator.next_Usize_spec]
    · -- exhausted range
      rename_i r hr hnx
      by_cases hlt : it.start.val < it.end.val
      · rw [(hnx.1 hlt).1] at hr; simp at hr
      · have hse : it.start.val = it.end.val := by omega
        rcases Bool.eq_false_or_eq_true res with hr1 | hr1
        · rw [hr1]
          have hall := hres.mp hr1
          simp only [true_eq_decide_iff]
          apply List.ext_getElem?
          intro j
          by_cases hj : j < it.start.val
          · exact hall j hj
          · rw [List.getElem?_eq_none_iff.mpr (by omega), List.getElem?_eq_none_iff.mpr (by omega)]
        · rw [hr1]
          simp only [false_eq_decide_iff]
          intro hab'
          have : res = true := by
            apply hres.mpr; intro j _; rw [hab']
          rw [hr1] at this; simp at this
    · rename_i r i hi hres1 hnx
      obtain ⟨hlt, hii, hs, he⟩ := core.ops.range.Range.next_Usize_some it r i hi hnx
      subst hii
      omega
    · rename_i r i hi hres1 hnx x hx
      obtain ⟨hlt, hii, hs, he⟩ := core.ops.range.Range.next_Usize_some it r i hi hnx
      subst hii
      omega
    · rename_i r i hi hres1 hnx x hx y hy c hc hdec
      obtain ⟨hlt, hii, hs, he⟩ := core.ops.range.Range.next_Usize_some it r i hi hnx
      subst hii
      have he' : r.2.end.val = it.end.val := by rw [he]
      have hxy : x = y := by subst hc; simpa using hdec.symm
      have hall := hres.mp hres1
      refine ⟨⟨by omega, by omega, ⟨fun _ j hj => ?_, fun _ => trivial⟩⟩, by omega⟩
      by_cases hji : j < it.start.val
      · exact hall j hji
      · have hj : j = it.start.val := by omega
        subst hj
        rw [List.getElem?_eq_getElem (by omega), List.getElem?_eq_getElem (by omega)]
        simp only [Option.some.injEq]
        rw [← hx, ← hy]; exact hxy
    · rename_i r i hi hres1 hnx x hx y hy c hc hdec
      obtain ⟨hlt, hii, hs, he⟩ := core.ops.range.Range.next_Usize_some it r i hi hnx
      subst hii
      have he' : r.2.end.val = it.end.val := by rw [he]
      have hne : x ≠ y := by
        intro hxy; apply hc; rw [hdec]; simp [hxy]
      refine ⟨⟨by omega, by omega, ⟨fun h => absurd h (by simp), fun hall => ?_⟩⟩, by omega⟩
      exfalso
      have := hall it.start.val (by omega)
      rw [List.getElem?_eq_getElem (by omega), List.getElem?_eq_getElem (by omega)] at this
      apply hne
      have h2 := Option.some.inj this
      rw [hx, hy]; exact h2
    · rename_i r i hi hres1 hnx
      obtain ⟨hlt, hii, hs, he⟩ := core.ops.range.Range.next_Usize_some it r i hi hnx
      subst hii
      have he' : r.2.end.val = it.end.val := by rw [he]
      refine ⟨⟨by omega, by omega, ⟨fun h => absurd h (by simp), fun hall => ?_⟩⟩, by omega⟩
      exfalso
      apply hres1
      apply hres.mpr
      intro j hj
      exact hall j (by omega)
  have hloop : ∀ (it : core.ops.range.Range Std.Usize) (res : Bool),
      it.end.val = a.val.length → a.val.length = b.val.length →
      it.start.val ≤ it.end.val → (res = true ↔ ∀ j, j < it.start.val → a.val[j]? = b.val[j]?) →
      ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq_loop inst it a b res
      ⦃ ⇓ r => ⌜ r = decide (a.val = b.val) ⌝ ⦄ := by
    intro it res hend hlen hle hres
    unfold alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq_loop
    apply Aeneas.Std.WP.spec_to_mvcgen
    apply Aeneas.Std.loop.spec_decr_nat
      (fun p : core.ops.range.Range Std.Usize × Bool => p.1.end.val - p.1.start.val)
      (fun p : core.ops.range.Range Std.Usize × Bool => p.1.end.val = a.val.length ∧
        p.1.start.val ≤ p.1.end.val ∧
        (p.2 = true ↔ ∀ j, j < p.1.start.val → a.val[j]? = b.val[j]?))
      (fun y => y = decide (a.val = b.val))
    · rintro ⟨it', res'⟩ hp
      obtain ⟨hp1, hp2, hp3⟩ := hp
      obtain ⟨v, hv, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
        (hbody it' res' hp1 hlen hp2 hp3)
      show Aeneas.Std.WP.spec (alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq_loop.body inst a b it' res') _
      rw [hv, Aeneas.Std.WP.spec_ok]
      cases v with
      | done y => exact hP
      | cont q => exact hP
    · exact ⟨hend, hle, hres⟩
  unfold alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq
  mvcgen
  · rename_i r1 h1 r2 h2
    intro h3
    subst h1 h2
    have hl : a.val.length = b.val.length := by scalar_tac
    exact hloop { start := 0#usize, «end» := Slice.len a } true (by simp [Slice.len]) hl
      (by simp [Slice.len]) (by simp) trivial
  · rename_i r1 h1 r2 hne h2
    subst h1 h2
    symm
    simp only [decide_eq_false_iff_not]
    intro hab
    exact hne (UScalar.eq_of_val_eq (by simp [Slice.len, hab]))

/-- `Vec::eq` does not fail when the element `eq` does not fail (total). -/
theorem alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq_pf {T : Type}
    (inst : core.cmp.PartialEq T T) (a b : alloc.vec.Vec T)
    (heq : ∀ x y, ⦃ ⌜ True ⌝ ⦄ inst.eq x y ⦃ ⇓ _ => ⌜ True ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq inst a b ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  have hbody : ∀ (it : core.ops.range.Range Std.Usize) (res : Bool),
      it.end.val = a.val.length → a.val.length = b.val.length → it.start.val ≤ it.end.val →
      ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq_loop.body inst a b it res
      ⦃ ⇓ r => ⌜ match r with
        | .done _ => True
        | .cont (it', _) => (it'.end.val = a.val.length ∧ it'.start.val ≤ it'.end.val) ∧
            it'.end.val - it'.start.val < it.end.val - it.start.val ⌝ ⦄ := by
    intro it res hend hlen hle
    unfold alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq_loop.body
    mvcgen [heq, core.ops.range.Range.Insts.CoreIterTraitsIteratorIterator.next_Usize_spec] <;>
      first | trivial | grind
  have hloop : ∀ (it : core.ops.range.Range Std.Usize) (res : Bool),
      it.end.val = a.val.length → a.val.length = b.val.length → it.start.val ≤ it.end.val →
      ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq_loop inst it a b res
      ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
    intro it res hend hlen hle
    unfold alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq_loop
    apply Aeneas.Std.WP.spec_to_mvcgen
    apply Aeneas.Std.loop.spec_decr_nat
      (fun p : core.ops.range.Range Std.Usize × Bool => p.1.end.val - p.1.start.val)
      (fun p : core.ops.range.Range Std.Usize × Bool =>
        p.1.end.val = a.val.length ∧ p.1.start.val ≤ p.1.end.val)
      (fun _ => True)
    · rintro ⟨it', res'⟩ ⟨hp1, hp2⟩
      obtain ⟨v, hv, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (hbody it' res' hp1 hlen hp2)
      show Aeneas.Std.WP.spec (alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq_loop.body inst a b it' res') _
      rw [hv, Aeneas.Std.WP.spec_ok]
      cases v <;> exact hP
    · exact ⟨hend, hle⟩
  unfold alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq
  mvcgen
  · rename_i r1 h1 r2 h2
    intro h3
    subst h1 h2
    have h := hloop { start := 0#usize, «end» := Slice.len a } true (by simp [Slice.len])
      (by scalar_tac) (by simp [Slice.len])
    exact h trivial

/-- The parent `eq` of an `Eq`-lawful instance does not fail. -/
theorem _root_.CoreModels.core.cmp.Eq.Lawful.eq_pf {T : Type} {inst : core.cmp.Eq T}
    (h : core.cmp.Eq.Lawful T inst) (x y : T) :
    ⦃ ⌜ True ⌝ ⦄ inst.PartialEqInst.eq x y ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  have hs := h.eq_spec x y
  mvcgen [hs]

theorem _root_.CoreModels.core.cmp.PartialEq.Lawful.eq_pf {T : Type} {inst : core.cmp.PartialEq T T}
    (h : core.cmp.PartialEq.Lawful T T inst) (x y : T) :
    ⦃ ⌜ True ⌝ ⦄ inst.eq x y ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  have hs := h.eq_spec x y
  mvcgen [hs]

/-- `Vec::eq`, when the element `eq` decides `=`, decides `=`. -/
theorem alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq_iff {T : Type}
    (inst : core.cmp.PartialEq T T) (a b : alloc.vec.Vec T)
    (heq : ∀ x y, ⦃ ⌜ True ⌝ ⦄ inst.eq x y ⦃ ⇓ r => ⌜ r = true ↔ x = y ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq inst a b
    ⦃ ⇓ r => ⌜ r = true ↔ a = b ⌝ ⦄ := by
  classical
  have hdec : ∀ x y, ⦃ ⌜ True ⌝ ⦄ inst.eq x y ⦃ ⇓ r => ⌜ r = decide (x = y) ⌝ ⦄ := by
    intro x y
    have h := heq x y
    mvcgen [h]
    intro hr
    rw [Bool.eq_iff_iff, hr]
    simp
  have h := alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq_spec inst a b hdec
  mvcgen [h]
  rintro rfl
  simp [Subtype.val_inj]
  rfl

/-- `Vec::eq`, when the element `eq` decides `HEq` (a `PartialEq.Lawful`), decides `=`. -/
theorem alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq_iff_of_lawful {T : Type}
    (inst : core.cmp.PartialEq T T) (a b : alloc.vec.Vec T)
    (hl : core.cmp.PartialEq.Lawful T T inst) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq inst a b
    ⦃ ⇓ r => ⌜ r = true ↔ a = b ⌝ ⦄ :=
  alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq_iff inst a b fun x y => by
    have h := hl.eq_spec x y
    simpa only [heq_iff_eq] using h

/-- `Vec<T>`'s `PartialEq.Lawful` from the element's (lives here, not in `MissingCoreModelsSpecs`,
because it uses the `Vec::eq` loop spec above). -/
theorem alloc.vec.Vec.Insts.CoreCmpPartialEqVec.Lawful {T : Type}
    (inst : core.cmp.PartialEq T T) (hl : core.cmp.PartialEq.Lawful T T inst) :
    core.cmp.PartialEq.Lawful (alloc.vec.Vec T) (alloc.vec.Vec T)
      (alloc.vec.Vec.Insts.CoreCmpPartialEqVec inst) := by
  have hs := fun a b => alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq_iff_of_lawful inst a b hl
  refine .of_eq_iff hs fun a b => ?_
  have h := hs a b
  show ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.CoreCmpPartialEqVec.ne inst a b ⦃ ⇓ _ => ⌜ True ⌝ ⦄
  unfold alloc.vec.Vec.Insts.CoreCmpPartialEqVec.ne
  mvcgen [h]

/-- `Vec<u8>::eq`: `decide` of list equality. -/
@[spec] theorem alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq_U8_spec (a b : alloc.vec.Vec Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq core.U8.Insts.CoreCmpPartialEqU8 a b
    ⦃ ⇓ r => ⌜ r = decide (a.val = b.val) ⌝ ⦄ :=
  alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq_spec _ a b
    core.U8.Insts.CoreCmpPartialEqU8.eq_decide_spec

/-- `TlsByteVecU8::eq`: `decide` of equality of the contents. -/
@[spec] theorem tls_vec.TlsByteVecU8.Insts.CoreCmpPartialEqTlsByteVecU8.eq_spec
    (a b : tls_vec.TlsByteVecU8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU8.Insts.CoreCmpPartialEqTlsByteVecU8.eq a b
    ⦃ ⇓ r => ⌜ r = decide (a.vec.val = b.vec.val) ⌝ ⦄ := by
  unfold tls_vec.TlsByteVecU8.Insts.CoreCmpPartialEqTlsByteVecU8.eq
  mvcgen

/-- `VLBytes::eq`: `decide` of equality of the contents. -/
@[spec] theorem quic_vec.VLBytes.Insts.CoreCmpPartialEqVLBytes.eq_decide_spec
    (a b : quic_vec.VLBytes) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLBytes.Insts.CoreCmpPartialEqVLBytes.eq a b
    ⦃ ⇓ r => ⌜ r = decide (a.vec.val = b.vec.val) ⌝ ⦄ := by
  unfold quic_vec.VLBytes.Insts.CoreCmpPartialEqVLBytes.eq
  mvcgen

/-- `PartialEq for u16`, in the `decide` form that the generic `Vec::eq` spec takes. -/
theorem core.U16.Insts.CoreCmpPartialEqU16.eq_decide_spec (x y : Std.U16) :
    ⦃ ⌜ True ⌝ ⦄ core.U16.Insts.CoreCmpPartialEqU16.eq x y ⦃ ⇓ r => ⌜ r = decide (x = y) ⌝ ⦄ := by
  simp only [core.U16.Insts.CoreCmpPartialEqU16]; mvcgen
  by_cases h : x = y <;> simp [h]

/-- `Vec<u16>::eq`: `decide` of list equality. -/
@[spec] theorem alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq_U16_spec (a b : alloc.vec.Vec Std.U16) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq core.U16.Insts.CoreCmpPartialEqU16 a b
    ⦃ ⇓ r => ⌜ r = decide (a.val = b.val) ⌝ ⦄ :=
  alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq_spec _ a b
    core.U16.Insts.CoreCmpPartialEqU16.eq_decide_spec

/-- `TlsByteVecU16::serialize_bytes_bytes`, when it returns `Ok`, gives the 2-byte length prefix followed by the payload. -/
theorem tls_vec.TlsByteVecU16.serialize_bytes_bytes_content (self : tls_vec.TlsByteVecU16) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU16.serialize_bytes_bytes self
    ⦃ ⇓? r => ⌜ ∀ out : alloc.vec.Vec Std.U8, r = .Ok out →
        ∃ n : Std.U16, n.val = self.vec.val.length ∧
          out.val = (Aeneas.Std.core.num.U16.to_be_bytes n).val ++ self.vec.val ⌝ ⦄ := by
  mvcgen [tls_vec.TlsByteVecU16.serialize_bytes_bytes,
    tls_vec.TlsByteVecU16.get_content_lengths_char,
    checked_alloc_len_total, alloc.vec.Vec.extend_from_slice_U8_spec,
    core.U16.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from_char,
    alloc.vec.Vec.with_capacity, core.result.Result.unwrap_ok_spec, U16_serialize_char,
    alloc.vec.Vec.len_spec, tls_vec.TlsByteVecU16.as_slice, CoreModels.core.slice.Slice.len_spec,
    tls_vec.TlsByteVecU16.assert_written_bytes_total]
  bytevec_ser_close

/-- `TlsByteVecU32::serialize_bytes_bytes`, when it returns `Ok`, gives the 4-byte length prefix followed by the payload. -/
theorem tls_vec.TlsByteVecU32.serialize_bytes_bytes_content (self : tls_vec.TlsByteVecU32) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU32.serialize_bytes_bytes self
    ⦃ ⇓? r => ⌜ ∀ out : alloc.vec.Vec Std.U8, r = .Ok out →
        ∃ n : Std.U32, n.val = self.vec.val.length ∧
          out.val = (Aeneas.Std.core.num.U32.to_be_bytes n).val ++ self.vec.val ⌝ ⦄ := by
  mvcgen [tls_vec.TlsByteVecU32.serialize_bytes_bytes,
    tls_vec.TlsByteVecU32.get_content_lengths_char,
    checked_alloc_len_total, alloc.vec.Vec.extend_from_slice_U8_spec,
    core.U32.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from_char,
    alloc.vec.Vec.with_capacity, core.result.Result.unwrap_ok_spec, U32_serialize_char,
    alloc.vec.Vec.len_spec, tls_vec.TlsByteVecU32.as_slice, CoreModels.core.slice.Slice.len_spec,
    tls_vec.TlsByteVecU32.assert_written_bytes_total]
  bytevec_ser_close

/-- `TlsByteVecU16::eq`: `decide` of equality of the contents. -/
@[spec] theorem tls_vec.TlsByteVecU16.Insts.CoreCmpPartialEqTlsByteVecU16.eq_spec
    (a b : tls_vec.TlsByteVecU16) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU16.Insts.CoreCmpPartialEqTlsByteVecU16.eq a b
    ⦃ ⇓ r => ⌜ r = decide (a.vec.val = b.vec.val) ⌝ ⦄ := by
  unfold tls_vec.TlsByteVecU16.Insts.CoreCmpPartialEqTlsByteVecU16.eq
  mvcgen

/-- `TlsByteVecU24::eq`: `decide` of equality of the contents. -/
@[spec] theorem tls_vec.TlsByteVecU24.Insts.CoreCmpPartialEqTlsByteVecU24.eq_spec
    (a b : tls_vec.TlsByteVecU24) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU24.Insts.CoreCmpPartialEqTlsByteVecU24.eq a b
    ⦃ ⇓ r => ⌜ r = decide (a.vec.val = b.vec.val) ⌝ ⦄ := by
  unfold tls_vec.TlsByteVecU24.Insts.CoreCmpPartialEqTlsByteVecU24.eq
  mvcgen

/-- `TlsByteVecU32::eq`: `decide` of equality of the contents. -/
@[spec] theorem tls_vec.TlsByteVecU32.Insts.CoreCmpPartialEqTlsByteVecU32.eq_spec
    (a b : tls_vec.TlsByteVecU32) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU32.Insts.CoreCmpPartialEqTlsByteVecU32.eq a b
    ⦃ ⇓ r => ⌜ r = decide (a.vec.val = b.vec.val) ⌝ ⦄ := by
  unfold tls_vec.TlsByteVecU32.Insts.CoreCmpPartialEqTlsByteVecU32.eq
  mvcgen

/-- `TlsByteVecU24::serialize_bytes_bytes`, when it returns `Ok`, gives the 3-byte length prefix followed by the payload. -/
theorem tls_vec.TlsByteVecU24.serialize_bytes_bytes_content (self : tls_vec.TlsByteVecU24) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU24.serialize_bytes_bytes self
    ⦃ ⇓? r => ⌜ ∀ out : alloc.vec.Vec Std.U8, r = .Ok out →
        ∃ b0 b1 b2 : Std.U8, b0.val * 65536 + b1.val * 256 + b2.val = self.vec.val.length ∧
          out.val = b0 :: b1 :: b2 :: self.vec.val ⌝ ⦄ := by
  mvcgen [tls_vec.TlsByteVecU24.serialize_bytes_bytes,
    tls_vec.TlsByteVecU24.get_content_lengths_char,
    checked_alloc_len_total, alloc.vec.Vec.extend_from_slice_U8_spec,
    U24.Insts.CoreConvertTryFromUsizeU24OverflowError.try_from_char,
    alloc.vec.Vec.with_capacity, core.result.Result.unwrap_ok_spec, U24_serialize_char,
    alloc.vec.Vec.len_spec, tls_vec.TlsByteVecU24.as_slice, CoreModels.core.slice.Slice.len_spec,
    tls_vec.TlsByteVecU24.assert_written_bytes_total]
  bytevec_ser_close

end tls_codec
