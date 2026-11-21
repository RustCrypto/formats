/- `TlsVarInt::write_bytes`: panic freedom and the bytes it writes (the varint prefix).

Obligations: none directly; the bytes-path halves of `PanicFreedom.lean` /
`FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): nothing ASSUMED. -/
import TlsCodec.Verification.Helpers.BigEndian
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! ### `TlsVarInt::write_bytes` -/

/-- One iteration of the `write_bytes` loops: needs `i ≤ len`, keeps the slice length. -/
theorem varint.TlsVarInt.write_bytes_loop0.body_spec (bytes : Slice Std.U8) (value : Std.U64)
    (i : Std.Usize) (h : i.val ≤ bytes.val.length) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.write_bytes_loop0.body bytes value i
    ⦃ ⇓ r => ⌜ match r with
      | .done y => y.val.length = bytes.val.length
      | .cont (b', _, i') => b'.val.length = bytes.val.length ∧ i'.val ≤ b'.val.length ∧ i'.val < i.val ⌝ ⦄ := by
  unfold varint.TlsVarInt.write_bytes_loop0.body
  mvcgen
  · rename_i i1 hi1 hge i2 hi2 i3 hi3 i4 hi4 i5 hi5 s hlt hs v hv1 hv2 hlt8
    subst hs
    have hl : (bytes.set i1 i5).length = bytes.length := by simp [Slice.set, Slice.length]
    refine ⟨?_, ?_, ?_⟩ <;> scalar_tac
  · rename_i i1 hi1 hge i2 hi2 i3 hi3 i4 hi4 i5 hi5 hlt
    obtain ⟨hx, _⟩ := hi4
    exfalso; scalar_tac
  · exfalso; scalar_tac
  · exfalso; scalar_tac


/-- The `write_bytes` loops preserve the slice length (given `i ≤ len`). -/
theorem varint.TlsVarInt.write_bytes_loop0_spec (bytes : Slice Std.U8) (value : Std.U64)
    (i : Std.Usize) (h : i.val ≤ bytes.val.length) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.write_bytes_loop0 bytes value i
    ⦃ ⇓ r => ⌜ r.val.length = bytes.val.length ⌝ ⦄ := by
  unfold varint.TlsVarInt.write_bytes_loop0
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.loop.spec_decr_nat
    (fun x : Slice Std.U8 × Std.U64 × Std.Usize => x.2.2.val)
    (fun x : Slice Std.U8 × Std.U64 × Std.Usize =>
      x.1.val.length = bytes.val.length ∧ x.2.2.val ≤ x.1.val.length)
    (fun y : Slice Std.U8 => y.val.length = bytes.val.length)
  · rintro ⟨b, v, j⟩ ⟨hb, hj⟩
    obtain ⟨r, hr, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (varint.TlsVarInt.write_bytes_loop0.body_spec b v j hj)
    dsimp only
    rw [hr, Aeneas.Std.WP.spec_ok]
    cases r with
    | done y => exact hP.trans hb
    | cont x =>
      obtain ⟨b', v', j'⟩ := x
      exact ⟨⟨hP.1.trans hb, hP.2.1⟩, hP.2.2⟩
  · exact ⟨rfl, h⟩


theorem varint.TlsVarInt.write_bytes_loop1_spec (bytes : Slice Std.U8) (value : Std.U64)
    (i : Std.Usize) (h : i.val ≤ bytes.val.length) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.write_bytes_loop1 bytes value i
    ⦃ ⇓ r => ⌜ r.val.length = bytes.val.length ⌝ ⦄ := by
  have := varint.TlsVarInt.write_bytes_loop0_spec bytes value i h
  unfold varint.TlsVarInt.write_bytes_loop1 varint.TlsVarInt.write_bytes_loop1.body
  unfold varint.TlsVarInt.write_bytes_loop0 varint.TlsVarInt.write_bytes_loop0.body at this
  exact this

theorem varint.TlsVarInt.write_bytes_loop2_spec (bytes : Slice Std.U8) (value : Std.U64)
    (i : Std.Usize) (h : i.val ≤ bytes.val.length) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.write_bytes_loop2 bytes value i
    ⦃ ⇓ r => ⌜ r.val.length = bytes.val.length ⌝ ⦄ := by
  have := varint.TlsVarInt.write_bytes_loop0_spec bytes value i h
  unfold varint.TlsVarInt.write_bytes_loop2 varint.TlsVarInt.write_bytes_loop2.body
  unfold varint.TlsVarInt.write_bytes_loop0 varint.TlsVarInt.write_bytes_loop0.body at this
  exact this

theorem varint.TlsVarInt.write_bytes_loop3_spec (bytes : Slice Std.U8) (value : Std.U64)
    (i : Std.Usize) (h : i.val ≤ bytes.val.length) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.write_bytes_loop3 bytes value i
    ⦃ ⇓ r => ⌜ r.val.length = bytes.val.length ⌝ ⦄ := by
  have := varint.TlsVarInt.write_bytes_loop0_spec bytes value i h
  unfold varint.TlsVarInt.write_bytes_loop3 varint.TlsVarInt.write_bytes_loop3.body
  unfold varint.TlsVarInt.write_bytes_loop0 varint.TlsVarInt.write_bytes_loop0.body at this
  exact this


/-- Cloning a replicated `u8` list is the identity. -/
theorem mapM_clone_replicate_U8 (n : Nat) (x : Std.U8) :
    (List.replicate n x).mapM core.U8.Insts.CoreCloneClone.clone = ok (List.replicate n x) := by
  induction n with
  | zero => rfl
  | succ n ih =>
    rw [List.replicate_succ, List.mapM_cons, ih]
    rfl

/-- `vec![x; len]` for `u8`: a vector of length `len`. -/
theorem alloc.vec.from_elem_U8_len_spec (item : Std.U8) (len : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.from_elem core.U8.Insts.CoreCloneClone item len
    ⦃ ⇓ r => ⌜ (r : Slice Std.U8).val.length = len.val ⌝ ⦄ := by
  unfold alloc.vec.from_elem rust_primitives.sequence.seq_create
  mvcgen
  · rename_i h
    simp [Slice.new, h]
  · rename_i hne cl hcl comb hle
    have hl := List.mapM_RustM_length hcl
    simp only [List.length_replicate] at hl
    simp only [comb, List.length_append, List.length_singleton, hl]
    scalar_tac
  · rename_i hne cl hcl comb hle
    have hl := List.mapM_RustM_length hcl
    simp only [List.length_replicate] at hl
    exfalso; apply hle
    simp only [comb, List.length_append, List.length_singleton, hl]
    scalar_tac
  · rename_i hne e hcl
    rw [mapM_clone_replicate_U8] at hcl
    cases hcl
  · rename_i hne hcl
    rw [mapM_clone_replicate_U8] at hcl
    cases hcl

/-- Length of `take`, in the `Slice` form used by the write-back lemmas. -/
theorem slice_take_length (l : List Std.U8) (n : Nat) (h : n ≤ l.length) :
    (l.take n).length = n := by simp [h]

/-- Exact result of `TlsVarInt::write_bytes` (contents of the written bytes are not tracked):
too short a buffer is returned unchanged with `InvalidVectorLength`; otherwise it returns the
encoded length and a buffer of the same length. -/
theorem varint.TlsVarInt.write_bytes_spec_le (self : varint.TlsVarInt) (buf : Slice Std.U8)
    (hv : self.val ≤ 2 ^ 62 - 1) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.write_bytes self buf
    ⦃ ⇓ r => ⌜ (buf.val.length < varint.lenOf self.val →
                  r = (.Err Error.InvalidVectorLength, buf)) ∧
               (varint.lenOf self.val ≤ buf.val.length →
                  (∃ l : Std.Usize, r.1 = .Ok l ∧ l.val = varint.lenOf self.val) ∧
                  r.2.val.length = buf.val.length) ⌝ ⦄ := by
  mvcgen [varint.TlsVarInt.write_bytes, varint.TlsVarInt.write_bytes_loop0_spec,
    varint.TlsVarInt.write_bytes_loop1_spec, varint.TlsVarInt.write_bytes_loop2_spec,
    varint.TlsVarInt.write_bytes_loop3_spec]
  · exfalso; scalar_tac -- `value > MAX`
  · rename_i len hlc blen hlt hbl
    have hc := varint.lenOf_char _ _ hlc
    refine ⟨fun _ => trivial, fun hle => ?_⟩
    exfalso; scalar_tac
  · rename_i len hlc blen hnlt hbl
    scalar_tac
  -- len = 1
  · rename_i len hlc blen hnlt hbl p hx hp s hlt hs
    have hc := varint.lenOf_char _ _ hlc
    have h2 : p.1.val.length = len.val := by rw [hp.1]; apply slice_take_length; scalar_tac
    have h3 : s.length = p.1.length := by rw [hs]; simp [Slice.set, Slice.length]
    scalar_tac
  · rename_i len hlc blen hnlt hbl p hx hp s hlt hs s2 buf1 hl2
    have hc := varint.lenOf_char _ _ hlc
    refine ⟨fun hlt' => ?_, fun hle => ⟨⟨_, rfl, ?_⟩, ?_⟩⟩
    · exfalso; scalar_tac
    · scalar_tac
    · change (p.2 s2).val.length = buf.val.length
      rw [hp.2 s2, List.length_setSlice!]
  · rename_i len hlc blen hnlt hbl p hx hp ha
    have hc := varint.lenOf_char _ _ hlc
    have h2 : p.1.val.length = len.val := by rw [hp.1]; apply slice_take_length; scalar_tac
    exfalso; scalar_tac
  -- len = 2
  · rename_i len hlc blen hnlt hbl p hx hp s hlt hs
    have hc := varint.lenOf_char _ _ hlc
    have h2 : p.1.val.length = len.val := by rw [hp.1]; apply slice_take_length; scalar_tac
    have h3 : s.length = p.1.length := by rw [hs]; simp [Slice.set, Slice.length]
    scalar_tac
  · rename_i len hlc blen hnlt hbl p hx hp s hlt hs s2 buf1 hl2
    have hc := varint.lenOf_char _ _ hlc
    refine ⟨fun hlt' => ?_, fun hle => ⟨⟨_, rfl, ?_⟩, ?_⟩⟩
    · exfalso; scalar_tac
    · scalar_tac
    · change (p.2 s2).val.length = buf.val.length
      rw [hp.2 s2, List.length_setSlice!]
  · rename_i len hlc blen hnlt hbl p hx hp ha
    have hc := varint.lenOf_char _ _ hlc
    have h2 : p.1.val.length = len.val := by rw [hp.1]; apply slice_take_length; scalar_tac
    exfalso; scalar_tac
  -- len = 4
  · rename_i len hlc blen hnlt hbl p hx hp s hlt hs
    have hc := varint.lenOf_char _ _ hlc
    have h2 : p.1.val.length = len.val := by rw [hp.1]; apply slice_take_length; scalar_tac
    have h3 : s.length = p.1.length := by rw [hs]; simp [Slice.set, Slice.length]
    scalar_tac
  · rename_i len hlc blen hnlt hbl p hx hp s hlt hs s2 buf1 hl2
    have hc := varint.lenOf_char _ _ hlc
    refine ⟨fun hlt' => ?_, fun hle => ⟨⟨_, rfl, ?_⟩, ?_⟩⟩
    · exfalso; scalar_tac
    · scalar_tac
    · change (p.2 s2).val.length = buf.val.length
      rw [hp.2 s2, List.length_setSlice!]
  · rename_i len hlc blen hnlt hbl p hx hp ha
    have hc := varint.lenOf_char _ _ hlc
    have h2 : p.1.val.length = len.val := by rw [hp.1]; apply slice_take_length; scalar_tac
    exfalso; scalar_tac
  -- len = 8
  · rename_i len hlc blen hnlt hbl p hx hp s hlt hs
    have hc := varint.lenOf_char _ _ hlc
    have h2 : p.1.val.length = len.val := by rw [hp.1]; apply slice_take_length; scalar_tac
    have h3 : s.length = p.1.length := by rw [hs]; simp [Slice.set, Slice.length]
    scalar_tac
  · rename_i len hlc blen hnlt hbl p hx hp s hlt hs s2 buf1 hl2
    have hc := varint.lenOf_char _ _ hlc
    refine ⟨fun hlt' => ?_, fun hle => ⟨⟨_, rfl, ?_⟩, ?_⟩⟩
    · exfalso; scalar_tac
    · scalar_tac
    · change (p.2 s2).val.length = buf.val.length
      rw [hp.2 s2, List.length_setSlice!]
  · rename_i len hlc blen hnlt hbl p hx hp ha
    have hc := varint.lenOf_char _ _ hlc
    have h2 : p.1.val.length = len.val := by rw [hp.1]; apply slice_take_length; scalar_tac
    exfalso; scalar_tac
  · rename_i len hlc blen hnlt hbl p n h1 h2 h4 h8 hx hp a1 a2
    have hc := varint.lenOf_char _ _ hlc
    have e1 : n ≠ 1 := h1
    have e2 : n ≠ 2 := h2
    have e4 : n ≠ 4 := h4
    have e8 : n ≠ 8 := h8
    exfalso; omega

/-- `TlsVarInt::write_bytes` for any value: a value above `MAX` or a too short buffer returns the
buffer unchanged with `InvalidVectorLength`; otherwise `write_bytes_spec_le`. -/
theorem varint.TlsVarInt.write_bytes_spec (self : varint.TlsVarInt) (buf : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.write_bytes self buf
    ⦃ ⇓ r => ⌜ (2 ^ 62 - 1 < self.val ∨ buf.val.length < varint.lenOf self.val →
                  r = (.Err Error.InvalidVectorLength, buf)) ∧
               (self.val ≤ 2 ^ 62 - 1 → varint.lenOf self.val ≤ buf.val.length →
                  (∃ l : Std.Usize, r.1 = .Ok l ∧ l.val = varint.lenOf self.val) ∧
                  r.2.val.length = buf.val.length) ⌝ ⦄ := by
  by_cases hv : self.val ≤ 2 ^ 62 - 1
  · refine triple_post_mono (varint.TlsVarInt.write_bytes_spec_le self buf hv) ?_
    rintro r ⟨h1, h2⟩
    exact ⟨fun h => h.elim (fun h => absurd hv (by omega)) h1, fun _ => h2⟩
  · obtain ⟨m, hm, hmv⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp varint.TlsVarInt.MAX_spec
    have hgt : self > m := by scalar_tac
    unfold varint.TlsVarInt.write_bytes
    rw [hm]
    simp only [bind_tc_ok, if_pos hgt]
    mvcgen
    exact ⟨by simp, fun h => absurd h hv⟩

/-- Exact behaviour of `TlsVarInt::tls_serialize_bytes` on a value at most `MAX`, on the length:
returns `lenOf` bytes. -/
theorem varint.TlsVarInt.serialize_len_char_le (self : varint.TlsVarInt)
    (hv : self.val ≤ 2 ^ 62 - 1) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.Insts.Tls_codecSerializeBytes.tls_serialize_bytes self
    ⦃ ⇓ r => ⌜ ∃ v : alloc.vec.Vec Std.U8, r = .Ok v ∧
        (v : Slice Std.U8).val.length = varint.lenOf self.val ⌝ ⦄ := by
  mvcgen [varint.TlsVarInt.Insts.Tls_codecSerializeBytes.tls_serialize_bytes,
    varint.TlsVarInt.bytes_len_spec, alloc.vec.from_elem_U8_len_spec,
    varint.TlsVarInt.write_bytes_spec, alloc.vec.Vec.Insts.CoreOpsDerefDerefMutSlice.deref_mut,
    alloc.vec.Vec.as_mut_slice, rust_primitives.sequence.seq_to_slice_mut]
  · rename_i len hlc vec hvl back wr hwr cf val hx byt hcf
    have hc := varint.lenOf_char _ _ hlc
    have hle : varint.lenOf self.val ≤ vec.val.length := by scalar_tac
    obtain ⟨_, hlen⟩ := hwr.2 hv hle
    refine ⟨_, rfl, ?_⟩
    show wr.2.val.length = _
    omega
  · rename_i len hlc vec hvl back wr hwr cf resid hx
    have hc := varint.lenOf_char _ _ hlc
    have hle : varint.lenOf self.val ≤ vec.val.length := by scalar_tac
    obtain ⟨⟨l, hl, _⟩, _⟩ := hwr.2 hv hle
    intro hb
    rw [hl] at hb
    simp only [tryCF, reduceCtorEq] at hb

/-- `TlsVarInt::tls_serialize_bytes` never panics: a value at most `MAX` gives `lenOf` bytes, a
larger one an error. -/
theorem varint.TlsVarInt.serialize_len_char (self : varint.TlsVarInt) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.Insts.Tls_codecSerializeBytes.tls_serialize_bytes self
    ⦃ ⇓ r => ⌜ (self.val ≤ 2 ^ 62 - 1 → ∃ v : alloc.vec.Vec Std.U8, r = .Ok v ∧
        (v : Slice Std.U8).val.length = varint.lenOf self.val) ∧
        (2 ^ 62 - 1 < self.val → ∃ e, r = .Err e) ⌝ ⦄ := by
  by_cases hv : self.val ≤ 2 ^ 62 - 1
  · refine triple_post_mono (varint.TlsVarInt.serialize_len_char_le self hv) ?_
    exact fun r h => ⟨fun _ => h, fun h' => absurd hv (by omega)⟩
  · mvcgen [varint.TlsVarInt.Insts.Tls_codecSerializeBytes.tls_serialize_bytes,
      varint.TlsVarInt.bytes_len_spec, alloc.vec.from_elem_U8_len_spec,
      varint.TlsVarInt.write_bytes_spec, alloc.vec.Vec.Insts.CoreOpsDerefDerefMutSlice.deref_mut,
      alloc.vec.Vec.as_mut_slice, rust_primitives.sequence.seq_to_slice_mut]
    · rename_i _ hwr _ _ _ _ hcf
      exfalso
      rw [hwr.1 (Or.inl (by omega))] at hcf
      simp [tryCF] at hcf
    · rename_i _ hwr _ _ _
      apply try_break_vc
      intro e he
      mvcgen [core.convert.From.Blanket.from_spec]
      simp [PostCond.ok, hv]
      intro _; omega

/-- The trait-level post of `TlsVarInt::tls_serialize_bytes` on an `Ok` output for a value at most
`MAX`: `lenOf` bytes. -/
theorem varint.TlsVarInt.serialize_post_le (self : varint.TlsVarInt) (v : alloc.vec.Vec Std.U8)
    (hle : self.val ≤ 2 ^ 62 - 1) (hv : (v : Slice Std.U8).val.length = varint.lenOf self.val) :
    (varint.TlsVarInt.Insts.Tls_codecSerializeBytes.tls_serialize_bytes.post self
      (core.result.Result.Ok v)).holds := by
  simp only [varint.TlsVarInt.Insts.Tls_codecSerializeBytes.tls_serialize_bytes.post]
  mvcgen [core.result.Result.is_ok_and_spec,
    varint.SerializeBytesTlsVarInt.tls_serialize_bytes._.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.call_once,
    varint.TlsVarInt.Insts.Tls_codecSize.tls_serialized_len, varint.TlsVarInt.bytes_len_spec]
  · rename_i _ _ _ t hok _ hbl _ hll hc1 _ hc2
    rw [core.result.Result.Ok.injEq] at hok
    subst hok
    have h1 := varint.lenOf_char _ _ hc1
    have h2 := varint.lenOf_char _ _ hc2
    simp only [decide_eq_true_eq]
    apply UScalar.eq_of_val_eq
    subst_vars
    simp only [Slice.len_val]
    scalar_tac
  · rename_i _ _ _ t hok _ hbl _ hne hc2
    rw [core.result.Result.Ok.injEq] at hok
    subst hok
    have h2 := varint.lenOf_char _ _ hc2
    exfalso
    apply hne
    apply UScalar.eq_of_val_eq
    subst_vars
    simp only [Slice.len_val]
    scalar_tac
  · exfalso; scalar_tac

/-- The post on an `Err` output, for a value above `MAX`. -/
theorem varint.TlsVarInt.serialize_post_gt (self : varint.TlsVarInt) (e : Error)
    (hgt : 2 ^ 62 - 1 < self.val) :
    (varint.TlsVarInt.Insts.Tls_codecSerializeBytes.tls_serialize_bytes.post self
      (core.result.Result.Err e)).holds := by
  simp only [varint.TlsVarInt.Insts.Tls_codecSerializeBytes.tls_serialize_bytes.post]
  mvcgen [core.result.Result.is_err_spec]
  intro _; exfalso; scalar_tac

/-- `saturating_add` does not saturate for small operands. -/
theorem Usize_saturating_add_val (x y : Std.Usize) (h : x.val + y.val < 2 ^ 32) :
    (UScalar.saturating_add x y).val = x.val + y.val := by
  have hm : x.val + y.val ≤ UScalar.max UScalarTy.Usize := by
    rcases System.Platform.numBits_eq with h' | h' <;>
      simp [UScalar.max, UScalarTy.numBits, h'] <;> omega
  have hlt : x.val + y.val < 2 ^ System.Platform.numBits := by
    rcases System.Platform.numBits_eq with h' | h' <;> rw [h'] <;> omega
  unfold UScalar.saturating_add
  rw [min_eq_right hm]
  unfold UScalar.val
  simp only [BitVec.toNat_ofNat]
  exact Nat.mod_eq_of_lt hlt

end tls_codec
