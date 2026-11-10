/- Serializers with a varint length prefix (`Vec::extend`, `String`).

Obligations: none directly; the bytes-path halves of `PanicFreedom.lean` /
`FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): ASSUMED
`alloc.string.FromUtf8Error.Insts.CoreFmtDisplay.fmt.ok_spec`, `size_of`, `size_of_U8`,
`size_of_Usize`, `numBits_eq_64`; 1 signature-only stub
(`alloc.string.FromUtf8Error.Insts.CoreFmtDisplay.fmt`). -/
import TlsCodec.Verification.Helpers.VarIntDe
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! ### Serializers with a varint length prefix (`Vec::extend`, `String`)

Only lengths are tracked: the contents of the varint prefix are not (see `write_bytes_spec`). -/

/-- `checked_alloc_len` of two small lengths is their sum. -/
theorem checked_alloc_len_small (a b : Std.Usize) (h : a.val + b.val < 2 ^ 31) :
    ⦃ ⌜ True ⌝ ⦄ checked_alloc_len a b
    ⦃ ⇓ r => ⌜ ∃ n : Std.Usize, r = .Ok n ∧ n.val = a.val + b.val ⌝ ⦄ := by
  have hm := Usize.hcast_Isize_MAX_val
  have hs := Usize_saturating_add_val a b (by omega)
  mvcgen [checked_alloc_len, checked_capacity, CoreModels.core.num.Usize.saturating_add_spec]
  · rename_i sat hsat hgt
    subst hsat
    exfalso; scalar_tac
  · rename_i sat hsat hle
    subst hsat
    exact ⟨_, rfl, hs⟩

/-- `Vec::<u8>::resize` sets the length. -/
theorem alloc.vec.Vec.resize_U8_len_spec (v : alloc.vec.Vec Std.U8) (n : Std.Usize) (x : Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.resize core.U8.Insts.CoreCloneClone v n x
    ⦃ ⇓ r => ⌜ (r : Slice Std.U8).val.length = n.val ⌝ ⦄ := by
  unfold alloc.vec.Vec.resize rust_primitives.sequence.seq_create
  simp only [mapM_clone_replicate_U8]
  mvcgen
  all_goals (simp_all +zetaDelta [Slice.new] <;> scalar_tac)

/-- `VLBytes::tls_serialize_bytes` never panics: a payload of at most `2^30 - 1` bytes gives the
varint length prefix followed by the payload (only the length is tracked), a longer one an error. -/
theorem quic_vec.VLBytes.serialize_char (self : quic_vec.VLBytes) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLBytes.Insts.Tls_codecSerializeBytes.tls_serialize_bytes self
    ⦃ ⇓ r => ⌜ (self.vec.val.length ≤ 2 ^ 30 - 1 → ∃ out : alloc.vec.Vec Std.U8, r = .Ok out ∧
                  out.val.length = self.vec.val.length + varint.lenOf self.vec.val.length) ∧
               (2 ^ 30 - 1 < self.vec.val.length → ∃ e, r = .Err e) ⌝ ⦄ := by
  mvcgen [quic_vec.VLBytes.Insts.Tls_codecSerializeBytes.tls_serialize_bytes,
    quic_vec.VLBytes.as_slice, quic_vec.VLBytes.impl.vec, alloc.vec.Vec.with_capacity,
    alloc.vec.Vec.resize_U8_len_spec, checked_alloc_len_small,
    alloc.vec.Vec.Insts.CoreOpsDerefDerefMutSlice.deref_mut, alloc.vec.Vec.as_mut_slice,
    rust_primitives.sequence.seq_to_slice_mut, varint.TlsVarInt.write_bytes_spec,
    alloc.vec.Vec.Insts.CoreIterTraitsCollectExtendSharedAT.extend_slice_spec]
  all_goals (try simp only [continue_eq_tryCF] at *)
  all_goals subst_vars
  all_goals (try simp only [Slice.len_val] at *)
  · -- `checked_alloc_len` gets small operands
    rename_i hr hv
    have := hr.2.1
    omega
  · -- room for the payload
    rename_i val r hr _ res hres back w hw _ out2 _ hv _
    have hc := varint.lenOf_char _ _ hr
    have hl := (hw.2 (by omega) (by omega)).2
    show w.2.val.length + _ ≤ _
    have : Slice.length self.vec ≤ 2 ^ 30 - 1 := hv.2
    scalar_tac
  · -- the length check passes
    rename_i val r hr _ res hres back w hw _ out2 out3 i hw1 hout3 hne hv _ hi _
    have hc := varint.lenOf_char _ _ hr
    have hl := (hw.2 (by omega) (by omega)).2
    have h3 : Slice.length out3 = w.2.val.length + Slice.length self.vec := by
      simp only [Slice.length, hout3, List.length_append]; rfl
    exfalso
    simp only [bne_iff_ne, ne_eq] at hne
    exact hne (by scalar_tac)
  · rename_i val r hr _ res hres back w hw _ out2 out3 i hw1 hout3 hne hv _ hi _
    have hc := varint.lenOf_char _ _ hr
    have hl := (hw.2 (by omega) (by omega)).2
    have hv2 : self.vec.val.length ≤ 2 ^ 30 - 1 := hv.2
    refine ⟨fun _ => ⟨out3, rfl, ?_⟩, fun h => by omega⟩
    rw [hout3, List.length_append]
    show w.2.val.length + _ = _
    have : val.val = self.vec.val.length := hv.1
    scalar_tac
  · rename_i val r hr _ res hres back w hw _ out2 out3 hw1 hout3 hv _ hlt
    have hc := varint.lenOf_char _ _ hr
    have hl := (hw.2 (by omega) (by omega)).2
    have h3 : Slice.length out3 = w.2.val.length + Slice.length self.vec := by
      simp only [Slice.length, hout3, List.length_append]; rfl
    exfalso; scalar_tac
  · -- `write_bytes` succeeds
    rename_i val r hr _ res hres back w hw resid hv _
    have hc := varint.lenOf_char _ _ hr
    obtain ⟨⟨l, hl, _⟩, _⟩ := hw.2 (by omega) (by omega)
    intro hb
    rw [hl] at hb
    simp only [tryCF, reduceCtorEq] at hb
  · -- `checked_alloc_len` succeeds
    rename_i r resid hn _
    obtain ⟨n, rfl, _⟩ := hn
    intro hb
    simp only [tryCF, reduceCtorEq] at hb
  · -- `from_usize` fails: the payload is too long
    rename_i r resid hr
    apply try_break_vc
    intro e he
    subst he
    have hr' : 2 ^ 30 - 1 < self.vec.val.length := hr
    mvcgen
    intro _
    exact ⟨fun h => absurd h (by omega), fun _ => ⟨_, rfl⟩⟩

/-- `VLByteSlice::tls_serialize_bytes` never panics: a payload of at most `2^30 - 1` bytes gives the
varint length prefix followed by the payload (only the length is tracked), a longer one an error. -/
theorem quic_vec.VLByteSlice.serialize_char (self : quic_vec.VLByteSlice) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLByteSlice.Insts.Tls_codecSerializeBytes.tls_serialize_bytes self
    ⦃ ⇓ r => ⌜ (self.val.length ≤ 2 ^ 30 - 1 → ∃ out : alloc.vec.Vec Std.U8, r = .Ok out ∧
                  out.val.length = self.val.length + varint.lenOf self.val.length) ∧
               (2 ^ 30 - 1 < self.val.length → ∃ e, r = .Err e) ⌝ ⦄ := by
  mvcgen [quic_vec.VLByteSlice.Insts.Tls_codecSerializeBytes.tls_serialize_bytes,
    quic_vec.ContentLength.Insts.Tls_codecSize.tls_serialized_len,
    varint.TlsVarInt.Insts.Tls_codecSize.tls_serialized_len,
    quic_vec.ContentLength.Insts.Tls_codecSerializeBytes.tls_serialize_bytes,
    varint.TlsVarInt.serialize_len_char, alloc.vec.Vec.with_capacity, checked_alloc_len_small,
    alloc.vec.Vec.append, rust_primitives.sequence.seq_concat,
    alloc.vec.Vec.Insts.CoreIterTraitsCollectExtendSharedAT.extend_slice_spec]
  all_goals (try simp only [continue_eq_tryCF] at *)
  all_goals subst_vars
  all_goals (try simp only [Slice.len_val] at *)
  · rename_i hr hv
    have := hr.2.1
    omega
  · -- room for the payload after the prefix
    rename_i val r hr _ v1 comb hcomb hv1 hv _
    obtain ⟨v, hv', hl⟩ := hv1.1 (by omega)
    cases hv'
    have hv2 : self.val.length ≤ 2 ^ 30 - 1 := hv.2
    have hlo : varint.lenOf val.val ≤ 8 := by unfold varint.lenOf; split_ifs <;> omega
    simp only [comb, List.length_append, hl]
    simp only [Slice.new, List.length_nil]
    scalar_tac
  · rename_i val r hr _ v1 out comb hcomb hout hv1 hv _
    obtain ⟨v, hv', hl⟩ := hv1.1 (by omega)
    cases hv'
    have hv2 : self.val.length ≤ 2 ^ 30 - 1 := hv.2
    have hvl : val.val = self.val.length := hv.1
    refine ⟨fun _ => ⟨out, rfl, ?_⟩, fun h => by omega⟩
    simp only [hout, comb, List.length_append, hl, hvl]
    simp only [Slice.new, List.length_nil]
    omega
  · rename_i val r hr _ v1 comb hcomb hv1 hv _
    obtain ⟨v, hv', hl⟩ := hv1.1 (by omega)
    cases hv'
    have hv2 : self.val.length ≤ 2 ^ 30 - 1 := hv.2
    have hlo : varint.lenOf val.val ≤ 8 := by unfold varint.lenOf; split_ifs <;> omega
    exfalso; apply hcomb
    simp only [comb, List.length_append, hl]
    simp only [Slice.new, List.length_nil]
    scalar_tac
  · -- the prefix serializes
    rename_i val r hr _ x hx resid hv _
    obtain ⟨v, rfl, _⟩ := hx.1 (by omega)
    intro hb
    simp only [tryCF, reduceCtorEq] at hb
  · -- `checked_alloc_len` succeeds
    rename_i r resid hn _
    obtain ⟨n, rfl, _⟩ := hn
    intro hb
    simp only [tryCF, reduceCtorEq] at hb
  · -- `from_usize` fails: the payload is too long
    rename_i r resid hr
    apply try_break_vc
    intro e he
    subst he
    have hr' : 2 ^ 30 - 1 < self.val.length := hr
    mvcgen
    intro _
    exact ⟨fun h => absurd h (by omega), fun _ => ⟨_, rfl⟩⟩

/-- The fold of `<&[u8]>::tls_serialized_len` counts the bytes (each `u8` has size 1). -/
theorem Shared0Slice.size_fold_U8_spec (it : core.slice.iter.Iter Std.U8) (acc : Std.Usize)
    (h : acc.val + (it : Slice Std.U8).val.length ≤ Usize.max) :
    ⦃ ⌜ True ⌝ ⦄
    core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.fold
      (quic_vec.SizeShared0Slice.tls_serialized_len.closure.Insts.CoreOpsFunctionFnMutPairUsizeSharedTUsize
        U8.Insts.Tls_codecSize) it acc ()
    ⦃ ⇓ r => ⌜ r.val = acc.val + (it : Slice Std.U8).val.length ⌝ ⦄ := by
  simp only [core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.fold,
    core.iter.traits.iterator.Iterator.fold.default, core.iter.traits.iterator.iter_fold,
    core.iter.traits.iterator.iter_fold_loop]
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.loop.spec_decr_nat
    (fun p : core.slice.iter.Iter Std.U8 × quic_vec.SizeShared0Slice.tls_serialized_len.closure Std.U8
        × Std.Usize => (p.1 : Slice Std.U8).val.length)
    (fun p => p.2.2.val + (p.1 : Slice Std.U8).val.length = acc.val + (it : Slice Std.U8).val.length)
  · rintro ⟨it', c, a⟩ hinv
    simp only [core.iter.traits.iterator.iter_fold_loop.body,
      core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.next,
      rust_primitives.sequence.seq_len, rust_primitives.sequence.seq_remove,
      quic_vec.SizeShared0Slice.tls_serialized_len.closure.Insts.CoreOpsFunctionFnMutPairUsizeSharedTUsize.call_mut,
      U8.Insts.Tls_codecSize.tls_serialized_len, len_add_ok] at hinv ⊢
    by_cases hz : Slice.len it' = 0#usize
    · have : (it' : Slice Std.U8).val = [] := by
        rw [← List.length_eq_zero_iff]; scalar_tac
      simp_all
    · have hpos : 0 < (it' : Slice Std.U8).val.length := by scalar_tac
      have hadd := UScalar.add_equiv a 1#usize
      split at hadd
      · rename_i z hz'
        obtain ⟨_, hzv, _⟩ := hadd
        simp [hz, hpos, hz']
        have := lenAddVal_val a 1#usize (by scalar_tac)
        scalar_tac
      · exfalso
        obtain ⟨_, hnb⟩ := hadd
        apply hnb
        simp only [UScalar.inBounds]
        scalar_tac
      · cases hadd
  · rfl

/-- `Result::map` with the length closure of `<&[T]>::tls_serialized_len`: an `Ok` content length
is mapped to `Ok` of its varint length, an `Err` is passed through. -/
theorem Shared0Slice.size_closure_map_spec {T : Type} (SizeInst : Size T)
    (x : core.result.Result quic_vec.ContentLength Error) :
    ⦃ ⌜ True ⌝ ⦄
    core.result.Result.map
      (quic_vec.SizeShared0Slice.tls_serialized_len.closure_1.Insts.CoreOpsFunctionFnOnceTupleContentLengthUsize
        SizeInst) x ()
    ⦃ ⇓ r => ⌜ (∀ t, x = .Ok t → ∃ u, r = .Ok u ∧ u.val = varint.lenOf t.val) ∧
               (∀ e, x = .Err e → r = .Err e) ⌝ ⦄ := by
  apply CoreModels.core.result.Result.map_spec
  · intro t ht
    mvcgen [quic_vec.SizeShared0Slice.tls_serialized_len.closure_1.Insts.CoreOpsFunctionFnOnceTupleContentLengthUsize.call_once]
    intro h1 h2 h3 h4 h5 h6
    subst ht
    refine ⟨fun t' h => ?_, fun e h => ?_⟩
    · obtain rfl := core.result.Result.Ok.inj h
      exact ⟨_, rfl, (varint.lenOf_char _ _ ⟨h1, h2, h3, h4, h5, h6⟩).1⟩
    · cases h
  · intro e he; subst he; simp [PostCond.ok]

/-- `<&[u8]>::tls_serialized_len` never panics: the length plus its varint prefix length (no prefix
counted above the `2^30 - 1` bound, where `ContentLength::from_usize` fails). -/
theorem Shared0Slice.size_U8_char (s : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ Shared0Slice.Insts.Tls_codecSize.tls_serialized_len U8.Insts.Tls_codecSize s
    ⦃ ⇓ r => ⌜ r.val = s.val.length +
        (if s.val.length ≤ 2 ^ 30 - 1 then varint.lenOf s.val.length else 0) ⌝ ⦄ := by
  have hs := s.property
  mvcgen [Shared0Slice.Insts.Tls_codecSize.tls_serialized_len, Shared0Slice.size_fold_U8_spec,
    Shared0Slice.size_closure_map_spec, len_add_triple]
  · subst_vars; scalar_tac
  · rename_i it hit n hn rc hrc rm hrm l hl sum
    intro hsum
    subst hit
    cases rc with
    | Ok c =>
      obtain ⟨u, rfl, hul⟩ := hrm.1 c rfl
      simp only at hl hrc
      subst hl
      have hle : varint.lenOf c.val ≤ 8 := by unfold varint.lenOf; split_ifs <;> omega
      have hsv := lenAddVal_val n l (by scalar_tac)
      rw [if_pos (by scalar_tac)]
      have hc : c.val = it.val.length := by scalar_tac
      rw [hsum, hsv, hul, hc]
      scalar_tac
    | Err e =>
      obtain rfl := hrm.2 e rfl
      simp only at hl hrc
      subst hl
      have hsv := lenAddVal_val n 0#usize (by scalar_tac)
      rw [if_neg (by scalar_tac)]
      rw [hsum]
      scalar_tac

/-- `String::tls_deserialize_bytes` never panics; on success the bytes of the string are the payload
that `VLByteVec::tls_deserialize_bytes` reads from the same input, with the same remainder. -/
theorem alloc.string.String.deserialize_char (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ alloc.string.String.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ t rem, r = .Ok (t, rem) → ∃ raw : quic_vec.VLByteVec,
        quic_vec.VLByteVec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes = ok (.Ok (raw, rem)) ∧
        alloc.string.String.utf8U8 t = raw.vec.val ⌝ ⦄ := by
  obtain ⟨r0, hr0, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (quic_vec.VLByteVec.deserialize_char bytes)
  unfold alloc.string.String.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
  rw [hr0]
  mvcgen [core.result.Result.map_err_spec, alloc.vec.VecU8.Insts.CoreConvertFromVLByteVec.from,
    string.DeserializeBytesString.tls_deserialize_bytes.closure.Insts.CoreOpsFunctionFnOnceTupleFromUtf8ErrorError.call_once]
  try_vcs
  · rename_i p _ hp r1 hr1 t1 ht1 _ v _ hv
    simp only [continue_eq_tryCF, core.result.Result.Ok.injEq] at hp hv
    subst hv ht1
    intro t rem h
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj (core.result.Result.Ok.inj h)
    obtain ⟨t', ht', hu⟩ | ⟨h1, _⟩ := hr1
    · cases ht'
      exact ⟨p.1, by rw [hp], hu⟩
    · cases h1
  · simp only [PostCond.ok]
    mvcgen
    try_vcs
    intro _ t rem h
    cases h
  · intro _ t rem h
    cases h

/-- `usize::try_from(u8)` through the blanket `TryFrom` impl for `Into` (`Error = Infallible`):
`Ok` of the widening cast. -/
@[spec]
theorem core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U8_spec (x : Std.U8) :
    ⦃ ⌜ True ⌝ ⦄
    core.convert.TryFromTUInfallible.Blanket.try_from
      (core.convert.Into.Blanket core.Usize.Insts.CoreConvertFromU8) x
    ⦃ ⇓ r => ⌜ r = .Ok (UScalar.cast .Usize x) ⌝ ⦄ := by
  unfold core.convert.TryFromTUInfallible.Blanket.try_from core.convert.Into.Blanket
  mvcgen [core.convert.Into.Blanket.into, CoreModels.core.Usize.Insts.CoreConvertFromU8.from_spec]
  subst_vars; rfl

/-- `Result::unwrap` of a value that is `Ok` (the `Err` case panics, so it is excluded by
hypothesis; used for `Result<_, Infallible>`). -/
@[spec]
theorem core.result.Result.unwrap_ok_spec {T E : Type} (fmtDebugInst : core.fmt.Debug E)
    (x : core.result.Result T E) (h : ∃ t, x = .Ok t) :
    ⦃ ⌜ True ⌝ ⦄ core.result.Result.unwrap fmtDebugInst x ⦃ ⇓ r => ⌜ x = .Ok r ⌝ ⦄ := by
  obtain ⟨t, rfl⟩ := h
  unfold core.result.Result.unwrap
  mvcgen

/-- `usize::checked_add`: `Some (x + y)` exactly when the sum does not overflow. -/
@[spec]
theorem core.num.Usize.checked_add_spec (x y : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ core.num.Usize.checked_add x y
    ⦃ ⇓ r => ⌜ (x.val + y.val ≤ Std.Usize.max → ∃ z : Std.Usize, r = some z ∧ z.val = x.val + y.val) ∧
               (Std.Usize.max < x.val + y.val → r = none) ⌝ ⦄ := by
  mvcgen [core.num.Usize.checked_add, core.num.Usize.overflowing_add]
  · rename_i hov
    have h := UScalar.overflowing_add_eq x y
    simp only [hov] at h
    by_cases hc : x.val + y.val > UScalar.max .Usize
    · simp only [if_pos hc] at h
      refine ⟨fun hle => ?_, fun _ => trivial⟩
      scalar_tac
    · simp only [if_neg hc] at h
      exact absurd h.2 (by simp)
  · rename_i hov
    have h := UScalar.overflowing_add_eq x y
    simp only [Bool.not_eq_true] at hov
    simp only [hov] at h
    by_cases hc : x.val + y.val > UScalar.max .Usize
    · simp only [if_pos hc] at h
      exact absurd h.2 (by simp)
    · simp only [if_neg hc] at h
      refine ⟨fun _ => ⟨_, rfl, by scalar_tac⟩, fun hlt => ?_⟩
      scalar_tac

/-- `s.get(start..end)`: if it returns `Some t`, the range is in bounds and `t` has `end - start`
elements. -/
@[spec]
theorem core.ops.range.RangeUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get_some_spec
    {T : Type} (r : core.ops.range.Range Std.Usize) (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ core.ops.range.RangeUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get r s
    ⦃ ⇓ o => ⌜ ∀ t, o = some t → r.start.val ≤ r.end.val ∧ r.end.val ≤ s.val.length ∧
        t.val.length = r.end.val - r.start.val ⌝ ⦄ := by
  unfold core.ops.range.RangeUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get
    rust_primitives.slice.slice_length rust_primitives.slice.slice_slice Slice.subslice
  mvcgen
  · rename_i h1 h2 h3
    have hl : (s.len).val = s.val.length := by simp
    intro t ht
    have ht' := Option.some.inj ht
    subst ht'
    refine ⟨h3.1, h3.2, ?_⟩
    have h4 : r.end.val ≤ s.val.length := h3.2
    have h5 : r.start.val ≤ r.end.val := h3.1
    simp [List.slice]
    omega
  · rename_i h1 h2 h3
    exfalso; apply h3
    have hl : (s.len).val = s.val.length := by simp
    exact ⟨by scalar_tac, by scalar_tac⟩
  · intro t ht; cases ht
  · intro t ht; cases ht

/-- `usize::from(u16)`. -/
@[spec]
theorem core.Usize.Insts.CoreConvertFromU16.from_spec (x : Std.U16) :
    ⦃ ⌜ True ⌝ ⦄ core.Usize.Insts.CoreConvertFromU16.from x
    ⦃ ⇓ r => ⌜ r = UScalar.cast .Usize x ⌝ ⦄ := by
  unfold core.Usize.Insts.CoreConvertFromU16.from; mvcgen

/-- `usize::try_from(u16)` through the blanket `TryFrom` impl for `Into` (`Error = Infallible`). -/
@[spec]
theorem core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U16_spec (x : Std.U16) :
    ⦃ ⌜ True ⌝ ⦄
    core.convert.TryFromTUInfallible.Blanket.try_from
      (core.convert.Into.Blanket core.Usize.Insts.CoreConvertFromU16) x
    ⦃ ⇓ r => ⌜ r = .Ok (UScalar.cast .Usize x) ⌝ ⦄ := by
  unfold core.convert.TryFromTUInfallible.Blanket.try_from core.convert.Into.Blanket
  mvcgen [core.convert.Into.Blanket.into, core.Usize.Insts.CoreConvertFromU16.from_spec]
  subst_vars; rfl

/-- `usize::try_from(u32)`: always `Ok` of the widening cast (`usize` is at least 32 bits). -/
@[spec]
theorem core.Usize.Insts.CoreConvertTryFromU32TryFromIntError.try_from_spec (x : Std.U32) :
    ⦃ ⌜ True ⌝ ⦄ core.Usize.Insts.CoreConvertTryFromU32TryFromIntError.try_from x
    ⦃ ⇓ r => ⌜ r = .Ok (UScalar.cast .Usize x) ⌝ ⦄ := by
  unfold core.Usize.Insts.CoreConvertTryFromU32TryFromIntError.try_from; mvcgen
  subst_vars; rfl

/-- `TlsByteVecU8::tls_serialized_len` is the payload length plus the one-byte length prefix (when
that does not overflow `usize`). -/
theorem tls_vec.TlsByteVecU8.serialized_len_char (self : tls_vec.TlsByteVecU8)
    (h : self.vec.val.length + 1 ≤ Std.Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU8.Insts.Tls_codecSize.tls_serialized_len self
    ⦃ ⇓ r => ⌜ r.val = self.vec.val.length + 1 ⌝ ⦄ := by
  mvcgen [tls_vec.TlsByteVecU8.Insts.Tls_codecSize.tls_serialized_len,
    tls_vec.TlsByteVecU8.tls_serialized_byte_length, tls_vec.TlsByteVecU8.as_slice,
    CoreModels.core.slice.Slice.len_spec]
  rename_i s hs n hn r
  intro hr
  subst hs; subst hn
  have e := lenAddVal_val (Slice.len self.vec) 1#usize (by scalar_tac)
  subst hr
  scalar_tac

/-- `TlsByteVecU16::tls_serialized_len` is the payload length plus the 2-byte length prefix (when
that does not overflow `usize`). -/
theorem tls_vec.TlsByteVecU16.serialized_len_char (self : tls_vec.TlsByteVecU16)
    (h : self.vec.val.length + 2 ≤ Std.Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU16.Insts.Tls_codecSize.tls_serialized_len self
    ⦃ ⇓ r => ⌜ r.val = self.vec.val.length + 2 ⌝ ⦄ := by
  mvcgen [tls_vec.TlsByteVecU16.Insts.Tls_codecSize.tls_serialized_len,
    tls_vec.TlsByteVecU16.tls_serialized_byte_length, tls_vec.TlsByteVecU16.as_slice,
    CoreModels.core.slice.Slice.len_spec]
  rename_i s hs n hn r
  intro hr
  subst hs; subst hn
  have e := lenAddVal_val (Slice.len self.vec) 2#usize (by scalar_tac)
  subst hr
  scalar_tac

/-- `TlsByteVecU24::tls_serialized_len` is the payload length plus the 3-byte length prefix (when
that does not overflow `usize`). -/
theorem tls_vec.TlsByteVecU24.serialized_len_char (self : tls_vec.TlsByteVecU24)
    (h : self.vec.val.length + 3 ≤ Std.Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU24.Insts.Tls_codecSize.tls_serialized_len self
    ⦃ ⇓ r => ⌜ r.val = self.vec.val.length + 3 ⌝ ⦄ := by
  mvcgen [tls_vec.TlsByteVecU24.Insts.Tls_codecSize.tls_serialized_len,
    tls_vec.TlsByteVecU24.tls_serialized_byte_length, tls_vec.TlsByteVecU24.as_slice,
    CoreModels.core.slice.Slice.len_spec]
  rename_i s hs n hn r
  intro hr
  subst hs; subst hn
  have e := lenAddVal_val (Slice.len self.vec) 3#usize (by scalar_tac)
  subst hr
  scalar_tac

/-- `TlsByteVecU32::tls_serialized_len` is the payload length plus the 4-byte length prefix (when
that does not overflow `usize`). -/
theorem tls_vec.TlsByteVecU32.serialized_len_char (self : tls_vec.TlsByteVecU32)
    (h : self.vec.val.length + 4 ≤ Std.Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU32.Insts.Tls_codecSize.tls_serialized_len self
    ⦃ ⇓ r => ⌜ r.val = self.vec.val.length + 4 ⌝ ⦄ := by
  mvcgen [tls_vec.TlsByteVecU32.Insts.Tls_codecSize.tls_serialized_len,
    tls_vec.TlsByteVecU32.tls_serialized_byte_length, tls_vec.TlsByteVecU32.as_slice,
    CoreModels.core.slice.Slice.len_spec]
  rename_i s hs n hn r
  intro hr
  subst hs; subst hn
  have e := lenAddVal_val (Slice.len self.vec) 4#usize (by scalar_tac)
  subst hr
  scalar_tac

/-- `usize::from(U24)` does not panic (64-bit `usize`, `numBits_eq_64`). -/
theorem Usize.Insts.CoreConvertFromU24.from_pf (value : U24) :
    ⦃ ⌜ True ⌝ ⦄ Usize.Insts.CoreConvertFromU24.from value ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  have := numBits_eq_64
  mvcgen [Usize.Insts.CoreConvertFromU24.from, FromUsizeU24.from.LEN,
    core.mem.size_of_Usize_spec, core.Array.Insts.CoreOpsIndexIndexMut.index_mut,
    core.array.Array.as_mut_slice, rust_primitives.slice.array_as_mut_slice,
    core.slice.Slice.copy_from_slice_U8_total, core.num.Usize.from_be_bytes,
    rust_primitives.arithmetic.from_be_bytes_usize]
  · rename_i bytes0 n hn i1 hi1 hle
    have : (Std.Array.to_slice_mut bytes0).1.length = 8 := by
      simp [Std.Array.to_slice_mut, Std.Array.to_slice, bytes0]
    scalar_tac
  · rename_i bytes0 n hn i1 hi1 hle p back hp
    obtain ⟨hp1, _⟩ := hp
    have hl2 : (Std.Array.to_slice value).val.length = 3 := by simp [Std.Array.to_slice]
    have hl1 : p.1.val.length = 8 - i1.val := by
      rw [hp1]; simp [Std.Array.to_slice_mut, Std.Array.to_slice, bytes0]
    rw [hl1, hl2]
    scalar_tac
  all_goals (exfalso; scalar_tac)

/-- `usize::from(U24)`, when it returns: the big-endian value of the three bytes (partial form, see `Usize.Insts.CoreConvertFromU24.from_char`). -/
theorem Usize.Insts.CoreConvertFromU24.from_content (value : U24) :
    ⦃ ⌜ True ⌝ ⦄ Usize.Insts.CoreConvertFromU24.from value
    ⦃ ⇓? r => ⌜ ∀ b0 b1 b2 : Std.U8, value.val = [b0, b1, b2] →
        r.val = b0.val * 65536 + b1.val * 256 + b2.val ⌝ ⦄ := by
  mvcgen [Usize.Insts.CoreConvertFromU24.from, FromUsizeU24.from.LEN,
    core.mem.size_of_Usize_spec, core.Array.Insts.CoreOpsIndexIndexMut.index_mut,
    core.array.Array.as_mut_slice, rust_primitives.slice.array_as_mut_slice,
    core.slice.Slice.copy_from_slice_U8_spec, core.num.Usize.from_be_bytes,
    rust_primitives.arithmetic.from_be_bytes_usize]
  · rename_i bytes0 n hn i1 hi1 hle
    have hnb := System.Platform.numBits_eq
    have : (Std.Array.to_slice_mut bytes0).1.length = 8 := by
      simp [Std.Array.to_slice_mut, Std.Array.to_slice, bytes0]
    scalar_tac
  · rename_i bytes0 n hn i1 hi1 hle p back hp s2 bytes1 hc
    have hnb := System.Platform.numBits_eq
    obtain ⟨hp1, hp2⟩ := hp
    obtain ⟨hlen, hs2⟩ := hc
    obtain ⟨vl, hvl⟩ := value
    obtain ⟨b0, b1, b2, rfl⟩ := List.length_eq_three.mp (by simpa using hvl)
    have hb0 : bytes0.val = List.replicate 8 0#u8 := rfl
    have hl1 : p.1.val.length = 8 - i1.val := by
      rw [hp1]; simp [Std.Array.to_slice_mut, Std.Array.to_slice, hb0]
    have hl2 : (Std.Array.to_slice (⟨[b0, b1, b2], hvl⟩ : U24)).val.length = 3 := by
      simp [Std.Array.to_slice]
    have hi5 : i1.val = 5 := by
      rw [hl1, hl2] at hlen
      omega
    have hn8 : n.val = 8 := by scalar_tac
    have hnb64 : System.Platform.numBits = 64 := by omega
    have hbytes1 : bytes1.val = [0#u8, 0#u8, 0#u8, 0#u8, 0#u8, b0, b1, b2] := by
      have e2 : (Std.Array.to_slice_mut bytes0).1.val = bytes0.val := rfl
      have e3 : (p.2 s2).val.length = 8 := by
        rw [hp2 s2, List.length_setSlice!, e2, hb0]; simp
      have e1 : bytes1.val = (p.2 s2).val :=
        Std.Array.from_slice_val bytes0 (p.2 s2) (by rw [e3]; rfl)
      rw [e1, hp2 s2, hs2, hi5, e2, hb0]
      simp [Std.Array.to_slice]
      rfl
    rw [hbytes1]
    intro c0 c1 c2 hc012
    have hv := usize_from_zero5_val b0 b1 b2 hnb64
    have h3 : [b0, b1, b2] = [c0, c1, c2] := hc012
    simp only [List.cons.injEq, and_true] at h3
    obtain ⟨rfl, rfl, rfl⟩ := h3
    exact hv

/-- A list of length 8 is a literal list. -/
theorem list_eq_eight {α : Type} (l : List α) (h : l.length = 8) :
    ∃ a0 a1 a2 a3 a4 a5 a6 a7, l = [a0, a1, a2, a3, a4, a5, a6, a7] := by
  match l, h with
  | [a0, a1, a2, a3, a4, a5, a6, a7], _ => exact ⟨_, _, _, _, _, _, _, _, rfl⟩

/-- Value of eight big-endian bytes. -/
theorem fromBEBytes_eight_toNat (b0 b1 b2 b3 b4 b5 b6 b7 : BitVec 8) :
    (BitVec.fromBEBytes [b0, b1, b2, b3, b4, b5, b6, b7]).toNat =
      b0.toNat * 72057594037927936 + b1.toNat * 281474976710656 + b2.toNat * 1099511627776 +
      b3.toNat * 4294967296 + b4.toNat * 16777216 + b5.toNat * 65536 + b6.toNat * 256 +
      b7.toNat := by
  unfold BitVec.fromBEBytes
  rw [BitVec.toNat_cast, fromLEBytes_toNat]
  simp [List.foldr]
  omega

/-- Arithmetic of the eight big-endian bytes of a value below `2^24`. -/
theorem eight_bytes_low3 (x0 x1 x2 x3 x4 x5 x6 x7 v : Nat)
    (h0 : x0 < 2 ^ 8) (h1 : x1 < 2 ^ 8) (h2 : x2 < 2 ^ 8) (h3 : x3 < 2 ^ 8) (h4 : x4 < 2 ^ 8)
    (h5 : x5 < 2 ^ 8) (h6 : x6 < 2 ^ 8) (h7 : x7 < 2 ^ 8) (hv : v ≤ 16777215)
    (h : v = x0 * 72057594037927936 + x1 * 281474976710656 + x2 * 1099511627776 +
      x3 * 4294967296 + x4 * 16777216 + x5 * 65536 + x6 * 256 + x7) :
    v = x5 * 65536 + x6 * 256 + x7 := by
  simp only [Nat.reducePow] at h0 h1 h2 h3 h4 h5 h6 h7
  subst h
  have e0 : x0 = 0 := by omega
  subst e0
  have e1 : x1 = 0 := by omega
  subst e1
  have e2 : x2 = 0 := by omega
  subst e2
  have e3 : x3 = 0 := by omega
  subst e3
  have e4 : x4 = 0 := by omega
  subst e4
  omega

/-- The three low bytes of the 8 big-endian bytes of a value below `2^24` (64-bit `usize`). -/
theorem usize_low3_bytes (value : Std.Usize) (h64 : System.Platform.numBits = 64)
    (hval : value.val ≤ 16777215) (n : Nat) (hn : n * 8 = 64) :
    ∃ b0 b1 b2 : Std.U8, List.drop (n - 3) (List.map (@UScalar.mk UScalarTy.U8)
        (BitVec.setWidth 64 value.bv).toBEBytes) = [b0, b1, b2] ∧
      value.val = b0.val * 65536 + b1.val * 256 + b2.val := by
  have hn8 : n - 3 = 5 := by omega
  rw [hn8]
  have hvlt : value.val < 2 ^ 64 := by
    show value.bv.toNat < 2 ^ 64
    exact Nat.lt_of_lt_of_le value.bv.isLt (by rw [h64])
  obtain ⟨c0, c1, c2, c3, c4, c5, c6, c7, hbl⟩ :=
    list_eq_eight (BitVec.setWidth 64 value.bv).toBEBytes
      (by simp)
  have hnat : value.val = (BitVec.fromBEBytes [c0, c1, c2, c3, c4, c5, c6, c7]).toNat := by
    have h := fromBEBytes_toBEBytes_toNat (w := 64) (by norm_num) (BitVec.setWidth 64 value.bv)
    rw [hbl, BitVec.toNat_setWidth] at h
    rw [h]
    exact (Nat.mod_eq_of_lt hvlt).symm
  rw [fromBEBytes_eight_toNat] at hnat
  exact ⟨UScalar.mk c5, UScalar.mk c6, UScalar.mk c7, by rw [hbl]; rfl, by
    show value.val = c5.toNat * 65536 + c6.toNat * 256 + c7.toNat
    exact eight_bytes_low3 _ _ _ _ _ _ _ _ _ c0.isLt c1.isLt c2.isLt c3.isLt c4.isLt c5.isLt c6.isLt
      c7.isLt hval hnat⟩

/-- `U24::try_from(usize)` never panics: `Ok` of the three low bytes when the value fits, `Err` otherwise. -/
theorem U24.Insts.CoreConvertTryFromUsizeU24OverflowError.try_from_char (value : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ U24.Insts.CoreConvertTryFromUsizeU24OverflowError.try_from value
    ⦃ ⇓ r => ⌜ (value.val ≤ 16777215 → ∃ (a : U24) (b0 b1 b2 : Std.U8), r = .Ok a ∧
          a.val = [b0, b1, b2] ∧ value.val = b0.val * 65536 + b1.val * 256 + b2.val) ∧
        (16777215 < value.val → r = .Err ()) ⌝ ⦄ := by
  have h64 := numBits_eq_64
  unfold U24.Insts.CoreConvertTryFromUsizeU24OverflowError.try_from
  have e24 : (24#i32).toNat = 24 := rfl
  have e16 : (16#i32).toNat = 16 := rfl
  have e8 : (8#i32).toNat = 8 := rfl
  have eU8 : UScalarTy.U8.numBits = 8 := rfl
  mvcgen
  all_goals (try simp only [e24, e16, e8, h64, Nat.shiftLeft_eq, gt_iff_lt, UScalar.lt_equiv] at *)
  · refine ⟨fun hv => ?_, fun _ => trivial⟩
    exfalso; scalar_tac
  · refine ⟨fun hv => ⟨_, _, _, _, rfl, rfl, ?_⟩, fun hv => ?_⟩
    · subst_vars
      simp only [UScalar.cast_val_eq, eU8]
      omega
    · exfalso; scalar_tac
  all_goals (exfalso; scalar_tac)

/-- `usize::from(U24)` is the big-endian value of the three bytes (total: `Usize.Insts.CoreConvertFromU24.from_pf`). -/
theorem Usize.Insts.CoreConvertFromU24.from_char (value : U24) :
    ⦃ ⌜ True ⌝ ⦄ Usize.Insts.CoreConvertFromU24.from value
    ⦃ ⇓ r => ⌜ ∀ b0 b1 b2 : Std.U8, value.val = [b0, b1, b2] →
        r.val = b0.val * 65536 + b1.val * 256 + b2.val ⌝ ⦄ :=
  total_of_pf_partial (Usize.Insts.CoreConvertFromU24.from_pf value)
    (Usize.Insts.CoreConvertFromU24.from_content value)

/-- `usize::try_from(U24)` through the blanket `TryFrom` impl for `Into` never fails: it is
`Ok` of the big-endian value of the three bytes. -/
theorem core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U24_content (x : U24) :
    ⦃ ⌜ True ⌝ ⦄
    core.convert.TryFromTUInfallible.Blanket.try_from
      (core.convert.Into.Blanket Usize.Insts.CoreConvertFromU24) x
    ⦃ ⇓ r => ⌜ ∃ y, r = .Ok y ∧ ∀ b0 b1 b2 : Std.U8, x.val = [b0, b1, b2] →
        y.val = b0.val * 65536 + b1.val * 256 + b2.val ⌝ ⦄ := by
  unfold core.convert.TryFromTUInfallible.Blanket.try_from core.convert.Into.Blanket
  mvcgen [core.convert.Into.Blanket.into, Usize.Insts.CoreConvertFromU24.from_char]
  exact ⟨_, rfl, ‹_›⟩

/-- `usize::try_from(U24)` (blanket `Into` impl) never fails. -/
theorem core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U24_ok (x : U24) :
    ⦃ ⌜ True ⌝ ⦄
    core.convert.TryFromTUInfallible.Blanket.try_from
      (core.convert.Into.Blanket Usize.Insts.CoreConvertFromU24) x
    ⦃ ⇓ r => ⌜ ∃ y, r = .Ok y ⌝ ⦄ :=
  triple_post_mono (core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U24_content x)
    fun _ ⟨y, hy, _⟩ => ⟨y, hy⟩

end tls_codec
