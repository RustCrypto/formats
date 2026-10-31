/- The hand-translated `<&[T]>::tls_serialize_bytes`, and `Vec::clone` (total when the element
`clone` is).

Obligations: none directly; the bytes-path halves of `PanicFreedom.lean` /
`FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): nothing ASSUMED. -/
import TlsCodec.Verification.Helpers.TlsByteVecSer
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! ### Specs of the hand-translated `<&[T]>::tls_serialize_bytes` -/

/-- One step of the serialisation loop (no element fails): either the iterator is exhausted, or
the head `e` is consumed and `f e` is appended. -/
def loop_append_step {T : Type} (f : T → List Std.U8) (it' : core.slice.iter.Iter T)
    (o : alloc.vec.Vec Std.U8)
    (r : ControlFlow (core.slice.iter.Iter T × alloc.vec.Vec Std.U8)
      (alloc.vec.Vec Std.U8 × core.option.Option Error)) : Prop :=
  match r with
  | .done y => y.1 = o ∧ y.2 = core.option.Option.None ∧ (it' : Slice T).val = []
  | .cont p => ∃ e, (it' : Slice T).val = e :: (p.1 : Slice T).val ∧ p.2.val = o.val ++ f e

/-- A `loop` that walks a slice iterator and appends `f e` to the output per element (the
serialisation loop of the hand-translated slice serializer, when no element fails).
`hbody`: one step. -/
theorem loop_append_spec {T : Type} (f : T → List Std.U8) (it : core.slice.iter.Iter T)
    (out : alloc.vec.Vec Std.U8)
    (body : core.slice.iter.Iter T × alloc.vec.Vec Std.U8 →
      RustM (ControlFlow (core.slice.iter.Iter T × alloc.vec.Vec Std.U8)
        (alloc.vec.Vec Std.U8 × core.option.Option Error)))
    (h : out.val.length + ((it : Slice T).val.flatMap f).length ≤ Std.Usize.max)
    (hbody : ∀ (it' : core.slice.iter.Iter T) (o : alloc.vec.Vec Std.U8),
      o.val.length + ((it' : Slice T).val.flatMap f).length ≤ Std.Usize.max →
      ⦃ ⌜ True ⌝ ⦄ body (it', o)
      ⦃ ⇓ r => ⌜ loop_append_step f it' o r ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ loop body (it, out)
    ⦃ ⇓ r => ⌜ r.2 = core.option.Option.None ∧
        r.1.val = out.val ++ (it : Slice T).val.flatMap f ⌝ ⦄ := by
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.loop.spec_decr_nat
    (fun p : core.slice.iter.Iter T × alloc.vec.Vec Std.U8 => (p.1 : Slice T).val.length)
    (fun p => p.2.val ++ (p.1 : Slice T).val.flatMap f = out.val ++ (it : Slice T).val.flatMap f)
  · rintro ⟨it', a⟩ hinv
    have hb := Aeneas.Std.WP.exists_imp_spec
      (Aeneas.Std.WP.triple_iff_exists_ok.mp (hbody it' a (by
        simp only at hinv
        have := congrArg List.length hinv
        simp only [List.length_append] at this
        omega)))
    apply Aeneas.Std.WP.spec_mono hb
    intro r hr
    simp only at hinv
    cases r with
    | done y =>
      obtain ⟨h1, h2, h3⟩ := hr
      refine ⟨h2, ?_⟩
      rw [h1, ← hinv, h3]; simp
    | cont p =>
      obtain ⟨e, hl, hv⟩ := hr
      refine ⟨?_, by simp only [hl]; simp⟩
      simp only [hv, ← hinv, hl, List.flatMap_cons, List.append_assoc]
  · simp

/-- `loop_append_spec` for `u8` elements (each serialises to its big-endian bytes). -/
theorem loop_append_U8_spec (it : core.slice.iter.Iter Std.U8) (out : alloc.vec.Vec Std.U8)
    (body : core.slice.iter.Iter Std.U8 × alloc.vec.Vec Std.U8 →
      RustM (ControlFlow (core.slice.iter.Iter Std.U8 × alloc.vec.Vec Std.U8)
        (alloc.vec.Vec Std.U8 × core.option.Option Error)))
    (h : out.val.length + ((it : Slice Std.U8).val.flatMap
      (fun x => (Aeneas.Std.core.num.U8.to_be_bytes x).val)).length ≤ Std.Usize.max)
    (hbody : ∀ (it' : core.slice.iter.Iter Std.U8) (o : alloc.vec.Vec Std.U8),
      o.val.length + ((it' : Slice Std.U8).val.flatMap
        (fun x => (Aeneas.Std.core.num.U8.to_be_bytes x).val)).length ≤ Std.Usize.max →
      ⦃ ⌜ True ⌝ ⦄ body (it', o)
      ⦃ ⇓ r => ⌜ loop_append_step (fun x => (Aeneas.Std.core.num.U8.to_be_bytes x).val) it' o r ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ loop body (it, out)
    ⦃ ⇓ r => ⌜ r.2 = core.option.Option.None ∧
        r.1.val = out.val ++ (it : Slice Std.U8).val.flatMap
          (fun x => (Aeneas.Std.core.num.U8.to_be_bytes x).val) ⌝ ⦄ :=
  loop_append_spec (fun x => (Aeneas.Std.core.num.U8.to_be_bytes x).val) it out body h hbody

/-- Concatenating the serialisations of `u8`s gives the list itself. -/
theorem U8_flatMap_to_be_bytes (l : List Std.U8) :
    l.flatMap (fun x => (Aeneas.Std.core.num.U8.to_be_bytes x).val) = l := by
  simp only [U8_to_be_bytes_val]; induction l <;> simp_all

-- `loop_append_U8_spec` needs priority over `mvcgen`'s built-in loop spec.
attribute [local spec high] loop_append_U8_spec in
/-- `<&[u8]>::tls_serialize_bytes` never panics: a slice of at most `2^30 - 1` bytes gives the
varint length prefix followed by the payload (only the length is tracked), a longer one an error. -/
theorem Shared0Slice.serialize_U8_char (s : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ Shared0Slice.Insts.Tls_codecSerializeBytes.tls_serialize_bytes
      U8.Insts.Tls_codecSerializeBytes s
    ⦃ ⇓ r => ⌜ (s.val.length ≤ 2 ^ 30 - 1 → ∃ out : alloc.vec.Vec Std.U8, r = .Ok out ∧
                  out.val.length = s.val.length + varint.lenOf s.val.length) ∧
               (2 ^ 30 - 1 < s.val.length → ∃ e, r = .Err e) ⌝ ⦄ := by
  unfold Shared0Slice.Insts.Tls_codecSerializeBytes.tls_serialize_bytes
  nth_rewrite 1 [slice_iter_ok]
  erw [bind_tc_ok]
  refine triple_bind_of_total (loop_len_sum_spec 1#usize _ 0#usize _ ?hlen ?hbody) ?hk
  case hlen => scalar_tac
  case hbody =>
    intro it a ha
    mvcgen [core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.next,
      U8.Insts.Tls_codecSize.tls_serialized_len, checked_len_add_triple, tls_codec.Copied.checked_len_add_triple]
    all_goals (fits_rw; simp_all [tryCF, -List.length_eq_zero_iff]; try first | scalar_tac | (have := checkedLenAddVal_val a 1#usize (by scalar_tac); scalar_tac))
  case hk =>
    rintro r ⟨v, rfl, hv⟩
    simp only [Copied.varint.TlsVarInt.bytes_len_eq,
      Copied.checked_alloc_len_eq, Copied.quic_vec.ContentLength.from_usize_eq]
    mvcgen [quic_vec.ContentLength.from_usize_spec, varint.TlsVarInt.bytes_len_spec,
      checked_alloc_len_small, alloc.vec.Vec.with_capacity,
      alloc.vec.Vec.resize_U8_len_spec,
      alloc.vec.Vec.Insts.CoreOpsDerefDerefMutSlice.deref_mut, alloc.vec.Vec.as_mut_slice,
      rust_primitives.sequence.seq_to_slice_mut, Copied.varint.TlsVarInt.write_bytes_spec,
      core.slice.Slice.iter, core.iter.traits.collect.IntoIterator.Blanket.into_iter, loop_append_U8_spec,
      core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.next, U8_serialize_char,
      alloc.vec.Vec.append, rust_primitives.sequence.seq_concat]
    all_goals (try simp only [continue_eq_tryCF] at *)
    all_goals subst_vars
    all_goals (try simp only [Slice.len_val] at *)
    · omega -- `value <= MAX` (from `write_bytes_spec`)
    · omega
    · -- the output (prefix + payload) fits in `usize`
      rename_i _ val len hbl _ out hout back w hw _ hOk _ hval _
      have hc := varint.lenOf_char _ _ hbl
      have hl := (hw.2 (by omega)).2
      have ho := core.result.Result.Ok.inj hOk
      show w.2.val.length + _ ≤ _
      rw [U8_flatMap_to_be_bytes]
      scalar_tac
    · -- iterator exhausted
      rename_i it o hb hlen _ _ _ _
      refine ⟨rfl, rfl, ?_⟩
      have : (it : Slice U8).val.length = 0 := by scalar_tac
      exact List.length_eq_zero_iff.mp this
    · -- one more element
      rename_i it o hb hne hlt bytes hv combined hcl _ _ _ _
      obtain ⟨b, hbb, hbv⟩ := hv
      obtain rfl := core.result.Result.Ok.inj hbb
      refine ⟨(it : Slice U8).val[0], ?_, ?_⟩
      · simp [List.getElem_zero, List.cons_head_tail]
      · simp [combined, hbv, List.get_eq_getElem]; rfl
    · -- the vector would exceed `usize`: impossible (bound)
      rename_i it o hb hne hlt bytes hv combined hncl _ _ _ _
      obtain ⟨b, hbb, hbv⟩ := hv
      obtain rfl := core.result.Result.Ok.inj hbb
      exfalso; apply hncl
      have h1 : (bytes : Slice U8).val.length = 1 := by rw [hbv, U8_to_be_bytes_val]; rfl
      rw [U8_flatMap_to_be_bytes] at hb
      simp only [combined, List.length_append]
      scalar_tac
    · -- the serialisation of a `u8` is not an error
      rename_i it o hb hne hlt err hv _ _ _ _
      obtain ⟨_, h, _⟩ := hv
      cases h
    · -- the iterator has an element
      rename_i it o hb hne hnlt _ _ _ _
      exfalso; apply hne
      apply UScalar.eq_of_val_eq
      simp only [Slice.len_val]
      scalar_tac
    · -- no failure
      rename_i r err hs hr _ _ _ _
      simp [hr.1] at hs
    · -- the length check passes
      rename_i val lenlen hbl _ out hout back w hw _ r hx hr i hne hOk hr1 hval hn hi hle
      exfalso
      have hc := varint.lenOf_char _ _ hbl
      have hl := (hw.2 (by omega)).2
      have ho := core.result.Result.Ok.inj hOk
      have h3 : Slice.length r.1 = w.2.val.length + Slice.length s := by
        simp only [Slice.length, hr.2, List.length_append, U8_flatMap_to_be_bytes]; rfl
      simp only [bne_iff_ne, ne_eq] at hne
      exact hne (by scalar_tac)
    · -- success
      rename_i val lenlen hbl _ out hout back w hw _ r hx hr i hne hOk hr1 hval hn hi hle
      have hc := varint.lenOf_char _ _ hbl
      have hl := (hw.2 (by omega)).2
      have ho := core.result.Result.Ok.inj hOk
      have h3 : Slice.length r.1 = w.2.val.length + Slice.length s := by
        simp only [Slice.length, hr.2, List.length_append, U8_flatMap_to_be_bytes]; rfl
      have hv' : val.val = s.val.length := by scalar_tac
      rw [hv'] at hc
      have hs : s.val.length ≤ 2 ^ 30 - 1 := by omega
      refine ⟨fun _ => ⟨_, rfl, ?_⟩, fun h => absurd h (by omega)⟩
      have h4 : (r.1 : Slice U8).val.length = w.2.val.length + s.val.length := h3
      omega
    · -- `usize` subtraction does not underflow
      rename_i val lenlen hbl _ out hout back w hw _ r hx hr hOk hr1 hval hn hlt
      exfalso
      have hc := varint.lenOf_char _ _ hbl
      have hl := (hw.2 (by omega)).2
      have h3 : Slice.length r.1 = w.2.val.length + Slice.length s := by
        simp only [Slice.length, hr.2, List.length_append, U8_flatMap_to_be_bytes]; rfl
      scalar_tac
    · -- `write_bytes` succeeds
      rename_i val lenlen hbl _ out hout back w hw resid hOk hval hn
      have hc := varint.lenOf_char _ _ hbl
      obtain ⟨⟨l, hl, _⟩, _⟩ := hw.2 (by omega)
      intro hb
      rw [hl] at hb
      simp only [tryCF, reduceCtorEq] at hb
    · -- `checked_alloc_len` succeeds
      rename_i val lenlen hbl r hn resid hOk hval
      obtain ⟨n, rfl, _⟩ := hn
      intro hb
      simp only [tryCF, reduceCtorEq] at hb
    · -- `from_usize` fails: the payload is too long
      rename_i acc r hr resid hOk
      apply try_break_vc
      intro e he
      subst he
      have ho := core.result.Result.Ok.inj hOk
      have hr' : 2 ^ 30 - 1 < s.val.length := by simp only at hr; scalar_tac
      mvcgen
      intro _
      exact ⟨fun h => absurd h (by omega), fun _ => ⟨_, rfl⟩⟩
    · intro hb
      simp only [tryCF, reduceCtorEq] at hb


/-! ### `Vec::clone` does not fail, given that the element `clone` does not -/

theorem vecCloneLoop_pf {T : Type} (inst : core.clone.Clone T)
    (hc : ∀ x, ⦃ ⌜ True ⌝ ⦄ inst.clone x ⦃ ⇓ _ => ⌜ True ⌝ ⦄)
    (it : core.slice.iter.Iter T) (w : rust_primitives.sequence.Seq T)
    (h : (w : Slice T).val.length + (it : Slice T).val.length ≤ Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.CoreCloneClone.clone_loop inst it w
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  unfold alloc.vec.Vec.Insts.CoreCloneClone.clone_loop
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.loop.spec_decr_nat
    (fun p : core.slice.iter.Iter T × rust_primitives.sequence.Seq T => (p.1 : Slice T).val.length)
    (fun p : core.slice.iter.Iter T × rust_primitives.sequence.Seq T =>
      (p.2 : Slice T).val.length + (p.1 : Slice T).val.length ≤ Usize.max)
  · rintro ⟨it, w⟩ hinv
    simp only [alloc.vec.Vec.Insts.CoreCloneClone.clone_loop.body,
      core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.next,
      rust_primitives.sequence.seq_len, rust_primitives.sequence.seq_remove,
      rust_primitives.sequence.seq_push]
    simp only at hinv
    by_cases hz : Slice.len it = 0#usize
    · simp [hz]
    · have hpos : 0 < (it : Slice T).val.length := by scalar_tac
      have hw : (w : Slice T).val.length < Usize.max := by omega
      simp [hz, hpos]
      obtain ⟨r, hr, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (hc ((it : Slice T).val[0]))
      simp [hr, hw]
      omega
  · exact h

theorem vecClone_pf {T : Type} (inst : core.clone.Clone T)
    (hc : ∀ x, ⦃ ⌜ True ⌝ ⦄ inst.clone x ⦃ ⇓ _ => ⌜ True ⌝ ⦄) (v : alloc.vec.Vec T) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.CoreCloneClone.clone inst v ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  unfold alloc.vec.Vec.Insts.CoreCloneClone.clone
  simp only [alloc.vec.Vec.Insts.CoreOpsDerefDerefSlice.deref, alloc.vec.Vec.as_slice,
    core.slice.Slice.iter, rust_primitives.sequence.seq_empty,
    rust_primitives.sequence.seq_to_slice, rust_primitives.sequence.seq_from_slice]
  have hl := vecCloneLoop_pf inst hc
  mvcgen [hl]
  simp [Slice.new]; scalar_tac

/-- Folding a slice iterator with a never-failing `call_mut` never fails. -/
theorem Shared0Slice.fold_pf {T C : Type}
    (inst : core.ops.function.FnMut C (Std.Usize × T) Std.Usize)
    (h : ∀ c p, ⦃ ⌜ True ⌝ ⦄ inst.call_mut c p ⦃ ⇓ _ => ⌜ True ⌝ ⦄)
    (it : core.slice.iter.Iter T) (acc : Std.Usize) (c : C) :
    ⦃ ⌜ True ⌝ ⦄
    core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.fold inst it acc c
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  simp only [core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.fold,
    core.iter.traits.iterator.Iterator.fold.default, core.iter.traits.iterator.iter_fold,
    core.iter.traits.iterator.iter_fold_loop]
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.loop.spec_decr_nat
    (fun p : core.slice.iter.Iter T × C × Std.Usize => (p.1 : Slice T).val.length)
    (fun _ => True)
  · rintro ⟨it', c', a⟩ _
    simp only [core.iter.traits.iterator.iter_fold_loop.body,
      core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.next,
      rust_primitives.sequence.seq_len, rust_primitives.sequence.seq_remove]
    by_cases hz : Slice.len it' = 0#usize
    · simp [hz]
    · have hpos : 0 < (it' : Slice T).val.length := by
        rcases Nat.eq_zero_or_pos (it' : Slice T).val.length with h0 | h0
        · exfalso; apply hz; apply UScalar.eq_of_val_eq; simp [Slice.len, h0]
        · exact h0
      obtain ⟨⟨a1, f1⟩, hv⟩ := triple_true_ok (h c' (a, (it' : Slice T).val[0]))
      simp [hz, hpos, hv]
  · trivial

/-- `<&[T]>::tls_serialized_len` does not fail when the element size does not. -/
theorem Shared0Slice.size_pf {T : Type} (SizeInst : Size T)
    (SizeInstLawful : Size.Lawful T SizeInst) (self_ : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ Shared0Slice.Insts.Tls_codecSize.tls_serialized_len SizeInst self_
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  have hcall : ∀ c p, ⦃ ⌜ True ⌝ ⦄
      (quic_vec.SizeShared0Slice.tls_serialized_len.closure.Insts.CoreOpsFunctionFnMutPairUsizeSharedTUsize
        SizeInst).call_mut c p ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
    rintro c ⟨a, e⟩
    have hs := SizeInstLawful.tls_serialized_len_spec
    mvcgen [quic_vec.SizeShared0Slice.tls_serialized_len.closure.Insts.CoreOpsFunctionFnMutPairUsizeSharedTUsize.call_mut,
      hs]
  have hl := Shared0Slice.fold_pf _ hcall
  have hm := Shared0Slice.size_closure_map_spec SizeInst
  mvcgen [Shared0Slice.Insts.Tls_codecSize.tls_serialized_len, hl, hm]

/-- `<&[T]>::tls_serialized_len` is positive, whatever the elements: the content length, or its
varint prefix when that is zero (and then `from_usize` succeeds). -/
theorem Shared0Slice.size_pos {T : Type} (SizeInst : Size T)
    (SizeInstLawful : Size.Lawful T SizeInst) (self_ : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ Shared0Slice.Insts.Tls_codecSize.tls_serialized_len SizeInst self_
    ⦃ ⇓ r => ⌜ 0 < r.val ⌝ ⦄ := by
  have hcall : ∀ c p, ⦃ ⌜ True ⌝ ⦄
      (quic_vec.SizeShared0Slice.tls_serialized_len.closure.Insts.CoreOpsFunctionFnMutPairUsizeSharedTUsize
        SizeInst).call_mut c p ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
    rintro c ⟨a, e⟩
    have hs := SizeInstLawful.tls_serialized_len_spec
    mvcgen [quic_vec.SizeShared0Slice.tls_serialized_len.closure.Insts.CoreOpsFunctionFnMutPairUsizeSharedTUsize.call_mut,
      hs]
  have hl := Shared0Slice.fold_pf _ hcall
  have hm := Shared0Slice.size_closure_map_spec SizeInst
  mvcgen [Shared0Slice.Insts.Tls_codecSize.tls_serialized_len, hl, hm, len_add_triple]
  rename_i _ _ cl rc _ _ hm ll hll _
  intro hf
  subst hf
  cases rc with
  | Ok c =>
    obtain ⟨u, rfl, hul⟩ := hm.1 c rfl
    simp only at hll
    subst hll
    have hle : varint.lenOf c.val ≤ 8 := by unfold varint.lenOf; split_ifs <;> omega
    have hge : 1 ≤ varint.lenOf c.val := by unfold varint.lenOf; split_ifs <;> omega
    have hsv := lenAddVal_val cl ll (by scalar_tac)
    scalar_tac
  | Err e =>
    obtain rfl := hm.2 e rfl
    simp only at hll
    subst hll
    have hsv := lenAddVal_val cl 0#usize (by scalar_tac)
    scalar_tac

/-- `Vec<T>::tls_serialized_len` does not fail when the element size does not. -/
theorem alloc.vec.Vec.size_pf {T : Type} (SizeInst : Size T)
    (SizeInstLawful : Size.Lawful T SizeInst) (self_ : alloc.vec.Vec T) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.Tls_codecSize.tls_serialized_len SizeInst self_
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  have hl := Shared0Slice.size_pf SizeInst SizeInstLawful
  mvcgen [alloc.vec.Vec.Insts.Tls_codecSize.tls_serialized_len, hl]

end tls_codec
