/- The generic slice serializer (`<&[T]>` / `Vec<T>` `tls_serialize_bytes`): partial
characterization.

Obligations: none directly; the bytes-path halves of `PanicFreedom.lean` /
`FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): nothing ASSUMED. -/
import TlsCodec.Verification.Helpers.QuicVec
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! ### Generic slice serializer: partial characterization

An `Ok` result of the `Slice` serializer has the size given by `tls_serialized_len` (partial
statement; panic freedom is `Shared0Slice.serialize_pf`). -/

/-- Partial-correctness spec of `loop`: an invariant `inv` preserved by every step, and its `done`
values satisfy `Q`. -/
theorem loop_partial_spec {α β : Type} (body : α → RustM (ControlFlow α β)) (init : α)
    (inv : α → Prop) (Q : β → Prop) (hinit : inv init)
    (hbody : ∀ x, inv x → ⦃ ⌜ True ⌝ ⦄ body x
      ⦃ ⇓? cf => ⌜ match cf with | .cont r => inv r | .done y => Q y ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ loop body init ⦃ ⇓? y => ⌜ Q y ⌝ ⦄ := by
  refine Aeneas.Std.loop_spec (γ := Unit) inv (fun _ _ => False) (fun _ => ()) ⟨fun _ => ⟨_, by simp⟩⟩
    hinit ?_
  intro x hx
  have := hbody x hx
  cases hb : body x <;> rw [hb] at this <;>
    simp_all [Triple, PostCond.mayThrow, PostCond.okAssertion, PostCond.failAssertion,
      PostCond.divAssertion, PostCond.div, WP.wp, PredTrans.apply] <;> (try split) <;> simp_all

/-- Weakening the post of a partial triple. -/
theorem partial_triple_post_mono {α : Type} {x : RustM α} {P Q : α → Prop}
    (h : ⦃ ⌜ True ⌝ ⦄ x ⦃ ⇓? r => ⌜ P r ⌝ ⦄) (hPQ : ∀ r, P r → Q r) :
    ⦃ ⌜ True ⌝ ⦄ x ⦃ ⇓? r => ⌜ Q r ⌝ ⦄ :=
  partial_triple_of_ok fun _ hr => hPQ _ (ok_of_partial_triple h hr)

/-- Exact sums of the element sizes (as naturals). -/
inductive SizeNat {T : Type} (S : Size T) : List T → Nat → Prop
  | nil : SizeNat S [] 0
  | cons (x : T) (l : List T) (n : Std.Usize) (N : Nat) :
      S.tls_serialized_len x = ok n → SizeNat S l N → SizeNat S (x :: l) (n.val + N)

/-- The size of a byte list is its length. -/
theorem SizeNat.u8 (l : List Std.U8) : SizeNat U8.Insts.Tls_codecSize l l.length := by
  induction l with
  | nil => exact .nil
  | cons x l ih =>
    have h := SizeNat.cons (S := U8.Insts.Tls_codecSize) x l 1#usize l.length rfl ih
    rwa [show (1#usize).val + l.length = (x :: l).length by simp [add_comm]] at h

theorem SizeNat.snoc {T : Type} {S : Size T} {l : List T} {N : Nat} (h : SizeNat S l N)
    (e : T) (n : Std.Usize) (hn : S.tls_serialized_len e = ok n) :
    SizeNat S (l ++ [e]) (N + n.val) := by
  induction h with
  | nil => simpa using SizeNat.cons e [] n 0 hn .nil
  | cons x l n' N' hx _ ih =>
    have := SizeNat.cons x _ n' _ hx ih
    rwa [show n'.val + (N' + n.val) = n'.val + N' + n.val by omega] at this

theorem SizeNat.head {T : Type} {S : Size T} {l : List T} {N : Nat} (h : SizeNat S l N)
    (hl : 0 < l.length) :
    ∃ (n : Std.Usize) (N' : Nat), S.tls_serialized_len (l.get ⟨0, hl⟩) = ok n ∧ N = n.val + N' := by
  cases h with
  | nil => exact absurd hl (by simp)
  | cons x l' n N' hx _ => exact ⟨n, N', hx, rfl⟩

/-- The folds are the exact sum when it fits. -/
theorem SizeFoldRel.val_eq {T : Type} {S : Size T} {a : Std.Usize} {l : List T} {r : Std.Usize}
    (h : SizeFoldRel S a l r) {N : Nat} (hN : SizeNat S l N) (hle : a.val + N ≤ Usize.max) :
    r.val = a.val + N := by
  induction h generalizing N with
  | nil a => cases hN; simp
  | cons a x l n r hx _ ih =>
    rcases hN with _ | ⟨_, _, n2, N2, hx2, hN2⟩
    · rw [hx] at hx2
      have hnn : n2 = n := (ok.inj hx2).symm
      subst hnn
      have := lenAddVal_val a n2 (by omega)
      rw [ih hN2 (by omega), this]
      omega

/-- A loop whose result is not tracked. -/
theorem loop_trivial_partial {α β : Type} (body : α → RustM (ControlFlow α β)) (x : α) :
    ⦃ ⌜ True ⌝ ⦄ loop body x ⦃ ⇓? _ => ⌜ True ⌝ ⦄ :=
  partial_triple_of_ok fun _ _ => trivial

/-- Partial spec of the serialisation loop of the slice serializer: if it finishes without error,
the output grew by the sum of the element sizes. -/
theorem loop_ser_partial_spec {T : Type} (S : Size T) (it : core.slice.iter.Iter T)
    (out : alloc.vec.Vec Std.U8)
    (body : core.slice.iter.Iter T × alloc.vec.Vec Std.U8 →
      RustM (ControlFlow (core.slice.iter.Iter T × alloc.vec.Vec Std.U8)
        (alloc.vec.Vec Std.U8 × core.option.Option Error)))
    (hbody : ∀ (it' : core.slice.iter.Iter T) (o : alloc.vec.Vec Std.U8),
      ⦃ ⌜ True ⌝ ⦄ body (it', o)
      ⦃ ⇓? r => ⌜ match r with
        | .done y => y.2 = core.option.Option.None → (it' : Slice T).val = [] ∧ y.1 = o
        | .cont p => ∃ e n, (it' : Slice T).val = e :: (p.1 : Slice T).val ∧
            S.tls_serialized_len e = ok n ∧
            (p.2 : Slice Std.U8).val.length = (o : Slice Std.U8).val.length + n.val ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ loop body (it, out)
    ⦃ ⇓? r => ⌜ r.2 = core.option.Option.None → ∃ N, SizeNat S (it : Slice T).val N ∧
        (r.1 : Slice Std.U8).val.length = (out : Slice Std.U8).val.length + N ⌝ ⦄ := by
  refine loop_partial_spec body (it, out)
    (fun p => ∃ lc N0, (it : Slice T).val = lc ++ (p.1 : Slice T).val ∧ SizeNat S lc N0 ∧
      (p.2 : Slice Std.U8).val.length = (out : Slice Std.U8).val.length + N0)
    _ ⟨[], 0, by simp, .nil, by simp⟩ ?_
  rintro ⟨it', o⟩ ⟨lc, N0, h1, h2, h3⟩
  apply partial_triple_post_mono (hbody it' o)
  intro r hr
  cases r with
  | done y =>
    intro hy
    obtain ⟨h0, rfl⟩ := hr hy
    refine ⟨N0, ?_, h3⟩
    simp only at h1 h0 ⊢
    rw [h1, h0, List.append_nil]; exact h2
  | cont p =>
    obtain ⟨e, n, hl, hn, hp⟩ := hr
    refine ⟨lc ++ [e], N0 + n.val, ?_, h2.snoc e n hn, ?_⟩
    · rw [h1, hl]; simp
    · rw [hp]; simp only at h3; omega


/-- Total spec of `loop`: an invariant `inv` preserved by every step with a decreasing measure `μ`,
and its `done` values satisfy `Q`. -/
theorem loop_total_spec {α β : Type} (body : α → RustM (ControlFlow α β)) (init : α)
    (inv : α → Prop) (μ : α → Nat) (Q : β → Prop) (hinit : inv init)
    (hbody : ∀ x, inv x → ⦃ ⌜ True ⌝ ⦄ body x
      ⦃ ⇓ cf => ⌜ match cf with | .cont r => inv r ∧ μ r < μ x | .done y => Q y ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ loop body init ⦃ ⇓ y => ⌜ Q y ⌝ ⦄ := by
  apply Aeneas.Std.WP.spec_to_mvcgen
  refine Aeneas.Std.loop.spec_decr_nat μ inv Q body init (fun x hx => ?_) hinit
  obtain ⟨r, hr, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (hbody x hx)
  rw [hr, Aeneas.Std.WP.spec_ok]
  cases r <;> exact hP

/-- Total spec of the sizing loop of the slice serializer: it does not fail, and an `Ok` result is the
exact sum of the element sizes. -/
theorem loop_sum_total {T : Type} (S : Size T) (it : core.slice.iter.Iter T) (acc : Std.Usize)
    (body : core.slice.iter.Iter T × Std.Usize →
      RustM (ControlFlow (core.slice.iter.Iter T × Std.Usize) (core.result.Result Std.Usize Error)))
    (hbody : ∀ (it' : core.slice.iter.Iter T) (a : Std.Usize),
      ⦃ ⌜ True ⌝ ⦄ body (it', a)
      ⦃ ⇓ r => ⌜ match r with
        | .done y => ∀ c, y = .Ok c → (it' : Slice T).val = [] ∧ c = a
        | .cont p => ∃ e n, (it' : Slice T).val = e :: (p.1 : Slice T).val ∧
            S.tls_serialized_len e = ok n ∧ p.2.val = a.val + n.val ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ loop body (it, acc)
    ⦃ ⇓ r => ⌜ ∀ c, r = .Ok c → ∃ N, SizeNat S (it : Slice T).val N ∧ c.val = acc.val + N ⌝ ⦄ := by
  refine loop_total_spec body (it, acc)
    (fun p => ∃ lc N0, (it : Slice T).val = lc ++ (p.1 : Slice T).val ∧ SizeNat S lc N0 ∧
      p.2.val = acc.val + N0)
    (fun p => (p.1 : Slice T).val.length) _ ⟨[], 0, by simp, .nil, by simp⟩ ?_
  rintro ⟨it', a⟩ ⟨lc, N0, h1, h2, h3⟩
  apply triple_post_mono (hbody it' a)
  intro r hr
  cases r with
  | done y =>
    intro c hy
    obtain ⟨h0, rfl⟩ := hr c hy
    simp only at h1 h0 h3
    exact ⟨N0, by rw [h1, h0, List.append_nil]; exact h2, h3⟩
  | cont p =>
    obtain ⟨e, n, hl, hn, hp⟩ := hr
    refine ⟨⟨lc ++ [e], N0 + n.val, ?_, h2.snoc e n hn, ?_⟩, ?_⟩
    · rw [h1, hl]; simp
    · simp only at h3; omega
    · simp [hl]

/-- Total spec of the serialisation loop of the slice serializer: it does not fail, as long as the
total size of the remaining elements still fits in the vector; the output does not shrink. -/
theorem loop_append_total {T : Type} (S : Size T) (it : core.slice.iter.Iter T)
    (out : alloc.vec.Vec Std.U8)
    (body : core.slice.iter.Iter T × alloc.vec.Vec Std.U8 →
      RustM (ControlFlow (core.slice.iter.Iter T × alloc.vec.Vec Std.U8)
        (alloc.vec.Vec Std.U8 × core.option.Option Error)))
    (hinit : ∃ N, SizeNat S (it : Slice T).val N ∧ (out : Slice Std.U8).val.length + N ≤ Usize.max)
    (hbody : ∀ (it' : core.slice.iter.Iter T) (o : alloc.vec.Vec Std.U8),
      (∃ N, SizeNat S (it' : Slice T).val N ∧ (o : Slice Std.U8).val.length + N ≤ Usize.max) →
      ⦃ ⌜ True ⌝ ⦄ body (it', o)
      ⦃ ⇓ r => ⌜ match r with
        | .done y => (o : Slice Std.U8).val.length ≤ (y.1 : Slice Std.U8).val.length
        | .cont p => ∃ e n, (it' : Slice T).val = e :: (p.1 : Slice T).val ∧
            S.tls_serialized_len e = ok n ∧
            (p.2 : Slice Std.U8).val.length = (o : Slice Std.U8).val.length + n.val ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ loop body (it, out)
    ⦃ ⇓ r => ⌜ (out : Slice Std.U8).val.length ≤ (r.1 : Slice Std.U8).val.length ⌝ ⦄ := by
  refine loop_total_spec body (it, out)
    (fun p => (∃ N, SizeNat S (p.1 : Slice T).val N ∧
        (p.2 : Slice Std.U8).val.length + N ≤ Usize.max) ∧
      (out : Slice Std.U8).val.length ≤ (p.2 : Slice Std.U8).val.length)
    (fun p => (p.1 : Slice T).val.length) _ ⟨hinit, le_refl _⟩ ?_
  rintro ⟨it', o⟩ ⟨hinv, hle⟩
  apply triple_post_mono (hbody it' o hinv)
  intro r hr
  cases r with
  | done y => exact le_trans hle hr
  | cont p =>
    obtain ⟨e, n, hl, hn, hp⟩ := hr
    obtain ⟨N, hN, hle'⟩ := hinv
    simp only at hN hle hle' ⊢
    rw [hl] at hN
    obtain _ | ⟨_, _, n2, N2, hx2, hN2⟩ := hN
    have := ok.inj (hn.symm.trans hx2)
    subst this
    exact ⟨⟨⟨N2, hN2, by omega⟩, by omega⟩, by simp [hl]⟩

theorem list_cons_get_drop {α : Type} (l : List α) (h : 0 < l.length) :
    l = l.get ⟨0, h⟩ :: l.drop 1 := by
  cases l with
  | nil => exact absurd h (Nat.lt_irrefl _)
  | cons x xs => rfl

/-- The element serializer of a lawful `SerializeBytes` instance does not panic and meets its size
contract (as a spec for `mvcgen`). -/
theorem SerializeBytes.elem_char {T : Type} (inst : SerializeBytes T)
    (hlaw : SerializeBytes.Lawful T inst) (x : T) :
    ⦃ ⌜ True ⌝ ⦄ inst.tls_serialize_bytes x
    ⦃ ⇓ r => ⌜ ∀ b, r = .Ok b → ∃ n, inst.SizeInst.tls_serialized_len x = ok n ∧
      (b : Slice Std.U8).val.length = n.val ⌝ ⦄ := by
  obtain ⟨a, ha, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (hlaw.tls_serialize_bytes_spec x (pre_holds_of_ok_true rfl))
  rw [ha]
  apply RustM.ok_spec
  intro b hb
  subst hb
  exact SerializeBytes.post_ok_elim _ _ _ _ hP

/-- The element serializer of a lawful `SerializeBytes` instance meets its size contract
(partial form, as a spec for `mvcgen`). -/
theorem SerializeBytes.elem_partial {T : Type} (inst : SerializeBytes T)
    (hlaw : SerializeBytes.Lawful T inst) (x : T) :
    ⦃ ⌜ True ⌝ ⦄ inst.tls_serialize_bytes x
    ⦃ ⇓? r => ⌜ ∀ b, r = .Ok b → ∃ n, inst.SizeInst.tls_serialized_len x = ok n ∧
      (b : Slice Std.U8).val.length = n.val ⌝ ⦄ :=
  partial_of_total (SerializeBytes.elem_char inst hlaw x)

/-- Close the side goal `value <= MAX` that the spec of the copy of `write_bytes` leaves for the
content length (at most `2^30 - 1`). -/
macro "close_hv" : tactic => `(tactic| any_goals (first
  | (show UScalar.val _ ≤ 2 ^ 62 - 1
     simp only [continue_eq_tryCF] at *
     subst_vars
     dsimp only at *
     omega)
  | skip))

/-- Unfold the hand-translated slice serializer, with the copies of the crate functions it calls
folded back to the originals (so that their specs apply). -/
macro "ser_slice_setup" : tactic => `(tactic| (
  unfold Shared0Slice.Insts.Tls_codecSerializeBytes.tls_serialize_bytes
  nth_rewrite 1 [slice_iter_ok]
  erw [bind_tc_ok]
  simp only [Copied.varint.TlsVarInt.bytes_len_eq,
    Copied.checked_alloc_len_eq, Copied.quic_vec.ContentLength.from_usize_eq]))

/-- `mvcgen` on the unfolded slice serializer, with the specs of the functions it calls; the
argument lists the specs of the two loops and of the element functions. -/
syntax "ser_slice_mvcgen" " [" Lean.Parser.Tactic.simpLemma,* "]" : tactic
macro_rules
  | `(tactic| ser_slice_mvcgen [$ts,*]) => `(tactic| mvcgen [-Aeneas.Std.loop_spec, $ts,*,
    quic_vec.ContentLength.from_usize_spec, varint.TlsVarInt.bytes_len_spec,
    checked_alloc_len_ok, alloc.vec.Vec.with_capacity, alloc.vec.Vec.resize_U8_len_spec,
    alloc.vec.Vec.Insts.CoreOpsDerefDerefMutSlice.deref_mut, alloc.vec.Vec.as_mut_slice,
    rust_primitives.sequence.seq_to_slice_mut, Copied.varint.TlsVarInt.write_bytes_spec,
    core.slice.Slice.iter, core.iter.traits.collect.IntoIterator.Blanket.into_iter,
    core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.next,
    alloc.vec.Vec.append, rust_primitives.sequence.seq_concat])

/-- The `<&[T]>::tls_serialize_bytes` of the trait contracts of `T`: an `Ok out` has the length given
by `tls_serialized_len` (partial form, see `Shared0Slice.serialize_pf`). -/
theorem Shared0Slice.serialize_partial {T : Type} (inst : SerializeBytes T)
    (hlaw : SerializeBytes.Lawful T inst) (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ Shared0Slice.Insts.Tls_codecSerializeBytes.tls_serialize_bytes inst s
    ⦃ ⇓? r => ⌜ ∀ out, r = .Ok out → ∃ n,
        Shared0Slice.Insts.Tls_codecSize.tls_serialized_len inst.SizeInst s = ok n ∧
        (out : Slice Std.U8).val.length = n.val ⌝ ⦄ := by
  have hs := SerializeBytes.elem_partial inst hlaw
  obtain ⟨n, hn, c', ll', hrel', hnv, hll'⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (Shared0Slice.size_rel inst.SizeInst hlaw.SizeInstLawful s)
  ser_slice_setup
  have hsum := loop_trivial_partial
    (α := core.slice.iter.Iter T × Std.Usize) (β := core.result.Result Std.Usize Error)
  have hser := @loop_ser_partial_spec T inst.SizeInst
  ser_slice_mvcgen [hsum, hser, hs]
  all_goals (try clear hsum hser)
  try_vcs
  close_hv
  all_goals (try (intros; simp [PostCond.ok]; done))
  · rw [← List.length_eq_zero_iff]
    scalar_tac
  · rename_i _ _ _ bytes _ hb comb hc
    obtain ⟨n, hn, hl⟩ := hb bytes rfl
    refine ⟨_, n, ?_, hn, ?_⟩
    · simp only [show (0#usize).val = 0 from rfl, List.take_zero, List.nil_append, zero_add]
      exact list_cons_get_drop _ ‹_›
    · simp [comb, hl]
  · intro h
    cases h
  · intro out h
    cases h
  · intro out h
    cases h
  · rename_i _ _ c _ _ _ hfrom _ val _ hcf1 ll hbl _ hchk _ _ _ _ _ _ _ hout1 back r3 hw _ _ _ _ r4 hnone hrel
      i3 hi3 i4 hi4 hge hne
    intro out hout
    obtain rfl := core.result.Result.Ok.inj hout
    simp only [continue_eq_tryCF] at hcf1
    subst hcf1
    simp only at hfrom
    obtain ⟨N, hN, hlen⟩ := hrel hnone
    have hc := varint.lenOf_char _ _ hbl
    have hw2 := (hw.2 (by omega)).2
    have hback : (back r3.2 : Slice Std.U8).val.length = (r3.2 : Slice Std.U8).val.length := rfl
    have h0 : (0#usize).val = 0 := rfl
    have hi3v : i3.val = (r4.1 : Slice Std.U8).val.length := by rw [hi3]; simp
    have hi4v : i4.val = i3.val - ll.val := hi4
    have hcv : i4.val = c.val := by simpa using hne
    have hbound : (r4.1 : Slice Std.U8).val.length ≤ Usize.max := (r4.1 : Slice Std.U8).property
    have hcN : c.val = N := by omega
    have hc' := hrel'.val_eq hN (by omega)
    have hll'v : ll'.val = varint.lenOf N := by
      rw [hll', if_pos (by omega)]
      congr 1
      omega
    have hllv : ll.val = varint.lenOf N := by rw [hc.1]; congr 1; omega
    refine ⟨n, hn, ?_⟩
    rw [hnv, lenAddVal_val _ _ (by omega)]
    omega


/-- The `<&[T]>::tls_serialize_bytes` of the trait contracts of `T` does not fail. -/
theorem Shared0Slice.serialize_pf {T : Type} (inst : SerializeBytes T)
    (hlaw : SerializeBytes.Lawful T inst) (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ Shared0Slice.Insts.Tls_codecSerializeBytes.tls_serialize_bytes inst s
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  have hs := SerializeBytes.elem_char inst hlaw
  have hz := Size.len_char inst.SizeInst hlaw.SizeInstLawful
  have hsum := @loop_sum_total T inst.SizeInst
  have happ := @loop_append_total T inst.SizeInst
  ser_slice_setup
  ser_slice_mvcgen [hsum, happ, hs, hz, checked_len_add_triple, tls_codec.Copied.checked_len_add_triple]
  all_goals (try clear hsum happ hs hz)
  try_vcs
  close_hv
  all_goals (try exact ‹core.ops.control_flow.ControlFlow.Break _ = tryCF _›)
  all_goals (try (intros; simp [PostCond.ok]; done))
  · rintro c ⟨⟩
    exact ⟨by rw [← List.length_eq_zero_iff]; scalar_tac, rfl⟩
  · simp only [continue_eq_tryCF] at *
    subst_vars
    exact ⟨_, _, by simpa using list_cons_get_drop _ ‹_›, ‹_›, (checkedLenAddRes_ok _ _ _ ‹_›).1⟩
  · intro h; subst h; simp [PostCond.ok]; mvcgen; simp
  · exfalso; scalar_tac
  · simp only [continue_eq_tryCF] at *
    subst_vars
    have hc := varint.lenOf_char _ _ ‹1 ≤ _ ∧ _›
    simp only [core.result.Result.Ok.injEq, forall_eq, forall_eq'] at *
    obtain ⟨N, hN, hv⟩ := ‹∃ N, _›
    obtain ⟨-, hl⟩ := ‹(_ < _ → _) ∧ (_ ≤ _ → _)›
    have hl := (hl (by omega)).2
    exact ⟨N, hN, by dsimp +zetaDelta only; scalar_tac⟩
  · simp only [core.result.Result.Ok.injEq, forall_eq'] at *
    obtain ⟨n, hn, hl⟩ := ‹∃ n, _›
    exact ⟨_, n, by simpa using list_cons_get_drop _ ‹_›, hn, by simp +zetaDelta [hl]⟩
  · exfalso
    obtain ⟨N, hN, hle⟩ := ‹∃ N, _›
    obtain ⟨n, N', hx, rfl⟩ := hN.head (by scalar_tac)
    simp only [core.result.Result.Ok.injEq, forall_eq'] at *
    obtain ⟨n2, hn2, hlen⟩ := ‹∃ n, _›
    obtain rfl := ok.inj (hx.symm.trans hn2)
    simp +zetaDelta [List.length_append] at *
    omega
  · exfalso; scalar_tac
  · exfalso
    have hc := varint.lenOf_char _ _ ‹1 ≤ _ ∧ _›
    obtain ⟨-, hl⟩ := ‹(_ < _ → _) ∧ (_ ≤ _ → _)›
    have hl := (hl (by omega)).2
    dsimp +zetaDelta only at *
    scalar_tac

theorem alloc.vec.Vec.as_slice_ok {T : Type} (v : alloc.vec.Vec T) :
    alloc.vec.Vec.as_slice v = ok (v : Slice T) := by
  obtain ⟨a, ha, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (alloc.vec.Vec.as_slice_spec v)
  rw [ha, hP]
  rfl

/-- The `Vec<T>` size is the size of its slice. -/
theorem alloc.vec.Vec.size_eq_slice {T : Type} (S : Size T) (v : alloc.vec.Vec T) :
    alloc.vec.Vec.Insts.Tls_codecSize.tls_serialized_len S v =
      Shared0Slice.Insts.Tls_codecSize.tls_serialized_len S (v : Slice T) := by
  unfold alloc.vec.Vec.Insts.Tls_codecSize.tls_serialized_len
  rw [alloc.vec.Vec.as_slice_ok]
  rfl

theorem Shared0Vec.size_eq_slice {T : Type} (S : Size T) (v : alloc.vec.Vec T) :
    Shared0Vec.Insts.Tls_codecSize.tls_serialized_len S v =
      Shared0Slice.Insts.Tls_codecSize.tls_serialized_len S (v : Slice T) := by
  unfold Shared0Vec.Insts.Tls_codecSize.tls_serialized_len
  rw [alloc.vec.Vec.size_eq_slice]

/-- The `&Vec<T>` serializer is the slice serializer of its slice. -/
theorem Shared0Vec.ser_eq_slice {T : Type} (inst : SerializeBytes T) (v : alloc.vec.Vec T) :
    Shared0Vec.Insts.Tls_codecSerializeBytes.tls_serialize_bytes inst v =
      Shared0Slice.Insts.Tls_codecSerializeBytes.tls_serialize_bytes inst (v : Slice T) := by
  unfold Shared0Vec.Insts.Tls_codecSerializeBytes.tls_serialize_bytes
  rw [alloc.vec.Vec.as_slice_ok]
  erw [bind_tc_ok]

/-- The `Vec<T>` serializer is the slice serializer of its slice. -/
theorem alloc.vec.Vec.ser_eq_slice {T : Type} (inst : SerializeBytes T) (v : alloc.vec.Vec T) :
    alloc.vec.Vec.Insts.Tls_codecSerializeBytes.tls_serialize_bytes inst v =
      Shared0Slice.Insts.Tls_codecSerializeBytes.tls_serialize_bytes inst (v : Slice T) := by
  unfold alloc.vec.Vec.Insts.Tls_codecSerializeBytes.tls_serialize_bytes
  rw [alloc.vec.Vec.as_slice_ok]
  erw [bind_tc_ok]

/-- The `&Vec<T>` serializer does not fail. -/
theorem Shared0Vec.serialize_pf {T : Type} (inst : SerializeBytes T)
    (hlaw : SerializeBytes.Lawful T inst) (v : alloc.vec.Vec T) :
    ⦃ ⌜ True ⌝ ⦄ Shared0Vec.Insts.Tls_codecSerializeBytes.tls_serialize_bytes inst v
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  rw [Shared0Vec.ser_eq_slice]
  exact Shared0Slice.serialize_pf inst hlaw _

/-- The `Vec<T>` serializer does not fail. -/
theorem alloc.vec.Vec.serialize_pf {T : Type} (inst : SerializeBytes T)
    (hlaw : SerializeBytes.Lawful T inst) (v : alloc.vec.Vec T) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.Tls_codecSerializeBytes.tls_serialize_bytes inst v
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  rw [alloc.vec.Vec.ser_eq_slice]
  exact Shared0Slice.serialize_pf inst hlaw _

/-- The slice serializer meets the trait-level post (partial). -/
theorem Shared0Slice.trait_fc {T : Type} (inst : SerializeBytes T)
    (hlaw : SerializeBytes.Lawful T inst) (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ Shared0Slice.Insts.Tls_codecSerializeBytes.tls_serialize_bytes inst s
    ⦃ ⇓? res => ⌜ (SerializeBytes.tls_serialize_bytes.post
        (Shared0Slice.Insts.Tls_codecSerializeBytes inst).SizeInst
        (Shared0Slice.Insts.Tls_codecSerializeBytes inst) s res).holds ⌝ ⦄ := by
  refine partial_triple_post_mono (Shared0Slice.serialize_partial inst hlaw s) ?_
  intro r h
  cases r with
  | Ok out =>
    obtain ⟨n, hn, hl⟩ := h out rfl
    exact SerializeBytes.post_ok _ _ _ out n hn hl
  | Err e => exact SerializeBytes.post_err _ _ _ e

/-- The `&Vec<T>` serializer meets the trait-level post (partial). -/
theorem Shared0Vec.trait_fc {T : Type} (inst : SerializeBytes T)
    (hlaw : SerializeBytes.Lawful T inst) (v : alloc.vec.Vec T) :
    ⦃ ⌜ True ⌝ ⦄ Shared0Vec.Insts.Tls_codecSerializeBytes.tls_serialize_bytes inst v
    ⦃ ⇓? res => ⌜ (SerializeBytes.tls_serialize_bytes.post
        (Shared0Vec.Insts.Tls_codecSerializeBytes inst).SizeInst
        (Shared0Vec.Insts.Tls_codecSerializeBytes inst) v res).holds ⌝ ⦄ := by
  rw [Shared0Vec.ser_eq_slice]
  refine partial_triple_post_mono (Shared0Slice.serialize_partial inst hlaw _) ?_
  intro r h
  cases r with
  | Ok out =>
    obtain ⟨n, hn, hl⟩ := h out rfl
    refine SerializeBytes.post_ok _ _ _ out n ?_ hl
    show Shared0Vec.Insts.Tls_codecSize.tls_serialized_len _ v = ok n
    rw [Shared0Vec.size_eq_slice]
    exact hn
  | Err e => exact SerializeBytes.post_err _ _ _ e

/-- The `Vec<T>` serializer meets the trait-level post (partial). -/
theorem alloc.vec.Vec.ser_trait_fc {T : Type} (inst : SerializeBytes T)
    (hlaw : SerializeBytes.Lawful T inst) (v : alloc.vec.Vec T) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.Tls_codecSerializeBytes.tls_serialize_bytes inst v
    ⦃ ⇓? res => ⌜ (SerializeBytes.tls_serialize_bytes.post
        (alloc.vec.Vec.Insts.Tls_codecSerializeBytes inst).SizeInst
        (alloc.vec.Vec.Insts.Tls_codecSerializeBytes inst) v res).holds ⌝ ⦄ := by
  rw [alloc.vec.Vec.ser_eq_slice]
  refine partial_triple_post_mono (Shared0Slice.serialize_partial inst hlaw _) ?_
  intro r h
  cases r with
  | Ok out =>
    obtain ⟨n, hn, hl⟩ := h out rfl
    refine SerializeBytes.post_ok _ _ _ out n ?_ hl
    show alloc.vec.Vec.Insts.Tls_codecSize.tls_serialized_len _ v = ok n
    rw [alloc.vec.Vec.size_eq_slice]
    exact hn
  | Err e => exact SerializeBytes.post_err _ _ _ e

end tls_codec
