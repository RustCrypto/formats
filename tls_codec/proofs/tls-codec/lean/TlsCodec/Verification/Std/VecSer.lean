/- The `Vec<T>` serializer: from the element's `Serialize.Lawful` to the behaviour of
`Vec<T>::tls_serialize` on lawful writers (`checked_len_fold`, the element loop).

Obligations: none directly; the `std`-path halves (`Serialize` / `Deserialize` `Lawful` fields,
lemma traits) of `PanicFreedom.lean` / `FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): nothing ASSUMED; 1 signature-only stub
(`core.io.error.Error.Insts.CoreFmtDebug.fmt`). -/
import Aeneas
import CoreModels
import Hax
import TlsCodec.Extraction
import TlsCodec.Verification.Helpers
import TlsCodec.Verification.Std.Io
import TlsCodec.Verification.Std.Bridge
import TlsCodec.Verification.Std.Containers
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! ### `checked_len_fold`: the checked sum of the element sizes -/

/-- The remaining elements of a slice iterator (a function, so that `rw` / `simp` see a
type-correct term at `instances` transparency). -/
def iterList {T : Type} (it : core.slice.iter.Iter T) : List T := (it : Slice T).val

/-- One step of a slice iterator. -/
theorem slice_iter_next {T : Type} (it : core.slice.iter.Iter T) :
    ∃ o it', core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.next it = ok (o, it') ∧
      ((iterList it = [] ∧ o = core.option.Option.None) ∨
      ∃ x l, iterList it = x :: l ∧ o = core.option.Option.Some x ∧ iterList it' = l) := by
  unfold iterList
  simp only [core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.next,
    rust_primitives.sequence.seq_len, rust_primitives.sequence.seq_remove]
  by_cases hz : Slice.len it = 0#usize
  · have : (it : Slice T).val = [] := by
      rw [← List.length_eq_zero_iff]; scalar_tac
    simp [hz, this]
  · have hpos : 0 < (it : Slice T).val.length := by scalar_tac
    obtain ⟨x, l, hl⟩ : ∃ x l, (it : Slice T).val = x :: l := by
      cases h : (it : Slice T).val with
      | nil => rw [h] at hpos; simp at hpos
      | cons y l => exact ⟨y, l, rfl⟩
    simp [hz, hl]

theorem slice_iter_next_spec {T : Type} (it : core.slice.iter.Iter T) :
    ⦃ ⌜ True ⌝ ⦄ core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.next it
    ⦃ ⇓ p => ⌜ (iterList it = [] ∧ p.1 = core.option.Option.None) ∨
      ∃ x l, iterList it = x :: l ∧ p.1 = core.option.Option.Some x ∧ iterList p.2 = l ⌝ ⦄ := by
  obtain ⟨o, it', h, hp⟩ := slice_iter_next it
  rw [h]
  exact ok_triple_of hp

/-- The checked fold of a slice with exact size sum `N`: `Ok N` when `N` fits, an `Err` otherwise. -/
theorem checked_len_fold_spec {T : Type} {S : Size T} (hS : Size.Lawful T S) (xs : Slice T)
    {N : Nat} (hN : SizeNat S xs.val N) :
    ⦃ ⌜ True ⌝ ⦄ tls_codec.HandTranslated.checked_len_fold S.tls_serialized_len xs
    ⦃ ⇓ r => ⌜ (N ≤ Usize.max → ∃ c, r = .Ok c ∧ c.val = N) ∧
      (Usize.max < N → ∃ e, r = .Err e) ⌝ ⦄ := by
  unfold tls_codec.HandTranslated.checked_len_fold
  nth_rewrite 1 [slice_iter_ok]
  erw [bind_tc_ok]
  refine triple_post_mono (loop_total_spec (α := core.slice.iter.Iter T × Std.Usize) _ (⟨xs.val, xs.property⟩, 0#usize)
    (fun p => ∃ R, SizeNat S (iterList p.1) R ∧ p.2.val + R = N)
    (fun p => (iterList p.1).length)
    (fun y => (∀ c, y = .Ok c → N ≤ Usize.max ∧ c.val = N) ∧ (∀ e, y = .Err e → Usize.max < N))
    ⟨N, hN, by simp⟩ ?_) ?_
  · rintro ⟨it, a⟩ ⟨R, hR, hsum⟩
    simp only at hR hsum
    have hlen := Size.len_char S hS
    mvcgen [slice_iter_next_spec, hlen, checked_len_add_triple, tls_codec.Copied.checked_len_add_triple]
    · rename_i p e hpe hcase n hn r1 hr1 cf acc hcfe hcf
      rcases hcase with ⟨-, h1⟩ | ⟨x, l, h0, h1, h2⟩
      · rw [h1] at hpe; cases hpe
      · rw [h1] at hpe
        simp only [core.option.Option.Some, Option.some.injEq] at hpe
        subst hpe
        rw [h0] at hR
        cases hR with
        | cons _ _ n' R' hx hR' =>
          obtain rfl : n' = n := ok.inj (hx.symm.trans hn)
          by_cases hfit : a.val + n'.val ≤ Usize.max
          · rw [hr1, checkedLenAddRes_fits _ _ hfit] at hcf
            simp only [tryCF, core.ops.control_flow.ControlFlow.Continue.injEq] at hcf
            subst hcf
            have := checkedLenAddVal_val a n' hfit
            exact ⟨⟨R', by rw [h2]; exact hR', by omega⟩, by rw [h2, h0]; simp⟩
          · rw [hr1] at hcf
            simp [checkedLenAddRes, hfit, tryCF] at hcf
    · rename_i p e hpe hcase n hn r1 hr1 cf res hcfe hcf
      rcases hcase with ⟨-, h1⟩ | ⟨x, l, h0, h1, h2⟩
      · rw [h1] at hpe; cases hpe
      · rw [h1] at hpe
        simp only [core.option.Option.Some, Option.some.injEq] at hpe
        subst hpe
        rw [h0] at hR
        cases hR with
        | cons _ _ n' R' hx hR' =>
          obtain rfl : n' = n := ok.inj (hx.symm.trans hn)
          by_cases hfit : a.val + n'.val ≤ Usize.max
          · rw [hr1, checkedLenAddRes_fits _ _ hfit] at hcf
            cases hcf
          · have hov : Usize.max < N := by omega
            simp only [hr1, checkedLenAddRes, hfit, if_false, tryCF,
              core.ops.control_flow.ControlFlow.Break.injEq] at hcf
            subst hcf
            refine ⟨_, rfl, ?_⟩
            mvcgen [core.convert.From.Blanket.from_spec]
            intro _
            mvcgen
            exact ⟨fun c hc => (by cases hc), fun e _ => hov⟩
    · rename_i p hpn hcase
      rcases hcase with ⟨h0, -⟩ | ⟨x, l, h0, h1, -⟩
      · rw [h0] at hR; cases hR
        refine ⟨fun c hc => ?_, fun e he => by cases he⟩
        cases hc
        exact ⟨by scalar_tac, by omega⟩
      · rw [h1] at hpn; cases hpn
  · intro y ⟨hok, herr⟩
    cases y with
    | Ok c =>
      obtain ⟨hle, hc⟩ := hok c rfl
      exact ⟨fun _ => ⟨c, rfl, hc⟩, fun h => by omega⟩
    | Err e => exact ⟨fun h => by have := herr e rfl; omega, fun _ => ⟨e, rfl⟩⟩

/-- `len_add` is the saturating sum. -/
theorem lenAddVal_min (a b : Std.Usize) : (lenAddVal a b).val = min (a.val + b.val) Usize.max := by
  by_cases h : a.val + b.val ≤ Usize.max
  · rw [lenAddVal_val _ _ h]; omega
  · rw [lenAddVal_sat _ _ (by omega)]; omega

/-- The (saturating) size fold is the exact sum, capped at `Usize.max`. -/
theorem SizeFoldRel.val_min {T : Type} {S : Size T} {a : Std.Usize} {l : List T} {r : Std.Usize}
    (h : SizeFoldRel S a l r) {N : Nat} (hN : SizeNat S l N) :
    r.val = min (a.val + N) Usize.max := by
  induction h generalizing N with
  | nil a => cases hN; have := a.hBounds; scalar_tac
  | cons a x l n r hx _ ih =>
    rcases hN with _ | ⟨_, _, n2, N2, hx2, hN2⟩
    obtain rfl : n2 = n := (ok.inj (hx.symm.trans hx2)).symm
    rw [ih hN2, lenAddVal_min]
    omega

/-! ### `serialize_elements`: the element loop -/

/-- The concatenated encodings of a list of elements (`none`: one of them is not encodable). -/
noncomputable def encAll {T : Type} (SI : Serialize T) : List T → Option (List Std.U8)
  | [] => some []
  | x :: l => (encOut SI x).bind fun b => (encAll SI l).map (b ++ ·)

theorem encAll_append {T : Type} (SI : Serialize T) (l1 l2 : List T) :
    encAll SI (l1 ++ l2) = (encAll SI l1).bind fun a => (encAll SI l2).map (a ++ ·) := by
  induction l1 with
  | nil => cases h : encAll SI l2 <;> simp [encAll, h]
  | cons x l ih =>
    simp only [List.cons_append, encAll, ih]
    cases encOut SI x with
    | none => simp
    | some b =>
      cases encAll SI l with
      | none => simp
      | some a => cases encAll SI l2 <;> simp

/-- An element's serializer as a triple with its room as precondition (for `mvcgen`). -/
theorem Serialize.Lawful.elem_spec {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    {W : Type} (WI : core.io.write.Write W) (hWI : core.io.write.Write.Lawful W WI)
    (x : T) (w : W) :
    ⦃ ⌜ ∀ sz, SI.SizeInst.tls_serialized_len x = ok sz →
        (core.io.write.Write.view WI w).length + sz.val ≤ imax ⌝ ⦄ SI.tls_serialize WI x w
    ⦃ ⇓ p => ⌜ (∀ b, encOut SI x = some b → (∃ n : Std.Usize, p.1 = .Ok n ∧ n.val = b.length) ∧
        core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w ++ b) ∧
      (encOut SI x = none → ∃ e, p.1 = .Err e) ⌝ ⦄ := by
  obtain ⟨sz, hsz⟩ := Size.lawful_ok _ hL.SizeInstLawful x
  intro hroom
  exact SerRuns.spec' (hL.runs x sz hsz) WI hWI w (hroom sz hsz)

/-- The postcondition of an element's serializer (`Serialize.Lawful.elem_spec`). -/
def ElemPost {T W : Type} (SI : Serialize T) (WI : core.io.write.Write W) (x : T) (w : W)
    (q : core.result.Result Std.Usize Error × W) : Prop :=
  (∀ b, encOut SI x = some b → (∃ n : Std.Usize, q.1 = .Ok n ∧ n.val = b.length) ∧
    core.io.write.Write.view WI q.2 = core.io.write.Write.view WI w ++ b) ∧
  (encOut SI x = none → ∃ e, q.1 = .Err e)

/-- Loop invariant of `serialize_elements`: the first `i` elements are written (`bs` their
encodings), `R` is the size of the others, `N` the total size. -/
def ElemsInv {T W : Type} (SI : Serialize T) (WI : core.io.write.Write W) (w : W) (s : List T)
    (N : Nat) (p : W × Std.Usize × Std.Usize) : Prop :=
  p.2.2.val ≤ s.length ∧ ∃ bs R, encAll SI (s.take p.2.2.val) = some bs ∧
    core.io.write.Write.view WI p.1 = core.io.write.Write.view WI w ++ bs ∧
    p.2.1.val = bs.length ∧ SizeNat SI.SizeInst (s.drop p.2.2.val) R ∧ bs.length + R = N

theorem encAll_take_succ {T : Type} (SI : Serialize T) (s : List T) (i : Nat) (hlt : i < s.length) :
    encAll SI (s.take (i + 1)) =
      (encAll SI (s.take i)).bind fun a => (encOut SI s[i]).map (a ++ ·) := by
  rw [List.take_add_one, List.getElem?_eq_getElem hlt, encAll_append]
  cases h1 : encAll SI (s.take i) <;> cases h2 : encOut SI s[i] <;> simp [encAll, h2]

/-- Once the written prefix is encodable and the next element is not, the whole list is not. -/
theorem encAll_none_of_elem {T : Type} (SI : Serialize T) (s : List T) (i : Nat) (hlt : i < s.length)
    (bs : List Std.U8) (hbs : encAll SI (s.take i) = some bs) (hn : encOut SI s[i] = none) :
    encAll SI s = none := by
  rw [← List.take_append_drop i s, encAll_append, hbs, List.drop_eq_getElem_cons hlt]
  simp [encAll, hn]

section ElemsLoop
variable {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI) {W : Type}
  (WI : core.io.write.Write W) (hWI : core.io.write.Write.Lawful W WI)

include hL hWI in
theorem ser_elems_body (w : W) (s : Slice T) (N : Nat) (p : W × Std.Usize × Std.Usize)
    (hp : ElemsInv SI WI w s.val N p) (hroom : (core.io.write.Write.view WI w).length + N ≤ imax) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.serialize_elements_loop.body SI WI s p.1 p.2.1 p.2.2
    ⦃ ⇓ r => ⌜ match r with
      | .done y => (y.2.2 = core.option.Option.None → ∃ bs, encAll SI s.val = some bs ∧
          core.io.write.Write.view WI y.1 = core.io.write.Write.view WI w ++ bs ∧
          y.2.1.val = N ∧ bs.length = N) ∧
        (∀ err, y.2.2 = core.option.Option.Some err → encAll SI s.val = none)
      | .cont p' => ElemsInv SI WI w s.val N p' ∧ s.val.length - p'.2.2.val < s.val.length - p.2.2.val
      ⌝ ⦄ := by
  obtain ⟨wr, wn, i⟩ := p
  obtain ⟨hi, bs, R, hbs, hv, hwn, hR, hbsR⟩ := hp
  dsimp only at hi hbs hv hwn hR
  have hT := fun x w' => Serialize.Lawful.elem_spec hL WI hWI x w'
  -- the element at `i` has a size, and the sizes of the others add up
  have hstep : ∀ hlt : i.val < s.val.length, ∃ sz R', SI.SizeInst.tls_serialized_len s.val[i.val] = ok sz ∧
      SizeNat SI.SizeInst (s.val.drop (i.val + 1)) R' ∧ R = sz.val + R' := by
    intro hlt
    rw [List.drop_eq_getElem_cons hlt] at hR
    cases hR with
    | cons _ _ sz R' hsz hR' => exact ⟨sz, R', hsz, hR', rfl⟩
  -- an `Ok` element: its size, its encoding, the writer
  have hok : ∀ (x : T) (sz : Std.Usize) (q : core.result.Result Std.Usize Error × W) (n : Std.Usize),
      SI.SizeInst.tls_serialized_len x = ok sz →
      (core.io.write.Write.view WI wr).length + sz.val ≤ imax → q.1 = .Ok n →
      ElemPost SI WI x wr q →
      n.val = sz.val ∧ ∃ b, encOut SI x = some b ∧ b.length = sz.val ∧
        core.io.write.Write.view WI q.2 = core.io.write.Write.view WI wr ++ b := by
    intro x sz q n hsz hr hqn hq
    cases hb : encOut SI x with
    | none => obtain ⟨e, he⟩ := hq.2 hb; rw [hqn] at he; cases he
    | some b =>
      obtain ⟨⟨n', hn', hnb⟩, hv'⟩ := hq.1 b hb
      rw [hqn] at hn'; cases hn'
      have := hL.enc_len x sz hsz (by have := imax_le; omega) b hb
      exact ⟨by omega, b, rfl, this, hv'⟩
  mvcgen [tls_vec.serialize_elements_loop.body, hT]
  · -- room for the element
    rename_i r1 hlt hr1 x hx
    obtain ⟨hlt', rfl⟩ := hx
    intro sz hsz
    obtain ⟨sz', R', hsz', -, hRs⟩ := hstep hlt'
    obtain rfl : sz' = sz := (ok.inj (hsz'.symm.trans hsz))
    rw [hv]; simp only [List.length_append]; omega
  · -- `Ok n`: the element is written
    rename_i r4 hlt hr4 x hx q n hqn hq w1 hw1 i2 hi2
    obtain ⟨hlt', rfl⟩ := hx
    obtain ⟨sz, R', hsz, hR', hRs⟩ := hstep hlt'
    have hroomx : (core.io.write.Write.view WI wr).length + sz.val ≤ imax := by
      rw [hv]; simp only [List.length_append]; omega
    obtain ⟨hn, b, hb, hbl, hqv⟩ := hok _ sz q n hsz hroomx hqn hq
    have hi2' : i2.val = i.val + 1 := by rw [hi2]; rfl
    have hlt'' : i.val < s.val.length := hlt'
    refine ⟨⟨by dsimp only; omega, bs ++ b, R', ?_, ?_, ?_, ?_, ?_⟩,
      (by show s.val.length - i2.val < s.val.length - i.val; omega)⟩
    · rw [hi2', encAll_take_succ _ _ _ hlt', hbs]; simp [hb]
    · rw [hqv, hv, List.append_assoc]
    · rw [hw1, hn] at *; simp only [List.length_append]; omega
    · rw [hi2']; exact hR'
    · simp only [List.length_append]; omega
  · -- the position counter does not overflow
    rename_i r hlt hr x hx q n hqn hq w1 hw1 hov
    exfalso
    obtain ⟨hlt', rfl⟩ := hx
    scalar_tac
  · -- the written total does not overflow
    rename_i r hlt hr x hx q n hqn hq hov
    exfalso
    obtain ⟨hlt', rfl⟩ := hx
    obtain ⟨sz, R', hsz, hR', hRs⟩ := hstep hlt'
    have hroomx : (core.io.write.Write.view WI wr).length + sz.val ≤ imax := by
      rw [hv]; simp only [List.length_append]; omega
    obtain ⟨hn, -⟩ := hok _ sz q n hsz hroomx hqn hq
    have := imax_le
    have hm : UScalar.max UScalarTy.Usize = Usize.max := by
      simp [UScalar.max, Usize.max, Usize.numBits]
    rw [hm] at hov
    rw [hv] at hroomx
    simp only [List.length_append] at hroomx
    omega
  · -- the element is not encodable
    rename_i r hlt hr x hx q err herr hq
    obtain ⟨hlt', rfl⟩ := hx
    refine ⟨fun h => (by cases h), fun err' _ => ?_⟩
    cases hb : encOut SI s.val[i.val] with
    | some b =>
      obtain ⟨⟨n, hn, -⟩, -⟩ := hq.1 b hb
      rw [herr] at hn; cases hn
    | none => exact encAll_none_of_elem SI _ _ hlt' bs hbs hb
  · -- index out of range
    rename_i r hlt hr hge
    exfalso; scalar_tac
  · -- all elements written
    rename_i r hnlt hr
    have hile : i.val = s.val.length := by scalar_tac
    rw [hile, List.drop_length] at hR
    cases hR
    rw [hile, List.take_length] at hbs
    exact ⟨⟨bs, hbs, hv, by omega, by omega⟩, fun err h => (by cases h)⟩

include hL hWI in
theorem ser_elems_loop (w : W) (s : Slice T) (N : Nat) (hN : SizeNat SI.SizeInst s.val N)
    (hroom : (core.io.write.Write.view WI w).length + N ≤ imax) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.serialize_elements_loop SI WI s w 0#usize 0#usize
    ⦃ ⇓ y => ⌜ (y.2.2 = core.option.Option.None → ∃ bs, encAll SI s.val = some bs ∧
          core.io.write.Write.view WI y.1 = core.io.write.Write.view WI w ++ bs ∧
          y.2.1.val = N ∧ bs.length = N) ∧
        (∀ err, y.2.2 = core.option.Option.Some err → encAll SI s.val = none) ⌝ ⦄ := by
  unfold tls_vec.serialize_elements_loop
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.loop.spec_decr_nat
    (fun q : W × Std.Usize × Std.Usize => s.val.length - q.2.2.val)
    (ElemsInv SI WI w s.val N)
  · rintro ⟨wr, wn, i⟩ hq
    have := ser_elems_body hL WI hWI w s N _ hq hroom
    obtain ⟨y, hy, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp this
    show Aeneas.Std.WP.spec (tls_vec.serialize_elements_loop.body SI WI s wr wn i) _
    rw [hy, Aeneas.Std.WP.spec_ok]
    cases y with
    | done y => exact hP
    | cont q => exact hP
  · exact ⟨by simp, [], N, by simp [encAll], by simp, by simp, by simpa using hN, by simp⟩

include hL hWI in
/-- The element loop on a lawful writer with room for the exact total size `N`: it appends the
concatenation of the elements' encodings and returns `Ok N`, or an `Err` if one is not encodable. -/
theorem serialize_elements_spec (w : W) (s : Slice T) (N : Nat)
    (hN : SizeNat SI.SizeInst s.val N)
    (hroom : (core.io.write.Write.view WI w).length + N ≤ imax) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.serialize_elements SI WI s w
    ⦃ ⇓ p => ⌜ (∀ bs, encAll SI s.val = some bs → (∃ n : Std.Usize, p.1 = .Ok n ∧ n.val = N) ∧
        core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w ++ bs ∧ bs.length = N) ∧
      (encAll SI s.val = none → ∃ e, p.1 = .Err e) ⌝ ⦄ := by
  have hl := ser_elems_loop hL WI hWI w s N hN hroom
  mvcgen [tls_vec.serialize_elements, hl]
  · rename_i y hnone hy
    obtain ⟨bs, hbs, hv, hn, hbl⟩ := hy.1 hnone
    refine ⟨fun bs' hbs' => ?_, fun hn' => by rw [hbs] at hn'; cases hn'⟩
    rw [hbs] at hbs'; cases hbs'
    exact ⟨⟨_, rfl, hn⟩, hv, hbl⟩
  · rename_i y e hsome hy
    have hnone := hy.2 e hsome
    exact ⟨fun bs hbs => (by rw [hnone] at hbs; cases hbs), fun _ => ⟨e, rfl⟩⟩

end ElemsLoop

/-! ### `Vec<T>`: the serializer -/

/-- ASSUMED here (proved from the varint lemmas elsewhere): `write_length` on a lawful writer with
room, for an encoder `enc` of lengths (`(enc m).length = varint.lenOf m`): for `n ≤ 2^30 - 1` it
returns `Ok (lenOf n)` and appends `enc n`, for a larger `n` it returns an `Err`. -/
def WriteLengthRuns (enc : Nat → List Std.U8) : Prop :=
  (∀ m, (enc m).length = varint.lenOf m) ∧
  ∀ (W : Type) (WI : core.io.write.Write W), core.io.write.Write.Lawful W WI →
    ∀ (w : W) (n : Std.Usize), (core.io.write.Write.view WI w).length + 8 ≤ Usize.max →
    ⦃ ⌜ True ⌝ ⦄ quic_vec.rw.write_length WI w n
    ⦃ ⇓ p => ⌜ (n.val ≤ 2 ^ 30 - 1 → (∃ l : Std.Usize, p.1 = .Ok l ∧ l.val = varint.lenOf n.val) ∧
        core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w ++ enc n.val) ∧
      (2 ^ 30 - 1 < n.val → ∃ e, p.1 = .Err e) ⌝ ⦄

/-- The encoding of a vector whose elements have total size `N`: the length prefix, then the
elements (`none`: the content length is not encodable, or an element is not). -/
noncomputable def vecOut {T : Type} (enc : Nat → List Std.U8) (SI : Serialize T) (l : List T)
    (N : Nat) : Option (List Std.U8) :=
  if N ≤ 2 ^ 30 - 1 then (encAll SI l).map (enc N ++ ·) else none

/-- The size of a vector, from its exact content size `N`, when the writer has room for it. -/
theorem Vec.size_exact {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (v : alloc.vec.Vec T) (sz : Std.Usize)
    (hsz : (alloc.vec.Vec.Insts.Tls_codecSize SI.SizeInst).tls_serialized_len v = ok sz)
    {N : Nat} (hN : SizeNat SI.SizeInst v.val N) :
    ∃ c, SizeFoldRel SI.SizeInst 0#usize v.val c ∧ c.val = min N Usize.max ∧
      sz.val = min (c.val + (if c.val ≤ 2 ^ 30 - 1 then varint.lenOf c.val else 0)) Usize.max := by
  obtain ⟨sz', hsz', c, ll, hrel, hr, hll⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (alloc.vec.Vec.size_rel SI.SizeInst hL.SizeInstLawful v)
  obtain rfl : sz' = sz := ok.inj (hsz'.symm.trans hsz)
  refine ⟨c, hrel, by simpa using hrel.val_min hN, ?_⟩
  rw [hr, lenAddVal_min, hll]

/-- The room arithmetic of a vector: for a content size `N ≤ 2^30 - 1` the size is exactly
`N + L N` (no saturation, since the writer has room for it). -/
theorem vec_room (L : Nat → Nat) {N c sz vl : Nat} (hc : c = min N Usize.max)
    (hsz : sz = min (c + if c ≤ 2 ^ 30 - 1 then L c else 0) Usize.max) (hroom : vl + sz ≤ imax)
    (hN : N ≤ 2 ^ 30 - 1) : vl + L N + N ≤ imax ∧ sz = N + L N := by
  have h1 := imax_eq
  have h2 := imax_ge
  obtain rfl : c = N := by omega
  rw [if_pos hN] at hsz
  omega

theorem vecOut_none_big {T : Type} (enc : Nat → List Std.U8) (SI : Serialize T) (l : List T)
    {N : Nat} (h : 2 ^ 30 - 1 < N) : vecOut enc SI l N = none := by
  unfold vecOut
  rw [if_neg (by omega)]

theorem vecOut_none_enc {T : Type} (enc : Nat → List Std.U8) (SI : Serialize T) (l : List T)
    (N : Nat) (h : encAll SI l = none) : vecOut enc SI l N = none := by
  simp [vecOut, h]

/-- The content length computed by `checked_content_length` is the exact content size `N`. -/
theorem vec_val {N : Nat} (r1 : core.result.Result Std.Usize Error) (val : Std.Usize)
    (hr1 : (N ≤ Usize.max → ∃ c, r1 = .Ok c ∧ c.val = N) ∧
      (Usize.max < N → ∃ e, r1 = .Err e))
    (hcf : core.ops.control_flow.ControlFlow.Continue val = tryCF r1) : val.val = N := by
  have hr1' := continue_eq_tryCF.mp hcf
  obtain ⟨hA, hB⟩ := hr1
  by_cases hN : N ≤ Usize.max
  · obtain ⟨c', hc', hcN⟩ := hA hN
    rw [hr1'] at hc'; cases hc'; exact hcN
  · obtain ⟨e, he⟩ := hB (by omega)
    rw [hr1'] at he; cases he

/-- After the content length `val` was computed and `write_length` succeeded on it: `val` is the
exact content size `N`, which fits a length prefix. -/
theorem vec_prefix {W : Type} {WI : core.io.write.Write W} {enc : Nat → List Std.U8} {w : W}
    {N : Nat} (r1 : core.result.Result Std.Usize Error) (val : Std.Usize)
    (hr1 : (N ≤ Usize.max → ∃ c, r1 = .Ok c ∧ c.val = N) ∧
      (Usize.max < N → ∃ e, r1 = .Err e))
    (hcf : core.ops.control_flow.ControlFlow.Continue val = tryCF r1)
    (wr : core.result.Result Std.Usize Error × W)
    (hwr : (val.val ≤ 2 ^ 30 - 1 → (∃ l : Std.Usize, wr.1 = .Ok l ∧ l.val = varint.lenOf val.val) ∧
        core.io.write.Write.view WI wr.2 = core.io.write.Write.view WI w ++ enc val.val) ∧
      (2 ^ 30 - 1 < val.val → ∃ e, wr.1 = .Err e))
    (val1 : Std.Usize) (hcf1 : core.ops.control_flow.ControlFlow.Continue val1 = tryCF wr.1) :
    val.val = N ∧ N ≤ 2 ^ 30 - 1 ∧ val1.val = varint.lenOf N := by
  have hval := vec_val r1 val hr1 hcf
  have hwr' := continue_eq_tryCF.mp hcf1
  have hv30 : val.val ≤ 2 ^ 30 - 1 := by
    by_contra hn
    obtain ⟨e, he⟩ := hwr.2 (by omega)
    rw [hwr'] at he; cases he
  obtain ⟨⟨l, hl, hlv⟩, -⟩ := hwr.1 hv30
  rw [hwr'] at hl; cases hl
  exact ⟨hval, hval ▸ hv30, hval ▸ hlv⟩

theorem Vec.ser_runs {enc : Nat → List Std.U8} (hW : WriteLengthRuns enc) {T : Type}
    {SI : Serialize T} (DbgI : core.fmt.Debug T) (hL : Serialize.Lawful T SI)
    (v : alloc.vec.Vec T) (sz : Std.Usize)
    (hsz : (alloc.vec.Vec.Insts.Tls_codecSize SI.SizeInst).tls_serialized_len v = ok sz)
    {N : Nat} (hN : SizeNat SI.SizeInst v.val N) :
    SerRuns (alloc.vec.Vec.Insts.Tls_codecSerialize SI DbgI) v sz (vecOut enc SI v.val N) := by
  intro W WI hWI w hroom
  have himax := imax_eq
  have hge := imax_ge
  obtain ⟨c, hrel, hc, hszv⟩ := Vec.size_exact hL v sz hsz hN
  suffices H : ⦃ ⌜ True ⌝ ⦄ (alloc.vec.Vec.Insts.Tls_codecSerialize SI DbgI).tls_serialize WI v w
      ⦃ ⇓ p => ⌜ (∀ b, vecOut enc SI v.val N = some b →
          (∃ n : Std.Usize, p.1 = .Ok n ∧ n.val = b.length) ∧
          core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w ++ b) ∧
        (vecOut enc SI v.val N = none → ∃ e, p.1 = .Err e) ⌝ ⦄ by
    obtain ⟨⟨r, w'⟩, h1, h2⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp H
    exact ⟨r, w', h1, h2⟩
  have hcc : ∀ s : Slice T, ⦃ ⌜ s = (v : Slice T) ⌝ ⦄ quic_vec.rw.checked_content_length SI.SizeInst s
      ⦃ ⇓ r => ⌜ (N ≤ Usize.max → ∃ c, r = .Ok c ∧ c.val = N) ∧
        (Usize.max < N → ∃ e, r = .Err e) ⌝ ⦄ := by
    intro s hs
    subst hs
    exact checked_len_fold_spec hL.SizeInstLawful _ hN trivial
  have hwl : ∀ (w' : W) (n : Std.Usize),
      ⦃ ⌜ (core.io.write.Write.view WI w').length + 8 ≤ Usize.max ⌝ ⦄
        quic_vec.rw.write_length WI w' n
      ⦃ ⇓ p => ⌜ (n.val ≤ 2 ^ 30 - 1 → (∃ l : Std.Usize, p.1 = .Ok l ∧ l.val = varint.lenOf n.val) ∧
          core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w' ++ enc n.val) ∧
        (2 ^ 30 - 1 < n.val → ∃ e, p.1 = .Err e) ⌝ ⦄ :=
    by intro w' n hr; exact hW.2 W WI hWI w' n hr trivial
  have hel : ∀ (s : Slice T) (w' : W),
      ⦃ ⌜ s = (v : Slice T) ∧ (core.io.write.Write.view WI w').length + N ≤ imax ⌝ ⦄
        tls_vec.serialize_elements SI WI s w'
      ⦃ ⇓ p => ⌜ (∀ bs, encAll SI v.val = some bs → (∃ n : Std.Usize, p.1 = .Ok n ∧ n.val = N) ∧
          core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w' ++ bs ∧ bs.length = N) ∧
        (encAll SI v.val = none → ∃ e, p.1 = .Err e) ⌝ ⦄ :=
    by intro s w' ⟨hs, hr⟩; subst hs; exact serialize_elements_spec hL WI hWI w' _ N hN hr trivial
  mvcgen [alloc.vec.Vec.Insts.Tls_codecSerialize.tls_serialize,
    Shared0Slice.Insts.Tls_codecSerialize.tls_serialize, hcc, hwl, hel, checked_len_add_triple, tls_codec.Copied.checked_len_add_triple]
  · -- room for `write_length`
    rename_i s hs r1 hr1 cf val hx hcf
    omega
  · -- room for the elements
    rename_i s hs r1 hr1 cf val hx hcf wr hwr cf1 val1 hx1 hcf1
    obtain ⟨hval, hv30, hl⟩ := vec_prefix r1 val hr1 hcf wr hwr val1 hcf1
    refine ⟨hs, ?_⟩
    obtain ⟨h1, -⟩ := vec_room varint.lenOf hc hszv hroom hv30
    rw [(hwr.1 (by omega)).2]
    simp only [List.length_append, hW.1, hval]
    omega
  · -- the written total differs from the content length: impossible
    rename_i s hs r1 hr1 cf val hx hcf wr hwr cf1 val1 hx1 hcf1 er her cf2 val2 hx2 hne hcf2
    exfalso
    have hval := vec_val r1 val hr1 hcf
    have hcf2' := continue_eq_tryCF.mp hcf2
    cases hb : encAll SI v.val with
    | none => obtain ⟨e, he⟩ := her.2 hb; rw [hcf2'] at he; cases he
    | some bs =>
      obtain ⟨⟨n, hn, hnN⟩, -⟩ := her.1 bs hb
      rw [hcf2'] at hn; cases hn
      obtain rfl : val2 = val := UScalar.eq_of_val_eq (by omega)
      simp at hne
  · -- the result
    rename_i s hs r1 hr1 cf val hx hcf wr hwr cf1 val1 hx1 hcf1 er her cf2 val2 hx2 hnne hcf2 r3 hr3
    obtain ⟨hval, hv30, hl⟩ := vec_prefix r1 val hr1 hcf wr hwr val1 hcf1
    have hcf2' := continue_eq_tryCF.mp hcf2
    cases hb : encAll SI v.val with
    | none => exfalso; obtain ⟨e, he⟩ := her.2 hb; rw [hcf2'] at he; cases he
    | some bs =>
      obtain ⟨⟨n, hn, hnN⟩, hver, hbsN⟩ := her.1 bs hb
      rw [hcf2'] at hn; cases hn
      obtain ⟨h1, h2⟩ := vec_room varint.lenOf hc hszv hroom hv30
      have hfit : val.val + val1.val ≤ Usize.max := by
        have := imax_eq; omega
      have hvo : vecOut enc SI v.val N = some (enc N ++ bs) := by unfold vecOut; rw [if_pos hv30, hb]; rfl
      rw [hvo]
      refine ⟨fun b hb' => ?_, fun h => (by cases h)⟩
      cases hb'
      rw [hr3, checkedLenAddRes_fits _ _ hfit]
      refine ⟨⟨_, rfl, ?_⟩, ?_⟩
      · rw [checkedLenAddVal_val _ _ hfit]; simp only [List.length_append, hW.1]; omega
      · rw [hver, (hwr.1 (by omega)).2, hval, List.append_assoc]
  · -- `Err` from the elements
    rename_i s hs r1 hr1 cf val hx hcf wr hwr cf1 val1 hx1 hcf1 er her cf2 res hx2 hcf2
    refine try_break_vc (x := er.1) (fun e he => ?_) hcf2
    have hvn : vecOut enc SI v.val N = none := by
      cases hb : encAll SI v.val with
      | none => exact vecOut_none_enc _ _ _ _ hb
      | some bs => obtain ⟨⟨n, hn, -⟩, -⟩ := her.1 bs hb; rw [he] at hn; cases hn
    mvcgen
    intro _
    mvcgen
    exact ⟨fun b hb' => (by rw [hvn] at hb'; cases hb'), fun _ => ⟨_, rfl⟩⟩
  · -- `Err` from `write_length`
    rename_i s hs r1 hr1 cf val hx hcf wr hwr cf1 res hx1 hcf1
    refine try_break_vc (x := wr.1) (fun e he => ?_) hcf1
    have hval := vec_val r1 val hr1 hcf
    have hvn : vecOut enc SI v.val N = none := by
      by_cases hN : N ≤ 2 ^ 30 - 1
      · obtain ⟨⟨l, hl, -⟩, -⟩ := hwr.1 (by omega); rw [he] at hl; cases hl
      · exact vecOut_none_big _ _ _ (by omega)
    mvcgen
    intro _
    mvcgen
    exact ⟨fun b hb' => (by rw [hvn] at hb'; cases hb'), fun _ => ⟨_, rfl⟩⟩
  · -- `Err` from the content length
    rename_i s hs r1 hr1 cf res hx hcf
    refine try_break_vc (x := r1) (fun e he => ?_) hcf
    have hvn : vecOut enc SI v.val N = none := by
      by_cases hN : N ≤ Usize.max
      · obtain ⟨c', hc', -⟩ := hr1.1 hN; rw [he] at hc'; cases hc'
      · exact vecOut_none_big _ _ _ (by omega)
    mvcgen
    intro _
    mvcgen
    exact ⟨fun b hb' => (by rw [hvn] at hb'; cases hb'), fun _ => ⟨_, rfl⟩⟩

theorem SizeNat.exists {T : Type} {S : Size T} (hS : Size.Lawful T S) (l : List T) :
    ∃ N, SizeNat S l N := by
  induction l with
  | nil => exact ⟨0, .nil⟩
  | cons x l ih =>
    obtain ⟨n, hn⟩ := Size.lawful_ok S hS x
    obtain ⟨N, hN⟩ := ih
    exact ⟨_, .cons x l n N hn hN⟩

/-- The concatenated encodings of elements of total size `N` (with room for it) have length `N`. -/
theorem encAll_length {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI) {l : List T}
    {N : Nat} (hN : SizeNat SI.SizeInst l N) (hroom : N ≤ imax) :
    ∀ bs, encAll SI l = some bs → bs.length = N := by
  induction hN with
  | nil => intro bs h; simp [encAll] at h; subst h; rfl
  | cons x l n N hx hl ih =>
    intro bs h
    cases hb : encOut SI x with
    | none => simp [encAll, hb] at h
    | some b =>
      cases hb' : encAll SI l with
      | none => simp [encAll, hb, hb'] at h
      | some bs' =>
        simp [encAll, hb, hb'] at h
        subst h
        have h1 := hL.enc_len x n hx (by omega) b hb
        have h2 := ih (by omega) bs' hb'
        simp only [List.length_append]
        omega

theorem Vec.ser_spec {enc : Nat → List Std.U8} (hW : WriteLengthRuns enc) {T : Type}
    {SI : Serialize T} (DbgI : core.fmt.Debug T) (hL : Serialize.Lawful T SI) {W : Type}
    (WI : core.io.write.Write W) (hWI : core.io.write.Write.Lawful W WI)
    (v : alloc.vec.Vec T) (w : W)
    (hpre : (Serialize.tls_serialize.pre WI (alloc.vec.Vec.Insts.Tls_codecSerialize SI DbgI).SizeInst
      (alloc.vec.Vec.Insts.Tls_codecSerialize SI DbgI) v w).holds) :
    ⦃ ⌜ True ⌝ ⦄ (alloc.vec.Vec.Insts.Tls_codecSerialize SI DbgI).tls_serialize WI v w
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize.post WI
      (alloc.vec.Vec.Insts.Tls_codecSerialize SI DbgI).SizeInst
      (alloc.vec.Vec.Insts.Tls_codecSerialize SI DbgI) v w r).holds ⌝ ⦄ := by
  obtain ⟨N, hN⟩ := SizeNat.exists hL.SizeInstLawful v.val
  obtain ⟨sz, hsz, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (alloc.vec.Vec.size_rel SI.SizeInst hL.SizeInstLawful v)
  have hsz' : (alloc.vec.Vec.Insts.Tls_codecSize SI.SizeInst).tls_serialized_len v = ok sz := hsz
  refine Serialize.tls_serialize_spec_of_runs' _ v sz hsz' (vecOut enc SI v.val N) ?_
    (Vec.ser_runs hW DbgI hL v sz hsz' hN) WI hWI w hpre
  intro hle b hb
  have h1 := imax_eq
  have h2 := imax_ge
  obtain ⟨c, -, hc, hszv⟩ := Vec.size_exact hL v sz hsz' hN
  unfold vecOut at hb
  split at hb
  · rename_i hN30
    obtain ⟨-, hszN⟩ := vec_room varint.lenOf (vl := 0) hc hszv (by omega) hN30
    cases hbs : encAll SI v.val with
    | none => simp [hbs] at hb
    | some bs =>
      simp only [hbs, Option.map_some, Option.some.injEq] at hb
      subst hb
      have := encAll_length hL hN (by omega) bs hbs
      simp only [List.length_append, hW.1]
      omega
  · cases hb

end tls_codec
