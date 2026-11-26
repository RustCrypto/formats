/- The round trip of `Vec<T>` (`RoundTripStd`, `NonEmptyStd`) from the elements' contracts. The
decoding loop reads the elements from a `Take` of the reader; an element's own round trip
(instantiated at the `Take`) gives it back and leaves the encodings of the next ones.

Obligations: none directly; the `std`-path halves (`Serialize` / `Deserialize` `Lawful` fields,
lemma traits) of `PanicFreedom.lean` / `FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): nothing ASSUMED; 1 signature-only stub
(`core.io.error.Error.Insts.CoreFmtDebug.fmt`); `native_decide` (1). -/
import TlsCodec.Verification.Std.VecVarInt
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! ### From a `RoundTripStd` contract to `DecodesTo` -/

/-- The `requires` of `round_trip_std`, from the reader's view. -/
theorem spec.io.RoundTripStd.round_trip_std.pre_intro {T R : Type} (RT : spec.io.RoundTripStd T)
    (RI : alloc.io.read.Read R) (x : T) (bv : alloc.vec.Vec Std.U8) (reader : R)
    (rest : Slice Std.U8) (henc : spec.io.encode RT.SerializeInst x = ok (.Ok bv))
    (hv : alloc.io.read.Read.view RI reader = (bv : Slice Std.U8).val ++ rest.val) :
    (spec.io.RoundTripStd.round_trip_std.pre RI RT.SerializeInst RT.DeserializeInst
      RT.corecmpPartialEqInst RT x reader rest).holds := by
  unfold spec.io.RoundTripStd.round_trip_std.pre RustM.holds
  mvcgen [henc, core.result.Result.is_ok_and, spec.io.stream, spec.io.is_concat,
    spec.io._.requires.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.call_once,
    alloc.vec.Vec.Insts.CoreOpsDerefDerefSlice.deref, alloc.vec.Vec.as_slice]
  simp [hv]

/-- What the `ensures` of `round_trip_std` gives: the deserializer returns `x` and leaves `rest`. -/
theorem spec.io.RoundTripStd.round_trip_std.post_elim {T R : Type} (RT : spec.io.RoundTripStd T)
    (hEq : core.cmp.PartialEq.Lawful T T RT.corecmpPartialEqInst)
    (RI : alloc.io.read.Read R) (x : T) (reader : R) (rest : Slice Std.U8)
    (h : (spec.io.RoundTripStd.round_trip_std.post RI RT.SerializeInst RT.DeserializeInst
      RT.corecmpPartialEqInst RT x reader rest ()).holds) :
    ∃ after, RT.DeserializeInst.tls_deserialize RI reader = ok (.Ok x, after) ∧
      alloc.io.read.Read.view RI after = rest.val := by
  cases hd : RT.DeserializeInst.tls_deserialize RI reader with
  | fail e =>
    obtain ⟨q, hq, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp h
    simp [spec.io.RoundTripStd.round_trip_std.post, spec.io.decode_std, hd, Functor.map] at hq
  | div =>
    obtain ⟨q, hq, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp h
    simp [spec.io.RoundTripStd.round_trip_std.post, spec.io.decode_std, hd, Functor.map] at hq
  | ok p =>
    obtain ⟨res, after⟩ := p
    refine ⟨after, ?_⟩
    have heq := fun o => hEq.eq_spec o x
    apply holds_imp' h
    unfold spec.io.RoundTripStd.round_trip_std.post
    mvcgen [spec.io.decode_std, hd, core.result.Result.is_ok_and, spec.io.stream,
      spec.io.__1.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleSelf_Bool.call_once,
      alloc.vec.Vec.as_slice, slice_eq_U8_spec, heq]
    · rename_i t _ b1 hb1 hiff b2 hb2
      intro hb
      subst hb1 hb
      have := eq_of_heq (hiff.mp rfl)
      subst this
      exact ⟨rfl, by simpa using hb2⟩
    · intro h; cases h
    · intro h; cases h

/-- A lawful `RoundTripStd` decodes every encoding it produces, on every lawful reader. -/
theorem spec.io.RoundTripStd.Lawful.decodes {T : Type} {RT : spec.io.RoundTripStd T}
    (hRT : spec.io.RoundTripStd.Lawful T RT) (x : T) (bv : alloc.vec.Vec Std.U8)
    (henc : spec.io.encode RT.SerializeInst x = ok (.Ok bv)) :
    DecodesTo RT.DeserializeInst (bv : Slice Std.U8).val x := by
  intro R RI v a law r rest hv
  have hRI : alloc.io.read.Read.Lawful R RI := ⟨⟨v, a, law⟩⟩
  have hvr := StdIo.view_eq law
  have hlen : rest.length ≤ Usize.max := by
    have := law.view_le r; rw [hv, List.length_append] at this; omega
  let rs : Slice Std.U8 := ⟨rest, hlen⟩
  have hpre := spec.io.RoundTripStd.round_trip_std.pre_intro RT RI x bv r rs henc
    (by rw [hvr, hv])
  obtain ⟨u, -, hpost⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (hRT.round_trip_std_spec RI hRI x r rs hpre)
  obtain ⟨after, hd, hva⟩ := spec.io.RoundTripStd.round_trip_std.post_elim RT
    hRT.corecmpPartialEqInstLawful RI x r rs hpost
  rw [hd]
  exact ok_triple_of ⟨rfl, by rw [← hvr]; exact hva⟩

/-- A lawful `NonEmptyStd`'s encodings are non-empty. -/
theorem spec.io.NonEmptyStd.Lawful.nonempty {T : Type} {NE : spec.io.NonEmptyStd T}
    (h : spec.io.NonEmptyStd.Lawful T NE) (x : T) (bv : alloc.vec.Vec Std.U8)
    (henc : spec.io.encode NE.RoundTripStdInst.SerializeInst x = ok (.Ok bv)) :
    (bv : Slice Std.U8).val ≠ [] := by
  obtain ⟨u, -, hpost⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (h.nonempty_std_spec x (pre_holds_of_ok_true rfl))
  apply holds_imp' hpost
  simp only [spec.io.NonEmptyStd.nonempty_std.post, henc, core.result.Result.is_err]
  mvcgen [core.result.Result.is_ok_and,
    spec.io.__3.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.call_once]
  rename_i _ l hl
  intro hd hnil
  simp only [decide_eq_true_eq, gt_iff_lt] at hd
  rw [UScalar.lt_equiv, hl, Slice.len_val] at hd
  simp [Slice.length, hnil] at hd

/-! ### The encoding of a `Vec<T>` -/

/-- The bytes of a successful `encode` of a vector: the varint length prefix of the content size
`N` (at most `2^30 - 1`), then the elements' encodings `B` (of length `N`). -/
theorem Vec.encode_cases {T : Type} {SI : Serialize T} (DbgI : core.fmt.Debug T)
    (hL : Serialize.Lawful T SI) (v : alloc.vec.Vec T) :
    ∃ e, spec.io.encode (alloc.vec.Vec.Insts.Tls_codecSerialize SI DbgI) v = ok e ∧
    ∀ bv : alloc.vec.Vec Std.U8, e = .Ok bv →
    ∃ N B, N ≤ 2 ^ 30 - 1 ∧ encAll SI v.val = some B ∧ B.length = N ∧
      (bv : Slice Std.U8).val = varint.enc N ++ B := by
  have h1 := imax_eq
  have h2 := imax_ge
  obtain ⟨N, hN⟩ := SizeNat.exists hL.SizeInstLawful v.val
  obtain ⟨sz, hsz, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (alloc.vec.Vec.size_rel SI.SizeInst hL.SizeInstLawful v)
  have hsz' : (alloc.vec.Vec.Insts.Tls_codecSize SI.SizeInst).tls_serialized_len v = ok sz := hsz
  obtain ⟨c, -, hc, hszv⟩ := Vec.size_exact hL v sz hsz' hN
  by_cases hN30 : N ≤ 2 ^ 30 - 1
  · have hl8 := varint.lenOf_le N
    have hcN : c.val = N := by omega
    rw [hcN, if_pos hN30] at hszv
    obtain ⟨e, he, hes, hen⟩ := encode_of_runs _ v sz _
      (Vec.ser_runs write_length_runs DbgI hL v sz hsz' hN) (by omega)
    refine ⟨e, he, fun bv hbv => ?_⟩
    subst hbv
    cases hB : encAll SI v.val with
    | none =>
      obtain ⟨err, herr⟩ := hen (vecOut_none_enc _ _ _ _ hB)
      cases herr
    | some B =>
      have hvo : vecOut varint.enc SI v.val N = some (varint.enc N ++ B) := by
        unfold vecOut; rw [if_pos hN30, hB]; rfl
      obtain ⟨bv', hbv', hbvv⟩ := hes _ hvo
      cases hbv'
      exact ⟨N, B, hN30, rfl, encAll_length hL hN (by omega) B hB, hbvv⟩
  · have hcc : ∀ s : Slice T, ⦃ ⌜ s = (v : Slice T) ⌝ ⦄
        quic_vec.rw.checked_content_length SI.SizeInst s
        ⦃ ⇓ r => ⌜ ∀ c, r = .Ok c → c.val = N ⌝ ⦄ := by
      intro s hs
      subst hs
      refine triple_post_mono (checked_len_fold_spec hL.SizeInstLawful _ hN) ?_ trivial
      intro r ⟨hA, hB⟩ c hc
      subst hc
      by_cases hm : N ≤ Usize.max
      · obtain ⟨c', hc', h'⟩ := hA hm; cases hc'; exact h'
      · obtain ⟨e, he⟩ := hB (by omega); cases he
    have hwl : ∀ (w' : alloc.vec.Vec Std.U8) (n : Std.Usize),
        ⦃ ⌜ (w' : Slice Std.U8).val.length + 8 ≤ Usize.max ⌝ ⦄
          quic_vec.rw.write_length alloc.vec.VecU8.Insts.CoreIoWriteWrite w' n
        ⦃ ⇓ p => ⌜ ∀ l, p.1 = .Ok l → n.val ≤ 2 ^ 30 - 1 ⌝ ⦄ := by
      intro w' n hr
      refine triple_post_mono (write_length_runs.2 _ _ StdIo.vec_lawful w' n
        (by rw [StdIo.vec_sink]; exact hr)) ?_ trivial
      intro p hp l hl
      by_contra hc
      obtain ⟨e, he⟩ := hp.2 (by omega)
      rw [hl] at he; cases he
    have hel : ∀ (s : Slice T) (w' : alloc.vec.Vec Std.U8), ⦃ ⌜ False ⌝ ⦄
        tls_vec.serialize_elements SI alloc.vec.VecU8.Insts.CoreIoWriteWrite s w'
        ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := fun _ _ h => h.elim
    have H : ⦃ ⌜ True ⌝ ⦄ spec.io.encode (alloc.vec.Vec.Insts.Tls_codecSerialize SI DbgI) v
        ⦃ ⇓ r => ⌜ ∃ e, r = .Err e ⌝ ⦄ := by
      mvcgen [spec.io.encode, alloc.vec.Vec.Insts.Tls_codecSerialize.tls_serialize,
        Shared0Slice.Insts.Tls_codecSerialize.tls_serialize, hcc, hwl, hel,
        CoreModels.alloc.vec.Vec.new]
      all_goals first
        | (simp only [Slice.new, List.length_nil]; scalar_tac)
        | (exfalso; simp only [continue_eq_tryCF] at *; simp_all; omega)
        | (rename_i hbr; refine try_break_vc (fun e _ => ?_) hbr; mvcgen; intro _; mvcgen
           all_goals (intro hb2; refine try_break_vc (fun e _ => ?_) hb2; mvcgen)
           all_goals (intro _; exact ⟨_, rfl⟩))
    obtain ⟨r, hr, e, he⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp H
    exact ⟨r, hr, fun bv hbv => by rw [he] at hbv; cases hbv⟩

theorem Vec.encode_shape {T : Type} {SI : Serialize T} (DbgI : core.fmt.Debug T)
    (hL : Serialize.Lawful T SI) (v : alloc.vec.Vec T) (bv : alloc.vec.Vec Std.U8)
    (henc : spec.io.encode (alloc.vec.Vec.Insts.Tls_codecSerialize SI DbgI) v = ok (.Ok bv)) :
    ∃ N B, N ≤ 2 ^ 30 - 1 ∧ encAll SI v.val = some B ∧ B.length = N ∧
      (bv : Slice Std.U8).val = varint.enc N ++ B := by
  obtain ⟨e, he, h⟩ := Vec.encode_cases DbgI hL v
  rw [henc] at he
  cases he
  exact h bv rfl

/-! ### The decoding loop of `Vec<T>` on the encodings of a list of elements -/

/-- Every element's encoding is non-empty and decodes back to it on every lawful reader. -/
def ElemsDecode {T : Type} (SI : Serialize T) (DI : Deserialize T) (xs : List T) : Prop :=
  ∀ x ∈ xs, ∀ bx, encOut SI x = some bx → bx ≠ [] ∧ DecodesTo DI bx x

theorem encAll_nil_of_decode {T : Type} {SI : Serialize T} {DI : Deserialize T} {xs : List T}
    (hxs : ElemsDecode SI DI xs) (h : encAll SI xs = some []) : xs = [] := by
  cases xs with
  | nil => rfl
  | cons x tl =>
    exfalso
    cases hx : encOut SI x with
    | none => simp [encAll, hx] at h
    | some bx =>
      cases ht : encAll SI tl with
      | none => simp [encAll, hx, ht] at h
      | some bt =>
        simp [encAll, hx, ht] at h
        exact (hxs x (by simp) bx hx).1 h.1

section VecRTLoop
variable {T : Type} {SI : Serialize T} {DI : Deserialize T} (hL : Deserialize.Lawful T DI) {R : Type}
  {RI : alloc.io.read.Read R} {v : R → List Std.U8} {a : R → Nat → R} (law : StdIo.RLaw RI v a)

/-- Loop invariant: `k` elements read (the result is `xs.take k`), `m` bytes consumed out of
`L = |B|` (`limit = L - m`), the remaining bytes are the encodings of the remaining elements. -/
def RtInv (SI : Serialize T) (a : R → Nat → R) (xs : List T) (B : List Std.U8) (r0 : R)
    (L : Nat) (p : (R → R) × R × Std.U64 × Std.U64 × alloc.vec.Vec T) : Prop :=
  ∃ k m, (∀ x, p.1 x = x) ∧ k ≤ m ∧ m ≤ L ∧ p.2.1 = a r0 m ∧ p.2.2.2.1.val + m = L ∧
    (p.2.2.2.2 : Slice T).val = xs.take k ∧ encAll SI (xs.drop k) = some (B.drop m)

include hL law in
theorem Vec.rt_loop_body (xs : List T) (B rest : List Std.U8) (r0 : R) (L : Nat)
    (hB : v r0 = B ++ rest) (hBL : B.length = L) (hxs : ElemsDecode SI DI xs)
    (p : (R → R) × R × Std.U64 × Std.U64 × alloc.vec.Vec T) (hp : RtInv SI a xs B r0 L p) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.Tls_codecDeserialize.tls_deserialize_loop.body DI RI
      p.1 p.2.1 p.2.2.1 p.2.2.2.1 p.2.2.2.2
    ⦃ ⇓ r => ⌜ match r with
      | .done y => y.2.2.1 = core.option.Option.None ∧ (y.2.1 : Slice T).val = xs ∧
          y.1.inner = a r0 L ∧ (∀ t, y.2.2.2 t = t.inner)
      | .cont p' => RtInv SI a xs B r0 L p' ∧ p'.2.2.2.1.val < p.2.2.2.1.val ⌝ ⦄ := by
  obtain ⟨back, t, len, lim, res⟩ := p
  obtain ⟨k, m, hback, hkm, hmL, ht, hlim, hres, henc⟩ := hp
  dsimp only at hback hmL ht hlim hres henc ⊢
  have hvl : (v r0).length = L + rest.length := by rw [hB, List.length_append, hBL]
  have hvt : v t = (B ++ rest).drop m := by rw [ht, law.adv_view r0 m (by omega), hB]
  have hview : StdIo.takeView v ⟨t, len, lim⟩ = B.drop m := by
    simp only [StdIo.takeView, hvt, List.drop_append_of_le_length (by omega : m ≤ B.length)]
    rw [List.take_append_of_le_length (by simp; omega), List.take_of_length_le (by simp; omega)]
  by_cases hpos : 0 < lim.val
  · -- the next element
    have hne : xs.drop k ≠ [] := by
      intro h0; rw [h0] at henc; simp [encAll] at henc
      omega
    obtain ⟨x, tl, hxtl⟩ := List.exists_cons_of_ne_nil hne
    have hk : k < xs.length := by
      by_contra hc; rw [List.drop_eq_nil_of_le (by omega)] at hxtl; cases hxtl
    have hxmem : x ∈ xs := by
      have : x ∈ xs.drop k := by rw [hxtl]; simp
      exact List.mem_of_mem_drop this
    rw [hxtl] at henc
    obtain ⟨bx, hbx, bt, hbt, hsplit⟩ : ∃ bx, encOut SI x = some bx ∧ ∃ bt, encAll SI tl = some bt ∧
        B.drop m = bx ++ bt := by
      cases h1 : encOut SI x with
      | none => simp [encAll, h1] at henc
      | some bx =>
        cases h2 : encAll SI tl with
        | none => simp [encAll, h1, h2] at henc
        | some bt =>
          simp [encAll, h1, h2] at henc
          exact ⟨bx, rfl, bt, rfl, henc.symm⟩
    obtain ⟨hbx0, hdec⟩ := hxs x hxmem bx hbx
    have hbxl : bx.length ≤ L - m := by
      have := congrArg List.length hsplit; simp at this; omega
    have hbx1 : 0 < bx.length := List.length_pos_iff.mpr hbx0
    -- the element's deserializer on the `Take`
    have hTd : ⦃ ⌜ True ⌝ ⦄ DI.tls_deserialize
        (alloc.core.io.util.Take.Insts.AllocIoReadRead (alloc.Mut0R.Insts.AllocIoReadRead RI))
        ⟨t, len, lim⟩
        ⦃ ⇓ q => ⌜ q.1 = .Ok x ∧ q.2 = StdIo.takeAdv a ⟨t, len, lim⟩ bx.length ⌝ ⦄ := by
      have h1 := hdec _ _ _ _ (StdIo.take_law law) ⟨t, len, lim⟩ bt (by rw [hview, hsplit])
      have h2 := Deserialize.Lawful.runs hL _ _ _ _ (StdIo.take_law law) ⟨t, len, lim⟩
      refine triple_post_mono (triple_and h1 h2) ?_
      rintro q ⟨⟨hq1, hq2⟩, hq⟩
      obtain ⟨n, sz, hn, hqa, -, -, -⟩ := hq x hq1
      refine ⟨hq1, ?_⟩
      rw [hqa] at hq2 ⊢
      rw [StdIo.take_adv_view law _ n hn, hview, hsplit] at hq2
      have := congrArg List.length hq2
      simp only [List.length_drop, List.length_append] at this
      rw [hview, hsplit] at hn; simp only [List.length_append] at hn
      congr 1; omega
    mvcgen [alloc.vec.Vec.Insts.Tls_codecDeserialize.tls_deserialize_loop.body,
      core.io.util.Take.impl.limit, hTd, core.convert.Into.Blanket.into]
    · exact toStr_utf8 _ _
    · rename_i q el hq1 hq heq _ _
      exfalso
      have := congrArg UScalar.val heq
      rw [hq.2, StdIo.takeAdv_limit] at this
      dsimp only at this
      omega
    · have hl := law.view_le r0
      rw [hres, List.length_take]
      omega
    · rename_i _ tdb q el hq1 hq hne' nv hnv
      obtain ⟨hq1', hq2⟩ := hq
      have hel : x = el := by rw [hq1'] at hq1; exact core.result.Result.Ok.inj hq1
      subst hel
      have hl := law.view_le r0
      have hxk : xs[k]? = some x := by rw [← List.head?_drop, hxtl]; rfl
      refine ⟨⟨k + 1, m + bx.length, fun _ => by simp +zetaDelta [hback], by omega, by omega,
        ?_, ?_, ?_, ?_⟩, ?_⟩
      · rw [hq2, StdIo.takeAdv_inner, ht, law.adv_adv r0 m bx.length (by omega)]
      · show q.2.limit.val + (m + bx.length) = L
        rw [hq2, StdIo.takeAdv_limit]; dsimp only; omega
      · show (nv : Slice T).val = xs.take (k + 1)
        rw [hnv, hres, List.take_add_one, hxk]; rfl
      · show encAll SI (xs.drop (k + 1)) = some (B.drop (m + bx.length))
        rw [← List.drop_drop, hxtl, ← List.drop_drop, hsplit]
        simpa using hbt
      · show q.2.limit.val < lim.val
        rw [hq2, StdIo.takeAdv_limit]; dsimp only; omega
    · rename_i q e hq1 hq
      rw [hq.1] at hq1; cases hq1
  · -- the limit is exhausted: every element was read
    have hlim0 : lim.val = 0 := by omega
    have hmL' : m = L := by omega
    have hdrop : xs.drop k = [] := by
      apply encAll_nil_of_decode (fun x hx => hxs x (List.mem_of_mem_drop hx))
      rw [henc, hmL', ← hBL, List.drop_length]
    mvcgen [alloc.vec.Vec.Insts.Tls_codecDeserialize.tls_deserialize_loop.body,
      core.io.util.Take.impl.limit]
    refine ⟨trivial, ?_, by rw [ht, hmL'], fun _ => hback _⟩
    rw [hres, List.take_of_length_le (by
      have := List.length_drop (l := xs) (i := k); rw [hdrop] at this; simp at this; omega)]

include hL law in
theorem Vec.rt_loop (xs : List T) (B rest : List Std.U8) (r0 : R) (L : Nat)
    (hB : v r0 = B ++ rest) (hBL : B.length = L) (hxs : ElemsDecode SI DI xs)
    (p : (R → R) × R × Std.U64 × Std.U64 × alloc.vec.Vec T) (hp : RtInv SI a xs B r0 L p) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.Tls_codecDeserialize.tls_deserialize_loop DI RI
      p.1 p.2.1 p.2.2.1 p.2.2.2.1 p.2.2.2.2
    ⦃ ⇓ y => ⌜ y.2.2.1 = core.option.Option.None ∧ (y.2.1 : Slice T).val = xs ∧
          y.1.inner = a r0 L ∧ (∀ t, y.2.2.2 t = t.inner) ⌝ ⦄ := by
  unfold alloc.vec.Vec.Insts.Tls_codecDeserialize.tls_deserialize_loop
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.loop.spec_decr_nat
    (fun q : (R → R) × R × Std.U64 × Std.U64 × alloc.vec.Vec T => q.2.2.2.1.val)
    (RtInv SI a xs B r0 L)
  · rintro ⟨b, t, ln, lm, rs⟩ hq
    have := Vec.rt_loop_body hL law xs B rest r0 L hB hBL hxs _ hq
    obtain ⟨y, hy, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp this
    show Aeneas.Std.WP.spec (alloc.vec.Vec.Insts.Tls_codecDeserialize.tls_deserialize_loop.body DI RI
      b t ln lm rs) _
    rw [hy, Aeneas.Std.WP.spec_ok]
    cases y with
    | done y => exact hP
    | cont q => exact hP
  · exact hp

end VecRTLoop

/-- `Vec<T>` decodes the encoding of `xs` (the length prefix of the content size `N`, then the
elements' encodings `B`) back to `xs`, on every lawful reader. -/
theorem Vec.decodes {T : Type} {SI : Serialize T} {DI : Deserialize T} (hL : Deserialize.Lawful T DI)
    (xs : alloc.vec.Vec T) (N : Nat) (B : List Std.U8) (hN : N ≤ 2 ^ 30 - 1)
    (hB : encAll SI xs.val = some B) (hBL : B.length = N) (hxs : ElemsDecode SI DI xs.val) :
    DecodesTo (alloc.vec.Vec.Insts.Tls_codecDeserialize DI) (varint.enc N ++ B) xs := by
  intro R RI v a law r rest hv
  have hr := read_length_decodes law r N hN (B ++ rest) (by rw [hv, List.append_assoc])
  have hloop := fun r0 hB0 p hp => Vec.rt_loop hL law xs.val B rest r0 N hB0 hBL hxs p hp
  mvcgen [alloc.vec.Vec.Insts.Tls_codecDeserialize.tls_deserialize, hr, hloop,
    alloc.io.read.Read.take.default, CoreModels.alloc.vec.Vec.new, rust_primitives.sequence.seq_empty]
  · rename_i q hq _ val _ hz hcf
    obtain ⟨⟨pr, hpr, hpr1, -⟩, hq2⟩ := hq
    rw [continue_eq_tryCF.mp hcf] at hpr; cases hpr
    have hN0 : N = 0 := by rw [← hpr1, hz]; rfl
    subst hN0
    have hB0 : B = [] := List.eq_nil_of_length_eq_zero hBL
    subst hB0
    have hx0 := encAll_nil_of_decode hxs hB
    refine ⟨?_, by simpa using hq2⟩
    congr 1
    apply Subtype.ext
    simp [Slice.new, hx0]
  · rename_i q hq _ val _ hz hcf
    obtain ⟨⟨pr, hpr, hpr1, -⟩, hq2⟩ := hq
    rw [continue_eq_tryCF.mp hcf] at hpr; cases hpr
    have hc : (UScalar.cast UScalarTy.U64 val.1).val = val.1.val := Usize.cast_U64_val_eq _
    have hinv : RtInv SI a xs.val B q.2 N
        ((fun t => t), q.2, UScalar.cast UScalarTy.U64 val.1, UScalar.cast UScalarTy.U64 val.1,
          Slice.new T) :=
      ⟨0, 0, fun _ => rfl, le_refl _, by omega, (law.adv_zero _).symm, by simp [hc, hpr1],
        by simp [Slice.new], by simpa using hB⟩
    have hl := hloop q.2 hq2 _ hinv
    mvcgen [hl]
    · rename_i y hnone hy
      obtain ⟨-, hres, hin, hback⟩ := hy
      refine ⟨?_, ?_⟩
      · congr 1; exact Subtype.ext hres
      · have hl0 := law.view_le q.2
        rw [hback, hin, law.adv_view _ _ (by rw [hq2]; simp; omega), hq2,
          List.drop_left' hBL]
    · rename_i y e he hy
      rw [hy.1] at he; cases he
  · rename_i q hq _ _ _ hbr
    obtain ⟨⟨pr, hpr, -, -⟩, -⟩ := hq
    exact try_break_vc (fun e he => by rw [hpr] at he; cases he) hbr

/-! ### `Vec<T>`: the lemma traits -/

theorem encOut_some {T : Type} {SI : Serialize T} {x : T} {b : List Std.U8}
    (h : encOut SI x = some b) :
    ∃ bv : alloc.vec.Vec Std.U8, spec.io.encode SI x = ok (.Ok bv) ∧ (bv : Slice Std.U8).val = b := by
  unfold encOut at h
  split at h
  · rename_i hex
    cases h
    exact ⟨_, Classical.choose_spec hex, rfl⟩
  · cases h

/-- The elements of a vector of `NonEmptyStd` values decode back (and are non-empty). -/
theorem NonEmptyStd.elems_decode {T : Type} {NE : spec.io.NonEmptyStd T}
    (hNE : spec.io.NonEmptyStd.Lawful T NE) (xs : List T) :
    ElemsDecode NE.RoundTripStdInst.SerializeInst NE.RoundTripStdInst.DeserializeInst xs := by
  intro x _ bx hbx
  obtain ⟨bv, he, rfl⟩ := encOut_some hbx
  exact ⟨hNE.nonempty x bv he, hNE.RoundTripStdInstLawful.decodes x bv he⟩

section VecLemmaTraits
variable {T : Type} (NE : spec.io.NonEmptyStd T) (DbgI : core.fmt.Debug T)
  (hNE : spec.io.NonEmptyStd.Lawful T NE)

include hNE in
/-- A vector of `NonEmptyStd` values decodes its own (successful) encoding. -/
theorem Vec.rt_decodes (v : alloc.vec.Vec T) (bv : alloc.vec.Vec Std.U8)
    (he : spec.io.encode (alloc.vec.Vec.Insts.Tls_codecSpecIoRoundTripStd NE DbgI).SerializeInst v =
      ok (.Ok bv)) :
    DecodesTo (alloc.vec.Vec.Insts.Tls_codecSpecIoRoundTripStd NE DbgI).DeserializeInst
      (bv : Slice Std.U8).val v := by
  have hRT := hNE.RoundTripStdInstLawful
  obtain ⟨N, B, hN, hB, hBL, hbv⟩ := Vec.encode_shape DbgI hRT.SerializeInstLawful v bv he
  rw [hbv]
  exact Vec.decodes hRT.DeserializeInstLawful v N B hN hB hBL (NonEmptyStd.elems_decode hNE _)

include hNE in
theorem Vec.round_trip_std {R : Type} (RI : alloc.io.read.Read R)
    (hRI : alloc.io.read.Read.Lawful R RI) (v : alloc.vec.Vec T) (reader : R) (rest : Slice Std.U8)
    (hpre : (spec.io.RoundTripStd.round_trip_std.pre RI
      (alloc.vec.Vec.Insts.Tls_codecSpecIoRoundTripStd NE DbgI).SerializeInst
      (alloc.vec.Vec.Insts.Tls_codecSpecIoRoundTripStd NE DbgI).DeserializeInst
      (alloc.vec.Vec.Insts.Tls_codecSpecIoRoundTripStd NE DbgI).corecmpPartialEqInst
      (alloc.vec.Vec.Insts.Tls_codecSpecIoRoundTripStd NE DbgI) v reader rest).holds) :
    ⦃ ⌜ True ⌝ ⦄ spec.io.RoundTripStd.round_trip_std.default RI v reader rest
    ⦃ ⇓ r => ⌜ (spec.io.RoundTripStd.round_trip_std.post RI
      (alloc.vec.Vec.Insts.Tls_codecSpecIoRoundTripStd NE DbgI).SerializeInst
      (alloc.vec.Vec.Insts.Tls_codecSpecIoRoundTripStd NE DbgI).DeserializeInst
      (alloc.vec.Vec.Insts.Tls_codecSpecIoRoundTripStd NE DbgI).corecmpPartialEqInst
      (alloc.vec.Vec.Insts.Tls_codecSpecIoRoundTripStd NE DbgI) v reader rest r).holds ⌝ ⦄ := by
  have hRT := hNE.RoundTripStdInstLawful
  have hEq := alloc.vec.Vec.Insts.CoreCmpPartialEqVec.Lawful _ hRT.corecmpPartialEqInstLawful
  obtain ⟨e, he, -⟩ := Vec.encode_cases DbgI hRT.SerializeInstLawful v
  cases e with
  | Err err =>
    exact (spec.io.RoundTripStd.round_trip_std.pre_err _ RI v reader rest err he hpre).elim
  | Ok bv =>
    exact spec.io.RoundTripStd.round_trip_std_of _ hEq v bv he (Vec.rt_decodes NE DbgI hNE v bv he)
      RI hRI reader rest hpre

include hNE in
theorem Vec.round_trip_exact (v : alloc.vec.Vec T) :
    ⦃ ⌜ True ⌝ ⦄ spec.io.RoundTripStd.round_trip_exact.default v
    ⦃ ⇓ r => ⌜ (spec.io.RoundTripStd.round_trip_exact.post
      (alloc.vec.Vec.Insts.Tls_codecSpecIoRoundTripStd NE DbgI).SerializeInst
      (alloc.vec.Vec.Insts.Tls_codecSpecIoRoundTripStd NE DbgI).DeserializeInst
      (alloc.vec.Vec.Insts.Tls_codecSpecIoRoundTripStd NE DbgI).corecmpPartialEqInst
      (alloc.vec.Vec.Insts.Tls_codecSpecIoRoundTripStd NE DbgI) v r).holds ⌝ ⦄ := by
  have hRT := hNE.RoundTripStdInstLawful
  have hEq := alloc.vec.Vec.Insts.CoreCmpPartialEqVec.Lawful _ hRT.corecmpPartialEqInstLawful
  obtain ⟨e, he, -⟩ := Vec.encode_cases DbgI hRT.SerializeInstLawful v
  cases e with
  | Err err => exact spec.io.RoundTripStd.round_trip_exact_err _ v err he
  | Ok bv =>
    exact spec.io.RoundTripStd.round_trip_exact_of _ hEq v bv he
      fun s hs => Deserialize.tls_deserialize_exact.default_decodes _ _ v
        (Vec.rt_decodes NE DbgI hNE v bv he) s hs

include hNE in
theorem Vec.nonempty_std (v : alloc.vec.Vec T) :
    ⦃ ⌜ True ⌝ ⦄ spec.io.NonEmptyStd.nonempty_std.default v
    ⦃ ⇓ r => ⌜ (spec.io.NonEmptyStd.nonempty_std.post
      (alloc.vec.Vec.Insts.Tls_codecSpecIoNonEmptyStd NE DbgI).RoundTripStdInst
      (alloc.vec.Vec.Insts.Tls_codecSpecIoNonEmptyStd NE DbgI) v r).holds ⌝ ⦄ := by
  have hRT := hNE.RoundTripStdInstLawful
  obtain ⟨e, he, hsh⟩ := Vec.encode_cases DbgI hRT.SerializeInstLawful v
  cases e with
  | Err err => exact spec.io.NonEmptyStd.nonempty_std_err _ v err he
  | Ok bv =>
    obtain ⟨N, B, -, -, -, hbv⟩ := hsh bv rfl
    refine spec.io.NonEmptyStd.nonempty_std_of _ v bv he ?_
    rw [hbv]
    intro h
    have h1 := congrArg List.length h
    have h2 := varint.lenOf_pos N
    simp only [List.length_append, varint.enc_length, List.length_nil] at h1
    omega

end VecLemmaTraits

end tls_codec
