/- Generic containers: from the trait-level contracts of the element type (`Serialize.Lawful` /
`Deserialize.Lawful`) to the behaviour of `Option<T>` and of the `Vec<T>` deserializer.

Obligations: none directly; the `std`-path halves (`Serialize` / `Deserialize` `Lawful` fields,
lemma traits) of `PanicFreedom.lean` / `FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): nothing ASSUMED; 1 signature-only stub
(`core.io.error.Error.Insts.CoreFmtDebug.fmt`); `native_decide` (1). -/
import Aeneas
import CoreModels
import Hax
import TlsCodec.Extraction
import TlsCodec.Verification.Helpers
import TlsCodec.Verification.Std.Io
import TlsCodec.Verification.Std.Bridge
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! ### From an element's contract to its behaviour -/

open Classical in
/-- The encoding of `x` as an option (`none`: `encode` returns `Err`). -/
noncomputable def encOut {T : Type} (SI : Serialize T) (x : T) : Option (List Std.U8) :=
  if h : ∃ bv : alloc.vec.Vec Std.U8, spec.io.encode SI x = ok (.Ok bv) then
    some (Classical.choose h : Slice Std.U8).val
  else none

theorem encOut_ok {T : Type} {SI : Serialize T} {x : T} {bv : alloc.vec.Vec Std.U8}
    (h : spec.io.encode SI x = ok (.Ok bv)) : encOut SI x = some (bv : Slice Std.U8).val := by
  have hex : ∃ bv : alloc.vec.Vec Std.U8, spec.io.encode SI x = ok (.Ok bv) := ⟨bv, h⟩
  unfold encOut
  rw [dif_pos hex]
  have h2 := (Classical.choose_spec hex).symm.trans h
  simp only [ok.injEq, core.result.Result.Ok.injEq] at h2
  exact congrArg (fun z : alloc.vec.Vec Std.U8 => some (z : Slice Std.U8).val) h2

theorem encOut_err {T : Type} {SI : Serialize T} {x : T} {err : Error}
    (h : spec.io.encode SI x = ok (.Err err)) : encOut SI x = none := by
  unfold encOut
  rw [dif_neg]
  rintro ⟨bv, hbv⟩
  rw [h] at hbv
  cases hbv

/-- A serializer meeting its trait-level contract behaves uniformly on lawful writers. -/
theorem Serialize.Lawful.runs {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI) (x : T)
    (sz : Std.Usize) (hsz : SI.SizeInst.tls_serialized_len x = ok sz) :
    SerRuns SI x sz (encOut SI x) := by
  intro W WI hWI w hroom
  obtain ⟨⟨r, w'⟩, hr, hp⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (hL.tls_serialize_spec WI hWI x w (Serialize.tls_serialize.pre_of_bound SI WI x w sz hsz hroom))
  obtain ⟨e, he, hok, herr⟩ := Serialize.tls_serialize.post_elim SI WI x w _ hp
  refine ⟨r, w', hr, ?_, ?_⟩
  · intro b hb
    cases e with
    | Ok bv =>
      rw [encOut_ok he] at hb
      cases hb
      obtain ⟨-, h1, h2⟩ := hok bv rfl
      exact ⟨⟨_, h1, by simp [Slice.len_val, Slice.length]⟩, h2⟩
    | Err err => rw [encOut_err he] at hb; cases hb
  · intro hn
    cases e with
    | Ok bv => rw [encOut_ok he] at hn; cases hn
    | Err err => exact herr err rfl

/-- The length of an element's encoding, given room for it. -/
theorem Serialize.Lawful.enc_len {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI) (x : T)
    (sz : Std.Usize) (hsz : SI.SizeInst.tls_serialized_len x = ok sz) (hroom : sz.val ≤ imax) :
    ∀ b, encOut SI x = some b → b.length = sz.val := by
  intro b hb
  obtain ⟨r, w', -, hs, -⟩ := hL.runs x sz hsz _ _ StdIo.vec_lawful ⟨[], by simp⟩
    (by rw [StdIo.vec_sink]; simpa using hroom)
  obtain ⟨-, hv⟩ := hs b hb
  obtain ⟨e, he, hes, -⟩ := encode_of_runs SI x sz _ (hL.runs x sz hsz) hroom
  obtain ⟨bv, rfl, hbv⟩ := hes b hb
  obtain ⟨⟨r2, w2⟩, hr2, hp2⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (hL.tls_serialize_spec _ StdIo.vec_lawful x ⟨[], by simp⟩
      (Serialize.tls_serialize.pre_of_bound SI _ x _ sz hsz (by rw [StdIo.vec_sink]; simpa using hroom)))
  obtain ⟨e2, he2, hok2, -⟩ := Serialize.tls_serialize.post_elim SI _ x _ _ hp2
  rw [he] at he2; cases he2
  obtain ⟨h1, -, -⟩ := hok2 bv rfl
  rw [hsz] at h1; cases h1
  rw [← hbv]; simp [Slice.len_val, Slice.length]

/-- A deserializer meeting its trait-level contract consumes exactly the size of its value, on
every lawful reader. -/
theorem Deserialize.Lawful.runs {T : Type} {DI : Deserialize T} (hL : Deserialize.Lawful T DI) :
    DeRuns DI (fun _ _ _ => True) := by
  intro R RI v a law r
  have hRI : alloc.io.read.Read.Lawful R RI := ⟨⟨v, a, law⟩⟩
  refine triple_post_mono (hL.tls_deserialize_spec RI hRI r (pre_holds_of_ok_true rfl)) ?_
  intro p hp val hval
  obtain ⟨⟨n, hn, hp2⟩, sz, hsz, hlen⟩ := Deserialize.tls_deserialize.post_elim DI RI r p val hval hp
  rw [StdIo.view_eq law] at hn hlen
  rw [StdIo.adv_eq law r n hn] at hp2
  rw [hp2, StdIo.view_eq law, law.adv_view r n hn, List.length_drop] at hlen
  exact ⟨n, sz, hn, hp2, hsz, by omega, trivial⟩

/-! ### `Option<T>` -/

theorem lenAddVal_sat (a b : Std.Usize) (h : Usize.max < a.val + b.val) :
    (lenAddVal a b).val = Usize.max := by
  obtain ⟨r, hr, hrv⟩ := len_add_spec_sat a b h
  rw [len_add_ok] at hr
  cases hr
  exact hrv

/-- `SerRuns` as a triple (the form `mvcgen` consumes). -/
theorem SerRuns.spec {T : Type} {SI : Serialize T} {x : T} {sz : Std.Usize}
    {out : Option (List Std.U8)} (h : SerRuns SI x sz out) {W : Type}
    (WI : core.io.write.Write W) (hWI : core.io.write.Write.Lawful W WI) (w : W)
    (hroom : (core.io.write.Write.view WI w).length + sz.val ≤ imax) :
    ⦃ ⌜ True ⌝ ⦄ SI.tls_serialize WI x w
    ⦃ ⇓ p => ⌜ (∀ b, out = some b → (∃ n : Std.Usize, p.1 = .Ok n ∧ n.val = b.length) ∧
        core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w ++ b) ∧
      (out = none → ∃ e, p.1 = .Err e) ⌝ ⦄ := by
  obtain ⟨r, w', hr, hs, hn⟩ := h W WI hWI w hroom
  rw [hr]
  exact ok_triple_of ⟨hs, hn⟩

/-- `SerRuns` as a triple with the room as precondition (for `mvcgen`, which leaves the room as
a verification condition). -/
theorem SerRuns.spec' {T : Type} {SI : Serialize T} {x : T} {sz : Std.Usize}
    {out : Option (List Std.U8)} (h : SerRuns SI x sz out) {W : Type}
    (WI : core.io.write.Write W) (hWI : core.io.write.Write.Lawful W WI) (w : W) :
    ⦃ ⌜ (core.io.write.Write.view WI w).length + sz.val ≤ imax ⌝ ⦄ SI.tls_serialize WI x w
    ⦃ ⇓ p => ⌜ (∀ b, out = some b → (∃ n : Std.Usize, p.1 = .Ok n ∧ n.val = b.length) ∧
        core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w ++ b) ∧
      (out = none → ∃ e, p.1 = .Err e) ⌝ ⦄ := by
  intro hroom
  exact h.spec WI hWI w hroom trivial

/-- `write_all` on a lawful writer with room, as a triple. -/
theorem write_all_spec {W : Type} {WI : core.io.write.Write W}
    (hWI : core.io.write.Write.Lawful W WI) (w : W) (s : Slice Std.U8)
    (h : (core.io.write.Write.view WI w).length + s.val.length ≤ Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ WI.write_all w s
    ⦃ ⇓ p => ⌜ p.1 = .Ok () ∧ core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w ++ s.val ⌝ ⦄ := by
  obtain ⟨w', hw, hv⟩ := hWI.law'.write_all_ok w s h
  rw [hw]
  exact ok_triple_of ⟨rfl, hv⟩

/-- The encoding of an `Option`: a tag byte, then the encoding of the value. -/
noncomputable def optOut {T : Type} (SI : Serialize T) : core.option.Option T → Option (List Std.U8)
  | .None => some [0#u8]
  | .Some e => (encOut SI e).map (List.cons 1#u8)

theorem Option.ser_runs {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (o : core.option.Option T) (sz : Std.Usize)
    (hsz : (core.option.Option.Insts.Tls_codecSize SI.SizeInst).tls_serialized_len o = ok sz) :
    SerRuns (core.option.Option.Insts.Tls_codecSerialize SI) o sz (optOut SI o) := by
  intro W WI hWI w hroom
  have := imax_le
  suffices H : ⦃ ⌜ True ⌝ ⦄ (core.option.Option.Insts.Tls_codecSerialize SI).tls_serialize WI o w
      ⦃ ⇓ p => ⌜ (∀ b, optOut SI o = some b → (∃ n : Std.Usize, p.1 = .Ok n ∧ n.val = b.length) ∧
        core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w ++ b) ∧
        (optOut SI o = none → ∃ e, p.1 = .Err e) ⌝ ⦄ by
    obtain ⟨⟨r, w'⟩, h1, h2⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp H
    exact ⟨r, w', h1, h2⟩
  cases o with
  | none =>
    have h0 := (Option_size_none SI.SizeInst).symm.trans hsz
    simp only [ok.injEq] at h0; subst h0
    have e1 : (1#usize).val = 1 := rfl
    have e0 : (0#usize).val = 0 := rfl
    rw [lenAddVal_val _ _ (by simp; scalar_tac), e1, e0] at hroom
    have hw := write_all_spec hWI w (Array.to_slice (Array.make 1#usize [0#u8])) (by simp; omega)
    mvcgen [core.option.Option.Insts.Tls_codecSerialize.tls_serialize, hw]
    · rename_i p hp _ _ _ _
      refine ⟨fun b hb => ?_, fun h => by simp [optOut] at h⟩
      simp only [optOut, Option.some.injEq] at hb; subst hb
      exact ⟨⟨1#usize, rfl, rfl⟩, by rw [hp.2]; rfl⟩
    · rename_i p hp _ _ _ hbr
      rw [hp.1] at hbr; simp [tryCF] at hbr
  | some e =>
    obtain ⟨se, hse, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (hL.SizeInstLawful.tls_serialized_len_spec e (pre_holds_of_ok_true rfl))
    have h0 := (Option_size_some SI.SizeInst e se hse).symm.trans hsz
    simp only [ok.injEq] at h0; subst h0
    have e1 : (1#usize).val = 1 := rfl
    have hfit : (core.io.write.Write.view WI w).length + 1 + se.val ≤ imax := by
      by_cases hov : Usize.max < (1#usize).val + se.val
      · rw [lenAddVal_sat _ _ hov] at hroom; have := imax_eq; omega
      · rw [lenAddVal_val _ _ (by omega), e1] at hroom; omega
    have hw := write_all_spec hWI w (Array.to_slice (Array.make 1#usize [1#u8])) (by simp; omega)
    have hT := SerRuns.spec' (hL.runs e se hse) WI hWI
    have hone : (Array.to_slice (Array.make 1#usize [1#u8])).val = [1#u8] := rfl
    mvcgen [core.option.Option.Insts.Tls_codecSerialize.tls_serialize, hw, hT,
      core.result.Result.map_spec]
    · rename_i p hp _ _ _ _
      rw [hp.2, hone]; simp; omega
    · rename_i p hp _ _ _ _ q hq t ht
      have hle := core.io.write.Write.view_le WI q.2
      unfold primitives.SerializeOption.tls_serialize.closure.Insts.CoreOpsFunctionFnOnceTupleUsizeUsize.call_once
      cases hb : encOut SI e with
      | none => obtain ⟨_, h'⟩ := hq.2 hb; rw [ht] at h'; cases h'
      | some b =>
        obtain ⟨⟨n, hn, hnb⟩, hv⟩ := hq.1 b hb
        rw [ht] at hn; cases hn
        rw [hv, hp.2, hone] at hle; simp at hle
        have hm : UScalar.max UScalarTy.Usize = Usize.max := by
          simp [UScalar.max, Usize.max, Usize.numBits]
        mvcgen
        case h_fail => rename_i hov; exfalso; rw [hm, e1] at hov; omega
        rename_i u hu
        refine ⟨fun b' hb' => ?_, fun h' => by simp [optOut, hb] at h'⟩
        simp only [optOut, hb, Option.map_some, Option.some.injEq] at hb'; subst hb'
        refine ⟨⟨u, rfl, by simp; omega⟩, by rw [hv, hp.2, hone]; simp⟩
    · rename_i p hp _ _ _ _ q hq err herr
      refine ⟨fun b' hb' => ?_, fun _ => ⟨_, rfl⟩⟩
      cases hb : encOut SI e with
      | none => simp [optOut, hb] at hb'
      | some b => obtain ⟨⟨n, hn, -⟩, -⟩ := hq.1 b hb; rw [herr] at hn; cases hn
    · rename_i p hp _ _ _ hbr
      rw [hp.1] at hbr; simp [tryCF] at hbr

theorem Option.ser_spec {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI) {W : Type}
    (WI : core.io.write.Write W) (hWI : core.io.write.Write.Lawful W WI)
    (o : core.option.Option T) (w : W)
    (hpre : (Serialize.tls_serialize.pre WI (core.option.Option.Insts.Tls_codecSerialize SI).SizeInst
      (core.option.Option.Insts.Tls_codecSerialize SI) o w).holds) :
    ⦃ ⌜ True ⌝ ⦄ (core.option.Option.Insts.Tls_codecSerialize SI).tls_serialize WI o w
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize.post WI (core.option.Option.Insts.Tls_codecSerialize SI).SizeInst
      (core.option.Option.Insts.Tls_codecSerialize SI) o w r).holds ⌝ ⦄ := by
  have e1 : (1#usize).val = 1 := rfl
  have e0 : (0#usize).val = 0 := rfl
  cases o with
  | none =>
    refine Serialize.tls_serialize_spec_of_runs' _ core.option.Option.None _ (Option_size_none SI.SizeInst) _ ?_
      (Option.ser_runs hL core.option.Option.None _ (Option_size_none SI.SizeInst)) WI hWI w hpre
    intro _ b hb
    simp only [optOut, Option.some.injEq] at hb; subst hb
    rw [lenAddVal_val _ _ (by simp; scalar_tac), e1, e0]; rfl
  | some e =>
    obtain ⟨se, hse, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (hL.SizeInstLawful.tls_serialized_len_spec e (pre_holds_of_ok_true rfl))
    refine Serialize.tls_serialize_spec_of_runs' _ (core.option.Option.Some e) _ (Option_size_some SI.SizeInst e se hse) _ ?_
      (Option.ser_runs hL (core.option.Option.Some e) _ (Option_size_some SI.SizeInst e se hse)) WI hWI w hpre
    intro hroom b hb
    have hfit : 1 + se.val ≤ imax ∧ (lenAddVal 1#usize se).val = 1 + se.val := by
      by_cases hov : Usize.max < (1#usize).val + se.val
      · rw [lenAddVal_sat _ _ hov] at hroom; have := imax_eq; omega
      · rw [lenAddVal_val _ _ (by omega), e1] at hroom ⊢; exact ⟨hroom, rfl⟩
    cases hb' : encOut SI e with
    | none => simp [optOut, hb'] at hb
    | some b' =>
      simp only [optOut, hb', Option.map_some, Option.some.injEq] at hb; subst hb
      rw [hfit.2, List.length_cons, hL.enc_len e se hse (by omega) b' hb']; omega

theorem Option.de_runs {T : Type} {DI : Deserialize T} (hL : Deserialize.Lawful T DI) :
    DeRuns (core.option.Option.Insts.Tls_codecDeserialize DI) (fun _ _ _ => True) := by
  intro R RI v a law r
  have hre := read_exact_spec law r
  have hT := fun r' => Deserialize.Lawful.runs hL R RI v a law r'
  have e1 : (1#usize).val = 1 := rfl
  have e0 : (0#usize).val = 0 := rfl
  -- `Continue` after `read_exact` of the tag: the reader had a byte, and is advanced by one
  have tag : ∀ (arr : Aeneas.Std.Array Std.U8 1#usize)
      (p : core.result.Result Unit core.io.error.Error × R × Slice Std.U8) u,
      ((arr.to_slice_mut.1 : Slice Std.U8).val.length ≤ (v r).length →
        p = (.Ok (), a r (arr.to_slice_mut.1 : Slice Std.U8).val.length,
          alloc.io.read.cut (v r) arr.to_slice_mut.1)) →
      ((v r).length < (arr.to_slice_mut.1 : Slice Std.U8).val.length →
        p.1 = .Err core.io.error.Error.READ_EXACT_EOF) →
      core.ops.control_flow.ControlFlow.Continue u = tryCF p.1 → 1 ≤ (v r).length ∧ p.2.1 = a r 1 := by
    intro arr p u hp1 hp2 hcf
    have hl : (arr.to_slice_mut.1 : Slice Std.U8).val.length = 1 := to_slice_mut_len arr
    by_cases h1 : 1 ≤ (v r).length
    · exact ⟨h1, by rw [hp1 (by rw [hl]; exact h1), hl]⟩
    · rw [hp2 (by rw [hl]; omega)] at hcf; simp [tryCF] at hcf
  mvcgen [core.option.Option.Insts.Tls_codecDeserialize.tls_deserialize, hre, hT]
  · rename_i arr p hp _ u _ _ hcf _ _ _
    obtain ⟨h1, h2⟩ := tag arr p u hp.1 hp.2 hcf
    intro val hval; cases hval
    refine ⟨1, _, h1, h2, Option_size_none DI.SizeInst, ?_⟩
    rw [lenAddVal_val _ _ (by simp; scalar_tac), e1, e0]
  · rename_i arr p hp _ u _ _ hcf _ _ _ q _ t _ hct hq
    obtain ⟨h1, h2⟩ := tag arr p u hp.1 hp.2 hcf
    intro val hval; cases hval
    obtain ⟨n, sz, hn, hq2, hsz, hszn⟩ := hq t (continue_eq_tryCF.mp hct)
    rw [h2, law.adv_view r 1 h1, List.length_drop] at hn
    rw [h2, law.adv_adv r 1 n (by omega)] at hq2
    refine ⟨1 + n, _, by omega, hq2, Option_size_some DI.SizeInst t sz hsz, ?_⟩
    have := law.view_le r
    rw [lenAddVal_val _ _ (by rw [e1]; omega), e1, hszn]
  · rename_i q _ res _ hbr _
    refine try_break_vc (x := q.1) (fun e _ => ?_) hbr
    mvcgen
    intro _
    mvcgen
    all_goals simp
  · intro val h; cases h
  · rename_i hlen0
    revert hlen0
    simp [Aeneas.Std.Array.length]
  · rename_i arr p hp _ res _ hbr
    have hl : (arr.to_slice_mut.1 : Slice Std.U8).val.length = 1 := to_slice_mut_len arr
    by_cases h1 : 1 ≤ (v r).length
    · rw [hp.1 (by rw [hl]; exact h1)] at hbr; simp [tryCF] at hbr
    · rw [hp.2 (by rw [hl]; omega)] at hbr
      simp only [tryCF] at hbr
      cases hbr
      refine ⟨_, rfl, ?_⟩
      rw [from_io_eof]
      refine ok_triple_of ?_
      mvcgen
      intro _ h; cases h

theorem Option.de_spec {T : Type} {DI : Deserialize T} (hL : Deserialize.Lawful T DI) {R : Type}
    (RI : alloc.io.read.Read R) (hRI : alloc.io.read.Read.Lawful R RI) (r : R) :
    ⦃ ⌜ True ⌝ ⦄ (core.option.Option.Insts.Tls_codecDeserialize DI).tls_deserialize RI r
    ⦃ ⇓ p => ⌜ (Deserialize.tls_deserialize.post RI
      (core.option.Option.Insts.Tls_codecDeserialize DI).SizeInst
      (core.option.Option.Insts.Tls_codecDeserialize DI) r p).holds ⌝ ⦄ :=
  Deserialize.tls_deserialize_spec_of_runs _ (Option.de_runs hL) RI hRI r

theorem Option.size_ok {T : Type} {S : Size T} (hS : Size.Lawful T S) (o : core.option.Option T) :
    ∃ sz, (core.option.Option.Insts.Tls_codecSize S).tls_serialized_len o = ok sz := by
  cases o with
  | none => exact ⟨_, Option_size_none S⟩
  | some e =>
    obtain ⟨se, hse, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (hS.tls_serialized_len_spec e (pre_holds_of_ok_true rfl))
    exact ⟨_, Option_size_some S e se hse⟩

/-! ### `Vec<T>`: the deserializer loop (elements read from a `Take` of the reader)

The loop terminates because an element that consumes nothing is rejected and one that consumes
`n > 0` bytes lowers the `Take`'s limit by `n`: the element's `DeRuns` on the `Take` (lawful, with
the `takeView` / `takeAdv` law) pins the new `Take` to `takeAdv _ n`. -/

section VecLoop
variable {T : Type} {DI : Deserialize T} (hL : Deserialize.Lawful T DI) {R : Type}
  {RI : alloc.io.read.Read R} {v : R → List Std.U8} {a : R → Nat → R} (law : StdIo.RLaw RI v a)

/-- Loop invariant: `m` bytes consumed out of `L` (`limit = L - m`), the elements read so far have
total size `m`. -/
def VecInv (DI : Deserialize T) (v : R → List Std.U8) (a : R → Nat → R) (r0 : R) (L : Nat)
    (p : (R → R) × R × Std.U64 × Std.U64 × alloc.vec.Vec T) : Prop :=
  ∃ m c, (∀ x, p.1 x = x) ∧ m ≤ (v r0).length ∧ p.2.1 = a r0 m ∧ p.2.2.2.1.val + m = L ∧
    SizeFoldRel DI.SizeInst 0#usize (p.2.2.2.2 : Slice T).val c ∧ c.val = m ∧
    (p.2.2.2.2 : Slice T).val.length ≤ m

include hL law in
theorem Vec.de_loop_body (r0 : R) (L : Nat)
    (p : (R → R) × R × Std.U64 × Std.U64 × alloc.vec.Vec T) (hp : VecInv DI v a r0 L p) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.Tls_codecDeserialize.tls_deserialize_loop.body DI RI
      p.1 p.2.1 p.2.2.1 p.2.2.2.1 p.2.2.2.2
    ⦃ ⇓ r => ⌜ match r with
      | .done y => y.2.2.1 = core.option.Option.None → y.1.limit.val = 0 ∧ L ≤ (v r0).length ∧
          y.1.inner = a r0 L ∧ (∀ t, y.2.2.2 t = t.inner) ∧
          ∃ c, SizeFoldRel DI.SizeInst 0#usize (y.2.1 : Slice T).val c ∧ c.val = L
      | .cont p' => VecInv DI v a r0 L p' ∧ p'.2.2.2.1.val < p.2.2.2.1.val ⌝ ⦄ := by
  obtain ⟨back, t, len, lim, res⟩ := p
  obtain ⟨m, c, hback, hmL, ht, hlim, hrel, hc, hres⟩ := hp
  dsimp only at hback hmL ht hlim hrel hc hres ⊢
  have hT := fun t' => Deserialize.Lawful.runs hL _ _ _ _ (StdIo.take_law law) t'
  have hvt : v t = (v r0).drop m := by rw [ht]; exact law.adv_view r0 m hmL
  -- an `Ok` element: consumed `n`, with `0 < n` when the limit moved
  have step : ∀ (q : core.result.Result T Error × core.io.util.Take R) el, q.1 = .Ok el →
      (∀ val, q.1 = .Ok val → ∃ n sz, n ≤ (StdIo.takeView v ⟨t, len, lim⟩).length ∧
        q.2 = StdIo.takeAdv a ⟨t, len, lim⟩ n ∧ DI.SizeInst.tls_serialized_len val = ok sz ∧
        sz.val = n) → ¬ q.2.limit = lim →
      ∃ n sz, 0 < n ∧ m + n ≤ L ∧ m + n ≤ (v r0).length ∧ q.2.limit.val = lim.val - n ∧
        q.2.inner = a r0 (m + n) ∧
        DI.SizeInst.tls_serialized_len el = ok sz ∧ sz.val = n := by
    intro q el hq1 hq hne
    obtain ⟨n, sz, hn, hq2, hsz, hszn⟩ := hq el hq1
    simp only [StdIo.takeView, List.length_take, hvt, List.length_drop] at hn
    have hn0 : 0 < n := by
      rcases Nat.eq_zero_or_pos n with h0 | h0
      · exfalso; apply hne; rw [hq2, h0]; exact UScalar.eq_of_val_eq (by simp)
      · exact h0
    refine ⟨n, sz, hn0, by omega, by omega, by rw [hq2]; simp, ?_, hsz, hszn⟩
    rw [hq2, StdIo.takeAdv_inner, ht, law.adv_adv r0 m n (by omega)]
  mvcgen [alloc.vec.Vec.Insts.Tls_codecDeserialize.tls_deserialize_loop.body,
    core.io.util.Take.impl.limit, hT, core.convert.Into.Blanket.into]
  · exact toStr_utf8 _ _
  · intro h; cases h
  · rename_i _ _ q el hq1 hne hq
    obtain ⟨n, sz, hn0, -, hmv, -, -, -, -⟩ := step q el hq1 hq hne
    have := law.view_le r0
    omega
  · rename_i _ _ q el hq1 hne nv hnv hq
    obtain ⟨n, sz, hn0, hmn, hmv, hlim', hinner, hsz, hszn⟩ := step q el hq1 hq hne
    refine ⟨⟨m + n, lenAddVal c sz, fun x => by simp +zetaDelta [hback], hmv, hinner,
      by show q.2.limit.val + (m + n) = L; omega, ?_, ?_, ?_⟩,
      by show q.2.limit.val < lim.val; omega⟩
    · rw [hnv]; exact hrel.snoc el sz hsz
    · have := law.view_le r0
      rw [lenAddVal_val _ _ (by omega), hc, hszn]
    · rw [hnv]; simp; omega
  · intro h; cases h
  · rename_i hle
    have h0 : lim.val = 0 := by
      have : ¬ (0#u64).val < lim.val := hle
      simp at this; omega
    refine ⟨h0, by omega, by rw [ht]; congr 1; omega, fun _ => hback _, c, hrel, by omega⟩

include hL law in
theorem Vec.de_loop (r0 : R) (L : Nat)
    (p : (R → R) × R × Std.U64 × Std.U64 × alloc.vec.Vec T) (hp : VecInv DI v a r0 L p) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.Tls_codecDeserialize.tls_deserialize_loop DI RI
      p.1 p.2.1 p.2.2.1 p.2.2.2.1 p.2.2.2.2
    ⦃ ⇓ y => ⌜ y.2.2.1 = core.option.Option.None → y.1.limit.val = 0 ∧ L ≤ (v r0).length ∧
          y.1.inner = a r0 L ∧ (∀ t, y.2.2.2 t = t.inner) ∧
          ∃ c, SizeFoldRel DI.SizeInst 0#usize (y.2.1 : Slice T).val c ∧ c.val = L ⌝ ⦄ := by
  unfold alloc.vec.Vec.Insts.Tls_codecDeserialize.tls_deserialize_loop
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.loop.spec_decr_nat
    (fun q : (R → R) × R × Std.U64 × Std.U64 × alloc.vec.Vec T => q.2.2.2.1.val)
    (VecInv DI v a r0 L)
  · rintro ⟨b, t, ln, lm, rs⟩ hq
    have := Vec.de_loop_body hL law r0 L _ hq
    obtain ⟨y, hy, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp this
    show Aeneas.Std.WP.spec (alloc.vec.Vec.Insts.Tls_codecDeserialize.tls_deserialize_loop.body DI RI
      b t ln lm rs) _
    rw [hy, Aeneas.Std.WP.spec_ok]
    cases y with
    | done y => exact hP
    | cont q => exact hP
  · exact hp

end VecLoop

/-! ### `Vec<T>`: the deserializer -/

/-- What `Vec<T>` needs from `read_length` (proved from the varint lemmas). -/
def ReadLengthRuns : Prop :=
  ∀ (R : Type) (RI : alloc.io.read.Read R) (v : R → List Std.U8) (a : R → Nat → R),
    StdIo.RLaw RI v a → ∀ r, ⦃ ⌜ True ⌝ ⦄ quic_vec.rw.read_length RI r
    ⦃ ⇓ p => ⌜ ∀ len ll, p.1 = .Ok (len, ll) → len.val ≤ 2 ^ 30 - 1 ∧
      varint.lenOf len.val ≤ (v r).length ∧ p.2 = a r (varint.lenOf len.val) ⌝ ⦄

theorem Vec.de_runs (hrl : ReadLengthRuns) {T : Type} {DI : Deserialize T}
    (hL : Deserialize.Lawful T DI) :
    DeRuns (alloc.vec.Vec.Insts.Tls_codecDeserialize DI) (fun _ _ _ => True) := by
  intro R RI v a law r
  have hr := hrl R RI v a law r
  have hloop := fun r0 L p hp => Vec.de_loop hL law r0 L p hp
  mvcgen [alloc.vec.Vec.Insts.Tls_codecDeserialize.tls_deserialize, hr, hloop,
    alloc.io.read.Read.take.default, CoreModels.alloc.vec.Vec.new, rust_primitives.sequence.seq_empty]
  · rename_i q hq _ val _ hz hcf
    obtain ⟨hlen, hlenv, hq2⟩ := hq val.1 val.2 (continue_eq_tryCF.mp hcf)
    intro x hx; cases hx
    have hl0 : varint.lenOf 0 = 1 := by simp [varint.lenOf]
    obtain ⟨n, hn, hnv⟩ := alloc.vec.Vec.size_ok DI.SizeInst hL.SizeInstLawful (Slice.new T) 0#usize
      (.nil _) (by simp [hl0]; scalar_tac)
    refine ⟨varint.lenOf val.1.val, n, hlenv, hq2, hn, ?_⟩
    rw [hnv, hz]; simp
  · rename_i q hq _ val _ hz hcf
    obtain ⟨hlen, hlenv, hq2⟩ := hq val.1 val.2 (continue_eq_tryCF.mp hcf)
    have hc : (UScalar.cast UScalarTy.U64 val.1).val = val.1.val := Usize.cast_U64_val_eq _
    have hinv : VecInv DI v a q.2 val.1.val
        ((fun t => t), q.2, UScalar.cast UScalarTy.U64 val.1, UScalar.cast UScalarTy.U64 val.1,
          Slice.new T) :=
      ⟨0, 0#usize, fun _ => rfl, by simp, (law.adv_zero _).symm, by simp [hc], .nil _, rfl,
        by simp [Slice.new]⟩
    have hl := hloop q.2 val.1.val _ hinv
    mvcgen [hl]
    · rename_i y hnone hy
      obtain ⟨-, hLv, hin, hback, c, hrel, hcL⟩ := hy hnone
      intro x hx; cases hx
      rw [hq2, law.adv_view r _ hlenv, List.length_drop] at hLv
      have hmax := law.view_le r
      obtain ⟨n, hn, hnv⟩ := alloc.vec.Vec.size_ok DI.SizeInst hL.SizeInstLawful _ c hrel
        (by rw [hcL, if_pos hlen]; omega)
      refine ⟨varint.lenOf val.1.val + val.1.val, n, by omega, ?_, hn, ?_⟩
      · rw [hback, hin, hq2, law.adv_adv r _ _ (by omega)]
      · rw [hnv, hcL, if_pos hlen]; omega
    · intro x hx; cases hx
  · rename_i q _ _ res _ hbr
    refine try_break_vc (x := q.1) (fun e _ => ?_) hbr
    mvcgen
    intro _
    mvcgen
    all_goals simp

end tls_codec
