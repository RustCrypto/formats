/- `U24`, `[u8; N]`, pairs and triples.

Obligations: none directly; the `std`-path halves (`Serialize` / `Deserialize` `Lawful` fields,
lemma traits) of `PanicFreedom.lean` / `FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): nothing ASSUMED; 1 signature-only stub
(`core.io.error.Error.Insts.CoreFmtDebug.fmt`). -/
import TlsCodec.Verification.Std.IntsWrappers
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! ### `U24` and `[u8; N]` -/

theorem U24.ser_runs (x : U24) : SerRuns U24.Insts.Tls_codecSerialize x 3#usize (some x.val) := by
  apply ser_runs_of_write_all U24.Insts.Tls_codecSerialize x (Array.to_slice x) 3#usize
    (by simpa [Array.to_slice] using x.property.symm)
  intro W WI w w' hw
  simp only [U24.Insts.Tls_codecSerialize.tls_serialize, U24.to_be_bytes, lift, bind_tc_ok, hw]
  rfl

theorem U24.serSpec (x : U24) : SerSpec U24.Insts.Tls_codecSerialize x :=
  fun _ WI hWI w hpre =>
  Serialize.tls_serialize_spec_of_runs U24.Insts.Tls_codecSerialize x 3#usize rfl _
    (fun b hb => by cases hb; simpa using x.property) (U24.ser_runs x) WI hWI w hpre

theorem Array.default_ok (N : Std.Usize) :
    ∃ a : Array Std.U8 N, core.Array.Insts.CoreDefaultDefault.default N
      core.U8.Insts.CoreDefaultDefault = ok a := by
  have h : ⦃ ⌜ True ⌝ ⦄ core.Array.Insts.CoreDefaultDefault.default N core.U8.Insts.CoreDefaultDefault
      ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
    mvcgen [core.Array.Insts.CoreDefaultDefault.default,
      core.array.DefaultArray.default.closure.Insts.CoreOpsFunctionFnMutTupleUsizeT,
      core.array.DefaultArray.default.closure.Insts.CoreOpsFunctionFnMutTupleUsizeT.call_mut,
      core.U8.Insts.CoreDefaultDefault.default]
  obtain ⟨a, ha, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp h
  exact ⟨a, ha⟩

theorem U24.fixed_runs: FixedRuns U24.Insts.Tls_codecDeserialize 3#usize (fun a => a) := by
  intro R RI v a law r
  have hre := read_exact_spec law r
  obtain ⟨a0, ha0⟩ := Array.default_ok 3#usize
  have hd : U24.Insts.CoreDefaultDefault.default = ok a0 := by
    unfold U24.Insts.CoreDefaultDefault.default; rw [ha0]; rfl
  mvcgen [U24.Insts.Tls_codecDeserialize.tls_deserialize, hre, hd, U24.to_be_bytes,
    U24.from_be_bytes]
  · rename_i p hp _ _ _ x1 hcf
    have hl : (a0.to_slice_mut).1.val.length = (3#usize).val := to_slice_mut_len a0
    by_cases h1 : (3#usize).val ≤ (v r).length
    · have hpe := hp.1 (by rw [hl]; exact h1)
      subst hpe
      exact ⟨fun _ => ⟨x1, read_fixed a0 (v r) h1, by rw [hl]⟩, fun h => by omega⟩
    · rw [hp.2 (by rw [hl]; omega)] at hcf
      simp [tryCF] at hcf
  · rename_i p hp _ res _ hcf
    have hl : (a0.to_slice_mut).1.val.length = (3#usize).val := to_slice_mut_len a0
    by_cases h1 : (3#usize).val ≤ (v r).length
    · rw [hp.1 (by rw [hl]; exact h1)] at hcf
      simp [tryCF] at hcf
    · rw [hp.2 (by rw [hl]; omega)] at hcf
      simp only [tryCF] at hcf
      cases hcf
      refine ⟨_, rfl, ?_⟩
      rw [from_io_eof]
      refine ok_triple_of ?_
      mvcgen
      exact ⟨fun h => by omega, fun _ => ⟨_, rfl⟩⟩

theorem U24.deSpec : DeSpec U24.Insts.Tls_codecDeserialize := fun _ RI hRI r =>
  Deserialize.tls_deserialize_spec_of_runs U24.Insts.Tls_codecDeserialize
    (DeRuns_of_fixed _ _ _ (fun _ => rfl) U24.fixed_runs) RI hRI r

theorem Shared0U24.serSpec (x : U24) : SerSpec Shared0U24.Insts.Tls_codecSerialize x :=
  (U24.serSpec x).transport _ (fun _ _ _ => rfl) rfl ⟨_, rfl⟩

theorem ArrayU8.ser_runs {LEN : Std.Usize} (x : Array Std.U8 LEN) :
    SerRuns (ArrayU8LEN.Insts.Tls_codecSerialize LEN) x LEN (some x.val) := by
  apply ser_runs_of_write_all (ArrayU8LEN.Insts.Tls_codecSerialize LEN) x (Array.to_slice x) LEN
    (by simpa [Array.to_slice] using x.property.symm)
  intro W WI w w' hw
  simp only [ArrayU8LEN.Insts.Tls_codecSerialize, ArrayU8LEN.Insts.Tls_codecSerialize.tls_serialize,
    lift, bind_tc_ok, hw]
  rfl

theorem ArrayU8.serSpec {LEN : Std.Usize} (x : Array Std.U8 LEN) :
    SerSpec (ArrayU8LEN.Insts.Tls_codecSerialize LEN) x :=
  fun _ WI hWI w hpre =>
  Serialize.tls_serialize_spec_of_runs (ArrayU8LEN.Insts.Tls_codecSerialize LEN) x LEN rfl _
    (fun b hb => by cases hb; simpa using x.property) (ArrayU8.ser_runs x) WI hWI w hpre

theorem ArrayU8.fixed_runs (LEN : Std.Usize) :
    FixedRuns (ArrayU8LEN.Insts.Tls_codecDeserialize LEN) LEN (fun a => a) := by
  intro R RI v a law r
  have hre := read_exact_spec law r
  mvcgen [ArrayU8LEN.Insts.Tls_codecDeserialize.tls_deserialize, hre]
  · rename_i arr p hp _ _ _ x1 hcf
    have hl : (arr.to_slice_mut).1.val.length = LEN.val := to_slice_mut_len arr
    by_cases h1 : LEN.val ≤ (v r).length
    · have hpe := hp.1 (by rw [hl]; exact h1)
      subst hpe
      exact ⟨fun _ => ⟨x1, read_fixed arr (v r) h1, by rw [hl]⟩, fun h => by omega⟩
    · rw [hp.2 (by rw [hl]; omega)] at hcf
      simp [tryCF] at hcf
  · rename_i arr p hp _ res _ hcf
    have hl : (arr.to_slice_mut).1.val.length = LEN.val := to_slice_mut_len arr
    by_cases h1 : LEN.val ≤ (v r).length
    · rw [hp.1 (by rw [hl]; exact h1)] at hcf
      simp [tryCF] at hcf
    · rw [hp.2 (by rw [hl]; omega)] at hcf
      simp only [tryCF] at hcf
      cases hcf
      refine ⟨_, rfl, ?_⟩
      rw [from_io_eof]
      refine ok_triple_of ?_
      mvcgen
      exact ⟨fun h => by omega, fun _ => ⟨_, rfl⟩⟩

theorem ArrayU8.deSpec (LEN : Std.Usize) : DeSpec (ArrayU8LEN.Insts.Tls_codecDeserialize LEN) :=
  fun _ RI hRI r =>
  Deserialize.tls_deserialize_spec_of_runs (ArrayU8LEN.Insts.Tls_codecDeserialize LEN)
    (DeRuns_of_fixed _ _ _ (fun _ => rfl) (ArrayU8.fixed_runs LEN)) RI hRI r

/-! ### Tuples -/

theorem step_ok {T W : Type} {SI : Serialize T} {x : T} (h : SerSpec SI x) (s : Std.Usize)
    (hs : SI.SizeInst.tls_serialized_len x = ok s) (hfit : s.val ≤ imax)
    {WI : core.io.write.Write W} {w : W} {p : core.result.Result Std.Usize Error × W}
    {val : Std.Usize}
    (hp : (∀ b, encOut SI x = some b → (∃ n : Std.Usize, p.1 = .Ok n ∧ n.val = b.length) ∧
        core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w ++ b) ∧
      (encOut SI x = none → ∃ e, p.1 = .Err e))
    (hcf : core.ops.control_flow.ControlFlow.Continue val = tryCF p.1) :
    ∃ b, encOut SI x = some b ∧ b.length = s.val ∧ val.val = b.length ∧
      core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w ++ b := by
  cases hb : encOut SI x with
  | none => obtain ⟨e, he⟩ := hp.2 hb; rw [he] at hcf; simp [tryCF] at hcf
  | some b =>
    obtain ⟨⟨n, hn, hnb⟩, hv⟩ := hp.1 b hb
    rw [hn] at hcf; simp [tryCF] at hcf; subst hcf
    exact ⟨b, rfl, h.enc_len s hs hfit b hb, hnb, hv⟩

theorem enc_none_of_err {T W : Type} {SI : Serialize T} {x : T}
    {WI : core.io.write.Write W} {w : W} {p : core.result.Result Std.Usize Error × W}
    (hp : (∀ b, encOut SI x = some b → (∃ n : Std.Usize, p.1 = .Ok n ∧ n.val = b.length) ∧
        core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w ++ b) ∧
      (encOut SI x = none → ∃ e, p.1 = .Err e)) (e : Error) (he : p.1 = .Err e) :
    encOut SI x = none := by
  cases hb : encOut SI x with
  | none => rfl
  | some b => obtain ⟨⟨n, hn, -⟩, -⟩ := hp.1 b hb; rw [he] at hn; cases hn

theorem Pair.ser_runs {T U : Type} {SI : Serialize T} {SI1 : Serialize U} {t : T} {u : U}
    (h1 : SerSpec SI t) (h2 : SerSpec SI1 u) (s1 s2 : Std.Usize)
    (hs1 : SI.SizeInst.tls_serialized_len t = ok s1)
    (hs2 : SI1.SizeInst.tls_serialized_len u = ok s2) :
    SerRuns (Pair.Insts.Tls_codecSerialize SI SI1) (t, u) (lenAddVal s1 s2)
      ((encOut SI t).bind fun b1 => (encOut SI1 u).map (b1 ++ ·)) := by
  intro W WI hWI w hroom
  have := imax_le
  have hfit : (core.io.write.Write.view WI w).length + s1.val + s2.val ≤ imax := by
    by_cases hov : Usize.max < s1.val + s2.val
    · rw [lenAddVal_sat _ _ hov] at hroom; have := imax_eq; omega
    · rw [lenAddVal_val _ _ (by omega)] at hroom; omega
  have hT1 := SerRuns.spec' (h1.runs s1 hs1) WI hWI w
  have hT2 := fun w => SerRuns.spec' (h2.runs s2 hs2) WI hWI w
  suffices H : ⦃ ⌜ True ⌝ ⦄ (Pair.Insts.Tls_codecSerialize SI SI1).tls_serialize WI (t, u) w
      ⦃ ⇓ p => ⌜ (∀ b, ((encOut SI t).bind fun b1 => (encOut SI1 u).map (b1 ++ ·)) = some b →
          (∃ n : Std.Usize, p.1 = .Ok n ∧ n.val = b.length) ∧
        core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w ++ b) ∧
        (((encOut SI t).bind fun b1 => (encOut SI1 u).map (b1 ++ ·)) = none → ∃ e, p.1 = .Err e) ⌝ ⦄ by
    obtain ⟨⟨r, w'⟩, h1, h2⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp H
    exact ⟨r, w', h1, h2⟩
  have hm : UScalar.max UScalarTy.Usize = Usize.max := by
    simp [UScalar.max, Usize.max, Usize.numBits]
  mvcgen [Pair.Insts.Tls_codecSerialize.tls_serialize, hT1, hT2, core.result.Result.map_spec]
  · omega
  · rename_i p hp _ val _ hcf
    obtain ⟨b, hb, hbl, hvl, hv⟩ := step_ok h1 s1 hs1 (by omega) hp hcf
    rw [hv]; simp; omega
  · rename_i p hp _ val _ hcf q hq t ht
    obtain ⟨b1, hb1, hbl1, hvl1, hv1⟩ := step_ok h1 s1 hs1 (by omega) hp hcf
    cases hb2 : encOut SI1 u with
    | none => obtain ⟨e, he⟩ := hq.2 hb2; rw [ht] at he; cases he
    | some b2 =>
      obtain ⟨⟨n, hn, hnb⟩, hv2⟩ := hq.1 b2 hb2
      rw [ht] at hn; cases hn
      have hl2 := h2.enc_len s2 hs2 (by omega) b2 hb2
      unfold primitives.SerializePair.tls_serialize.closure.Insts.CoreOpsFunctionFnOnceTupleUsizeUsize.call_once
      mvcgen
      case h_fail => rename_i hov; exfalso; rw [hm] at hov; omega
      rename_i u hu
      refine ⟨fun b' hb' => ?_, fun h' => by simp [hb1, hb2] at h'⟩
      simp only [hb1, hb2, Option.bind_some, Option.map_some, Option.some.injEq] at hb'; subst hb'
      refine ⟨⟨u, rfl, by simp; omega⟩, by rw [hv2, hv1]; simp⟩
  · rename_i p hp _ val _ hcf q hq e he
    have := enc_none_of_err hq e he
    refine ⟨fun b hb => ?_, fun _ => ⟨e, rfl⟩⟩
    simp [this] at hb
  · rename_i p hp _ residual _ hcf
    refine try_break_vc (x := p.1) (fun e he => ?_) hcf
    have := enc_none_of_err hp e he
    mvcgen
    intro _
    mvcgen
    exact ⟨fun b hb => by simp [this] at hb, fun _ => ⟨_, rfl⟩⟩

theorem Pair.serSpec {T U : Type} {SI : Serialize T} {SI1 : Serialize U} {t : T} {u : U}
    (h1 : SerSpec SI t) (h2 : SerSpec SI1 u)
    (hs1 : ∃ s, SI.SizeInst.tls_serialized_len t = ok s)
    (hs2 : ∃ s, SI1.SizeInst.tls_serialized_len u = ok s) :
    SerSpec (Pair.Insts.Tls_codecSerialize SI SI1) (t, u) := by
  obtain ⟨s1, hs1⟩ := hs1
  obtain ⟨s2, hs2⟩ := hs2
  intro W WI hWI w hpre
  refine Serialize.tls_serialize_spec_of_runs' _ (t, u) _ (Pair_size _ _ t u s1 s2 hs1 hs2) _ ?_
    (Pair.ser_runs h1 h2 s1 s2 hs1 hs2) WI hWI w hpre
  intro hroom b hb
  have := imax_eq
  have hs : s1.val + s2.val ≤ Usize.max := by
    by_contra hov
    rw [lenAddVal_sat _ _ (by omega)] at hroom; omega
  rw [lenAddVal_val _ _ hs] at hroom ⊢
  obtain ⟨b1, hb1, b2, hb2, rfl⟩ : ∃ b1, encOut SI t = some b1 ∧ ∃ b2, encOut SI1 u = some b2 ∧
      b = b1 ++ b2 := by
    cases h : encOut SI t with
    | none => simp [h] at hb
    | some b1 =>
      cases h' : encOut SI1 u with
      | none => simp [h, h'] at hb
      | some b2 => simp [h, h'] at hb; exact ⟨b1, rfl, b2, rfl, hb.symm⟩
  rw [List.length_append, h1.enc_len s1 hs1 (by omega) b1 hb1, h2.enc_len s2 hs2 (by omega) b2 hb2]

theorem Pair.de_runs {T U : Type} {DI : Deserialize T} {DI1 : Deserialize U} (h1 : DeSpec DI)
    (h2 : DeSpec DI1) :
    DeRuns (Pair.Insts.Tls_codecDeserialize DI DI1) (fun _ _ _ => True) := by
  intro R RI v a law r
  have hT1 := fun r' => h1.runs R RI v a law r'
  have hT2 := fun r' => h2.runs R RI v a law r'
  mvcgen [Pair.Insts.Tls_codecDeserialize.tls_deserialize, hT1, hT2]
  · rename_i p _ val1 _ hct1 q _ val2 _ hct2 hh1 hh2
    intro val hval; cases hval
    obtain ⟨n1, sz1, hn1, hq1, hsz1, hszn1⟩ := hh1 val1 (continue_eq_tryCF.mp hct1)
    obtain ⟨n2, sz2, hn2, hq2, hsz2, hszn2⟩ := hh2 val2 (continue_eq_tryCF.mp hct2)
    rw [hq1, law.adv_view r n1 hn1, List.length_drop] at hn2
    rw [hq1, law.adv_adv r n1 n2 (by omega)] at hq2
    refine ⟨n1 + n2, lenAddVal sz1 sz2, by omega, hq2, Pair_size _ _ _ _ sz1 sz2 hsz1 hsz2, ?_⟩
    rw [lenAddVal_val _ _ (by have := law.view_le r; omega)]; omega
  · rename_i _ _ _ _ _ q _ _ _ hbr _ _
    refine try_break_vc (x := q.1) (fun e _ => ?_) hbr
    mvcgen
    intro _
    mvcgen
    all_goals simp
  · rename_i q _ _ _ hbr _
    refine try_break_vc (x := q.1) (fun e _ => ?_) hbr
    mvcgen
    intro _
    mvcgen
    all_goals simp

theorem lenAdd3_fit (a b c : Std.Usize) (L : Nat)
    (h : L + (lenAddVal (lenAddVal a b) c).val ≤ imax) : L + a.val + b.val + c.val ≤ imax := by
  have := imax_eq
  by_cases h1 : Usize.max < a.val + b.val
  · have e1 := lenAddVal_sat a b h1
    by_cases h2 : Usize.max < (lenAddVal a b).val + c.val
    · rw [lenAddVal_sat _ _ h2] at h; omega
    · rw [lenAddVal_val _ _ (by omega)] at h; omega
  · have e1 := lenAddVal_val a b (by omega)
    by_cases h2 : Usize.max < (lenAddVal a b).val + c.val
    · rw [lenAddVal_sat _ _ h2] at h; omega
    · rw [lenAddVal_val _ _ (by omega)] at h; omega

theorem Triple.ser_runs {T U V : Type} {SI : Serialize T} {SI1 : Serialize U} {SI2 : Serialize V}
    {t : T} {u : U} {v : V}
    (h1 : SerSpec SI t) (h2 : SerSpec SI1 u) (h3 : SerSpec SI2 v) (s1 s2 s3 : Std.Usize)
    (hs1 : SI.SizeInst.tls_serialized_len t = ok s1)
    (hs2 : SI1.SizeInst.tls_serialized_len u = ok s2)
    (hs3 : SI2.SizeInst.tls_serialized_len v = ok s3) :
    SerRuns (TupleTUV.Insts.Tls_codecSerialize SI SI1 SI2) (t, u, v)
      (lenAddVal (lenAddVal s1 s2) s3)
      ((encOut SI t).bind fun b1 => (encOut SI1 u).bind fun b2 =>
        (encOut SI2 v).map fun b3 => b1 ++ b2 ++ b3) := by
  intro W WI hWI w hroom
  have := imax_le
  have hfit := lenAdd3_fit s1 s2 s3 _ hroom
  have hT1 := SerRuns.spec' (h1.runs s1 hs1) WI hWI w
  have hT2 := fun w => SerRuns.spec' (h2.runs s2 hs2) WI hWI w
  have hT3 := fun w => SerRuns.spec' (h3.runs s3 hs3) WI hWI w
  suffices H : ⦃ ⌜ True ⌝ ⦄ (TupleTUV.Insts.Tls_codecSerialize SI SI1 SI2).tls_serialize WI (t, u, v) w
      ⦃ ⇓ p => ⌜ (∀ b, ((encOut SI t).bind fun b1 => (encOut SI1 u).bind fun b2 =>
          (encOut SI2 v).map fun b3 => b1 ++ b2 ++ b3) = some b →
          (∃ n : Std.Usize, p.1 = .Ok n ∧ n.val = b.length) ∧
        core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w ++ b) ∧
        (((encOut SI t).bind fun b1 => (encOut SI1 u).bind fun b2 =>
          (encOut SI2 v).map fun b3 => b1 ++ b2 ++ b3) = none → ∃ e, p.1 = .Err e) ⌝ ⦄ by
    obtain ⟨⟨r, w'⟩, h1, h2⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp H
    exact ⟨r, w', h1, h2⟩
  have hm : UScalar.max UScalarTy.Usize = Usize.max := by
    simp [UScalar.max, Usize.max, Usize.numBits]
  mvcgen [TupleTUV.Insts.Tls_codecSerialize.tls_serialize, hT1, hT2, hT3,
    core.result.Result.map_spec]
  · omega
  · rename_i p hp _ val _ hcf
    obtain ⟨b, hb, hbl, hvl, hv⟩ := step_ok h1 s1 hs1 (by omega) hp hcf
    rw [hv]; simp; omega
  · rename_i p1 hp1 _ val1 _ hct1 p2 hp2 _ val2 _ hct2 r hr
    obtain ⟨b1, hb1, hbl1, hvl1, hv1⟩ := step_ok h1 s1 hs1 (by omega) hp1 hct1
    obtain ⟨b2, hb2, hbl2, hvl2, hv2⟩ := step_ok h2 s2 hs2 (by omega) hp2 hct2
    rw [hv2, hv1]; simp; omega
  · rename_i p1 hp1 _ val1 _ hct1 p2 hp2 _ val2 _ hct2 r hr p3 hp3 t ht
    obtain ⟨b1, hb1, hbl1, hvl1, hv1⟩ := step_ok h1 s1 hs1 (by omega) hp1 hct1
    obtain ⟨b2, hb2, hbl2, hvl2, hv2⟩ := step_ok h2 s2 hs2 (by omega) hp2 hct2
    cases hb3 : encOut SI2 v with
    | none => obtain ⟨e, he⟩ := hp3.2 hb3; rw [ht] at he; cases he
    | some b3 =>
      obtain ⟨⟨n, hn, hnb⟩, hv3⟩ := hp3.1 b3 hb3
      rw [ht] at hn; cases hn
      have hl3 := h3.enc_len s3 hs3 (by omega) b3 hb3
      unfold primitives.SerializeTupleTUV.tls_serialize.closure.Insts.CoreOpsFunctionFnOnceTupleUsizeUsize.call_once
      mvcgen
      case h_fail => rename_i hov; exfalso; rw [hm] at hov; omega
      rename_i u' hu
      refine ⟨fun b' hb' => ?_, fun h' => by simp [hb1, hb2, hb3] at h'⟩
      simp only [hb1, hb2, hb3, Option.bind_some, Option.map_some, Option.some.injEq] at hb'
      subst hb'
      refine ⟨⟨u', rfl, by simp; omega⟩, by rw [hv3, hv2, hv1]; simp⟩
  · rename_i p1 hp1 _ val1 _ hct1 p2 hp2 _ val2 _ hct2 r hr p3 hp3 e he
    have := enc_none_of_err hp3 e he
    refine ⟨fun b hb => ?_, fun _ => ⟨e, rfl⟩⟩
    simp [this] at hb
  · rename_i p1 hp1 _ val1 _ hct1 p2 hp2 _ val2 _ hct2 hov
    obtain ⟨b1, hb1, hbl1, hvl1, hv1⟩ := step_ok h1 s1 hs1 (by omega) hp1 hct1
    obtain ⟨b2, hb2, hbl2, hvl2, hv2⟩ := step_ok h2 s2 hs2 (by omega) hp2 hct2
    exfalso; rw [hm] at hov; omega
  · rename_i p1 hp1 _ val1 _ hct1 p2 hp2 _ res _ hbr
    refine try_break_vc (x := p2.1) (fun e he => ?_) hbr
    have := enc_none_of_err hp2 e he
    mvcgen
    intro _
    mvcgen
    exact ⟨fun b hb => by simp [this] at hb, fun _ => ⟨_, rfl⟩⟩
  · rename_i p1 hp1 _ res _ hbr
    refine try_break_vc (x := p1.1) (fun e he => ?_) hbr
    have := enc_none_of_err hp1 e he
    mvcgen
    intro _
    mvcgen
    exact ⟨fun b hb => by simp [this] at hb, fun _ => ⟨_, rfl⟩⟩

theorem Triple.serSpec {T U V : Type} {SI : Serialize T} {SI1 : Serialize U} {SI2 : Serialize V}
    {t : T} {u : U} {v : V}
    (h1 : SerSpec SI t) (h2 : SerSpec SI1 u) (h3 : SerSpec SI2 v)
    (hs1 : ∃ s, SI.SizeInst.tls_serialized_len t = ok s)
    (hs2 : ∃ s, SI1.SizeInst.tls_serialized_len u = ok s)
    (hs3 : ∃ s, SI2.SizeInst.tls_serialized_len v = ok s) :
    SerSpec (TupleTUV.Insts.Tls_codecSerialize SI SI1 SI2) (t, u, v) := by
  obtain ⟨s1, hs1⟩ := hs1
  obtain ⟨s2, hs2⟩ := hs2
  obtain ⟨s3, hs3⟩ := hs3
  intro W WI hWI w hpre
  refine Serialize.tls_serialize_spec_of_runs' _ (t, u, v) _
    (TupleTUV_size _ _ _ t u v s1 s2 s3 hs1 hs2 hs3) _ ?_
    (Triple.ser_runs h1 h2 h3 s1 s2 s3 hs1 hs2 hs3) WI hWI w hpre
  intro hroom b hb
  have := imax_eq
  have hfit := lenAdd3_fit s1 s2 s3 0 (by omega)
  have hs : s1.val + s2.val ≤ Usize.max := by omega
  have e1 := lenAddVal_val _ _ hs
  rw [lenAddVal_val _ _ (by omega), e1]
  obtain ⟨b1, hb1, b2, hb2, b3, hb3, rfl⟩ : ∃ b1, encOut SI t = some b1 ∧ ∃ b2,
      encOut SI1 u = some b2 ∧ ∃ b3, encOut SI2 v = some b3 ∧ b = b1 ++ b2 ++ b3 := by
    cases h : encOut SI t with
    | none => simp [h] at hb
    | some b1 =>
      cases h' : encOut SI1 u with
      | none => simp [h, h'] at hb
      | some b2 =>
        cases h'' : encOut SI2 v with
        | none => simp [h, h', h''] at hb
        | some b3 => simp [h, h', h''] at hb; exact ⟨b1, rfl, b2, rfl, b3, rfl, by simp [← hb]⟩
  simp only [List.length_append, h1.enc_len s1 hs1 (by omega) b1 hb1,
    h2.enc_len s2 hs2 (by omega) b2 hb2, h3.enc_len s3 hs3 (by omega) b3 hb3]

theorem Triple.de_runs {T U V : Type} {DI : Deserialize T} {DI1 : Deserialize U}
    {DI2 : Deserialize V} (h1 : DeSpec DI) (h2 : DeSpec DI1) (h3 : DeSpec DI2) :
    DeRuns (TupleTUV.Insts.Tls_codecDeserialize DI DI1 DI2) (fun _ _ _ => True) := by
  intro R RI v a law r
  have hT1 := fun r' => h1.runs R RI v a law r'
  have hT2 := fun r' => h2.runs R RI v a law r'
  have hT3 := fun r' => h3.runs R RI v a law r'
  mvcgen [TupleTUV.Insts.Tls_codecDeserialize.tls_deserialize, hT1, hT2, hT3]
  · rename_i p1 _ val1 _ hct1 p2 _ val2 _ hct2 p3 _ val3 _ hct3 hh1 hh2 hh3
    intro val hval; cases hval
    obtain ⟨n1, sz1, hn1, hq1, hsz1, hszn1⟩ := hh1 val1 (continue_eq_tryCF.mp hct1)
    obtain ⟨n2, sz2, hn2, hq2, hsz2, hszn2⟩ := hh2 val2 (continue_eq_tryCF.mp hct2)
    obtain ⟨n3, sz3, hn3, hq3, hsz3, hszn3⟩ := hh3 val3 (continue_eq_tryCF.mp hct3)
    rw [hq1, law.adv_view r n1 hn1, List.length_drop] at hn2
    rw [hq1, law.adv_adv r n1 n2 (by omega)] at hq2
    rw [hq2, law.adv_view r (n1 + n2) (by omega), List.length_drop] at hn3
    rw [hq2, law.adv_adv r (n1 + n2) n3 (by omega)] at hq3
    refine ⟨n1 + n2 + n3, lenAddVal (lenAddVal sz1 sz2) sz3, by omega, hq3,
      TupleTUV_size _ _ _ _ _ _ sz1 sz2 sz3 hsz1 hsz2 hsz3, ?_⟩
    have e1 := lenAddVal_val sz1 sz2 (by have := law.view_le r; omega)
    rw [lenAddVal_val _ _ (by have := law.view_le r; omega), e1]; omega
  · rename_i _ _ _ _ _ _ _ _ _ _ p3 _ _ _ hbr _ _ _
    refine try_break_vc (x := p3.1) (fun e _ => ?_) hbr
    mvcgen
    intro _
    mvcgen
    all_goals simp
  · rename_i _ _ _ _ _ p2 _ _ _ hbr _ _
    refine try_break_vc (x := p2.1) (fun e _ => ?_) hbr
    mvcgen
    intro _
    mvcgen
    all_goals simp
  · rename_i p1 _ _ _ hbr _
    refine try_break_vc (x := p1.1) (fun e _ => ?_) hbr
    mvcgen
    intro _
    mvcgen
    all_goals simp

/-! ### `()` and `PhantomData<T>`: zero bytes -/

theorem Unit.serSpec (x : Unit) : SerSpec Tuple.Insts.Tls_codecSerialize x := by
  intro W WI hWI w hpre
  refine Serialize.tls_serialize_spec_of_runs _ x 0#usize rfl (some []) (fun b hb => by cases hb; rfl)
    ?_ WI hWI w hpre
  intro W WI hWI w hroom
  refine ⟨_, w, rfl, fun b hb => ?_, fun h => by cases h⟩
  cases hb
  exact ⟨⟨0#usize, rfl, rfl⟩, by simp⟩

theorem Unit.deSpec : DeSpec Tuple.Insts.Tls_codecDeserialize := by
  refine fun R RI hRI r => Deserialize.tls_deserialize_spec_of_runs
    (P := fun _ _ _ => True) _ ?_ RI hRI r
  intro R RI v a law r
  exact ok_triple_of fun val _ => ⟨0, 0#usize, by omega, (law.adv_zero r).symm, rfl, rfl, trivial⟩

theorem Phantom.serSpec (T : Type) (x : core.marker.PhantomData T) :
    SerSpec (core.marker.PhantomData.Insts.Tls_codecSerialize T) x := by
  intro W WI hWI w hpre
  refine Serialize.tls_serialize_spec_of_runs _ x 0#usize rfl (some []) (fun b hb => by cases hb; rfl)
    ?_ WI hWI w hpre
  intro W WI hWI w hroom
  refine ⟨_, w, rfl, fun b hb => ?_, fun h => by cases h⟩
  cases hb
  exact ⟨⟨0#usize, rfl, rfl⟩, by simp⟩

theorem Phantom.deSpec (T : Type) : DeSpec (core.marker.PhantomData.Insts.Tls_codecDeserialize T) := by
  refine fun R RI hRI r => Deserialize.tls_deserialize_spec_of_runs
    (P := fun _ _ _ => True) _ ?_ RI hRI r
  intro R RI v a law r
  exact ok_triple_of fun val _ => ⟨0, 0#usize, by omega, (law.adv_zero r).symm, rfl, rfl, trivial⟩

/-! #### Contracts from the components' `Lawful` -/

theorem Pair.serSpec' {T U : Type} {SI : Serialize T} {SI1 : Serialize U}
    (h1 : Serialize.Lawful T SI) (h2 : Serialize.Lawful U SI1) (x : T × U) :
    SerSpec (Pair.Insts.Tls_codecSerialize SI SI1) x :=
  Pair.serSpec (h1.serSpec x.1) (h2.serSpec x.2) (Size.lawful_ok _ h1.SizeInstLawful x.1)
    (Size.lawful_ok _ h2.SizeInstLawful x.2)

theorem Pair.size_ex {T U : Type} {SI : Serialize T} {SI1 : Serialize U}
    (h1 : Serialize.Lawful T SI) (h2 : Serialize.Lawful U SI1) (x : T × U) :
    ∃ sz, (Pair.Insts.Tls_codecSerialize SI SI1).SizeInst.tls_serialized_len x = ok sz := by
  obtain ⟨s1, hs1⟩ := Size.lawful_ok _ h1.SizeInstLawful x.1
  obtain ⟨s2, hs2⟩ := Size.lawful_ok _ h2.SizeInstLawful x.2
  exact ⟨_, Pair_size _ _ x.1 x.2 s1 s2 hs1 hs2⟩

theorem Pair.deSpec' {T U : Type} {DI : Deserialize T} {DI1 : Deserialize U}
    (h1 : Deserialize.Lawful T DI) (h2 : Deserialize.Lawful U DI1) :
    DeSpec (Pair.Insts.Tls_codecDeserialize DI DI1) :=
  fun _ RI hRI r => Deserialize.tls_deserialize_spec_of_runs _
    (Pair.de_runs h1.deSpec h2.deSpec) RI hRI r

theorem Triple.serSpec' {T U V : Type} {SI : Serialize T} {SI1 : Serialize U} {SI2 : Serialize V}
    (h1 : Serialize.Lawful T SI) (h2 : Serialize.Lawful U SI1) (h3 : Serialize.Lawful V SI2)
    (x : T × U × V) : SerSpec (TupleTUV.Insts.Tls_codecSerialize SI SI1 SI2) x :=
  Triple.serSpec (h1.serSpec x.1) (h2.serSpec x.2.1) (h3.serSpec x.2.2)
    (Size.lawful_ok _ h1.SizeInstLawful x.1) (Size.lawful_ok _ h2.SizeInstLawful x.2.1)
    (Size.lawful_ok _ h3.SizeInstLawful x.2.2)

theorem Triple.size_ex {T U V : Type} {SI : Serialize T} {SI1 : Serialize U} {SI2 : Serialize V}
    (h1 : Serialize.Lawful T SI) (h2 : Serialize.Lawful U SI1) (h3 : Serialize.Lawful V SI2)
    (x : T × U × V) :
    ∃ sz, (TupleTUV.Insts.Tls_codecSerialize SI SI1 SI2).SizeInst.tls_serialized_len x = ok sz := by
  obtain ⟨s1, hs1⟩ := Size.lawful_ok _ h1.SizeInstLawful x.1
  obtain ⟨s2, hs2⟩ := Size.lawful_ok _ h2.SizeInstLawful x.2.1
  obtain ⟨s3, hs3⟩ := Size.lawful_ok _ h3.SizeInstLawful x.2.2
  exact ⟨_, TupleTUV_size _ _ _ x.1 x.2.1 x.2.2 s1 s2 s3 hs1 hs2 hs3⟩

theorem Triple.deSpec' {T U V : Type} {DI : Deserialize T} {DI1 : Deserialize U}
    {DI2 : Deserialize V} (h1 : Deserialize.Lawful T DI) (h2 : Deserialize.Lawful U DI1)
    (h3 : Deserialize.Lawful V DI2) :
    DeSpec (TupleTUV.Insts.Tls_codecDeserialize DI DI1 DI2) :=
  fun _ RI hRI r => Deserialize.tls_deserialize_spec_of_runs _
    (Triple.de_runs h1.deSpec h2.deSpec h3.deSpec) RI hRI r

end tls_codec
