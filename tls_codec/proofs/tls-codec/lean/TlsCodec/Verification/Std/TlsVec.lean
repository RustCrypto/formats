/- `TlsVecU*<T>`, `SecretTlsVecU*<T>`. The per-width extracted functions are one generic function
up to the wrapper (`mk`, `vec`, `push`), the prefix codec and its conversion to `usize`: each width
links its loop body / loop / deserializer to the generic one by `rfl` (the message literal of the
loop body is existentially quantified, so that no `toStr` is re-elaborated here).

Obligations: none directly; the `std`-path halves (`Serialize` / `Deserialize` `Lawful` fields,
lemma traits) of `PanicFreedom.lean` / `FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): nothing ASSUMED. -/
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

namespace TlsVecStd

variable {T V : Type}

/-- The loop body of `TlsVecU*::deserialize` over an abstract wrapper `V` (`push`, `msg`: the
zero-consumption message). -/
noncomputable def body {R : Type} (push : V → T → RustM V) (msg : Str) (DI : Deserialize T)
    (RI : alloc.io.read.Read R) (back : R → R) (result : V) (t : R) (i : Std.U64) (i1 : Std.U64) :
    RustM (ControlFlow ((R → R) × V × R × Std.U64 × Std.U64)
      (V × (core.io.util.Take R) × (core.option.Option Error) × (core.io.util.Take R → R))) := do
  let i2 ← core.io.util.Take.impl.limit { inner := t, len := i, limit := i1 }
  if i2 > 0#u64
  then
    let tls_deserialize_back := fun (x : core.io.util.Take R) => x
    let (r, sub) ←
      DI.tls_deserialize
        (alloc.core.io.util.Take.Insts.AllocIoReadRead (alloc.Mut0R.Insts.AllocIoReadRead RI))
        { inner := t, len := i, limit := i1 }
    match r with
    | core.result.Result.Ok element =>
      let i3 ← core.io.util.Take.impl.limit sub
      if i3 = i2
      then
        let a ← core.fmt.Arguments.from_str msg
        let s ← alloc.fmt.format a
        let s1 ← core.hint.must_use s
        ok (done (result, sub, core.option.Option.Some (Error.DecodingError s1),
          fun t1 =>
            let ⟨ t2, _, _ ⟩ := t1
            back (tls_deserialize_back { sub with inner := t2 }).inner))
      else
        let result1 ← push result element
        ok (cont
          (fun t1 => back (tls_deserialize_back { sub with inner := t1 }).inner,
          result1, sub.inner, sub.len, sub.limit))
    | core.result.Result.Err e =>
      ok (done (result, sub, core.option.Option.Some e,
        fun t1 => back (tls_deserialize_back t1).inner))
  else
    ok (done (result, { inner := t, len := i, limit := i1 },
      core.option.Option.None, fun t1 => let ⟨ t2, _, _ ⟩ := t1
                                         back t2))

noncomputable def dloop {R : Type} (push : V → T → RustM V) (msg : Str) (DI : Deserialize T)
    (RI : alloc.io.read.Read R) (back : R → R) (result : V) (t : R) (i : Std.U64) (i1 : Std.U64) :
    RustM (V × (core.io.util.Take R) × (core.option.Option Error) × (core.io.util.Take R → R)) := do
  loop
    (fun (back1, result1, t1, i2, i3) => body push msg DI RI back1 result1 t1 i2 i3)
    (back, result, t, i, i1)

/-- `TlsVecU*::deserialize` (`PDI`: the prefix codec, `conv` / `dbg`: its conversion to `usize`,
`lp`: the element loop). -/
noncomputable def de {R P E : Type} (mk : alloc.vec.Vec T → V) (PDI : Deserialize P)
    (conv : P → RustM (core.result.Result Std.Usize E)) (dbg : core.fmt.Debug E)
    (lp : (R → R) → V → R → Std.U64 → Std.U64 →
      RustM (V × (core.io.util.Take R) × (core.option.Option Error) × (core.io.util.Take R → R)))
    (RI : alloc.io.read.Read R) (bytes : R) : RustM ((core.result.Result V Error) × R) := do
  let v ← alloc.vec.Vec.new T
  let (r, bytes1) ← PDI.tls_deserialize RI bytes
  let cf ← core.result.Result.Insts.CoreOpsTry_traitTry.branch r
  match cf with
  | core.ops.control_flow.ControlFlow.Continue val =>
    let r1 ← conv val
    let length ← core.result.Result.unwrap dbg r1
    let i ← lift (UScalar.cast .U64 length)
    let (sub, take_back) ←
      alloc.io.read.Read.take.default (alloc.Mut0R.Insts.AllocIoReadRead RI) bytes1 i
    let (result, sub1, failure, back) ← lp (fun t => t) (mk v) sub.inner sub.len sub.limit
    match failure with
    | core.option.Option.None =>
      let t := back sub1
      let bytes2 := take_back { sub with inner := t }
      ok (core.result.Result.Ok result, bytes2)
    | core.option.Option.Some e =>
      let t := back sub1
      let bytes2 := take_back { sub with inner := t }
      ok (core.result.Result.Err e, bytes2)
  | core.ops.control_flow.ControlFlow.Break residual =>
    let r1 ←
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
        V (core.convert.From.Blanket Error) residual
    ok (r1, bytes1)

/-! #### The element loop (as `Vec.de_loop`, over the wrapper) -/

section Loop
variable {DI : Deserialize T} (hL : Deserialize.Lawful T DI) {R : Type}
  {RI : alloc.io.read.Read R} {v : R → List Std.U8} {a : R → Nat → R} (law : StdIo.RLaw RI v a)
  {vec : V → alloc.vec.Vec T} {push : V → T → RustM V}
  (hpush : ∀ w x, ⦃ ⌜ (vec w).val.length < Usize.max ⌝ ⦄ push w x
    ⦃ ⇓ r => ⌜ (vec r).val = (vec w).val ++ [x] ⌝ ⦄)

/-- Loop invariant: `m` bytes consumed out of `L` (`limit = L - m`), the elements read so far have
total size `m`. -/
def Inv (DI : Deserialize T) (vec : V → alloc.vec.Vec T) (v : R → List Std.U8) (a : R → Nat → R)
    (r0 : R) (L : Nat) (p : (R → R) × V × R × Std.U64 × Std.U64) : Prop :=
  ∃ m c, (∀ x, p.1 x = x) ∧ m ≤ (v r0).length ∧ p.2.2.1 = a r0 m ∧ p.2.2.2.2.val + m = L ∧
    SizeFoldRel DI.SizeInst 0#usize (vec p.2.1).val c ∧ c.val = m ∧ (vec p.2.1).val.length ≤ m

/-- Loop post: on `None`, everything (`L` bytes) was consumed. -/
def Post (DI : Deserialize T) (vec : V → alloc.vec.Vec T) (v : R → List Std.U8) (a : R → Nat → R)
    (r0 : R) (L : Nat)
    (y : V × (core.io.util.Take R) × (core.option.Option Error) × (core.io.util.Take R → R)) : Prop :=
  y.2.2.1 = core.option.Option.None → y.2.1.limit.val = 0 ∧ L ≤ (v r0).length ∧
    y.2.1.inner = a r0 L ∧ (∀ t, y.2.2.2 t = t.inner) ∧
    ∃ c, SizeFoldRel DI.SizeInst 0#usize (vec y.1).val c ∧ c.val = L

include hL law hpush in
theorem body_spec (msg : Str) (r0 : R) (L : Nat)
    (p : (R → R) × V × R × Std.U64 × Std.U64) (hp : Inv DI vec v a r0 L p) :
    ⦃ ⌜ True ⌝ ⦄ body push msg DI RI p.1 p.2.1 p.2.2.1 p.2.2.2.1 p.2.2.2.2
    ⦃ ⇓ r => ⌜ match r with
      | .done y => Post DI vec v a r0 L y
      | .cont p' => Inv DI vec v a r0 L p' ∧ p'.2.2.2.2.val < p.2.2.2.2.val ⌝ ⦄ := by
  obtain ⟨back, res, t, len, lim⟩ := p
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
  mvcgen [body, core.io.util.Take.impl.limit, hT, hpush, core.fmt.Arguments.from_str]
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
    intro _
    refine ⟨h0, by omega, by dsimp only; rw [ht]; congr 1; omega, fun _ => hback _, c, hrel, by omega⟩

include hL law hpush in
theorem dloop_spec (msg : Str) (r0 : R) (L : Nat)
    (p : (R → R) × V × R × Std.U64 × Std.U64) (hp : Inv DI vec v a r0 L p) :
    ⦃ ⌜ True ⌝ ⦄ dloop push msg DI RI p.1 p.2.1 p.2.2.1 p.2.2.2.1 p.2.2.2.2
    ⦃ ⇓ y => ⌜ Post DI vec v a r0 L y ⌝ ⦄ := by
  unfold dloop
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.loop.spec_decr_nat
    (fun q : (R → R) × V × R × Std.U64 × Std.U64 => q.2.2.2.2.val) (Inv DI vec v a r0 L)
  · rintro ⟨b, rs, t, ln, lm⟩ hq
    obtain ⟨y, hy, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (body_spec hL law hpush msg r0 L _ hq)
    show Aeneas.Std.WP.spec (body push msg DI RI b rs t ln lm) _
    rw [hy, Aeneas.Std.WP.spec_ok]
    cases y with
    | done y => exact hP
    | cont q => exact hP
  · exact hp

end Loop

/-- The size of a wrapper whose elements' zero-based fold is `L`, from prefix width `kz`, when
`kz + L` fits. -/
theorem size_shift {S : Size T} (hS : Size.Lawful T S) {l : List T} {c r kz : Std.Usize}
    (hc : SizeFoldRel S 0#usize l c) (hr : SizeFoldRel S kz l r) (hfit : kz.val + c.val ≤ Usize.max) :
    r.val = kz.val + c.val := by
  obtain ⟨N, hN⟩ := SizeNat.exists hS l
  have h1 := hc.val_min hN
  have h2 := hr.val_min hN
  simp at h1
  omega

/-- `TlsVecU*::deserialize` on lawful readers: an `Ok` consumes exactly the size of the value. -/
theorem de_runs {DI : Deserialize T} (hL : Deserialize.Lawful T DI) {vec : V → alloc.vec.Vec T} {push : V → T → RustM V}
    (hpush : ∀ w x, ⦃ ⌜ (vec w).val.length < Usize.max ⌝ ⦄ push w x
      ⦃ ⇓ r => ⌜ (vec r).val = (vec w).val ++ [x] ⌝ ⦄)
    {P E : Type} (mk : alloc.vec.Vec T → V) (hmk : ∀ v, vec (mk v) = v) (PDI : Deserialize P)
    {Q : List Std.U8 → P → Nat → Prop} (hP : DeRuns PDI Q) (kz : Std.Usize)
    (hk : ∀ x, PDI.SizeInst.tls_serialized_len x = ok kz)
    (conv : P → RustM (core.result.Result Std.Usize E))
    (hconv : ∀ p, ⦃ ⌜ True ⌝ ⦄ conv p ⦃ ⇓ r => ⌜ ∃ y, r = .Ok y ⌝ ⦄) (dbg : core.fmt.Debug E)
    (msg : Str) (DI' : Deserialize V)
    (hde : ∀ (R : Type) (RI : alloc.io.read.Read R) r,
      DI'.tls_deserialize RI r = de mk PDI conv dbg (dloop push msg DI RI) RI r)
    (hsz : ∀ x, ⦃ ⌜ True ⌝ ⦄ DI'.SizeInst.tls_serialized_len x
      ⦃ ⇓ r => ⌜ SizeFoldRel DI.SizeInst kz (vec x).val r ⌝ ⦄) :
    DeRuns DI' (fun _ _ _ => True) := by
  intro R RI v a law r
  rw [hde]
  have hr := hP R RI v a law r
  have hloop := fun r0 L p hp => dloop_spec hL law hpush msg r0 L p hp
  mvcgen [de, hr, hconv, hloop, alloc.io.read.Read.take.default, CoreModels.alloc.vec.Vec.new,
    rust_primitives.sequence.seq_empty, core.result.Result.unwrap]
  · rename_i q hq _ val _ hcf rc _ y _
    obtain ⟨n, sz, hn, hq2, hsz', hszn, -⟩ := hq val (continue_eq_tryCF.mp hcf)
    obtain rfl : kz = sz := ok.inj ((hk val).symm.trans hsz')
    have hc : (UScalar.cast UScalarTy.U64 y).val = y.val := Usize.cast_U64_val_eq _
    have hinv : Inv DI vec v a q.2 y.val
        ((fun t => t), mk (Slice.new T), q.2, UScalar.cast UScalarTy.U64 y,
          UScalar.cast UScalarTy.U64 y) :=
      ⟨0, 0#usize, fun _ => rfl, by simp, (law.adv_zero _).symm, by simp [hc],
        by rw [hmk]; exact .nil _, rfl, by simp [hmk, Slice.new]⟩
    have hl := hloop q.2 y.val _ hinv
    mvcgen [hl]
    · rename_i z hnone hz
      obtain ⟨-, hLv, hin, hback, c, hrel, hcL⟩ := hz hnone
      intro x hx; cases hx
      rw [hq2, law.adv_view r _ hn, List.length_drop] at hLv
      have hmax := law.view_le r
      obtain ⟨s, hs, hsP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (hsz z.1)
      refine ⟨kz.val + y.val, s, by omega, ?_, hs, ?_⟩
      · rw [hback, hin, hq2, law.adv_adv r _ _ (by omega), hszn]
      · rw [size_shift hL.SizeInstLawful hrel hsP (by omega)]; omega
    · intro x hx; cases hx
  · rename_i hex _ hx
    obtain ⟨y, hy⟩ := hex
    rw [hy] at hx; cases hx
  · rename_i q _ _ res _ hbr
    refine try_break_vc (x := q.1) (fun e _ => ?_) hbr
    mvcgen
    intro _
    mvcgen
    all_goals simp

end TlsVecStd

/-! #### The serializer -/

namespace TlsVecStd

variable {T : Type}

/-- `TlsVecU*::serialize` (`gcl`: `get_content_lengths`, `tryP` / `dbg`: the conversion of the
content length to the prefix type, `PSI`: the prefix codec, `slc`: `as_slice`, `aw`:
`assert_written_bytes`). -/
noncomputable def ser {W P E : Type} (gcl : RustM (core.result.Result (Std.Usize × Std.Usize) Error))
    (tryP : Std.Usize → RustM (core.result.Result P E)) (dbg : core.fmt.Debug E)
    (PSI : Serialize P) (slc : RustM (Slice T))
    (aw : Std.Usize → Std.Usize → RustM (core.result.Result Unit Error))
    (SI : Serialize T) (WI : core.io.write.Write W) (writer : W) :
    RustM ((core.result.Result Std.Usize Error) × W) := do
  let r ← gcl
  let cf ← core.result.Result.Insts.CoreOpsTry_traitTry.branch r
  match cf with
  | core.ops.control_flow.ControlFlow.Continue val =>
    let (tls_serialized_len, byte_length) := val
    let r1 ← tryP byte_length
    let i ← core.result.Result.unwrap dbg r1
    let (r2, writer1) ← PSI.tls_serialize WI i writer
    let cf1 ← core.result.Result.Insts.CoreOpsTry_traitTry.branch r2
    match cf1 with
    | core.ops.control_flow.ControlFlow.Continue val1 =>
      let s ← slc
      let (r3, writer2) ← tls_vec.serialize_elements SI WI s writer1
      let cf2 ← core.result.Result.Insts.CoreOpsTry_traitTry.branch r3
      match cf2 with
      | core.ops.control_flow.ControlFlow.Continue val2 =>
        let written ← val1 + val2
        let r4 ← aw tls_serialized_len written
        let cf3 ← core.result.Result.Insts.CoreOpsTry_traitTry.branch r4
        match cf3 with
        | core.ops.control_flow.ControlFlow.Continue _ =>
          ok (core.result.Result.Ok written, writer2)
        | core.ops.control_flow.ControlFlow.Break residual =>
          let r5 ←
            core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
              Std.Usize (core.convert.From.Blanket Error) residual
          ok (r5, writer2)
      | core.ops.control_flow.ControlFlow.Break residual =>
        let r4 ←
          core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
            Std.Usize (core.convert.From.Blanket Error) residual
        ok (r4, writer2)
    | core.ops.control_flow.ControlFlow.Break residual =>
      let r3 ←
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
          Std.Usize (core.convert.From.Blanket Error) residual
      ok (r3, writer1)
  | core.ops.control_flow.ControlFlow.Break residual =>
    let r1 ←
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
        Std.Usize (core.convert.From.Blanket Error) residual
    ok (r1, writer)

/-- `get_content_lengths` on elements of exact total size `N`: `Ok (N + k, N)` when `N ≤ M`, an
`Err` otherwise. -/
theorem gcl_spec {S : Size T} (hS : Size.Lawful T S) (xs : Slice T) {N : Nat}
    (hN : SizeNat S xs.val N) (k : Std.Usize) (mx : RustM Std.Usize) (M : Nat)
    (hmx : ⦃ ⌜ True ⌝ ⦄ mx ⦃ ⇓ r => ⌜ r.val = M ⌝ ⦄) (hkM : M + k.val ≤ Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ tls_codec.HandTranslated.get_content_lengths_std S.tls_serialized_len k mx xs
    ⦃ ⇓ r => ⌜ (N ≤ M → ∃ a b : Std.Usize, r = .Ok (a, b) ∧ a.val = N + k.val ∧ b.val = N) ∧
      (M < N → ∃ e, r = .Err e) ⌝ ⦄ := by
  have hf := checked_len_fold_spec hS xs hN
  mvcgen [tls_codec.HandTranslated.get_content_lengths_std, hf, checked_len_add_triple, tls_codec.Copied.checked_len_add_triple, hmx]
  · rename_i r1 hr1 _ acc _ hcf _ _ _ _ _ _ mv hgt hmv
    have := vec_val r1 acc hr1 hcf
    have : M < N := by rw [← hmv, ← this]; exact hgt
    exact ⟨fun h => by omega, fun _ => ⟨_, rfl⟩⟩
  · rename_i r1 hr1 _ acc _ hcf r2 hr2 _ acc' _ hcf' mv hgt hmv
    have hN := vec_val r1 acc hr1 hcf
    have hle : N ≤ M := by
      have : ¬ mv.val < acc.val := hgt
      omega
    have hfit : acc.val + k.val ≤ Usize.max := by omega
    rw [hr2, checkedLenAddRes_fits _ _ hfit] at hcf'
    simp only [tryCF, core.ops.control_flow.ControlFlow.Continue.injEq] at hcf'
    subst hcf'
    refine ⟨fun _ => ⟨_, _, rfl, ?_, hN⟩, fun h => by omega⟩
    rw [checkedLenAddVal_val _ _ hfit, hN]
  · rename_i r1 hr1 _ acc _ hcf r2 hr2 _ res _
    intro hbr
    have hN := vec_val r1 acc hr1 hcf
    refine try_break_vc (x := r2) (fun e he => ?_) hbr
    have hgt : M < N := by
      by_contra hle
      rw [hr2, checkedLenAddRes_fits _ _ (by omega)] at he; cases he
    mvcgen
    intro _
    mvcgen
    exact ⟨fun h => by omega, fun _ => ⟨_, rfl⟩⟩
  · rename_i r1 hr1 _ res _
    intro hbr
    refine try_break_vc (x := r1) (fun e he => ?_) hbr
    have hgt : Usize.max < N := by
      by_contra hle
      obtain ⟨c, hc, -⟩ := hr1.1 (by omega)
      rw [hc] at he; cases he
    mvcgen
    intro _
    mvcgen
    exact ⟨fun h => by omega, fun _ => ⟨_, rfl⟩⟩

/-- The encoding of a `TlsVecU*` with content size `N` (`pre`: the encoding of the prefix `N`,
`M`: the largest encodable content length). -/
noncomputable def out (SI : Serialize T) (pre : List Std.U8) (M : Nat) (l : List T) (N : Nat) :
    Option (List Std.U8) :=
  if N ≤ M then (encAll SI l).map (pre ++ ·) else none

theorem ser_runs {P E X : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI) (SI' : Serialize X)
    (x : X) (s : Slice T) {N : Nat} (hN : SizeNat SI.SizeInst s.val N) (k : Std.Usize) (M : Nat)
    (_hkM : M + k.val ≤ Usize.max)
    (gcl : RustM (core.result.Result (Std.Usize × Std.Usize) Error))
    (hgcl : ⦃ ⌜ True ⌝ ⦄ gcl
      ⦃ ⇓ r => ⌜ (N ≤ M → ∃ a b : Std.Usize, r = .Ok (a, b) ∧ a.val = N + k.val ∧ b.val = N) ∧
        (M < N → ∃ e, r = .Err e) ⌝ ⦄)
    (tryP : Std.Usize → RustM (core.result.Result P E)) (dbg : core.fmt.Debug E)
    (PSI : Serialize P) (pre : List Std.U8)
    (hpre0 : N ≤ M → pre.length = k.val ∧
      ∃ n0 p, n0.val = N ∧ tryP n0 = ok (.Ok p) ∧ SerRuns PSI p k (some pre))
    (slc : RustM (Slice T)) (hslc : slc = ok s)
    (aw : Std.Usize → Std.Usize → RustM (core.result.Result Unit Error))
    (haw : ∀ a, aw a a = ok (.Ok ()))
    (hser : ∀ (W : Type) (WI : core.io.write.Write W) w,
      SI'.tls_serialize WI x w = ser gcl tryP dbg PSI slc aw SI WI w)
    (sz : Std.Usize) (hszv : N ≤ M → sz.val = N + k.val) :
    SerRuns SI' x sz (out SI pre M s.val N) := by
  intro W WI hWI w hroom
  suffices H : ⦃ ⌜ True ⌝ ⦄ SI'.tls_serialize WI x w
      ⦃ ⇓ p => ⌜ (∀ b, out SI pre M s.val N = some b →
          (∃ n : Std.Usize, p.1 = .Ok n ∧ n.val = b.length) ∧
          core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w ++ b) ∧
        (out SI pre M s.val N = none → ∃ e, p.1 = .Err e) ⌝ ⦄ by
    obtain ⟨⟨r, w'⟩, h1, h2⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp H
    exact ⟨r, w', h1, h2⟩
  have hel : ∀ (s' : Slice T) (w' : W),
      ⦃ ⌜ s' = s ∧ (core.io.write.Write.view WI w').length + N ≤ imax ⌝ ⦄
        tls_vec.serialize_elements SI WI s' w'
      ⦃ ⇓ p => ⌜ (∀ bs, encAll SI s.val = some bs → (∃ n : Std.Usize, p.1 = .Ok n ∧ n.val = N) ∧
          core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w' ++ bs ∧ bs.length = N) ∧
        (encAll SI s.val = none → ∃ e, p.1 = .Err e) ⌝ ⦄ :=
    by intro s' w' ⟨hs, hr⟩; subst hs; exact serialize_elements_spec hL WI hWI w' _ N hN hr trivial
  rw [hser]
  obtain ⟨g, hg, hgP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp hgcl
  by_cases hNM : N ≤ M
  · obtain ⟨a, b, rfl, ha, hb⟩ := hgP.1 hNM
    obtain ⟨hencP, n0, p, hn0, ht, hrun⟩ := hpre0 hNM
    obtain rfl : b = n0 := UScalar.eq_of_val_eq (by omega)
    have hpre : ∀ (i : P) (w' : W), ⦃ ⌜ SerRuns PSI i k (some (pre)) ∧
          (core.io.write.Write.view WI w').length + k.val ≤ imax ⌝ ⦄ PSI.tls_serialize WI i w'
        ⦃ ⇓ p => ⌜ (∃ n : Std.Usize, p.1 = .Ok n ∧ n.val = k.val) ∧
          core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w' ++ pre ⌝ ⦄ := by
      intro i w' ⟨hr, hroom'⟩
      refine triple_post_mono (hr.spec WI hWI w' hroom') (fun p hp => ?_) trivial
      obtain ⟨⟨n, hn, hnv⟩, hv⟩ := hp.1 _ rfl
      exact ⟨⟨n, hn, by rw [hnv, hencP]⟩, hv⟩
    have hroom' : (core.io.write.Write.view WI w).length + (N + k.val) ≤ imax := by
      rw [← hszv hNM]; exact hroom
    have hawt : ∀ c d : Std.Usize, ⦃ ⌜ c = d ⌝ ⦄ aw c d ⦃ ⇓ r => ⌜ r = .Ok () ⌝ ⦄ := by
      intro c d hcd; subst hcd; rw [haw]; mvcgen
    have hgt : ⦃ ⌜ True ⌝ ⦄ gcl ⦃ ⇓ r => ⌜ r = .Ok (a, b) ⌝ ⦄ := by rw [hg]; mvcgen
    have htp : ∀ n, ⦃ ⌜ n = b ⌝ ⦄ tryP n ⦃ ⇓ r => ⌜ r = .Ok p ⌝ ⦄ := by
      intro n hn; subst hn; rw [ht]; mvcgen
    -- the content: `v2 = N` when the elements loop continued
    have hv2 : ∀ (q : core.result.Result Std.Usize Error × W) v2 w',
        (∀ bs, encAll SI s.val = some bs → (∃ n : Std.Usize, q.1 = .Ok n ∧ n.val = N) ∧
          core.io.write.Write.view WI q.2 = core.io.write.Write.view WI w' ++ bs ∧ bs.length = N) →
        (encAll SI s.val = none → ∃ e, q.1 = .Err e) →
        core.ops.control_flow.ControlFlow.Continue v2 = tryCF q.1 →
        v2.val = N ∧ ∃ bs, encAll SI s.val = some bs ∧
          core.io.write.Write.view WI q.2 = core.io.write.Write.view WI w' ++ bs ∧ bs.length = N := by
      intro q v2 w' he1 he2 hcf2
      have := continue_eq_tryCF.mp hcf2
      cases hb : encAll SI s.val with
      | none => obtain ⟨e', he'⟩ := he2 hb; rw [this] at he'; cases he'
      | some bs =>
        obtain ⟨⟨n, hn, hnN⟩, hv, hl⟩ := he1 bs hb
        rw [this] at hn; cases hn
        exact ⟨hnN, bs, rfl, hv, hl⟩
    have hv1 : ∀ (q : core.result.Result Std.Usize Error × W) v1,
        (∃ n : Std.Usize, q.1 = .Ok n ∧ n.val = k.val) →
        core.ops.control_flow.ControlFlow.Continue v1 = tryCF q.1 → v1.val = k.val := by
      intro q v1 ⟨n, hn, hnk⟩ hcf1
      rw [continue_eq_tryCF.mp hcf1] at hn; cases hn; exact hnk
    have hab : ∀ (g' : core.result.Result (Std.Usize × Std.Usize) Error) val, g' = .Ok (a, b) →
        core.ops.control_flow.ControlFlow.Continue val = tryCF g' → val = (a, b) := by
      intro g' val hg' hcf
      rw [hg'] at hcf; cases continue_eq_tryCF.mp hcf; rfl
    mvcgen [ser, hgt, htp, hslc, hpre, hel, hawt, core.result.Result.unwrap_ok_spec]
    · rename_i g' hg' _ val _ hcf
      rw [hab g' val hg' hcf]
    · rename_i h; exact ⟨_, h⟩
    · rename_i h1 _ h2
      rw [h1] at h2; cases h2
      exact ⟨hrun, by omega⟩
    · rename_i q hq _ _ _ _
      refine ⟨trivial, ?_⟩
      rw [hq.2, List.length_append, hencP]; omega
    · rename_i g' hg' _ val _ hcf _ _ _ _ q hq _ v1 _ hcf1 e he _ v2 _ hcf2 wr hwr
      rw [hab g' val hg' hcf]
      have := hv1 q v1 hq.1 hcf1
      have := (hv2 e v2 q.2 he.1 he.2 hcf2).1
      exact UScalar.eq_of_val_eq (by simp only; omega)
    · rename_i g' hg' _ val _ hcf _ _ _ _ q hq _ v1 _ hcf1 e he _ v2 _ hcf2 wr hwr _ _ _ _ _ _
      have h1 := hv1 q v1 hq.1 hcf1
      obtain ⟨h2, bs, hbs, hv, hl⟩ := hv2 e v2 q.2 he.1 he.2 hcf2
      have hout : out SI pre M s.val N = some (pre ++ bs) := by simp [out, hNM, hbs]
      rw [hout]
      refine ⟨fun b' hb' => ?_, fun h => by cases h⟩
      cases hb'
      refine ⟨⟨wr, rfl, ?_⟩, ?_⟩
      · rw [List.length_append, hencP]; omega
      · rw [hv, hq.2, List.append_assoc]
    · rename_i hr1 _ _ _ hbr
      rw [hr1] at hbr; simp [tryCF] at hbr
    · rename_i _ _ _ _ _ _ _ _ _ _ q hq _ v1 _ hcf1 e he _ v2 _ hcf2 hov
      have h1 := hv1 q v1 hq.1 hcf1
      have h2 := (hv2 e v2 q.2 he.1 he.2 hcf2).1
      exfalso; scalar_tac
    · rename_i e he _ res _ hbr
      refine try_break_vc (x := e.1) (fun er her => ?_) hbr
      have hout : out SI pre M s.val N = none := by
        cases hb : encAll SI s.val with
        | none => simp [out, hb]
        | some bs => obtain ⟨⟨n, hn, -⟩, -⟩ := he.1 bs hb; rw [her] at hn; cases hn
      rw [hout]
      mvcgen
      intro _
      mvcgen
      exact ⟨fun b h => (by simp at h), _, rfl⟩
    · rename_i q hq _ res _ hbr
      obtain ⟨n, hn, -⟩ := hq.1
      rw [hn] at hbr; simp [tryCF] at hbr
    · rename_i g' hg' _ res _ hbr
      rw [hg'] at hbr; simp [tryCF] at hbr
  · obtain ⟨e, rfl⟩ := hgP.2 (by omega)
    unfold ser
    rw [hg]
    have hout : out SI pre M s.val N = none := by simp [out, hNM]
    rw [hout]
    mvcgen
    rename_i hbr
    refine ⟨e, by simpa [tryCF] using hbr, ?_⟩
    mvcgen
    intro _
    mvcgen
    exact ⟨fun b h => (by simp at h), _, rfl⟩

/-- The trait-level contract of `TlsVecU*::tls_serialize`, from the width's pieces (`k`: the prefix
width, `M`: the largest content length, `mx` computing it). -/
theorem serSpec {P E X : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI) (SI' : Serialize X)
    (x : X) (s : Slice T) (k : Std.Usize) (M : Nat) (hkM : M + k.val ≤ Usize.max)
    (mx : RustM Std.Usize) (hmx : ⦃ ⌜ True ⌝ ⦄ mx ⦃ ⇓ r => ⌜ r.val = M ⌝ ⦄)
    (gcl : RustM (core.result.Result (Std.Usize × Std.Usize) Error))
    (hgcl : gcl = tls_codec.HandTranslated.get_content_lengths_std SI.SizeInst.tls_serialized_len k mx s)
    (tryP : Std.Usize → RustM (core.result.Result P E)) (dbg : core.fmt.Debug E) (PSI : Serialize P)
    (hP : ∀ n : Std.Usize, n.val ≤ M → ∃ p pre, tryP n = ok (.Ok p) ∧ SerRuns PSI p k (some pre) ∧
      pre.length = k.val)
    (slc : RustM (Slice T)) (hslc : slc = ok s)
    (aw : Std.Usize → Std.Usize → RustM (core.result.Result Unit Error))
    (haw : ∀ a, aw a a = ok (.Ok ()))
    (hser : ∀ (W : Type) (WI : core.io.write.Write W) w,
      SI'.tls_serialize WI x w = ser gcl tryP dbg PSI slc aw SI WI w)
    (hsz : ⦃ ⌜ True ⌝ ⦄ SI'.SizeInst.tls_serialized_len x
      ⦃ ⇓ r => ⌜ SizeFoldRel SI.SizeInst k s.val r ⌝ ⦄) : SerSpec SI' x := by
  obtain ⟨N, hN⟩ := SizeNat.exists hL.SizeInstLawful s.val
  obtain ⟨sz, hsz', hrel⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp hsz
  have hszm := hrel.val_min hN
  have hszv : N ≤ M → sz.val = N + k.val := by intro h; omega
  have hg := gcl_spec hL.SizeInstLawful s hN k mx M hmx hkM
  rw [← hgcl] at hg
  obtain ⟨pre, hpre0⟩ : ∃ pre, N ≤ M → pre.length = k.val ∧
      ∃ n0 p, n0.val = N ∧ tryP n0 = ok (.Ok p) ∧ SerRuns PSI p k (some pre) := by
    by_cases h : N ≤ M
    · obtain ⟨g, -, hgP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp hg
      obtain ⟨a, b, -, -, hb⟩ := hgP.1 h
      obtain ⟨p, pre, ht, hr, hl⟩ := hP b (by omega)
      exact ⟨pre, fun _ => ⟨hl, b, p, hb, ht, hr⟩⟩
    · exact ⟨[], fun h' => absurd h' h⟩
  have hruns := ser_runs hL SI' x s hN k M hkM gcl hg tryP dbg PSI pre hpre0 slc hslc aw haw hser sz
    hszv
  intro W WI hWI w hpre
  refine Serialize.tls_serialize_spec_of_runs' SI' x sz hsz' _ (fun hle b hb => ?_) hruns WI hWI w hpre
  unfold out at hb
  split at hb
  · rename_i hNM
    obtain ⟨hl, -⟩ := hpre0 hNM
    cases hbs : encAll SI s.val with
    | none => simp [hbs] at hb
    | some bs =>
      simp only [hbs, Option.map_some, Option.some.injEq] at hb
      subst hb
      have hbl := encAll_length hL hN (by omega) bs hbs
      rw [List.length_append, hl, hbl, hszv hNM, Nat.add_comm]
  · cases hb

/-- The default `tls_serialize_detached`, from the contract and a total size. -/
theorem detached_of {X : Type} {SI : Serialize X} {x : X} {Q : Std.Usize → Prop} (h : SerSpec SI x)
    (hsz : ⦃ ⌜ True ⌝ ⦄ SI.SizeInst.tls_serialized_len x ⦃ ⇓ r => ⌜ Q r ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default SI x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post SI.SizeInst SI x r).holds ⌝ ⦄ := by
  obtain ⟨sz, h1, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp hsz
  exact h.detached ⟨sz, h1⟩

end TlsVecStd

/-! #### Links: each width is the generic function -/

namespace TlsVecStd

/-- A width's loop body is `body` (`∃ msg`: the message literal is not re-elaborated). -/
macro "tlsvec_body_eq" b:ident : tactic => `(tactic| (
  apply Exists.intro; intros; unfold $b:ident TlsVecStd.body; rfl))

/-- A width's deserializer is `de`, from its loop-body link `h`. -/
macro "tlsvec_de_eq" i:ident f:ident d:ident l:ident h:term : tactic => `(tactic| (
  unfold $i:ident $f:ident $d:ident TlsVecStd.de $l:ident TlsVecStd.dloop
  simp only [$h:term]
  congr 1; funext v; congr 1; funext r; congr 1; funext cf; cases cf <;> rfl))

/-- `DeSpec` from `de_runs`. -/
theorem deSpec {V : Type} {DI' : Deserialize V} (h : DeRuns DI' (fun _ _ _ => True)) : DeSpec DI' :=
  fun _ RI hRI r => Deserialize.tls_deserialize_spec_of_runs DI' h RI hRI r

/-- A `push` spec with its precondition as a hypothesis, as a triple. -/
theorem pre_triple {α : Type} {P : Prop} {m : RustM α} {Q : α → Prop}
    (h : P → ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓ r => ⌜ Q r ⌝ ⦄) : ⦃ ⌜ P ⌝ ⦄ m ⦃ ⇓ r => ⌜ Q r ⌝ ⦄ := by
  intro hP; exact h hP trivial

end TlsVecStd

end tls_codec
