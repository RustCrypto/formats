/- Agreement of the decoders (`DecodersAgree`) and the mixed round trip (`RoundTripMixed`) of
composed codecs: the downstream crates' derived and hand-written impls.

`AgreeF d b` / `BIndepF b`: `Agree` / `BIndep` (`Std/Agree.lean`) for a `std` decoder `d` and a
byte-slice decoder `b` given as functions. Derived decoders are chains of field decoders joined
by `?` (`seqStd` / `seqB`, the shape of the extraction, so a derived decoder is an instance by
`rfl`); the facts compose (`AgreeF.seq`, `BIndepF.seq`) from those of the fields and of the
continuation (`retStd` / `retB` for a constructor, `errStd` / `errB` for a rejected value, or a
`match` of these). Hand-written byte-slice decoders that run the `std` decoder on the slice
(`viaB`) agree when the `std` decoder agrees with some byte-slice decoder (`AgreeF.via`), or
when it reads a fixed number of bytes (`FixedRunsM`, `AgreeF.of_fixedM_via`).
`DecodersAgree.lawful_of_facts` and `RoundTripMixed.lawful_of` (`Std/Agree.lean`) then close the
lemma-trait obligations.

Obligations: none in TlsCodec; the downstream `DecodersAgree` / `RoundTripMixed` obligations use it.
Axioms reached: none beyond those of `Std/Agree.lean`. -/
import TlsCodec.Verification.ProofObligations
import TlsCodec.Verification.Std.Agree
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec.Derive
open tls_codec

/-! ## The predicates on functions -/

/-- `Agree` for a `std` decoder and a byte-slice decoder given as functions. -/
def AgreeF {T : Type}
    (d : ∀ {R : Type}, alloc.io.read.Read R → R → RustM (core.result.Result T Error × R))
    (b : Slice Std.U8 → RustM (core.result.Result (T × Slice Std.U8) Error)) : Prop :=
  ∀ (R : Type) (RI : alloc.io.read.Read R) (v : R → List Std.U8) (a : R → Nat → R),
    StdIo.RLaw RI v a → ∀ r, ⦃ ⌜ True ⌝ ⦄ d RI r
    ⦃ ⇓ p => ⌜ ∀ s : Slice Std.U8, s.val = v r → ∃ res, b s = ok res ∧ AgreeRes v res p ⌝ ⦄

/-- `BIndep` for a byte-slice decoder given as a function. -/
def BIndepF {T : Type} (b : Slice Std.U8 → RustM (core.result.Result (T × Slice Std.U8) Error)) :
    Prop :=
  ∀ s x t, b s = ok (.Ok (x, t)) →
    ∃ pre, s.val = pre ++ t.val ∧ ∀ (s' : Slice Std.U8) (rest : List Std.U8),
      s'.val = pre ++ rest → ∃ t', b s' = ok (.Ok (x, t')) ∧ t'.val = rest

theorem Agree.of_F {T : Type} {DI : Deserialize T} {DB : DeserializeBytes T}
    (h : AgreeF (fun RI r => DI.tls_deserialize RI r) DB.tls_deserialize_bytes) : Agree DI DB := h

theorem BIndep.of_F {T : Type} {DB : DeserializeBytes T} (h : BIndepF DB.tls_deserialize_bytes) :
    BIndep DB := h

theorem AgreeF.of_agree {T : Type} {DI : Deserialize T} {DB : DeserializeBytes T}
    (h : Agree DI DB) : AgreeF (fun RI r => DI.tls_deserialize RI r) DB.tls_deserialize_bytes := h

theorem BIndepF.of_bindep {T : Type} {DB : DeserializeBytes T} (h : BIndep DB) :
    BIndepF DB.tls_deserialize_bytes := h

theorem AgreeF.total {T : Type}
    {d : ∀ {R : Type}, alloc.io.read.Read R → R → RustM (core.result.Result T Error × R)}
    {b : Slice Std.U8 → RustM (core.result.Result (T × Slice Std.U8) Error)} (h : AgreeF d b)
    (s : Slice Std.U8) : ∃ res, b s = ok res := by
  obtain ⟨p, -, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (h _ _ _ _ StdIo.slice_law s)
  obtain ⟨res, hres, -⟩ := hP s rfl
  exact ⟨res, hres⟩

theorem AgreeF.congr {T : Type}
    {d d' : ∀ {R : Type}, alloc.io.read.Read R → R → RustM (core.result.Result T Error × R)}
    {b b' : Slice Std.U8 → RustM (core.result.Result (T × Slice Std.U8) Error)}
    (h : AgreeF d b) (hd : ∀ (R : Type) (RI : alloc.io.read.Read R) (r : R), d' RI r = d RI r)
    (hb : ∀ s, b' s = b s) : AgreeF d' b' := by
  intro R RI v a law r
  show ⦃ ⌜ True ⌝ ⦄ d' RI r ⦃ ⇓ p => ⌜ ∀ s : Slice Std.U8, s.val = v r →
    ∃ res, b' s = ok res ∧ AgreeRes v res p ⌝ ⦄
  rw [hd]
  refine triple_post_mono (h R RI v a law r) fun p hp s hs => ?_
  rw [hb]
  exact hp s hs

theorem BIndepF.congr {T : Type}
    {b b' : Slice Std.U8 → RustM (core.result.Result (T × Slice Std.U8) Error)}
    (h : BIndepF b) (hb : ∀ s, b' s = b s) : BIndepF b' := by
  intro s x t hs
  rw [hb] at hs
  obtain ⟨pre, h1, h2⟩ := h s x t hs
  exact ⟨pre, h1, fun s' rest h' => by rw [hb]; exact h2 s' rest h'⟩

/-! ## Sequential composition (`?`) -/

/-- A `std` decoder running `m`, then `k` on its value (the shape of a derived decoder). -/
def seqStd {A T : Type}
    (m : ∀ {R : Type}, alloc.io.read.Read R → R → RustM (core.result.Result A Error × R))
    (k : A → ∀ {R : Type}, alloc.io.read.Read R → R → RustM (core.result.Result T Error × R))
    {R : Type} (RI : alloc.io.read.Read R) (bytes : R) :
    RustM (core.result.Result T Error × R) := do
  let (r, bytes1) ← m RI bytes
  let cf ← core.result.Result.Insts.CoreOpsTry_traitTry.branch r
  match cf with
  | core.ops.control_flow.ControlFlow.Continue val => k val RI bytes1
  | core.ops.control_flow.ControlFlow.Break residual =>
    let r1 ← core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
      T (core.convert.From.Blanket Error) residual
    ok (r1, bytes1)

/-- A byte-slice decoder running `m`, then `k` on its value and remainder. -/
def seqB {A T : Type} (m : Slice Std.U8 → RustM (core.result.Result (A × Slice Std.U8) Error))
    (k : A → Slice Std.U8 → RustM (core.result.Result (T × Slice Std.U8) Error))
    (bytes : Slice Std.U8) : RustM (core.result.Result (T × Slice Std.U8) Error) := do
  let r ← m bytes
  let cf ← core.result.Result.Insts.CoreOpsTry_traitTry.branch r
  match cf with
  | core.ops.control_flow.ControlFlow.Continue p =>
    let (v, bytes1) := p
    k v bytes1
  | core.ops.control_flow.ControlFlow.Break residual =>
    core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
      (T × Slice Std.U8) (core.convert.From.Blanket Error) residual

theorem rustm_bind_congr {α β : Type} {m : RustM α} {f g : α → RustM β} (h : ∀ x, f x = g x) :
    (m >>= f) = (m >>= g) := by
  rw [funext h]

/-- An extracted decoder equals its `seqStd` / `seqB` form: the two differ only in the
`match` functions the elaborator generates, so the proof splits each bound value (a pair, a
`Result`, a control flow) and reduces. -/
macro "seq_eq" : tactic => `(tactic| (
  repeat (first
    | rfl
    | (refine rustm_bind_congr fun x => ?_
       first
         | (obtain ⟨a, b⟩ := x; cases a)
         | cases x
       all_goals (try simp only [core.result.Result.Insts.CoreOpsTry_traitTry.branch,
         core.result.Result.Insts.CoreOpsTry_traitTryTResultInfallibleE.branch, bind_tc_ok]))
    | (cases ‹core.result.Result _ _› <;> rfl))))

/-- `d RI r = seqStd …` of an extracted `std` decoder `d` (its definition). -/
macro "seq_std_eq " d:ident : tactic => `(tactic| (
  show $d _ _ = _
  unfold $d:ident
  (try unfold seqStd)
  (try unfold retStd)
  seq_eq))

/-- `b s = seqB …` of an extracted byte-slice decoder `b` (its definition). -/
macro "seq_b_eq " b:ident : tactic => `(tactic| (
  show $b _ = _
  unfold $b:ident
  (try unfold seqB)
  (try unfold retB)
  seq_eq))

/-- The end of a derived `std` decoder: the value. -/
def retStd {T : Type} (x : T) {R : Type} (_RI : alloc.io.read.Read R) (bytes : R) :
    RustM (core.result.Result T Error × R) := ok (.Ok x, bytes)

/-- The end of a derived byte-slice decoder: the value and the remainder. -/
def retB {T : Type} (x : T) (bytes : Slice Std.U8) :
    RustM (core.result.Result (T × Slice Std.U8) Error) := ok (.Ok (x, bytes))

theorem seqStd_ok {A T R : Type}
    {m : ∀ {R : Type}, alloc.io.read.Read R → R → RustM (core.result.Result A Error × R)}
    {k : A → ∀ {R : Type}, alloc.io.read.Read R → R → RustM (core.result.Result T Error × R)}
    {RI : alloc.io.read.Read R} {r r1 : R} {x : A} (h : m RI r = ok (.Ok x, r1)) :
    seqStd m k RI r = k x RI r1 := by
  simp only [seqStd, h, bind_tc_ok]; rfl

theorem seqStd_err {A T R : Type}
    {m : ∀ {R : Type}, alloc.io.read.Read R → R → RustM (core.result.Result A Error × R)}
    {k : A → ∀ {R : Type}, alloc.io.read.Read R → R → RustM (core.result.Result T Error × R)}
    {RI : alloc.io.read.Read R} {r r1 : R} {e : Error} (h : m RI r = ok (.Err e, r1)) :
    seqStd m k RI r = ok (.Err e, r1) := by
  simp only [seqStd, h, bind_tc_ok]; rfl

theorem seqB_ok {A T : Type} {m : Slice Std.U8 → RustM (core.result.Result (A × Slice Std.U8) Error)}
    {k : A → Slice Std.U8 → RustM (core.result.Result (T × Slice Std.U8) Error)}
    {s t : Slice Std.U8} {x : A} (h : m s = ok (.Ok (x, t))) : seqB m k s = k x t := by
  simp only [seqB, h, bind_tc_ok]; rfl

theorem seqB_err {A T : Type} {m : Slice Std.U8 → RustM (core.result.Result (A × Slice Std.U8) Error)}
    {k : A → Slice Std.U8 → RustM (core.result.Result (T × Slice Std.U8) Error)}
    {s : Slice Std.U8} {e : Error} (h : m s = ok (.Err e)) : seqB m k s = ok (.Err e) := by
  simp only [seqB, h, bind_tc_ok]; rfl

theorem AgreeF.seq {A T : Type}
    {m : ∀ {R : Type}, alloc.io.read.Read R → R → RustM (core.result.Result A Error × R)}
    {mb : Slice Std.U8 → RustM (core.result.Result (A × Slice Std.U8) Error)}
    {k : A → ∀ {R : Type}, alloc.io.read.Read R → R → RustM (core.result.Result T Error × R)}
    {kb : A → Slice Std.U8 → RustM (core.result.Result (T × Slice Std.U8) Error)}
    (hm : AgreeF m mb) (hk : ∀ x, AgreeF (k x) (kb x)) :
    AgreeF (seqStd m k) (seqB mb kb) := by
  intro R RI v a law r
  dsimp only
  obtain ⟨p1, hp1, hP1⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (hm R RI v a law r)
  obtain ⟨res1, r1⟩ := p1
  cases res1 with
  | Ok x =>
    rw [seqStd_ok hp1]
    refine triple_post_mono (hk x R RI v a law r1) fun p hp s hs => ?_
    obtain ⟨rb, hrb, hrel⟩ := hP1 s hs
    cases rb with
    | Ok xt =>
      obtain ⟨x', t⟩ := xt
      obtain ⟨h1, h2⟩ := hrel
      cases h1
      rw [seqB_ok hrb]
      exact hp t h2.symm
    | Err e =>
      obtain ⟨e', he'⟩ := hrel
      cases he'
  | Err e =>
    rw [seqStd_err hp1]
    refine ok_triple_of fun s hs => ?_
    obtain ⟨rb, hrb, hrel⟩ := hP1 s hs
    cases rb with
    | Ok xt =>
      obtain ⟨x', t⟩ := xt
      obtain ⟨h1, -⟩ := hrel
      cases h1
    | Err e' =>
      exact ⟨_, seqB_err hrb, e, rfl⟩

theorem BIndepF.seq {A T : Type}
    {mb : Slice Std.U8 → RustM (core.result.Result (A × Slice Std.U8) Error)}
    {kb : A → Slice Std.U8 → RustM (core.result.Result (T × Slice Std.U8) Error)}
    (hm : BIndepF mb) (hk : ∀ x, BIndepF (kb x))
    (htot : ∀ s, ∃ res, mb s = ok res) : BIndepF (seqB mb kb) := by
  intro s y t h
  obtain ⟨r1, hr1⟩ := htot s
  cases r1 with
  | Err e =>
    rw [seqB_err hr1] at h
    cases h
  | Ok xt =>
    obtain ⟨x, t1⟩ := xt
    rw [seqB_ok hr1] at h
    obtain ⟨pre1, hpre1, hall1⟩ := hm s x t1 hr1
    obtain ⟨pre2, hpre2, hall2⟩ := hk x t1 y t h
    refine ⟨pre1 ++ pre2, by rw [hpre1, hpre2, List.append_assoc], fun s' rest hs' => ?_⟩
    obtain ⟨t1', ht1', ht1v⟩ := hall1 s' (pre2 ++ rest) (by rw [hs', List.append_assoc])
    rw [seqB_ok ht1']
    exact hall2 t1' rest ht1v

theorem AgreeF.ret {T : Type} (x : T) : AgreeF (retStd x) (retB x) := by
  intro R RI v a law r
  exact ok_triple_of fun s hs => ⟨_, rfl, rfl, hs.symm⟩

theorem BIndepF.ret {T : Type} (x : T) : BIndepF (retB x) := by
  intro s y t h
  simp only [retB] at h
  cases h
  exact ⟨[], rfl, fun s' rest hs' => ⟨s', rfl, hs'⟩⟩

/-- The end of a decoder whose value comes from a total computation `f` (e.g. a `From`). -/
theorem AgreeF.bindRet {A T : Type} (f : RustM A) (g : A → T) (hf : ∃ y, f = ok y) :
    AgreeF (fun _ b => do let y ← f; ok (.Ok (g y), b)) (fun t => do let y ← f; ok (.Ok (g y, t))) := by
  obtain ⟨y, hy⟩ := hf
  intro R RI v a law r
  simp only [hy, bind_tc_ok]
  exact ok_triple_of fun s hs => ⟨.Ok (g y, s), rfl, rfl, hs.symm⟩

theorem BIndepF.bindRet {A T : Type} (f : RustM A) (g : A → T) (hf : ∃ y, f = ok y) :
    BIndepF (fun t => do let y ← f; ok (.Ok (g y, t))) := by
  obtain ⟨y, hy⟩ := hf
  intro s x t h
  simp only [hy, bind_tc_ok] at h
  cases h
  exact ⟨[], rfl, fun s' rest hs' => ⟨s', by simp only [hy, bind_tc_ok], hs'⟩⟩

/-- Both decoders reject the value (e.g. an unknown enum discriminant). -/
theorem AgreeF.err {T : Type}
    {d : ∀ {R : Type}, alloc.io.read.Read R → R → RustM (core.result.Result T Error × R)}
    {b : Slice Std.U8 → RustM (core.result.Result (T × Slice Std.U8) Error)}
    (hd : ∀ (R : Type) (RI : alloc.io.read.Read R) r, ∃ e, d RI r = ok (.Err e, r))
    (hb : ∀ s, ∃ e, b s = ok (.Err e)) : AgreeF d b := by
  intro R RI v a law r
  dsimp only
  obtain ⟨e, he⟩ := hd R RI r
  rw [he]
  refine ok_triple_of fun s _ => ?_
  obtain ⟨e', he'⟩ := hb s
  exact ⟨_, he', e, rfl⟩

theorem BIndepF.err {T : Type} {b : Slice Std.U8 → RustM (core.result.Result (T × Slice Std.U8) Error)}
    (hb : ∀ s, ∃ e, b s = ok (.Err e)) : BIndepF b := by
  intro s x t h
  obtain ⟨e, he⟩ := hb s
  rw [he] at h
  cases h

theorem AgreeF.total_of_ret {T : Type} (x : T) (s : Slice Std.U8) : ∃ res, retB x s = ok res :=
  ⟨_, rfl⟩

/-! ## Derived enums -/

theorem spec_of_eq {α : Type} {m : RustM α} {x : α} (h : m = ok x) :
    ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓ r => ⌜ r = x ⌝ ⦄ := by
  rw [h]; exact ok_triple_of rfl

open Lean Elab Tactic Meta in
/-- `intro s hs`, then instantiate the (last) field fact `∀ s : Slice u8, s.val = … → ∃ res, …` of
the context on it: `res`, `hres`, `hrel`. -/
elab "agree_obtain" : tactic => withMainContext do
  let mut H? : Option Expr := none
  for d in (← getLCtx) do
    if d.isImplementationDetail then continue
    let ty ← instantiateMVars d.type
    if let .forallE _ dom body _ := ty then
      if dom.isAppOf ``Aeneas.Std.Slice && body.isForall then H? := some d.toExpr
  let some H := H? | throwError "agree_obtain: no field fact"
  let Hs ← Term.exprToSyntax H
  let (s, hs) := (mkIdent `s, mkIdent `hs)
  let (res, hres, hrel) := (mkIdent `res, mkIdent `hres, mkIdent `hrel)
  evalTactic (← `(tactic| (intro $s:ident $hs:ident; obtain ⟨$res:ident, $hres:ident, $hrel:ident⟩ := $Hs $s $hs)))

open Lean Elab Tactic Meta in
/-- `hq1 : x = .Ok v` from the context's `Continue v = tryCF x`. -/
elab "agree_cont" : tactic => withMainContext do
  for d in (← getLCtx) do
    if d.isImplementationDetail then continue
    let ty ← instantiateMVars d.type
    if let some (_, lhs, _) := ty.eq? then
      if lhs.isAppOf ``core.ops.control_flow.ControlFlow.Continue then
        let hs ← Term.exprToSyntax d.toExpr
        evalTactic (← `(tactic| have $(mkIdent `hq1):ident := continue_eq_tryCF.mp $hs))
        return
  throwError "agree_cont: no `Continue _ = tryCF _`"

open Lean Elab Tactic Meta in
/-- The `Break` hypothesis `Break r = tryCF x` of the context. -/
elab "agree_break" : tactic => withMainContext do
  for d in (← getLCtx) do
    if d.isImplementationDetail then continue
    let ty ← instantiateMVars d.type
    if let some (_, lhs, _) := ty.eq? then
      if lhs.isAppOf ``core.ops.control_flow.ControlFlow.Break then
        let hs ← Term.exprToSyntax d.toExpr
        evalTactic (← `(tactic| refine try_break_vc (fun $(mkIdent `e):ident $(mkIdent `he):ident => ?_) $hs))
        return
  throwError "agree_break: no `Break _ = tryCF _`"

set_option hygiene false in
/-- The verification conditions of `AgreeF` for a derived enum (a field decoder, typically
`u16`, then a `match` on its value), after `mvcgen` on the `std` decoder with the field's
`AgreeF` triple: instantiate the field fact on the slice, then evaluate the bytes decoder
(`db` its definition) on the same field result. Hygiene is off: the names come from
`agree_obtain` / `agree_cont` / `agree_break`. -/
macro "enum_agree_vcs " db:ident : tactic => `(tactic| (
  all_goals first
    | (agree_obtain
       agree_cont
       cases res with
       | Ok vt =>
         obtain ⟨v', t⟩ := vt
         obtain ⟨h1, h2⟩ := hrel
         rw [hq1] at h1
         cases h1
         refine ⟨.Ok (?_, t), ?_, ?_⟩
         pick_goal 2
         · simp only [$db:ident, hres, bind_tc_ok]
           rfl
         all_goals exact ⟨rfl, h2⟩
       | Err e =>
         obtain ⟨e', he'⟩ := hrel
         rw [hq1] at he'
         cases he')
    | (mvcgen
       agree_obtain
       agree_cont
       cases res with
       | Ok vt =>
         obtain ⟨v', t⟩ := vt
         obtain ⟨h1, h2⟩ := hrel
         rw [hq1] at h1
         cases h1
         have hb : ⦃ ⌜ True ⌝ ⦄ $db:ident s ⦃ ⇓ r => ⌜ ∃ e, r = .Err e ⌝ ⦄ := by
           have hU := spec_of_eq hres
           mvcgen [$db:ident, hU]
           all_goals first
             | (exfalso; rename_i h1 _ _ _ hx hc; subst h1; simp [tryCF] at hc; subst hc; simp_all; done)
             | (mvcgen; exact ⟨_, rfl⟩)
             | (intro hbr; rename_i h1 _ _ _; subst h1; simp [tryCF] at hbr)
         obtain ⟨r0, hr0, e0, he0⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp hb
         subst he0
         exact ⟨_, hr0, _, rfl⟩
       | Err e =>
         obtain ⟨e', he'⟩ := hrel
         rw [hq1] at he'
         cases he')
    | (agree_break
       refine triple_post_mono (core.convert.From.Blanket.from_spec _) ?_
       intro f hf
       subst hf
       simp only [PostCond.ok]
       mvcgen
       agree_obtain
       cases res with
       | Ok vt =>
         obtain ⟨h1, -⟩ := hrel
         rw [he] at h1
         cases h1
       | Err e' =>
         refine ⟨.Err ?_, ?_, ?_⟩
         pick_goal 2
         · simp only [$db:ident, hres, bind_tc_ok]
           rfl
         all_goals exact ⟨_, rfl⟩)))

/-- `BIndepF` of a byte-slice decoder `b` that runs a field decoder `mb` (with `BIndepF`) and then
a continuation of the field's value alone: a success leaves the field's remainder, and any
input on which `mb` gives the same value gives the same result. -/
theorem BIndepF.of_field {A T : Type}
    {mb : Slice Std.U8 → RustM (core.result.Result (A × Slice Std.U8) Error)}
    {b : Slice Std.U8 → RustM (core.result.Result (T × Slice Std.U8) Error)}
    (hm : BIndepF mb) (htot : ∀ s, ∃ res, mb s = ok res)
    (hstep : ∀ s k t1, mb s = ok (.Ok (k, t1)) → ∀ y u, b s = ok (.Ok (y, u)) → u = t1 ∧
      ∀ (s' t' : Slice Std.U8), mb s' = ok (.Ok (k, t')) → b s' = ok (.Ok (y, t')))
    (herr : ∀ s e, mb s = ok (.Err e) → ∀ y u, b s ≠ ok (.Ok (y, u))) : BIndepF b := by
  intro s y u h
  obtain ⟨r1, hr1⟩ := htot s
  cases r1 with
  | Err e => exact absurd h (herr s e hr1 y u)
  | Ok kt =>
    obtain ⟨k, t1⟩ := kt
    obtain ⟨hu, hall⟩ := hstep s k t1 hr1 y u h
    subst hu
    obtain ⟨pre, hpre, hallm⟩ := hm s k u hr1
    refine ⟨pre, hpre, fun s' rest hs' => ?_⟩
    obtain ⟨t', ht', ht'v⟩ := hallm s' rest hs'
    exact ⟨t', hall s' t' ht', ht'v⟩

set_option hygiene false in
/-- `BIndepF` of a derived enum's byte-slice decoder `db` (field decoder `mb`, e.g. `u16`, with
facts `fa : AgreeF _ mb ∧ BIndepF mb`), through `BIndepF.of_field`: `mvcgen` on `db` with the
field result known; a variant is rebuilt on any input with the same discriminant. -/
macro "enum_bindep " db:ident "," mb:term "," fa:term : tactic => `(tactic| (
  refine BIndepF.of_field ($fa).2 (AgreeF.total ($fa).1) (fun s k t1 hr1 y u h => ?_)
    (fun s e hr1 y u h => ?_)
  · change $db:ident s = _ at h
    have hT : ⦃ ⌜ True ⌝ ⦄ $db:ident s ⦃ ⇓ r => ⌜ ∀ y u, r = .Ok (y, u) → u = t1 ∧
        ∀ (s' t' : Slice Std.U8), $mb s' = ok (.Ok (k, t')) → $db:ident s' = ok (.Ok (y, t')) ⌝ ⦄ := by
      have hU1 := spec_of_eq hr1
      mvcgen [$db:ident, hU1]
      all_goals first
        | (rename_i h1 _ p _ hx hc
           subst h1
           simp only [tryCF, core.ops.control_flow.ControlFlow.Continue.injEq] at hc
           subst hc
           simp only at hx
           subst hx
           intro y u hyu
           simp only [core.result.Result.Ok.injEq, Prod.mk.injEq] at hyu
           obtain ⟨rfl, rfl⟩ := hyu
           refine ⟨rfl, fun s' t' hs' => ?_⟩
           simp only [$db:ident, hs', bind_tc_ok]
           rfl)
        | (mvcgen; intro y u hyu; cases hyu)
        | (intro hbr; rename_i h1 _ _ _; subst h1; simp [tryCF] at hbr)
    obtain ⟨r, hr, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp hT
    rw [hr] at h
    cases h
    exact hP y u rfl
  · change $db:ident s = _ at h
    have hT : ⦃ ⌜ True ⌝ ⦄ $db:ident s ⦃ ⇓ r => ⌜ ∃ e, r = .Err e ⌝ ⦄ := by
      have hU1 := spec_of_eq hr1
      mvcgen [$db:ident, hU1]
      all_goals first
        | (agree_cont; exfalso; simp_all; done)
        | (first | agree_break | (intro hbr; agree_break)
           refine triple_post_mono (core.convert.From.Blanket.from_spec _) ?_
           intro f hf
           subst hf
           simp only [PostCond.ok]
           mvcgen
           exact ⟨_, rfl⟩)
    obtain ⟨r, hr, e', he'⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp hT
    rw [hr, he'] at h
    cases h))

/-! ## Byte-slice decoders running the `std` decoder on the slice -/

/-- The byte-slice decoder that runs `d` on a slice reader and returns the reader left. -/
def viaB {T : Type}
    (d : ∀ {R : Type}, alloc.io.read.Read R → R → RustM (core.result.Result T Error × R))
    (bytes : Slice Std.U8) : RustM (core.result.Result (T × Slice Std.U8) Error) := do
  let (r, bytes1) ← d alloc.Shared0SliceU8.Insts.AllocIoReadRead bytes
  let cf ← core.result.Result.Insts.CoreOpsTry_traitTry.branch r
  match cf with
  | core.ops.control_flow.ControlFlow.Continue val => ok (.Ok (val, bytes1))
  | core.ops.control_flow.ControlFlow.Break residual =>
    core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
      (T × Slice Std.U8) (core.convert.From.Blanket Error) residual

/-- `viaB d` computes what any byte-slice decoder agreeing with `d` computes. -/
theorem viaB_of_agree {T : Type}
    {d : ∀ {R : Type}, alloc.io.read.Read R → R → RustM (core.result.Result T Error × R)}
    {b : Slice Std.U8 → RustM (core.result.Result (T × Slice Std.U8) Error)} (h : AgreeF d b)
    (s : Slice Std.U8) :
    (∃ res, b s = ok res ∧ viaB d s = ok res) ∨
      (∃ e e', b s = ok (.Err e) ∧ viaB d s = ok (.Err e')) := by
  obtain ⟨p, hp, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (h _ _ _ _ StdIo.slice_law s)
  obtain ⟨res, hres, hrel⟩ := hP s rfl
  obtain ⟨r1, s1⟩ := p
  cases res with
  | Ok xt =>
    obtain ⟨x, t⟩ := xt
    obtain ⟨h1, h2⟩ := hrel
    simp only at h1 h2
    subst h1
    have : s1 = t := Subtype.ext h2
    subst this
    left
    exact ⟨_, hres, by simp only [viaB, hp, bind_tc_ok]; rfl⟩
  | Err e =>
    obtain ⟨e', he'⟩ := hrel
    simp only at he'
    subst he'
    right
    exact ⟨e, e', hres, by simp only [viaB, hp, bind_tc_ok]; rfl⟩

/-- A hand-written byte-slice decoder running the `std` decoder on the slice agrees with it when
the `std` decoder agrees with some byte-slice decoder `b`. -/
theorem AgreeF.via {T : Type}
    {d : ∀ {R : Type}, alloc.io.read.Read R → R → RustM (core.result.Result T Error × R)}
    {b : Slice Std.U8 → RustM (core.result.Result (T × Slice Std.U8) Error)}
    (h : AgreeF d b) (hI : BIndepF b) : AgreeF d (viaB d) ∧ BIndepF (viaB d) := by
  refine ⟨fun R RI v a law r => ?_, fun s x t hst => ?_⟩
  · refine triple_post_mono (h R RI v a law r) fun p hp s hs => ?_
    obtain ⟨res, hres, hrel⟩ := hp s hs
    rcases viaB_of_agree h s with ⟨res', hb, hv⟩ | ⟨e, e', hb, hv⟩
    · rw [hres] at hb; cases hb
      exact ⟨_, hv, hrel⟩
    · rw [hres] at hb; cases hb
      obtain ⟨e'', he''⟩ := hrel
      exact ⟨_, hv, e'', he''⟩
  · rcases viaB_of_agree h s with ⟨res', hb, hv⟩ | ⟨e, e', hb, hv⟩
    · rw [hst] at hv; cases hv
      obtain ⟨pre, hpre, hall⟩ := hI s x t hb
      refine ⟨pre, hpre, fun s' rest hs' => ?_⟩
      obtain ⟨t', ht', ht'v⟩ := hall s' rest hs'
      rcases viaB_of_agree h s' with ⟨res'', hb', hv'⟩ | ⟨e2, e2', hb', hv'⟩
      · rw [ht'] at hb'; cases hb'
        exact ⟨t', hv', ht'v⟩
      · rw [ht'] at hb'; cases hb'
    · rw [hst] at hv; cases hv

/-! ## Fixed-size `std` decoders -/

/-- A `std` decoder reading `N` bytes (failing when fewer are left) and mapping them with the
total `g` (which may reject them). -/
def FixedRunsM {T : Type}
    (d : ∀ {R : Type}, alloc.io.read.Read R → R → RustM (core.result.Result T Error × R))
    (N : Std.Usize) (g : Aeneas.Std.Array Std.U8 N → RustM (core.result.Result T Error)) : Prop :=
  ∀ (R : Type) (RI : alloc.io.read.Read R) (v : R → List Std.U8) (a : R → Nat → R),
    StdIo.RLaw RI v a → ∀ r, ⦃ ⌜ True ⌝ ⦄ d RI r
    ⦃ ⇓ p => ⌜ (N.val ≤ (v r).length → ∃ arr : Aeneas.Std.Array Std.U8 N,
        arr.val = (v r).take N.val ∧ g arr = ok p.1 ∧ (∀ x, p.1 = .Ok x → p.2 = a r N.val)) ∧
      ((v r).length < N.val → ∃ e, p.1 = .Err e) ⌝ ⦄

/-- A fixed-size `std` decoder and the byte-slice decoder running it on the slice agree. -/
theorem AgreeF.of_fixedM_via {T : Type}
    {d : ∀ {R : Type}, alloc.io.read.Read R → R → RustM (core.result.Result T Error × R)}
    (N : Std.Usize) (g : Aeneas.Std.Array Std.U8 N → RustM (core.result.Result T Error))
    (hF : FixedRunsM d N g) : AgreeF d (viaB d) ∧ BIndepF (viaB d) := by
  have hlen : ∀ arr : Aeneas.Std.Array Std.U8 N, arr.val.length = N.val := fun arr => by simp
  -- the bytes decoder on a slice: `d` on the slice reader
  have hB : ∀ s : Slice Std.U8, ∃ res, viaB d s = ok res ∧
      (N.val ≤ s.val.length → ∃ arr : Aeneas.Std.Array Std.U8 N, arr.val = s.val.take N.val ∧
        ∃ q, g arr = ok q ∧ (∀ x, q = .Ok x → res = .Ok (x, StdIo.sliceAdv s N.val)) ∧
          (∀ e, q = .Err e → ∃ e', res = .Err e')) ∧
      (s.val.length < N.val → ∃ e, res = .Err e) := by
    intro s
    obtain ⟨p, hp, h1, h2⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (hF _ _ _ _ StdIo.slice_law s)
    obtain ⟨q, s1⟩ := p
    cases q with
    | Ok x =>
      have hN : N.val ≤ s.val.length := by
        by_contra hc; obtain ⟨e, he⟩ := h2 (by omega); cases he
      obtain ⟨arr, harr, hg, hadv⟩ := h1 hN
      have hs1 := hadv x rfl
      simp only at hs1
      subst hs1
      refine ⟨_, by simp only [viaB, hp, bind_tc_ok]; rfl, fun _ => ⟨arr, harr, .Ok x, hg,
        (fun y hy => by cases hy; rfl), (fun e he => by cases he)⟩, fun hc => by omega⟩
    | Err e =>
      refine ⟨_, by simp only [viaB, hp, bind_tc_ok]; rfl, fun hN => ?_, fun _ => ⟨e, rfl⟩⟩
      obtain ⟨arr, harr, hg, -⟩ := h1 hN
      exact ⟨arr, harr, .Err e, hg, (fun y hy => by cases hy), (fun e' _ => ⟨e, rfl⟩)⟩
  refine ⟨fun R RI v a law r => ?_, fun s x t hst => ?_⟩
  · refine triple_post_mono (hF R RI v a law r) fun p hp s hs => ?_
    obtain ⟨res, hres, hb1, hb2⟩ := hB s
    refine ⟨res, hres, ?_⟩
    by_cases hN : N.val ≤ (v r).length
    · obtain ⟨arr, harr, hg, hadv⟩ := hp.1 hN
      obtain ⟨arr', harr', q, hq, hqok, hqerr⟩ := hb1 (by rw [hs]; exact hN)
      have : arr' = arr := Subtype.ext (by rw [harr', harr, hs])
      subst this
      rw [hg] at hq
      cases hq
      rcases hp1 : p.1 with x | e
      · rw [hqok x hp1]
        refine ⟨hp1, ?_⟩
        rw [hadv x hp1, law.adv_view r _ hN]
        simp [StdIo.sliceAdv, hs]
      · obtain ⟨e', he'⟩ := hqerr e hp1
        rw [he']
        exact ⟨e, hp1⟩
    · obtain ⟨e, he⟩ := hp.2 (by omega)
      obtain ⟨e', he'⟩ := hb2 (by rw [hs]; omega)
      rw [he']
      exact ⟨e, he⟩
  · obtain ⟨res, hres, hb1, hb2⟩ := hB s
    rw [hst] at hres
    cases hres
    have hN : N.val ≤ s.val.length := by
      by_contra hc; obtain ⟨e, he⟩ := hb2 (by omega); cases he
    obtain ⟨arr, harr, q, hq, hqok, hqerr⟩ := hb1 hN
    have hq' : q = .Ok x := by
      cases q with
      | Ok y => have := hqok y rfl; cases this; rfl
      | Err e => obtain ⟨e', he'⟩ := hqerr e rfl; cases he'
    subst hq'
    have ht := hqok x rfl
    cases ht
    refine ⟨arr.val, ?_, fun s' rest hs' => ?_⟩
    · rw [harr]; simp [StdIo.sliceAdv]
    · obtain ⟨res', hres', hb1', hb2'⟩ := hB s'
      have hN' : N.val ≤ s'.val.length := by rw [hs', List.length_append, hlen]; omega
      obtain ⟨arr', harr', q', hq', hqok', -⟩ := hb1' hN'
      have : arr' = arr := Subtype.ext (by rw [harr', hs', List.take_left' (hlen arr)])
      subst this
      rw [hq] at hq'
      cases hq'
      rw [hqok' x rfl] at hres'
      exact ⟨_, hres', by simp [StdIo.sliceAdv, hs', List.drop_left' (hlen arr')]⟩

/-! ## The lemma traits -/

/-- `b s = viaB d s` of an extracted byte-slice decoder `b` running `d` on the slice. -/
macro "via_eq " b:ident : tactic => `(tactic| (
  show $b _ = _
  unfold $b:ident viaB
  seq_eq))

/-- `DecodersAgree` of an impl whose decoders agree (`Agree` and `BIndep` given on the impl's
decoders as functions). -/
theorem DecodersAgree.lawful_of_facts {T : Type} (DA : spec.io.DecodersAgree T)
    (hD : Deserialize.Lawful T DA.DeserializeInst)
    (hDB : DeserializeBytes.Lawful T DA.DeserializeBytesInst)
    (hEq : core.cmp.PartialEq.Lawful T T DA.corecmpPartialEqInst)
    (hA : AgreeF (fun RI r => DA.DeserializeInst.tls_deserialize RI r)
      DA.DeserializeBytesInst.tls_deserialize_bytes)
    (hI : BIndepF DA.DeserializeBytesInst.tls_deserialize_bytes)
    (hda : ∀ {R : Type} (RI : alloc.io.read.Read R),
      DA.decoders_agree RI = spec.io.DecodersAgree.decoders_agree.default T RI)
    (hbp : DA.bytes_prefix_only = spec.io.DecodersAgree.bytes_prefix_only.default T) :
    spec.io.DecodersAgree.Lawful T DA :=
  DecodersAgree.lawful_of DA hD hDB hEq hA hI hda hbp

end tls_codec.Derive
