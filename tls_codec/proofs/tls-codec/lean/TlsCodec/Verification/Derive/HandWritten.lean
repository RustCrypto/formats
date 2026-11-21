/- Generic lemmas and tactics for proving hand-written `std` codecs of a downstream crate (first
user: OpenMLS's `Extension`, `openmls/src/extensions/codec.rs`), next to the derive tactics of
`Derive/Std.lean`:
- `Deserialize.Lawful.exact_slice`: `T::tls_deserialize_exact(&[u8])` from `T`'s
  `Deserialize.Lawful` (an `Ok v` has the size of the input);
- `encAll_u8`: the element encodings of a byte list are the bytes themselves;
- `name_conts`, `name_hyp_with`, `name_neg`, `guard_target_has`: name the anonymous hypotheses
  `mvcgen` leaves, by their shape rather than their position.
Obligations: none directly (downstream ones use these). Assumptions: nothing assumed here. -/
import TlsCodec.Verification.Derive.Std
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

/-- `T::tls_deserialize_exact` on a byte slice, from `T`'s `Deserialize.Lawful`: an `Ok v` has
the size of the slice. -/
theorem Deserialize.Lawful.exact_slice {T : Type} {DI : Deserialize T}
    (h : Deserialize.Lawful T DI) (s : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ DI.tls_deserialize_exact
      (core.Shared0T.Insts.CoreConvertAsRef (core.Slice.Insts.CoreConvertAsRefSlice Std.U8)) s
    ⦃ ⇓ r => ⌜ ∀ v, r = .Ok v → (szv DI.SizeInst v).val = s.val.length ⌝ ⦄ := by
  have hspec := h.tls_deserialize_exact_spec _ core.Shared0T.Insts.CoreConvertAsRef.slice_lawful s
    (pre_holds_of_ok_true rfl)
  refine triple_post_mono hspec ?_
  intro r hr v hv
  subst hv
  have hsz := size_ok h.SizeInstLawful v
  apply holds_imp hr
  simp only [tls_codec.Deserialize.tls_deserialize_exact.post, core.result.Result.is_err]
  mvcgen [core.result.Result.is_ok_and, hsz,
    __8.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleSelf_Bool.call_once,
    core.Shared0T.Insts.CoreConvertAsRef, core.Slice.Insts.CoreConvertAsRefSlice.as_ref]
  rename_i _ l hl; intro hd; simp only [decide_eq_true_eq] at hd; rw [hd, hl, Slice.len_val]

/-- The `u8` element encodings of a byte list are the bytes themselves. -/
theorem encAll_u8 (l : List Std.U8) : encAll U8.Insts.Tls_codecSerialize l = some l := by
  induction l with
  | nil => rfl
  | cons x l ih =>
    have hx : encOut U8.Insts.Tls_codecSerialize x = some [x] :=
      encOut_of_runs _ x 1#usize [x] (U8.ser_runs x) (by have := imax_ge; simp; omega)
    simp [encAll, hx, ih]

/-! ### Naming `mvcgen`'s anonymous hypotheses by shape -/

open Lean Elab Tactic Meta in
/-- Names `hc0` / `hc1` the `Continue _ = tryCF r0` / `Continue _ = tryCF r1` hypotheses left by
`mvcgen` (anonymous otherwise). -/
elab "name_conts " r0:term:max r1:term:max : tactic => withMainContext do
  let e0 ← instantiateMVars (← Term.elabTerm r0 none)
  let e1 ← instantiateMVars (← Term.elabTerm r1 none)
  let mut g ← getMainGoal
  for d in (← getLCtx) do
    if d.isImplementationDetail then continue
    let t ← instantiateMVars d.type
    unless t.isAppOfArity ``Eq 3 do continue
    let rhs := t.getArg! 2
    let isTry := match rhs.getAppFn.constName? with
      | some n => n.toString.endsWith "tryCF"
      | none => false
    unless isTry do continue
    unless (t.getArg! 1).isAppOf ``core.ops.control_flow.ControlFlow.Continue do continue
    if rhs.appArg! == e0 then g ← g.rename d.fvarId `hc0
    else if rhs.appArg! == e1 then g ← g.rename d.fvarId `hc1
  replaceMainGoal [g]

open Lean Elab Tactic Meta in
/-- Renames `n` the last hypothesis whose type mentions the constant `c`. -/
elab "name_hyp_with " c:ident n:ident : tactic => withMainContext do
  let cn ← realizeGlobalConstNoOverloadWithInfo c
  let g ← getMainGoal
  let mut found : Option FVarId := none
  for d in (← getLCtx) do
    if d.isImplementationDetail then continue
    let t ← instantiateMVars d.type
    if (t.find? fun e => e.isConstOf cn).isSome then found := some d.fvarId
  match found with
  | some f => replaceMainGoal [← g.rename f n.getId]
  | none => throwError "name_hyp_with: no hypothesis mentions {cn}"

open Lean Elab Tactic Meta in
/-- Renames `n` the last hypothesis of the form `¬ a = b`. -/
elab "name_neg " n:ident : tactic => withMainContext do
  let g ← getMainGoal
  let mut found : Option FVarId := none
  for d in (← getLCtx) do
    if d.isImplementationDetail then continue
    let t ← instantiateMVars d.type
    if t.isAppOfArity ``Not 1 && (t.getArg! 0).isAppOfArity ``Eq 3 then found := some d.fvarId
  match found with
  | some f => replaceMainGoal [← g.rename f n.getId]
  | none => throwError "name_neg: no hypothesis of the form ¬ a = b"

open Lean Elab Tactic Meta in
/-- Fails unless the target mentions the constant `c`. -/
elab "guard_target_has " c:ident : tactic => withMainContext do
  let cn ← realizeGlobalConstNoOverloadWithInfo c
  let t ← instantiateMVars (← getMainTarget)
  unless (t.find? fun e => e.isConstOf cn).isSome do throwError "guard_target_has: no {cn}"

end tls_codec.Derive
