import TlsCodec
open Lean Elab Command

/-! Audit of the proofs (open with `lean_diagnostic_messages`; needs a built project).

Counts, per group, the theorems whose axioms do not include `sorryAx`, and writes the clean
ones with their non-standard axioms to `scripts/audit_<group>_clean.txt`:
- `PF` / `FC` / `PO`: `X.spec.panic_freedom` / `X.spec.functional_correctness` / `X.spec.proof`
  (function specs);
- `LPF` / `LFC`: `I.m_spec.panic_freedom` / `I.m_spec.functional_correctness` (per-impl
  `Lawful` method fields);
- `LAW`: the per-impl `I.Lawful` theorems, each line tagged with its trait.
Finally, the union of the non-standard axioms of all clean theorems. -/

/-- Memoised axiom collection (shared across all theorems). -/
partial def axsOf (env : Environment) (memo : IO.Ref (Std.HashMap Name (Array Name))) (n : Name) :
    IO (Array Name) := do
  if let some r := (← memo.get)[n]? then return r
  let some ci := env.find? n | return #[]
  let mut deps : Array Name := ci.type.getUsedConstants
  if let some v := ci.value? (allowOpaque := true) then deps := deps ++ v.getUsedConstants
  match ci with
  | .inductInfo i => deps := deps ++ i.ctors.toArray
  | .ctorInfo c => deps := deps.push c.induct
  | .recInfo r => deps := deps ++ r.all.toArray
  | _ => pure ()
  memo.modify (·.insert n #[])
  let mut acc : Array Name := #[]
  if let .axiomInfo _ := ci then acc := acc.push n
  for d in deps do
    if d != n then
      for a in (← axsOf env memo d) do
        unless acc.contains a do acc := acc.push a
  memo.modify (·.insert n acc)
  return acc

/-- Head constant of the conclusion of a theorem type. -/
partial def concl : Expr → Name
  | .forallE _ _ b _ => concl b
  | e => e.getAppFn.constName?.getD .anonymous

elab "#audit" : command => do
  let env ← getEnv
  let std : List Name := [``propext, ``Classical.choice, ``Quot.sound]
  let memo ← IO.mkRef ({} : Std.HashMap Name (Array Name))
  let isThm (n : Name) : Bool := match env.find? n with | some (.thmInfo _) => true | _ => false
  let groups : List (String × (Name → Bool)) := [
    ("PF", fun n => n.getString! == "panic_freedom" && n.getPrefix.getString! == "spec"),
    ("FC", fun n => n.getString! == "functional_correctness" && n.getPrefix.getString! == "spec"),
    ("PO", fun n => n.getString! == "proof" && n.getPrefix.getString! == "spec"),
    ("LPF", fun n => n.getString! == "panic_freedom" && n.getPrefix.getString!.endsWith "_spec"),
    ("LFC", fun n => n.getString! == "functional_correctness" && n.getPrefix.getString!.endsWith "_spec"),
    ("LAW", fun n => n.getString! == "Lawful" && (`tls_codec).isPrefixOf n)]
  let mut allExtra : Array Name := #[]
  for (g, p) in groups do
    let ns := env.constants.fold (fun acc n _ =>
      if !n.hasMacroScopes && isThm n && p n then acc.push n else acc) #[]
    let mut lines : Array String := #[]
    let mut clean := 0
    let mut perTrait : Std.HashMap Name (Nat × Nat) := {}
    for n in ns do
      let axs ← axsOf env memo n
      let ok := !axs.contains ``sorryAx
      let tr := if g == "LAW" then concl (env.find? n).get!.type else .anonymous
      if g == "LAW" then
        let (a, b) := perTrait.getD tr (0, 0)
        perTrait := perTrait.insert tr (a + 1, b + (if ok then 1 else 0))
      if ok then
        clean := clean + 1
        let ex := axs.filter (fun a => !(std.contains a))
        for a in ex do
          unless allExtra.contains a do allExtra := allExtra.push a
        lines := lines.push s!"{n}\t{if g == "LAW" then s!"{tr}\t" else ""}{ex.toList}"
    logInfo m!"{g}: total {ns.size}, without sorryAx {clean}"
    if g == "LAW" then
      for (t, (a, b)) in perTrait.toList do
        logInfo m!"  LAW {t}: {b} / {a}"
    IO.FS.writeFile s!"scripts/audit_{g}_clean.txt" ("\n".intercalate (lines.qsort (· < ·)).toList)
  logInfo m!"non-standard axioms in clean theorems: {allExtra.toList}"
#audit
