import Lean
open Lean Elab Command

/-! Axiom whitelist gate.

`#axiom_gate "Pfx" "scripts/axiom_whitelist.txt"` collects the axioms of every theorem declared
in a module whose name starts with `Pfx` (e.g. `TlsCodec.Verification`, `OpenmlsCodec`) and logs
an **error** if one of them is not in the whitelist file. The file lists one axiom name per line
(`#` starts a comment); a line `open <theorem>` exempts that theorem from the `sorryAx` check only
(an obligation left OPEN on purpose). Open the calling script with `lean_diagnostic_messages`
(shell `lean` / `lake` do not run here): no error = gate passed. Imported by the library root
(so that `lean_build` rebuilds it); the projects' `scripts/AxiomGate.lean` call it. -/

namespace TlsCodec.Tools

/-- Memoised axiom collection (as in `scripts/Audit.lean`). -/
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

elab "#axiom_gate " pfx:str path:str : command => do
  let env ← getEnv
  let content ← IO.FS.readFile path.getString
  let mut allowed : Std.HashSet Name := {}
  let mut opens : Std.HashSet Name := {}
  for line in content.splitOn "\n" do
    let l := ((line.splitOn "#").headD "").trim
    if l.isEmpty then continue
    if l.startsWith "open " then opens := opens.insert (l.drop 5).trim.toName
    else allowed := allowed.insert l.toName
  let pfxN := pfx.getString.toName
  let memo ← IO.mkRef ({} : Std.HashMap Name (Array Name))
  let thms := env.constants.fold (fun acc n ci =>
    match ci, env.getModuleIdxFor? n with
    | .thmInfo _, some idx =>
      if !n.hasMacroScopes && !n.isInternal && pfxN.isPrefixOf (env.header.moduleNames[idx.toNat]!)
      then acc.push n else acc
    | _, _ => acc) #[]
  -- offending axiom ↦ (number of theorems, one example)
  let mut bad : Std.HashMap Name (Nat × Name) := {}
  let mut used : Std.HashSet Name := {}
  for t in thms do
    for a in (← axsOf env memo t) do
      used := used.insert a
      if allowed.contains a then continue
      if a == ``sorryAx && opens.contains t then continue
      let (k, ex) := bad.getD a (0, t)
      bad := bad.insert a (k + 1, ex)
  let unused := allowed.toArray.filter (!used.contains ·)
  logInfo m!"axiom gate {pfx.getString}: {thms.size} theorems, {used.size} axioms used, \
    {allowed.size} whitelisted ({unused.size} whitelisted but unused: {unused.qsort (·.toString < ·.toString)})"
  unless bad.isEmpty do
    let lines := bad.toArray.map (fun (a, k, ex) => s!"{a}  ({k} theorems, e.g. {ex})")
    logError m!"axiom gate {pfx.getString} FAILED, {bad.size} axiom(s) outside the whitelist:\n\
      {"\n".intercalate (lines.qsort (· < ·)).toList}"

end TlsCodec.Tools
