/- The `std` (`Read` / `Write`) path of the derived impls (`TlsSerialize`, `TlsDeserialize`):
generic lemmas and tactics proving the trait-level contracts of a derived struct / enum from its
fields' `Serialize.Lawful` / `Deserialize.Lawful`. Entry points:
`derive_ser_std_lawful`, `derive_de_std_lawful`; for single-field and `u16`-enum impls
`ser_lawful_of_runs` / `de_lawful_of_runs`, `u16_enum_ser` / `u16_enum_de`, `newtype_ser` /
`newtype_de`, `debytes_via_std`.

Obligations: none in TlsCodec; the downstream projects' `std` derive obligations use these.
Axioms reached (`scripts/axiom_whitelist.txt`): ASSUMED `size_of`, `size_of_U16`; 1 signature-only
stub (`core.io.error.Error.Insts.CoreFmtDebug.fmt`). -/
import TlsCodec.Verification.Derive.Bytes
import TlsCodec.Verification.Std.IntsWrappers
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

/-! ## Serializers

A field serializer call, in flat form for `mvcgen`: on a lawful writer with room for the field,
an `Ok n` has `n = szv` and appended the field's encoding `b` (`encOut … = some b`), an `Err`
means the field has no encoding. The derived serializer's own post has the same shape, with the
encoding `out` of the whole value: the chain `seqL` of the fields' encodings, found by the
closing tactic from the field facts. -/

/-- The flat post of a serializer call that writes the encoding `o` (of length `sz`) on `w`. -/
def SerPost {W : Type} (WI : core.io.write.Write W) (o : Option (List Std.U8)) (sz : Nat) (w : W)
    (p : core.result.Result Std.Usize Error × W) : Prop :=
  (∀ n, p.1 = .Ok n → n.val = sz ∧ ∃ b, o = some b ∧ b.length = sz ∧
    core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w ++ b) ∧
  (∀ e, p.1 = .Err e → o = none)

@[simp] theorem SerPost_ok {W : Type} (WI : core.io.write.Write W) (o : Option (List Std.U8))
    (sz : Nat) (w w' : W) (n : Std.Usize) :
    SerPost WI o sz w (.Ok n, w') ↔ n.val = sz ∧ ∃ b, o = some b ∧ b.length = sz ∧
      core.io.write.Write.view WI w' = core.io.write.Write.view WI w ++ b := by
  simp [SerPost]

@[simp] theorem SerPost_err {W : Type} (WI : core.io.write.Write W) (o : Option (List Std.U8))
    (sz : Nat) (w w' : W) (e : Error) : SerPost WI o sz w (.Err e, w') ↔ o = none := by
  simp [SerPost]

/-- A field serializer call (from the field type's `Serialize.Lawful`). -/
theorem ser_std_spec {T : Type} {SI : Serialize T} (h : Serialize.Lawful T SI) {W : Type}
    (WI : core.io.write.Write W) (hWI : core.io.write.Write.Lawful W WI) (x : T) (w : W) :
    ⦃ ⌜ (core.io.write.Write.view WI w).length + (szv SI.SizeInst x).val ≤ imax ⌝ ⦄
      SI.tls_serialize WI x w
    ⦃ ⇓ p => ⌜ SerPost WI (encOut SI x) (szv SI.SizeInst x).val w p ⌝ ⦄ := by
  intro hroom
  have hroom' : (core.io.write.Write.view WI w).length + (szv SI.SizeInst x).val ≤ imax := hroom
  have hsz := size_ok h.SizeInstLawful x
  obtain ⟨r, w', hr, hs, hn⟩ := h.runs x _ hsz W WI hWI w hroom
  rw [hr]
  have key : SerPost WI (encOut SI x) (szv SI.SizeInst x).val w (r, w') := by
    unfold SerPost
    dsimp only
    refine ⟨fun n hn' => ?_, fun e he => ?_⟩
    · cases ho : encOut SI x with
      | none => obtain ⟨e, he⟩ := hn ho; rw [hn'] at he; cases he
      | some b =>
        obtain ⟨⟨m, hm, hmb⟩, hv⟩ := hs b ho
        rw [hn'] at hm; cases hm
        have hl := h.enc_len x _ hsz (by omega) b ho
        exact ⟨by omega, b, rfl, hl, hv⟩
    · cases ho : encOut SI x with
      | none => rfl
      | some b => obtain ⟨⟨m, hm, -⟩, -⟩ := hs b ho; rw [he] at hm; cases hm
  exact ok_triple_of key trivial

theorem usize_zero_val : (0#usize : Std.Usize).val = 0 := rfl

/-- The chain of the fields' encodings (`none` when one has none). -/
def seqL : List (Option (List Std.U8)) → Option (List Std.U8)
  | [] => some []
  | o :: os => o.bind fun b => (seqL os).map (b ++ ·)

@[simp] theorem seqL_nil : seqL [] = some [] := rfl
@[simp] theorem seqL_cons_some (b : List Std.U8) (os : List (Option (List Std.U8))) :
    seqL (some b :: os) = (seqL os).map (b ++ ·) := rfl
@[simp] theorem seqL_cons_none (os : List (Option (List Std.U8))) : seqL (none :: os) = none := rfl

open Lean Elab Tactic Meta in
/-- On the success VC of a derived serializer (goal `SerPost WI ?out sz w (Ok _, _)`): assigns
the encoding `?out` (writer-independent, created before the writer was introduced) to the chain
`seqL [o₁, …]` of the fields' encodings, read off the field facts `SerPost WI oᵢ …` in context
order. Fails on any other goal. -/
elab "derive_std_assign_out" : tactic => withMainContext do
  let tgt ← instantiateMVars (← getMainTarget)
  unless tgt.isAppOfArity ``SerPost 6 do throwError "derive_std_assign_out: not a SerPost goal"
  let p := tgt.getArg! 5
  unless p.isAppOfArity ``Prod.mk 4 && (p.getArg! 2).isAppOfArity ``core.result.Result.Ok 3 do
    throwError "derive_std_assign_out: not the success VC"
  let out := tgt.getArg! 2
  unless out.isMVar do throwError "derive_std_assign_out: encoding already fixed"
  let mut os : Array Expr := #[]
  for d in (← getLCtx) do
    if d.isImplementationDetail then continue
    let ty ← instantiateMVars d.type
    if ty.isAppOfArity ``SerPost 6 then os := os.push (ty.getArg! 2)
  let optTy ← inferType out
  let l ← mkListLit optTy os.toList
  out.mvarId!.assign (← mkAppM ``seqL #[l])

open Lean Elab Tactic Meta in
/-- `derive_size_eqs h [L₀, …]`: rewrites the derived size call in `h : size x = ok r` to the
`len_add` chain of its fields' `szv`: for each field `Size.Lawful` `Lᵢ` (instance `Sz`), the
equation `f y = ok (szv Sz y)` where `f` is `Sz`'s method unfolded (reducible), so that it matches
the calls in the derived body. -/
elab "derive_size_eqs " h:ident " [" ls:term,* "]" : tactic => withMainContext do
  let mut names : Array Ident := #[]
  let mut i := 0
  for l in ls.getElems do
    let prf ← Term.elabTerm (← `(fun y => size_ok $l y)) none
    Term.synthesizeSyntheticMVarsNoPostponing
    let prf ← instantiateMVars prf
    let ty ← inferType prf
    let ty' ← forallTelescope ty fun xs body => do
      let some (α, lhs, rhs) := body.eq? | throwError "derive_size_eqs: not an equation"
      let lhs' ← whnfR lhs
      mkForallFVars xs (← mkEq lhs' rhs)
    let n := Name.mkSimple s!"h_szeq{i}"
    i := i + 1
    let g ← getMainGoal
    let g ← g.assert n ty' prf
    let (_, g) ← g.intro1P
    replaceMainGoal [g]
    names := names.push (mkIdent n)
  let extra := #[mkIdent ``tls_codec.len_add_ok, mkIdent ``bind_tc_ok, mkIdent ``ok.injEq,
    mkIdent ``CoreModels.core.mem.size_of_U8, mkIdent ``CoreModels.core.mem.size_of_U16]
  let args ← (names ++ extra).mapM fun n => do
    let l ← `(Lean.Parser.Tactic.simpLemma| $n:term)
    pure (⟨l.raw⟩ : MvArg)
  evalTactic (← `(tactic| simp only [$args,*] at $h:ident))

/-- The contract of a derived serializer on `x`, from its flat post on every lawful writer with
room (for some writer-independent encoding `out`). -/
theorem SerSpec.of_post {T : Type} (SI : Serialize T) (hS : Size.Lawful T SI.SizeInst) (x : T)
    (h : ∃ out : Option (List Std.U8), ∀ (W : Type) (WI : core.io.write.Write W),
      core.io.write.Write.Lawful W WI → ∀ w : W,
      (core.io.write.Write.view WI w).length + (szv SI.SizeInst x).val ≤ imax →
      ⦃ ⌜ True ⌝ ⦄ SI.tls_serialize WI x w
      ⦃ ⇓ p => ⌜ SerPost WI out (szv SI.SizeInst x).val w p ⌝ ⦄) :
    SerSpec SI x := by
  obtain ⟨out, h⟩ := h
  have hsz := size_ok hS x
  have hr : SerRuns SI x (szv SI.SizeInst x) out := by
    intro W WI hWI w hroom
    obtain ⟨⟨r, w'⟩, hrun, hp⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (h W WI hWI w hroom)
    refine ⟨r, w', hrun, fun b hb => ?_, fun hn => ?_⟩
    · cases r with
      | Ok n =>
        obtain ⟨hn, b', hb', hl, hv⟩ := hp.1 n rfl
        rw [hb] at hb'; cases hb'
        exact ⟨⟨n, rfl, by omega⟩, hv⟩
      | Err e => have := hp.2 e rfl; rw [hb] at this; cases this
    · cases r with
      | Ok n => obtain ⟨-, b', hb', -⟩ := hp.1 n rfl; rw [hn] at hb'; cases hb'
      | Err e => exact ⟨e, rfl⟩
  intro W WI hWI w hpre
  refine Serialize.tls_serialize_spec_of_runs' SI x _ hsz out (fun hle b hb => ?_) hr WI hWI w hpre
  obtain ⟨⟨r, w'⟩, -, hp⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (h _ _ StdIo.vec_lawful ⟨[], by simp⟩ (by rw [StdIo.vec_sink]; simpa using hle))
  cases r with
  | Ok n => obtain ⟨-, b', hb', hl, -⟩ := hp.1 n rfl; rw [hb] at hb'; cases hb'; exact hl
  | Err e => have := hp.2 e rfl; rw [hb] at this; cases this

/-- Closes the VCs of a derived serializer after `mvcgen` (see `derive_ser_std`). -/
macro "derive_ser_std_vcs" : tactic => `(tactic| (
  -- the success VC first: it fixes the encoding `?out` (then a writer-independent term)
  all_goals (try subst_vars)
  all_goals (try derive_std_assign_out)
  -- `?` breaks: the residual is the field's `Err`
  all_goals (try (rename_i hbr; refine try_break_vc (fun e he => ?_) hbr; mvcgen; intro _; mvcgen))
  all_goals (try simp only [continue_eq_tryCF] at *)
  all_goals (try simp_all only [SerPost, core.result.Result.Ok.injEq, core.result.Result.Err.injEq,
    reduceCtorEq, forall_eq',
    false_implies, implies_true, and_true, true_and, forall_const, bne_self_eq_false,
    Bool.false_eq_true, not_false_eq_true, List.length_append, List.length_nil])
  all_goals (try casesm* _ ∧ _, ∃ _, _)
  all_goals (try simp_all only [seqL_cons_some, seqL_cons_none, seqL_nil, Option.map_some,
    Option.map_none, Option.some.injEq, reduceCtorEq, List.append_nil, List.append_assoc,
    List.length_append, List.length_nil, exists_eq_left', exists_eq_left, true_and, and_true])
  all_goals (try simp only [UScalar.max_USize_eq, usize_zero_val, Nat.zero_add, szv_simps] at *)
  all_goals (try (have := imax_le; have := imax_ge; have := imax_eq; first
    | rfl
    | omega
    | (simp_all only [List.length_append, List.length_nil, List.append_assoc]; done)
    | (simp_all only [List.length_append, List.length_nil, List.append_assoc]; omega)
    | (exfalso; simp_all only [List.length_append, List.length_nil]; omega)
    | derive_arith))))

/-- The contract of a derived serializer, `∀ x, SerSpec SI x`. `sz`: its `Size.Lawful`; `ds`: the
serializer and the derived defs it calls (the `&Self` size, the discriminant constants); `zs`:
the size defs to unfold (the size instance and method); `ls`: the fields' `Serialize.Lawful`. -/
syntax "derive_ser_std " term:max " [" Lean.Parser.Tactic.simpArg,* "]" " [" Lean.Parser.Tactic.simpArg,* "]"
  " [" term,* "]" : tactic
macro_rules
  | `(tactic| derive_ser_std $sz [$ds,*] [$zs,*] [$ls,*]) => do
    let ls := ls.getElems
    let ns := freshNames "h_ser" ls.size
    let hs ← haves ns ls fun l => `(ser_std_spec $l WI hWI)
    let zl ← ls.mapM fun l => `(Serialize.Lawful.SizeInstLawful $l)
    let xs ← mvArgs ds.getElems ns
    `(tactic| (
      intro x
      apply SerSpec.of_post _ $sz x
      have hr := size_ok $sz x
      have hS := size_spec $sz
      cases x
      all_goals (
        conv at hr => lhs; simp only [$zs,*]
        derive_size_eqs hr [$zl,*]
        have hdec := congrArg UScalar.val hr
        simp only [lenAddVal_min] at hdec
        refine ⟨?_, fun W WI hWI w hroom => ?_⟩
        swap
        $hs:tactic
        mvcgen [$xs,*, hS]
        derive_ser_std_vcs)))

/-! ## Deserializers

A field deserializer call, in flat form: an `Ok v` consumed `szv v` bytes of the reader's view
(a lawful reader with view `v` and advance `a`). -/

/-- The flat post of a deserializer call on a law `(v, a)`. -/
def DePost {T R : Type} (S : Size T) (v : R → List Std.U8) (a : R → Nat → R) (r : R)
    (p : core.result.Result T Error × R) : Prop :=
  ∀ val, p.1 = .Ok val → (szv S val).val ≤ (v r).length ∧ p.2 = a r (szv S val).val

@[simp] theorem DePost_ok {T R : Type} (S : Size T) (v : R → List Std.U8) (a : R → Nat → R)
    (r r' : R) (val : T) :
    DePost S v a r (.Ok val, r') ↔ (szv S val).val ≤ (v r).length ∧ r' = a r (szv S val).val := by
  simp [DePost]

@[simp] theorem DePost_err {T R : Type} (S : Size T) (v : R → List Std.U8) (a : R → Nat → R)
    (r r' : R) (e : Error) : DePost S v a r (.Err e, r') ↔ True := by
  simp [DePost]

/-- A field deserializer call (from the field type's `Deserialize.Lawful`). -/
theorem de_std_spec {T : Type} {DI : Deserialize T} (h : Deserialize.Lawful T DI) {R : Type}
    {RI : alloc.io.read.Read R} {v : R → List Std.U8} {a : R → Nat → R} (law : StdIo.RLaw RI v a)
    (r : R) :
    ⦃ ⌜ True ⌝ ⦄ DI.tls_deserialize RI r ⦃ ⇓ p => ⌜ DePost DI.SizeInst v a r p ⌝ ⦄ := by
  refine triple_post_mono (h.runs R RI v a law r) ?_
  intro p hp val hval
  obtain ⟨n, sz, hn, hp2, hsz, hszn, -⟩ := hp val hval
  rw [szv_eq hsz, hszn]
  exact ⟨hn, hp2⟩

/-- The contract of a derived deserializer, from its flat post on every lawful reader. -/
theorem DeSpec.of_post {T : Type} (DI : Deserialize T) (hS : Size.Lawful T DI.SizeInst)
    (h : ∀ (R : Type) (RI : alloc.io.read.Read R) (v : R → List Std.U8) (a : R → Nat → R),
      StdIo.RLaw RI v a → ∀ r, ⦃ ⌜ True ⌝ ⦄ DI.tls_deserialize RI r
      ⦃ ⇓ p => ⌜ DePost DI.SizeInst v a r p ⌝ ⦄) : DeSpec DI := by
  have hr : DeRuns DI (fun _ _ _ => True) := by
    intro R RI v a law r
    refine triple_post_mono (h R RI v a law r) ?_
    intro p hp val hval
    obtain ⟨hn, hp2⟩ := hp val hval
    exact ⟨_, _, hn, hp2, size_ok hS val, rfl, trivial⟩
  intro R RI hRI r
  exact Deserialize.tls_deserialize_spec_of_runs DI hr RI hRI r

theorem adv_le {R : Type} {RI : alloc.io.read.Read R} {v : R → List Std.U8} {a : R → Nat → R}
    (law : StdIo.RLaw RI v a) {r : R} {n m : Nat} (h1 : n ≤ (v r).length)
    (h2 : m ≤ (v (a r n)).length) : n + m ≤ (v r).length := by
  rw [law.adv_view r n h1, List.length_drop] at h2; omega

theorem adv_adv' {R : Type} {RI : alloc.io.read.Read R} {v : R → List Std.U8} {a : R → Nat → R}
    (law : StdIo.RLaw RI v a) {r : R} {n m : Nat} (h1 : n ≤ (v r).length)
    (h2 : m ≤ (v (a r n)).length) : a (a r n) m = a r (n + m) :=
  law.adv_adv r n m (adv_le law h1 h2)

open Lean Elab Tactic Meta in
/-- Normalises the reader positions of a derived deserializer's VC: for hypotheses
`n ≤ |v x|` and `m ≤ |v (a x n)|`, adds `n + m ≤ |v x|` and rewrites `a (a x n) m` to
`a x (n + m)` everywhere, until none applies (`law : StdIo.RLaw RI v a`). -/
elab "derive_adv_norm " law:term:max : tactic => do
  let mut fuel := 64
  let mut used : Array FVarId := #[]
  while fuel > 0 do
    fuel := fuel - 1
    let g ← getMainGoal
    let found ← g.withContext do
      let lawE ← Term.elabTerm law none
      let lctx ← getLCtx
      for d2 in lctx do
        if d2.isImplementationDetail || used.contains d2.fvarId then continue
        let t2 ← instantiateMVars d2.type
        unless t2.isAppOfArity ``LE.le 4 do continue
        let len2 := t2.getArg! 3
        unless len2.isAppOfArity ``List.length 2 do continue
        let vx := len2.appArg!            -- v (a x n)
        unless vx.isApp do continue
        let axn := vx.appArg!             -- a x n
        unless axn.getAppNumArgs ≥ 2 do continue
        let x := axn.appFn!.appArg!
        let n := axn.appArg!
        for d1 in lctx do
          if d1.isImplementationDetail then continue
          let t1 ← instantiateMVars d1.type
          unless t1.isAppOfArity ``LE.le 4 do continue
          unless ← isDefEq (t1.getArg! 2) n do continue
          let len1 := t1.getArg! 3
          unless len1.isAppOfArity ``List.length 2 do continue
          unless ← isDefEq len1.appArg! (mkApp vx.appFn! x) do continue
          let hle ← mkAppM ``adv_le #[lawE, d1.toExpr, d2.toExpr]
          let heq ← mkAppM ``adv_adv' #[lawE, d1.toExpr, d2.toExpr]
          return some (d2.fvarId, hle, heq)
      return none
    let some (fv, hle, heq) := found | break
    used := used.push fv
    let g ← g.assert `h_advle (← inferType hle) hle
    let (_, g) ← g.intro1P
    let g ← g.assert `h_adveq (← inferType heq) heq
    let (_, g) ← g.intro1P
    replaceMainGoal [g]
    let he := mkIdent `h_adveq
    evalTactic (← `(tactic| (try simp only [$he:ident] at *); clear $he:ident))

open Lean Elab Tactic Meta in
/-- On a success VC of a derived deserializer (`DePost S v a r0 (Ok V, x)`): adds `hdec`, the value
of `szv S V` as the `len_add` chain of its fields' `szv` (`sz`: the `Size.Lawful` of `S`; `zs`:
the size defs to unfold; `zl`: the fields' `Size.Lawful`). -/
elab "derive_de_size " sz:term:max " [" zs:Lean.Parser.Tactic.simpArg,* "]" " [" zl:term,* "]" :
    tactic => withMainContext do
  let tgt ← instantiateMVars (← getMainTarget)
  unless tgt.isAppOfArity ``DePost 7 do throwError "derive_de_size: not a DePost goal"
  let p := tgt.getArg! 6
  unless p.isAppOfArity ``Prod.mk 4 && (p.getArg! 2).isAppOfArity ``core.result.Result.Ok 3 do
    throwError "derive_de_size: not a success VC"
  let V := (p.getArg! 2).appArg!
  let szE ← Term.elabTerm sz none
  let prf ← mkAppM ``size_ok #[szE, V]
  let g ← getMainGoal
  let g ← g.assert `hr_de (← inferType prf) prf
  let (_, g) ← g.intro1P
  replaceMainGoal [g]
  let hr := mkIdent `hr_de
  let zs' : Array MvArg := zs.getElems.map fun z => ⟨z.raw⟩
  evalTactic (← `(tactic| (
    conv at $hr:ident => lhs; simp only [$zs',*]
    derive_size_eqs $hr:ident [$zl,*]
    have hdec := congrArg UScalar.val $hr
    simp only [lenAddVal_min] at hdec)))

/-- The contract of a derived deserializer, `DeSpec DI`. `sz`: its `Size.Lawful`; `ds`: the
deserializer and the derived defs it calls; `zs`: the size defs to unfold; `ls`: the fields'
`Deserialize.Lawful` (for an enum, the discriminant's first). -/
syntax "derive_de_std " term:max " [" Lean.Parser.Tactic.simpArg,* "]" " [" Lean.Parser.Tactic.simpArg,* "]"
  " [" term,* "]" : tactic
macro_rules
  | `(tactic| derive_de_std $sz [$ds,*] [$zs,*] [$ls,*]) => do
    let ls := ls.getElems
    let ns := freshNames "h_de" ls.size
    let hs ← haves ns ls fun l => `(fun r => de_std_spec $l law r)
    let zl ← ls.mapM fun l => `(Deserialize.Lawful.SizeInstLawful $l)
    let xs ← mvArgs ds.getElems ns
    `(tactic| (
      apply DeSpec.of_post _ $sz
      intro R RI v a law r0
      have hvl := law.view_le r0
      $hs:tactic
      mvcgen [$xs,*]
      all_goals (try (rename_i hbr; refine try_break_vc (fun e he => ?_) hbr; mvcgen; intro _; mvcgen))
      all_goals (try simp only [continue_eq_tryCF] at *)
      all_goals (try simp only [DePost_err])
      all_goals (try (derive_de_size $sz [$zs,*] [$zl,*]))
      all_goals (try simp_all only [DePost, core.result.Result.Ok.injEq, forall_eq'])
      all_goals (try casesm* _ ∧ _)
      all_goals (try derive_adv_norm law)
      all_goals (try simp only [UScalar.max_USize_eq, usize_zero_val, Nat.zero_add, szv_simps] at *)
      all_goals (try (have := imax_le; first
        | (refine ⟨by omega, ?_⟩; congr 1; omega)
        | omega
        | derive_arith))))

/-! ## Whole `Lawful`s (what the generated obligations call) -/

theorem Serialize.Lawful.of_serSpec {T : Type} {SI : Serialize T} (hS : Size.Lawful T SI.SizeInst)
    (h : ∀ x, SerSpec SI x)
    (hdet : ∀ x, SI.tls_serialize_detached x = Serialize.tls_serialize_detached.default SI x) :
    Serialize.Lawful T SI :=
  ⟨hS, fun WI hWI x w hpre => h x _ WI hWI w hpre,
    fun x _ => by rw [hdet]; exact SerSpec.detached (h x) ⟨_, size_ok hS x⟩⟩

theorem Deserialize.Lawful.of_deSpec {T : Type} {DI : Deserialize T} (hS : Size.Lawful T DI.SizeInst)
    (h : DeSpec DI)
    (hex : ∀ {T1 : Type} (AI : core.convert.AsRef T1 (Slice Std.U8)) b,
      DI.tls_deserialize_exact AI b = Deserialize.tls_deserialize_exact.default DI AI b) :
    Deserialize.Lawful T DI :=
  ⟨hS, fun RI hRI r _ => h _ RI hRI r,
    fun AI hAI b _ => by rw [hex]; exact DeSpec.exact h AI hAI b⟩

/-- `Serialize.Lawful` of a derived impl (arguments as `derive_ser_std`). -/
syntax "derive_ser_std_lawful " term:max " [" Lean.Parser.Tactic.simpArg,* "]"
  " [" Lean.Parser.Tactic.simpArg,* "]" " [" term,* "]" : tactic
macro_rules
  | `(tactic| derive_ser_std_lawful $sz [$ds,*] [$zs,*] [$ls,*]) =>
    `(tactic| (
      refine Serialize.Lawful.of_serSpec $sz ?_ (fun _ => rfl)
      derive_ser_std $sz [$ds,*] [$zs,*] [$ls,*]))

/-- `Deserialize.Lawful` of a derived impl (arguments as `derive_de_std`). -/
syntax "derive_de_std_lawful " term:max " [" Lean.Parser.Tactic.simpArg,* "]"
  " [" Lean.Parser.Tactic.simpArg,* "]" " [" term,* "]" : tactic
macro_rules
  | `(tactic| derive_de_std_lawful $sz [$ds,*] [$zs,*] [$ls,*]) =>
    `(tactic| (
      refine Deserialize.Lawful.of_deSpec $sz ?_ (fun _ _ => rfl)
      derive_de_std $sz [$ds,*] [$zs,*] [$ls,*]))

/-! ## Single-field and `u16` helpers

Bridges from TlsCodec's `SerRuns` / `DeRuns` to whole `Lawful`s for impls that keep the default
`tls_serialize_detached` / `tls_deserialize_exact`, and tactics for the shapes OpenMLS has besides
the multi-field derives above: unit-variant `#[repr(u16)]` enums (`u16_enum_ser` / `u16_enum_de`),
hand-written `u16`-coded enums (`ser_some_of_write_u16`), derived newtypes (`newtype_ser` /
`newtype_de`), and hand-written `DeserializeBytes` that run the `std` deserializer on the slice
(`debytes_via_std`). -/

/-- `Serialize.Lawful` of an impl that keeps the default `tls_serialize_detached`, from its
`Size.Lawful` and its behaviour on lawful writers (`SerRuns`) with an encoding of the right length. -/
theorem ser_lawful_of_runs {T : Type} (SI : Serialize T) (hS : Size.Lawful T SI.SizeInst)
    (out : T → Option (List Std.U8))
    (h : ∀ x, ∃ sz, SI.SizeInst.tls_serialized_len x = ok sz ∧
      (sz.val ≤ imax → ∀ b, out x = some b → b.length = sz.val) ∧ SerRuns SI x sz (out x))
    (hdet : ∀ x, SI.tls_serialize_detached x = Serialize.tls_serialize_detached.default SI x) :
    Serialize.Lawful T SI where
  SizeInstLawful := hS
  tls_serialize_spec WI hWI x w hpre := by
    obtain ⟨sz, hsz, hlen, hr⟩ := h x
    exact Serialize.tls_serialize_spec_of_runs' SI x sz hsz (out x) hlen hr WI hWI w hpre
  tls_serialize_detached_spec x _ := by
    obtain ⟨sz, hsz, hlen, hr⟩ := h x
    rw [hdet]
    exact Serialize.tls_serialize_detached.default_spec SI x sz hsz fun w hpre =>
      Serialize.tls_serialize_spec_of_runs' SI x sz hsz (out x) hlen hr _ StdIo.vec_lawful w hpre

/-- `Deserialize.Lawful` of an impl that keeps the default `tls_deserialize_exact`, from its
`Size.Lawful` and its behaviour on lawful readers (`DeRuns`). -/
theorem de_lawful_of_runs {T : Type} (DI : Deserialize T) (hS : Size.Lawful T DI.SizeInst)
    {P : List Std.U8 → T → Nat → Prop} (h : DeRuns DI P)
    (hex : ∀ {T1 : Type} (AI : core.convert.AsRef T1 (Slice Std.U8)) (bytes : T1),
      DI.tls_deserialize_exact AI bytes = Deserialize.tls_deserialize_exact.default DI AI bytes) :
    Deserialize.Lawful T DI where
  SizeInstLawful := hS
  tls_deserialize_spec RI hRI r _ := Deserialize.tls_deserialize_spec_of_runs DI h RI hRI r
  tls_deserialize_exact_spec AI hAI bytes _ := by
    rw [hex]
    exact Deserialize.tls_deserialize_exact.default_spec DI AI hAI bytes fun s =>
      Deserialize.tls_deserialize_spec_of_runs DI h _ StdIo.slice_lawful s

/-- A run with one `Ok` output determines `encOut`. -/
theorem encOut_of_runs {T : Type} (SI : Serialize T) (x : T) (sz : Std.Usize) (b : List Std.U8)
    (h : SerRuns SI x sz (some b)) (hroom : sz.val ≤ imax) : encOut SI x = some b := by
  obtain ⟨e, he, hs, -⟩ := encode_of_runs SI x sz _ h hroom
  obtain ⟨bv, rfl, hbv⟩ := hs b rfl
  rw [encOut_ok he, hbv]

/-- `ser_lawful_of_runs` for serializers that always succeed with `sz ≤ isize::MAX` bytes. -/
theorem ser_lawful_of_some {T : Type} (SI : Serialize T) (hS : Size.Lawful T SI.SizeInst)
    (h : ∀ x, ∃ sz b, SI.SizeInst.tls_serialized_len x = ok sz ∧ sz.val ≤ imax ∧
      b.length = sz.val ∧ SerRuns SI x sz (some b))
    (hdet : ∀ x, SI.tls_serialize_detached x = Serialize.tls_serialize_detached.default SI x) :
    Serialize.Lawful T SI :=
  ser_lawful_of_runs SI hS (encOut SI) (fun x => by
    obtain ⟨sz, b, hsz, hroom, hl, hr⟩ := h x
    rw [encOut_of_runs SI x sz b hr hroom]
    exact ⟨sz, hsz, fun _ b' hb' => by cases hb'; exact hl, hr⟩) hdet

/-- The `?` re-wrapping of a delegated serializer call is the call itself. -/
theorem try_reroll {W : Type} (m : RustM (core.result.Result Std.Usize tls_codec.Error × W)) :
    (do
      let (r, w1) ← m
      let cf ← core.result.Result.Insts.CoreOpsTry_traitTry.branch r
      match cf with
      | core.ops.control_flow.ControlFlow.Continue val => ok (core.result.Result.Ok val, w1)
      | core.ops.control_flow.ControlFlow.Break residual => do
        let r1 ← core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
          Std.Usize (core.convert.From.Blanket tls_codec.Error) residual
        ok (r1, w1)) = m := by
  rcases m with ⟨⟨r, w1⟩⟩ | e | _
  · cases r <;> rfl
  · rfl
  · rfl

/-- `0 + i` (the `written` accumulator of the derived serializers). -/
theorem zero_add_ok (i : Std.Usize) : (0#usize + i : RustM Std.Usize) = ok i := by
  have := Aeneas.Std.UScalar.add_equiv (0#usize) i
  cases hc : (0#usize + i : RustM Std.Usize) with
  | ok z =>
    rw [hc] at this
    obtain ⟨_, hz, _⟩ := this
    congr 1
    apply UScalar.eq_of_val_eq
    simpa using hz
  | fail e =>
    rw [hc] at this
    exfalso
    apply this.2
    scalar_tac
  | div => rw [hc] at this; exact this.elim

/-- `a + 0` (the discriminant constants of the derived enum codecs). -/
theorem add_zero_u16 (a : Std.U16) : (a + 0#u16 : RustM Std.U16) = ok a := by
  have := Aeneas.Std.UScalar.add_equiv a (0#u16)
  cases hc : (a + 0#u16 : RustM Std.U16) with
  | ok z =>
    rw [hc] at this
    obtain ⟨_, hz, _⟩ := this
    congr 1
    apply UScalar.eq_of_val_eq
    simpa using hz
  | fail e =>
    rw [hc] at this
    exfalso
    apply this.2
    scalar_tac
  | div => rw [hc] at this; exact this.elim

/-- A serializer that delegates to `u16`'s (the unit-variant enums): it writes 2 bytes. -/
theorem ser_some_of_u16 {T : Type} (SI : Serialize T) (x : T)
    (hsz : SI.SizeInst.tls_serialized_len x = ok 2#usize)
    (h : ∃ c : Std.U16, ∀ {W : Type} (WI : core.io.write.Write W) (w : W),
      SI.tls_serialize WI x w = U16.Insts.Tls_codecSerialize.tls_serialize WI c w) :
    ∃ sz b, SI.SizeInst.tls_serialized_len x = ok sz ∧ sz.val ≤ imax ∧
      b.length = sz.val ∧ SerRuns SI x sz (some b) := by
  obtain ⟨c, hc⟩ := h
  refine ⟨2#usize, (Aeneas.Std.core.num.U16.to_be_bytes c).val, hsz,
    by have := imax_ge; simp; omega, by simp, ?_⟩
  intro W WI hWI w hroom
  rw [hc]
  exact U16.ser_runs c W WI hWI w hroom

/-- A serializer that writes the 2 big-endian bytes of `k` with `write_all` (hand-written
`u16`-coded enums of OpenMLS). -/
theorem ser_some_of_write_u16 {T : Type} (SI : Serialize T) (x : T) (k : Std.U16)
    (hsz : SI.SizeInst.tls_serialized_len x = ok 2#usize)
    (h : ∀ {W : Type} (WI : core.io.write.Write W) (w w' : W),
      WI.write_all w (Array.to_slice (Aeneas.Std.core.num.U16.to_be_bytes k)) = ok (.Ok (), w') →
      SI.tls_serialize WI x w = ok (.Ok 2#usize, w')) :
    ∃ sz b, SI.SizeInst.tls_serialized_len x = ok sz ∧ sz.val ≤ imax ∧
      b.length = sz.val ∧ SerRuns SI x sz (some b) :=
  ⟨2#usize, _, hsz, by have := imax_ge; simp; omega, by simp [Array.to_slice],
    ser_runs_of_write_all SI x _ 2#usize (by simp [Array.to_slice]) h⟩

/-- `size_of::<u16>()` plus nothing. -/
theorem u16_enum_size : (do let l ← core.mem.size_of Std.U16; len_add l 0#usize : RustM Std.Usize)
    = ok 2#usize := by
  rw [core.mem.size_of_U16]
  simp only [bind_tc_ok, len_add_ok]
  congr 1
  exact UScalar.eq_of_val_eq (by rw [lenAddVal_val _ _ (by scalar_tac)]; rfl)

theorem lenAdd_0_2 : lenAddVal 0#usize 2#usize = 2#usize :=
  UScalar.eq_of_val_eq (by rw [lenAddVal_val _ _ (by scalar_tac)]; rfl)


theorem u16_size (u : Std.U16) : U16.Insts.Tls_codecSize.tls_serialized_len u = ok 2#usize := by
  simp [U16.Insts.Tls_codecSize.tls_serialized_len]

/-- `SerRuns` of a unit-variant enum with a `u16` discriminant (`#[repr(u16)]` derive): `x` the
value, `ds` the serializer and its discriminant constants to unfold. -/
macro "u16_enum_ser" SI:term "," x:ident "[" ds:ident,* "]" : tactic => `(tactic| (
  refine ser_some_of_u16 $SI $x u16_enum_size ?_
  cases $x:ident <;> refine ⟨?_, fun WI w => ?_⟩ <;> try (
    simp only [$[$ds:ident],*, add_zero_u16, bind_tc_ok]
    exact try_reroll _)))

/-- `DeRuns` of a unit-variant enum with a `u16` discriminant: `ds` the deserializer to unfold. -/
macro "u16_enum_de" "[" ds:ident,* "]" : tactic => `(tactic| (
  intro R RI v a law r
  have hT := U16.de_runs R RI v a law r
  mvcgen [$[$ds:ident],*, hT, core.U64.Insts.CoreConvertFromU16.from]
  all_goals first
    | (rename_i q _ _ res _ hbr
       refine try_break_vc (x := q.1) (fun e _ => ?_) hbr
       mvcgen
       intro _
       mvcgen
       all_goals simp
       done)
    | (intro _ h; cases h; done)
    | (rename_i p hp _ _ _ _ hcf
       intro val' hval'
       obtain ⟨n, sz, hn, h2, hsz, hszn, -⟩ := hp _ (continue_eq_tryCF.mp hcf)
       rw [u16_size] at hsz; cases hsz
       exact ⟨n, 2#usize, hn, h2, u16_enum_size, hszn⟩)))

theorem lenAdd_0 (s : Std.Usize) : lenAddVal 0#usize s = s :=
  UScalar.eq_of_val_eq (by rw [lenAddVal_val _ _ (by simp; scalar_tac)]; simp)

/-- `SerRuns S x s (encOut FS fx)` of a derived one-field struct / newtype serializer `ser`
(field serializer `FS` on `fx`, lawful by `hL`, of size `s` by `hs`; `sh` / `sz` the struct's
`&T` and own size functions): the field's encoding, then the derive's `debug_assert`. -/
macro "newtype_ser" FS:term "," fx:term "," x:term "," hL:term "," s:term "," hs:term ","
    ser:ident "," sh:ident "," sz:ident : tactic => `(tactic| (
    intro W WI hWI w hroom
    have hT := SerRuns.spec'
      (Serialize.Lawful.runs $hL $fx $s $hs) WI hWI w
    have hexp : $sh $x = ok $s := by
      simp only [$sh:ident, $sz:ident]; rw [$hs:term]; simp [len_add_ok, lenAdd_0]
    suffices H : ⦃ ⌜ True ⌝ ⦄ $ser WI $x w
        ⦃ ⇓ p => ⌜ (∀ b, encOut $FS $fx = some b →
          (∃ n : Std.Usize, p.1 = .Ok n ∧ n.val = b.length) ∧
          core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w ++ b) ∧
          (encOut $FS $fx = none →
            ∃ e, p.1 = .Err e) ⌝ ⦄ by
      obtain ⟨⟨r, w'⟩, h1, h2⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp H
      exact ⟨r, w', h1, h2⟩
    have hle : ($s : Std.Usize).val ≤ imax := by omega
    have hel := Serialize.Lawful.enc_len
      $hL $fx $s $hs hle
    -- the field's `Ok val` is its encoding, of `s` bytes
    have key : ∀ (p : core.result.Result Std.Usize tls_codec.Error × W) (val : Std.Usize),
        (∀ b, encOut $FS $fx = some b →
          (∃ n : Std.Usize, p.1 = .Ok n ∧ n.val = b.length) ∧
          core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w ++ b) →
        (encOut $FS $fx = none →
            ∃ e, p.1 = .Err e) → p.1 = .Ok val →
        val.val = ($s : Std.Usize).val ∧ ∃ b, encOut $FS $fx = some b ∧
          val.val = b.length ∧ core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w ++ b := by
      intro p val hp1 hp2 hv
      have hp : _ ∧ _ := ⟨hp1, hp2⟩
      cases hb : encOut $FS $fx with
      | none => obtain ⟨e, he⟩ := hp.2 hb; rw [hv] at he; cases he
      | some b =>
        obtain ⟨⟨n, hn1, hn2⟩, hview⟩ := hp.1 b hb
        rw [hv] at hn1; cases hn1
        exact ⟨by rw [hn2, hel b hb], b, rfl, hn2, hview⟩
    mvcgen [$ser:ident, hT, hexp]
    · rename_i heq hne _ _ _ _ _ _; simp [heq] at hne
    · rename_i p hp _ val _ hcf r hr heq _
      obtain ⟨hvs, b, hb, hvb, hview⟩ := key p val hp.1 hp.2 (continue_eq_tryCF.mp hcf)
      refine ⟨fun b' hb' => ?_, fun hn => by rw [hb] at hn; cases hn⟩
      rw [hb] at hb'; cases hb'
      exact ⟨⟨r, rfl, by rw [hr]; simp; omega⟩, hview⟩
    · rename_i p hp _ val _ hcf r hr hne _ _ _
      obtain ⟨hvs, -⟩ := key p val hp.1 hp.2 (continue_eq_tryCF.mp hcf)
      exact hne (UScalar.eq_of_val_eq (by rw [hr]; simp; omega))
    · rename_i p hp _ val _ hcf hov
      obtain ⟨hvs, -⟩ := key p val hp.1 hp.2 (continue_eq_tryCF.mp hcf)
      have := imax_le
      simp [UScalar.max, Usize.max] at hov ⊢
      scalar_tac
    · rename_i p hp _ res _ hbr
      refine try_break_vc (x := p.1) (fun e he => ?_) hbr
      mvcgen
      intro _
      mvcgen
      refine ⟨fun b hb => ?_, fun _ => ⟨_, rfl⟩⟩
      obtain ⟨⟨n, hn1, -⟩, -⟩ := hp.1 b hb
      rw [he] at hn1; cases hn1))

/-- `DeRuns D True` of a derived one-field struct / newtype deserializer `de` (field deserializer
lawful by `hL`; `hsize`: the struct's size is the field's). -/
macro "newtype_de" hL:term "," de:ident "," hsize:term : tactic => `(tactic| (
  intro R RI v a law r
  have hT := Deserialize.Lawful.runs $hL R RI v a law r
  mvcgen [$de:ident, hT]
  · rename_i p _ u _ hcf hp
    intro val hval; cases hval
    obtain ⟨n, sz, hn, h2, hsz, hszn⟩ := hp u (continue_eq_tryCF.mp hcf)
    exact ⟨n, sz, hn, h2, $hsize u sz hsz, hszn⟩
  · rename_i q _ res _ hbr _
    refine try_break_vc (x := q.1) (fun e _ => ?_) hbr
    mvcgen
    intro _
    mvcgen
    all_goals simp))

/-- `DeserializeBytes.Lawful` of a hand-written bytes deserializer that runs the type's `std`
`tls_deserialize` on the slice and returns the rest from index `tls_serialized_len` (`DB` the
instance, `fn` its function, `hDe` / `hS` the `std` `Deserialize.Lawful` / `Size.Lawful`). -/
macro "debytes_via_std" DB:term "," fn:ident "," hDe:term "," hS:term : tactic => `(tactic| (
  have hd : ∀ bytes, ⦃ ⌜ True ⌝ ⦄ $fn bytes
      ⦃ ⇓ r => ⌜ (DeserializeBytes.tls_deserialize_bytes.post
        ($DB).SizeInst
        $DB bytes r).holds ⌝ ⦄ := by
    intro bytes
    have hT := ($hDe).runs _ _ _ _ StdIo.slice_law bytes
    mvcgen [$fn:ident, hT]
    · rename_i p _ u _ hcf hp
      obtain ⟨n, sz, hn, -, hsz, hszn⟩ := hp u (continue_eq_tryCF.mp hcf)
      have hidx := core.ops.range.RangeFromUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.index_spec
        ⟨sz⟩ bytes (by simp; omega)
      mvcgen [hsz, core.Slice.Insts.CoreOpsIndexIndex.index, hidx]
      intro h1 _
      obtain ⟨t, ht, htv⟩ := h1 (by omega)
      refine ⟨t, ht, ?_⟩
      mvcgen
      exact DeserializeBytes.post_ok _ _ _ _ _ sz hsz (by rw [htv]; simp; omega)
        (by rw [htv]; exact List.drop_suffix _ _)
    · rename_i q _ _ _ _
      intro hbr
      refine try_break_vc (x := q.1) (fun e he => ?_) hbr
      mvcgen
      intro _
      exact DeserializeBytes.post_err _ _ _ _
  exact ⟨$hS, fun b _ => hd b,
    fun b _ => exact_bytes_spec $DB hd b⟩))

end tls_codec.Derive
