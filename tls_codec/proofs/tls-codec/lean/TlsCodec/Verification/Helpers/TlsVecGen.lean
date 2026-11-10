/- `TlsVecU*` / `SecretTlsVecU*` `tls_deserialize_bytes` (the loop over the elements): the generic
proof `TlsVecGen`, and `TlsSliceU*::tls_serialized_length`.

Obligations: none directly; the bytes-path halves of `PanicFreedom.lean` /
`FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): nothing ASSUMED. -/
import TlsCodec.Verification.Helpers.Containers
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! ### `TlsVecU*` / `SecretTlsVecU*` `deserialize_bytes` (loop over the elements)

The size of a vector is a fold of `len_add` (saturating) over the element sizes, starting at the
prefix width `a0`; `SizeFoldRel` is its relational model. The loop invariant `DesLoopInv` ties the
elements read so far to the bytes consumed. Termination: an element that consumes `0` bytes is
rejected by the code itself (`consumed = 0` => error), so `remainder.len` strictly decreases. -/

/-- Relational model of the size fold of a vector: fold of `lenAddVal` of the element sizes. -/
inductive SizeFoldRel {T : Type} (S : Size T) : Std.Usize → List T → Std.Usize → Prop
  | nil (a : Std.Usize) : SizeFoldRel S a [] a
  | cons (a : Std.Usize) (x : T) (l : List T) (n : Std.Usize) (r : Std.Usize) :
      S.tls_serialized_len x = ok n → SizeFoldRel S (lenAddVal a n) l r →
      SizeFoldRel S a (x :: l) r

theorem SizeFoldRel.snoc {T : Type} {S : Size T} {a : Std.Usize} {l : List T} {r : Std.Usize}
    (h : SizeFoldRel S a l r) (e : T) (n : Std.Usize) (hn : S.tls_serialized_len e = ok n) :
    SizeFoldRel S a (l ++ [e]) (lenAddVal r n) := by
  induction h with
  | nil a => exact .cons a e [] n _ hn (.nil _)
  | cons a x l n' r hx _ ih => exact .cons a x _ n' _ hx ih

theorem SizeFoldRel.functional {T : Type} {S : Size T} {a : Std.Usize} {l : List T} {r r' : Std.Usize}
    (h : SizeFoldRel S a l r) (h' : SizeFoldRel S a l r') : r = r' := by
  induction h generalizing r' with
  | nil a => cases h'; rfl
  | cons a x l n r hx _ ih =>
    cases h' with
    | cons _ _ _ n2 _ hx2 h2 =>
      rw [hx] at hx2
      cases hx2
      exact ih h2

theorem size_fold_rel {T C : Type} (S : Size T) (hS : ∀ e, ∃ n, S.tls_serialized_len e = ok n)
    (inst : core.ops.function.FnMut C (Std.Usize × T) Std.Usize)
    (hcall : ∀ c a e n, S.tls_serialized_len e = ok n → inst.call_mut c (a, e) = ok (lenAddVal a n, c))
    (it : core.slice.iter.Iter T) (acc : Std.Usize) (c : C) :
    ⦃ ⌜ True ⌝ ⦄
    core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.fold inst it acc c
    ⦃ ⇓ r => ⌜ SizeFoldRel S acc (it : Slice T).val r ⌝ ⦄ := by
  simp only [core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.fold,
    core.iter.traits.iterator.Iterator.fold.default, core.iter.traits.iterator.iter_fold,
    core.iter.traits.iterator.iter_fold_loop]
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.loop.spec_decr_nat
    (fun p : core.slice.iter.Iter T × C × Std.Usize => (p.1 : Slice T).val.length)
    (fun p => ∀ r, SizeFoldRel S p.2.2 (p.1 : Slice T).val r → SizeFoldRel S acc (it : Slice T).val r)
  · rintro ⟨it', c', a⟩ hinv
    simp only [core.iter.traits.iterator.iter_fold_loop.body,
      core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.next,
      rust_primitives.sequence.seq_len, rust_primitives.sequence.seq_remove] at hinv ⊢
    by_cases hz : Slice.len it' = 0#usize
    · have h0 : (it' : Slice T).val = [] := by
        rw [← List.length_eq_zero_iff]; scalar_tac
      simp only [hz]
      simp
      exact hinv a (by rw [h0]; exact .nil a)
    · have hpos : 0 < (it' : Slice T).val.length := by scalar_tac
      obtain ⟨x, l, hl⟩ : ∃ x l, (it' : Slice T).val = x :: l := by
        cases h : (it' : Slice T).val with
        | nil => rw [h] at hpos; simp at hpos
        | cons y l => exact ⟨y, l, rfl⟩
      obtain ⟨n, hn⟩ := hS x
      simp [hz, hl, hcall _ _ _ _ hn]
      intro r hr
      apply hinv
      rw [hl]
      exact .cons _ _ _ n _ hn hr
  · intro r h; exact h

/-- A lawful `Size` instance never fails. -/
theorem Size.lawful_ok {T : Type} (S : Size T) (hl : Size.Lawful T S) (e : T) :
    ∃ n, S.tls_serialized_len e = ok n := by
  obtain ⟨v, hv, _⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (hl.tls_serialized_len_spec e (pre_holds_of_ok_true rfl))
  exact ⟨v, hv⟩

/-- A lawful `Size` instance never fails (as a spec for `mvcgen`, naming the result). -/
theorem Size.len_char {T : Type} (S : Size T) (hl : Size.Lawful T S) (e : T) :
    ⦃ ⌜ True ⌝ ⦄ S.tls_serialized_len e ⦃ ⇓ r => ⌜ S.tls_serialized_len e = ok r ⌝ ⦄ := by
  obtain ⟨n, hn⟩ := Size.lawful_ok S hl e
  rw [hn]
  apply RustM.ok_spec
  rfl

/-- Invariant of the `deserialize_bytes` loops: `l` are the elements read so far, `a0` the prefix
width, `N` the length of the whole input, `B` the whole input (the remainder is a suffix of it). -/
def DesLoopInv {T : Type} (S : Size T) (a0 : Std.Usize) (N : Nat) (B : List Std.U8) (l : List T)
    (remainder : Slice Std.U8) (read : Std.Usize) : Prop :=
  l.length ≤ read.val ∧ (∃ s, SizeFoldRel S a0 l s ∧ s.val + remainder.val.length = N) ∧
  read.val + remainder.val.length + a0.val = N ∧ remainder.val <:+ B

/-- The remainder after a successful length-prefix read. -/
theorem prefix_rem {U : Type} (W : Nat) {bytes : Slice Std.U8}
    {r : core.result.Result (U × Slice Std.U8) Error} {p : U × Slice Std.U8}
    (hP : (W ≤ bytes.val.length → ∃ t : Slice Std.U8, t.val = bytes.val.drop W ∧ ∃ x, r = .Ok (x, t)) ∧
      (bytes.val.length < W → r = .Err Error.EndOfStream))
    (hr : r = .Ok p) : p.2.val.length + W = bytes.val.length ∧ p.2.val <:+ bytes.val := by
  by_cases h : W ≤ bytes.val.length
  · obtain ⟨t, ht, x, hx⟩ := hP.1 h
    rw [hx] at hr
    have := core.result.Result.Ok.inj hr
    subst this
    simp only [ht]
    exact ⟨by simp; omega, List.drop_suffix _ _⟩
  · have := hP.2 (by omega)
    rw [this] at hr
    cases hr

/-! #### Generic `TlsVecU*` / `SecretTlsVecU*` (`TlsVecGen`)

The extracted per-width functions are identical modulo the wrapper type (`structure … where vec`),
the prefix codec and its conversion to `usize`, and the prefix width. They are stated once here
over an abstract wrapper `W` (`vec : W → Vec T`, `mk`, `push`); each width links its concrete
function to the generic one by `rfl` (definitional unfolding; `deserialize_bytes` needs a case split
on the `?` match, and the message literals are existentially quantified so that no `toStr` is
re-elaborated here), and its per-width lemmas are one-line corollaries. -/

namespace TlsVecGen

variable {T W : Type}

/-- The loop body of `TlsVecU*::deserialize_bytes` / `SecretTlsVecU*::deserialize_bytes`, over
an abstract wrapper `W` with its `push` (`msg`: the error message literal). -/
theorem push_spec (vec : W → alloc.vec.Vec T) (mk : alloc.vec.Vec T → W) (hmk : ∀ v, vec (mk v) = v)
    (w : W) (x : T) (h : (vec w).val.length < Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ (do let v ← alloc.vec.Vec.push (vec w) x; ok (mk v) : RustM W)
    ⦃ ⇓ r => ⌜ (vec r).val = (vec w).val ++ [x] ⌝ ⦄ := by
  have := alloc.vec.Vec.push_spec (vec w) x h
  mvcgen [this]
  simp_all

noncomputable def body (push : W → T → RustM W) (msg : Str) (inst : DeserializeBytes T) (length : Std.Usize)
    (result : W) (remainder : Slice Std.U8) (read : Std.Usize) :
    RustM (ControlFlow (W × Slice Std.U8 × Std.Usize)
      (W × Slice Std.U8 × Std.Usize × core.option.Option Error)) := do
  if read < length
  then
    let r ← inst.tls_deserialize_bytes remainder
    match r with
    | core.result.Result.Ok p =>
      let (element, next_remainder) := p
      let i ← core.slice.Slice.len remainder
      let i1 ← core.slice.Slice.len next_remainder
      let consumed ← i - i1
      let result1 ← push result element
      if consumed = 0#usize
      then
        let a ← core.fmt.Arguments.from_str msg
        let s ← alloc.fmt.format a
        let s1 ← core.hint.must_use s
        ok (done (result1, next_remainder, read, core.option.Option.Some
          (Error.DecodingError s1)))
      else
        let read1 ← read + consumed
        ok (cont (result1, next_remainder, read1))
    | core.result.Result.Err e =>
      ok (done (result, remainder, read, core.option.Option.Some e))
  else ok (done (result, remainder, read, core.option.Option.None))

theorem body_char (vec : W → alloc.vec.Vec T) (push : W → T → RustM W)
    (push_spec : ∀ w x, (vec w).val.length < Usize.max →
      ⦃ ⌜ True ⌝ ⦄ push w x ⦃ ⇓ r => ⌜ (vec r).val = (vec w).val ++ [x] ⌝ ⦄)
    (msg : Str) (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (a0 : Std.Usize) (length : Std.Usize) (N : Nat)
    {B : List Std.U8} (hN : N ≤ Usize.max)
    (result : W) (remainder : Slice Std.U8) (read : Std.Usize)
    (hinv : DesLoopInv inst.SizeInst a0 N B (vec result).val remainder read) :
    ⦃ ⌜ True ⌝ ⦄
    body push msg inst length result remainder read
    ⦃ ⇓ r => ⌜ match r with
      | .done (res, rem, _, fl) => fl = core.option.Option.None →
          ∃ s, SizeFoldRel inst.SizeInst a0 (vec res).val s ∧ s.val + rem.val.length = N ∧
            rem.val <:+ B
      | .cont (res, rem, rd) => DesLoopInv inst.SizeInst a0 N B (vec res).val rem rd ∧
          rem.val.length < remainder.val.length ⌝ ⦄ := by
  have hd := fun b => hlaw.tls_deserialize_bytes_spec b (pre_holds_of_ok_true rfl)
  obtain ⟨hres, ⟨s, hs, hsN⟩, hr, hB⟩ := hinv
  mvcgen [body, hd, push_spec, core.fmt.Arguments.from_str]
  case vc1.a =>
    rename_i hlt r p hx hpost r2 h2 r1 h1 r0 ha hb
    scalar_tac
  case vc3.hQ =>
    rename_i hlt r p hx hpost r2 h2 r1 h1 r0 ha hb res hnz hpush rd hrd
    obtain ⟨e, nxt⟩ := p
    obtain ⟨n, hn, hl⟩ := DeserializeBytes.post_ok_elim _ _ _ _ _ hpost
    subst h2 h1
    have l1 := Slice.len_val remainder
    have l2 := Slice.len_val nxt
    simp only [Slice.length] at l1 l2
    have hnz' : r0.val ≠ 0 := fun h => hnz (UScalar.eq_of_val_eq (by simpa using h))
    have hr0 : r0.val = n.val := by dsimp only at *; omega
    have hsn : (lenAddVal s n).val = s.val + n.val := lenAddVal_val s n (by dsimp only at *; omega)
    have hsuf := (DeserializeBytes.post_ok_suffix _ _ _ _ _ hpost).trans hB
    refine ⟨⟨?_, ⟨lenAddVal s n, ?_, ?_⟩, ?_, hsuf⟩, ?_⟩
    · rw [hpush]; simp; dsimp only at *; omega
    · rw [hpush]; exact hs.snoc e n hn
    · dsimp only at *; omega
    · dsimp only at *; omega
    · dsimp only at *; omega
  case vc4.h_fail =>
    exfalso
    rename_i hlt r p hx hpost r2 h2 r1 h1 r0 ha hb res hnz hpush hbig
    obtain ⟨e, nxt⟩ := p
    obtain ⟨n, hn, hl⟩ := DeserializeBytes.post_ok_elim _ _ _ _ _ hpost
    subst h2 h1
    have l1 := Slice.len_val remainder
    have l2 := Slice.len_val nxt
    simp only [Slice.length] at l1 l2
    dsimp only at *
    scalar_tac
  case vc5.h_fail =>
    exfalso
    rename_i hlt r p hx hpost r2 h2 r1 h1 hlt2
    obtain ⟨e, nxt⟩ := p
    obtain ⟨n, hn, hl⟩ := DeserializeBytes.post_ok_elim _ _ _ _ _ hpost
    subst h2 h1
    have l1 := Slice.len_val remainder
    have l2 := Slice.len_val nxt
    simp only [Slice.length] at l1 l2
    dsimp only at *
    scalar_tac
  all_goals (try (intros; simp_all; done))
  exact ⟨s, hs, hsN, hB⟩


/-- The loop of `deserialize_bytes`, over its body `bodyF` (fixed `length`). -/
def dloop (bodyF : W → Slice Std.U8 → Std.Usize → RustM (ControlFlow (W × Slice Std.U8 × Std.Usize)
      (W × Slice Std.U8 × Std.Usize × core.option.Option Error)))
    (result : W) (remainder : Slice Std.U8) (read : Std.Usize) :
    RustM (W × Slice Std.U8 × Std.Usize × core.option.Option Error) :=
  loop (fun (result1, remainder1, read1) => bodyF result1 remainder1 read1) (result, remainder, read)

theorem loop_char (vec : W → alloc.vec.Vec T) (push : W → T → RustM W)
    (push_spec : ∀ w x, (vec w).val.length < Usize.max →
      ⦃ ⌜ True ⌝ ⦄ push w x ⦃ ⇓ r => ⌜ (vec r).val = (vec w).val ++ [x] ⌝ ⦄)
    (inst : DeserializeBytes T) (length : Std.Usize) (msg : Str)
    {bodyF : W → Slice Std.U8 → Std.Usize → RustM (ControlFlow (W × Slice Std.U8 × Std.Usize)
      (W × Slice Std.U8 × Std.Usize × core.option.Option Error))}
    (hbody : bodyF = body push msg inst length)
    (hlaw : DeserializeBytes.Lawful T inst) (a0 : Std.Usize) (N : Nat) {B : List Std.U8}
    (hN : N ≤ Usize.max)
    (result : W) (remainder : Slice Std.U8) (read : Std.Usize)
    (hinv : DesLoopInv inst.SizeInst a0 N B (vec result).val remainder read) :
    ⦃ ⌜ True ⌝ ⦄
    dloop bodyF result remainder read
    ⦃ ⇓ r => ⌜ r.2.2.2 = core.option.Option.None →
        ∃ s, SizeFoldRel inst.SizeInst a0 (vec r.1).val s ∧ s.val + r.2.1.val.length = N ∧
          r.2.1.val <:+ B ⌝ ⦄ := by
  subst hbody
  unfold dloop
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.loop.spec_decr_nat
    (fun p : W × Slice Std.U8 × Std.Usize => p.2.1.val.length)
    (fun p => DesLoopInv inst.SizeInst a0 N B (vec p.1).val p.2.1 p.2.2)
  · rintro ⟨res, rem, rd⟩ h
    obtain ⟨v, hv, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (body_char vec push push_spec msg inst hlaw a0 length N hN res rem rd h)
    dsimp only
    rw [hv]
    refine (Aeneas.Std.WP.spec_ok v).mpr ?_
    cases v with
    | done y => exact hP
    | cont x => exact hP
  · exact hinv


/-- `tls_serialized_length` of a `TlsVecU*` / `SecretTlsVecU*` / `TlsSliceU*`: fold of the closure `F`
over the elements (`asSlice`) from the prefix width `w`. -/
def serLen {X C : Type} (asSlice : X → RustM (Slice T))
    (F : core.ops.function.FnMut C (Std.Usize × T) Std.Usize) (c : C) (w : Std.Usize) (x : X) :
    RustM Std.Usize := do
  let s ← asSlice x
  let i ← core.slice.Slice.iter s
  core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.fold F i w c

theorem ok_view (x : Slice T) : ⦃ ⌜ True ⌝ ⦄ (ok x : RustM (Slice T)) ⦃ ⇓ s => ⌜ s = x ⌝ ⦄ := by
  mvcgen

theorem serLen_rel {X C : Type} (S : Size T) (hl : Size.Lawful T S)
    (asSlice : X → RustM (Slice T)) {view : X → Slice T}
    (has : ∀ x, ⦃ ⌜ True ⌝ ⦄ asSlice x ⦃ ⇓ s => ⌜ s = view x ⌝ ⦄)
    (F : core.ops.function.FnMut C (Std.Usize × T) Std.Usize)
    (hF : ∀ c a e, F.call_mut c (a, e) = (do
      let i ← S.tls_serialized_len e
      let i1 ← len_add a i
      ok (i1, c)))
    (c : C) (w : Std.Usize) (x : X) :
    ⦃ ⌜ True ⌝ ⦄ serLen asSlice F c w x ⦃ ⇓ r => ⌜ SizeFoldRel S w (view x).val r ⌝ ⦄ := by
  have hcall : ∀ c a e n, S.tls_serialized_len e = ok n → F.call_mut c (a, e) = ok (lenAddVal a n, c) := by
    intro c a e n hn
    simp [hF, hn, len_add_ok]
  have hf := size_fold_rel S (Size.lawful_ok S hl) _ hcall
  mvcgen [serLen, has, hf]
  intro h; subst_vars; exact h


/-- `deserialize_bytes` of a vector wrapper: length prefix `readLen`, conversion `conv` (unwrapped
with `dbg`), then the element loop `dloop` (`pieces`: the mismatch message literal). -/
noncomputable def deser {P E : Type} {M : Std.Usize} (mk : alloc.vec.Vec T → W)
    (readLen : Slice Std.U8 → RustM (core.result.Result (P × Slice Std.U8) Error))
    (conv : P → RustM (core.result.Result Std.Usize E)) (dbg : core.fmt.Debug E)
    (dloop : W → Slice Std.U8 → Std.Usize → Std.Usize →
      RustM (W × Slice Std.U8 × Std.Usize × core.option.Option Error))
    (pieces : Aeneas.Std.Array Std.U8 M) (bytes : Slice Std.U8) :
    RustM (core.result.Result (W × Slice Std.U8) Error) := do
  let v ← alloc.vec.Vec.new T
  let r ← readLen bytes
  let cf ← core.result.Result.Insts.CoreOpsTry_traitTry.branch r
  match cf with
  | core.ops.control_flow.ControlFlow.Continue p =>
    let (len, remainder) := p
    let r1 ← conv len
    let length ← core.result.Result.unwrap dbg r1
    let (result, remainder1, read, failure) ← dloop (mk v) remainder length 0#usize
    match failure with
    | core.option.Option.None =>
      if read != length
      then
        let a ← core.fmt.rt.Argument.new_display core.Usize.Insts.CoreFmtDisplay length
        let a1 ← core.fmt.rt.Argument.new_display core.Usize.Insts.CoreFmtDisplay read
        let a2 ← core.fmt.Arguments.new pieces (Array.make 2#usize [ a, a1 ])
        let s ← alloc.fmt.format a2
        let s1 ← core.hint.must_use s
        ok (core.result.Result.Err (Error.DecodingError s1))
      else ok (core.result.Result.Ok (result, remainder1))
    | core.option.Option.Some e => ok (core.result.Result.Err e)
  | core.ops.control_flow.ControlFlow.Break residual =>
    core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
      (W × Slice Std.U8) (core.convert.From.Blanket Error) residual


/-- Post of the element loop from the prefix width `w` and the input length `N`. -/
abbrev LoopPost (S : Size T) (vec : W → alloc.vec.Vec T) (w : Std.Usize) (N : Nat) (B : List Std.U8)
    (r : W × Slice Std.U8 × Std.Usize × core.option.Option Error) : Prop :=
  r.2.2.2 = core.option.Option.None → ∃ s, SizeFoldRel S w (vec r.1).val s ∧
    s.val + r.2.1.val.length = N ∧ r.2.1.val <:+ B

theorem deser_char {P E : Type} {M : Std.Usize} (S : Size T) (vec : W → alloc.vec.Vec T)
    (mk : alloc.vec.Vec T → W) (hmk : ∀ v, vec (mk v) = v) (size : W → RustM Std.Usize)
    (w : Std.Usize) (hsz : ∀ v, ⦃ ⌜ True ⌝ ⦄ size v ⦃ ⇓ r => ⌜ SizeFoldRel S w (vec v).val r ⌝ ⦄)
    (readLen : Slice Std.U8 → RustM (core.result.Result (P × Slice Std.U8) Error))
    (hread : ∀ bytes, ⦃ ⌜ True ⌝ ⦄ readLen bytes
      ⦃ ⇓ r => ⌜ ∀ p, r = .Ok p → p.2.val.length + w.val = bytes.val.length ∧
        p.2.val <:+ bytes.val ⌝ ⦄)
    (conv : P → RustM (core.result.Result Std.Usize E))
    (hconv : ∀ p, ⦃ ⌜ True ⌝ ⦄ conv p ⦃ ⇓ r => ⌜ ∃ y, r = .Ok y ⌝ ⦄) (dbg : core.fmt.Debug E)
    (dloop : W → Slice Std.U8 → Std.Usize → Std.Usize →
      RustM (W × Slice Std.U8 × Std.Usize × core.option.Option Error))
    (hloop : ∀ N (B : List Std.U8), N ≤ Usize.max → ∀ result remainder length read,
      DesLoopInv S w N B (vec result).val remainder read →
      ⦃ ⌜ True ⌝ ⦄ dloop result remainder length read ⦃ ⇓ r => ⌜ LoopPost S vec w N B r ⌝ ⦄)
    (pieces : Aeneas.Std.Array Std.U8 M) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ deser mk readLen conv dbg dloop pieces bytes
    ⦃ ⇓ r => ⌜ ∀ v rem, r = .Ok (v, rem) → ∃ n, size v = ok n ∧
        rem.val.length + n.val = bytes.val.length ∧ rem.val <:+ bytes.val ⌝ ⦄ := by
  have hN : bytes.val.length ≤ Usize.max := by have := bytes.property; scalar_tac
  have hl := hloop _ bytes.val hN
  mvcgen [deser, hread, hconv, hl, core.result.Result.unwrap]
  try_vcs
  all_goals (try simp only [continue_eq_tryCF] at *)
  all_goals (try (intro _ _ h; cases h; done))
  all_goals (try (intros; simp [PostCond.ok]; done))
  all_goals (try (exfalso; simp_all; done))
  case vc1.a =>
    subst_vars
    simp only [core.result.Result.Ok.injEq, forall_eq'] at *
    refine ⟨by simp [hmk, Slice.new], ⟨w, by rw [hmk]; exact .nil _, ?_⟩, ?_, ?_⟩ <;> try scalar_tac
  case vc3 =>
    intro v rem h
    simp only [core.result.Result.Ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    obtain ⟨s, hs, hsN, hsB⟩ := ‹LoopPost _ _ _ _ _ _› ‹_ = core.option.Option.None›
    obtain ⟨n, hn, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (hsz _)
    exact ⟨n, hn, (hs.functional hP) ▸ (Nat.add_comm _ _).trans hsN, hsB⟩


/-- The function-level post of `deserialize_bytes` (`ensures` closure: `rem.len + size v = bytes.len`). -/
def post (size : W → RustM Std.Usize) (bytes : Slice Std.U8)
    (res : core.result.Result (W × Slice Std.U8) Error) : RustM Bool := do
  let b ← core.result.Result.is_err res
  if b
  then ok true
  else
    core.result.Result.is_ok_and
      ({ call_once := fun (c : Slice Std.U8) (tupled_args : W × Slice Std.U8) => do
          let (vec, remainder) := tupled_args
          let i ← core.slice.Slice.len remainder
          let i1 ← size vec
          let i2 ← i + i1
          let i3 ← core.slice.Slice.len c
          ok (i2 = i3) } : core.ops.function.FnOnce (Slice Std.U8) (W × Slice Std.U8) Bool) res bytes

theorem post_of_char (size : W → RustM Std.Usize) (bytes : Slice Std.U8)
    (r : core.result.Result (W × Slice Std.U8) Error)
    (h : ∀ v rem, r = .Ok (v, rem) → ∃ n, size v = ok n ∧ rem.val.length + n.val = bytes.val.length ∧
      rem.val <:+ bytes.val) :
    (post size bytes r).holds := by
  have hl : ∀ (s : Slice Std.U8), core.slice.Slice.len s = ok (Slice.len s) := by
    intro s; unfold core.slice.Slice.len; rfl
  cases r with
  | Err e =>
    simp [post, core.result.Result.is_err, RustM.holds]
    mvcgen
  | Ok p =>
    obtain ⟨v, rem⟩ := p
    obtain ⟨n, hn, hrem, -⟩ := h v rem rfl
    have hb : bytes.val.length ≤ Std.Usize.max := by
      have := bytes.property; scalar_tac
    have hadd : (Slice.len rem + n : RustM Std.Usize) = ok (Slice.len bytes) := by
      have := Aeneas.Std.UScalar.add_equiv (Slice.len rem) n
      cases hc : (Slice.len rem + n : RustM Std.Usize) with
      | ok z =>
        rw [hc] at this
        obtain ⟨_, hz, _⟩ := this
        congr 1
        apply UScalar.eq_of_val_eq
        simp only [Slice.len_val, Slice.length] at hz ⊢
        omega
      | fail e =>
        rw [hc] at this
        exfalso
        apply this.2
        simp only [Slice.len_val, Slice.length] at *
        scalar_tac
      | div => rw [hc] at this; exact this.elim
    simp only [post, core.result.Result.is_err, core.result.Result.is_ok_and, hl]
    simp [hn, hadd, RustM.holds]
    mvcgen

/-- The function-level post from a total characterization. -/
theorem fc_of_char (size : W → RustM Std.Usize) (bytes : Slice Std.U8)
    {m : RustM (core.result.Result (W × Slice Std.U8) Error)}
    (h : ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓ r => ⌜ ∀ v rem, r = .Ok (v, rem) → ∃ n, size v = ok n ∧
      rem.val.length + n.val = bytes.val.length ∧ rem.val <:+ bytes.val ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓? res => ⌜ (post size bytes res).holds ⌝ ⦄ := by
  obtain ⟨v, hv, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp h
  rw [hv]
  apply RustM.ok_spec
  exact post_of_char size bytes v hP

/-- The remainder after a successful length-prefix read of width `w = n` (from `U*_deserialize_char`). -/
theorem prefix_len {U X : Type} (w : Std.Usize) (n : Nat) (hn : w.val = n) {f : X → U} {A : Slice Std.U8 → X → Prop}
    {readLen : Slice Std.U8 → RustM (core.result.Result (U × Slice Std.U8) Error)}
    (h : ∀ bytes, ⦃ ⌜ True ⌝ ⦄ readLen bytes
      ⦃ ⇓ r => ⌜ (n ≤ bytes.val.length → ∃ (a : X) (t : Slice Std.U8),
          A bytes a ∧ t.val = bytes.val.drop n ∧ r = .Ok (f a, t)) ∧
        (bytes.val.length < n → r = .Err Error.EndOfStream) ⌝ ⦄)
    (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ readLen bytes
    ⦃ ⇓ r => ⌜ ∀ p, r = .Ok p → p.2.val.length + w.val = bytes.val.length ∧
      p.2.val <:+ bytes.val ⌝ ⦄ := by
  obtain ⟨r, hr, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (h bytes)
  rw [hr, hn]
  apply RustM.ok_spec
  exact fun p hp => prefix_rem n ⟨fun h => let ⟨_, t, _, ht, hr⟩ := hP.1 h; ⟨t, ht, _, hr⟩, hP.2⟩ hp

/-- A conversion that always returns `Ok`. -/
theorem conv_ok {P E : Type} {conv : P → RustM (core.result.Result Std.Usize E)} {g : P → Std.Usize}
    (h : ∀ p, ⦃ ⌜ True ⌝ ⦄ conv p ⦃ ⇓ r => ⌜ r = .Ok (g p) ⌝ ⦄) (p : P) :
    ⦃ ⌜ True ⌝ ⦄ conv p ⦃ ⇓ r => ⌜ ∃ y, r = .Ok y ⌝ ⦄ := by
  obtain ⟨r, hr, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (h p)
  rw [hr]
  apply RustM.ok_spec
  exact ⟨_, hP⟩

end TlsVecGen

/-! #### `TlsSliceU*::tls_serialized_length` -/

/-- `TlsSliceU8::tls_serialized_length` does not fail when the element size does not. -/
theorem tls_vec.TlsSliceU8.tls_serialized_length_pf {T : Type} (SizeInst : Size T)
    (SizeInstLawful : Size.Lawful T SizeInst) (self_ : tls_vec.TlsSliceU8 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsSliceU8.tls_serialized_length SizeInst self_
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  pf_of_total (TlsVecGen.serLen_rel SizeInst SizeInstLawful tls_vec.TlsSliceU8.as_slice TlsVecGen.ok_view _ (fun _ _ _ => rfl) () 1#usize self_)

/-- `TlsSliceU16::tls_serialized_length` does not fail when the element size does not. -/
theorem tls_vec.TlsSliceU16.tls_serialized_length_pf {T : Type} (SizeInst : Size T)
    (SizeInstLawful : Size.Lawful T SizeInst) (self_ : tls_vec.TlsSliceU16 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsSliceU16.tls_serialized_length SizeInst self_
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  pf_of_total (TlsVecGen.serLen_rel SizeInst SizeInstLawful tls_vec.TlsSliceU16.as_slice TlsVecGen.ok_view _ (fun _ _ _ => rfl) () 2#usize self_)

/-- `TlsSliceU24::tls_serialized_length` does not fail when the element size does not. -/
theorem tls_vec.TlsSliceU24.tls_serialized_length_pf {T : Type} (SizeInst : Size T)
    (SizeInstLawful : Size.Lawful T SizeInst) (self_ : tls_vec.TlsSliceU24 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsSliceU24.tls_serialized_length SizeInst self_
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  pf_of_total (TlsVecGen.serLen_rel SizeInst SizeInstLawful tls_vec.TlsSliceU24.as_slice TlsVecGen.ok_view _ (fun _ _ _ => rfl) () 3#usize self_)

/-- `TlsSliceU32::tls_serialized_length` does not fail when the element size does not. -/
theorem tls_vec.TlsSliceU32.tls_serialized_length_pf {T : Type} (SizeInst : Size T)
    (SizeInstLawful : Size.Lawful T SizeInst) (self_ : tls_vec.TlsSliceU32 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsSliceU32.tls_serialized_length SizeInst self_
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  pf_of_total (TlsVecGen.serLen_rel SizeInst SizeInstLawful tls_vec.TlsSliceU32.as_slice TlsVecGen.ok_view _ (fun _ _ _ => rfl) () 4#usize self_)

end tls_codec
