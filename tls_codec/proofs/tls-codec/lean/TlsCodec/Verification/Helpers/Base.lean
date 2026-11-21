/- Base lemmas: length sums (`len_add` / `checked_len_add`), `pre.holds` hypotheses, `?` on
`Result`, scalar casts, `usize` indexing, specs of small shared functions, `len` of the vector
wrappers, `Vec::pop`, FC closers, partial triples with a trivial post.

Obligations: none directly; the bytes-path halves of `PanicFreedom.lean` /
`FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): nothing ASSUMED. -/
import Aeneas
import CoreModels
import Hax
import TlsCodec.Extraction
import TlsCodec.Assumptions.MissingCoreModelsSpecs
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-- Value of a saturating add: capped at the type's maximum. -/
@[simp, scalar_tac_simps] theorem UScalar.saturating_add_val {ty : UScalarTy} (x y : UScalar ty) :
    (UScalar.saturating_add x y).val = min (UScalar.max ty) (x.val + y.val) := by
  have hmax : UScalar.max ty < 2 ^ ty.numBits := by
    simp only [UScalar.max]; have := Nat.two_pow_pos ty.numBits; omega
  have hlt : min (UScalar.max ty) (x.val + y.val) < 2 ^ ty.numBits :=
    Nat.lt_of_le_of_lt (Nat.min_le_left _ _) hmax
  simp only [UScalar.saturating_add, UScalar.val, BitVec.toNat_ofNat]
  exact Nat.mod_eq_of_lt hlt

/-! ### Length sums (`len_add` / `checked_len_add`)

Both are extracted: `len_add a b` is `a.saturating_add(b)` and
`checked_len_add a b` is `a.checked_add(b).ok_or(InvalidVectorLength)`, on every target.
`len_add_spec` / `len_add_spec_sat` / `checked_len_add_spec` are theorems about these bodies
(the statements of the former ASSUMED axioms). Their results get names (`lenAddVal a b`,
`checkedLenAddVal a b`), with equations (`len_add_ok`, `checked_len_add_ok`) and `@[spec]`
triples whose post pins the result, so `mvcgen` substitutes it; the value is the exact sum
whenever it fits (`lenAddVal_val`, `checkedLenAddVal_val`, conditional, so use them
explicitly). -/

/-- `len_add` never fails, and is the exact sum whenever it fits in `usize`. -/
theorem len_add_spec (a b : Usize) :
    ∃ r, len_add a b = ok r ∧ (a.val + b.val ≤ Usize.max → r.val = a.val + b.val) := by
  refine ⟨UScalar.saturating_add a b, rfl, fun h => ?_⟩
  rw [UScalar.saturating_add_val]
  have : UScalar.max .Usize = Usize.max := by scalar_tac
  omega

/-- `len_add` saturates when the sum does not fit. -/
theorem len_add_spec_sat (a b : Usize) (h : Usize.max < a.val + b.val) :
    ∃ r, len_add a b = ok r ∧ r.val = Usize.max := by
  refine ⟨UScalar.saturating_add a b, rfl, ?_⟩
  rw [UScalar.saturating_add_val]
  have : UScalar.max .Usize = Usize.max := by scalar_tac
  omega

/-- `checked_len_add` is the checked sum: `Ok (a + b)` when it fits in `usize`,
    `Err InvalidVectorLength` otherwise. -/
theorem checked_len_add_spec (a b : Usize) :
    (a.val + b.val ≤ Usize.max →
       ∃ r, checked_len_add a b = ok (.Ok r) ∧ r.val = a.val + b.val) ∧
    (Usize.max < a.val + b.val →
       checked_len_add a b = ok (.Err tls_codec.Error.InvalidVectorLength)) := by
  have h := UScalar.overflowing_add_eq a b
  have hm : UScalar.max .Usize = Usize.max := by scalar_tac
  rcases hz : UScalar.overflowing_add a b with ⟨z1, z2⟩
  rw [hz] at h
  simp only [checked_len_add, core.num.Usize.checked_add, core.num.Usize.overflowing_add,
    rust_primitives.arithmetic.overflowing_add_usize, core.option.Option.ok_or, hz]
  by_cases hc : a.val + b.val > UScalar.max .Usize
  · simp only [if_pos hc] at h
    refine ⟨fun hle => by omega, fun _ => ?_⟩
    simp [h.2]
  · simp only [if_neg hc] at h
    refine ⟨fun _ => ⟨z1, by simp [h.2], h.1⟩, fun hlt => by omega⟩

/-- The result of `len_add a b` (`len_add_spec`). -/
noncomputable def lenAddVal (a b : Std.Usize) : Std.Usize := Classical.choose (len_add_spec a b)

/-- The `Ok` payload of `checked_len_add a b` when the sum fits (`checked_len_add_spec`);
    `0` otherwise (then the result is `Err`). -/
noncomputable def checkedLenAddVal (a b : Std.Usize) : Std.Usize :=
  if h : a.val + b.val ≤ Usize.max then Classical.choose ((checked_len_add_spec a b).1 h)
  else 0#usize

/-- The result of `checked_len_add a b`: `Ok` of the sum when it fits, else
    `Err InvalidVectorLength` (`checked_len_add_spec`). -/
noncomputable def checkedLenAddRes (a b : Std.Usize) : core.result.Result Std.Usize Error :=
  if a.val + b.val ≤ Usize.max then .Ok (checkedLenAddVal a b) else .Err .InvalidVectorLength

theorem len_add_ok (a b : Std.Usize) : len_add a b = ok (lenAddVal a b) :=
  (Classical.choose_spec (len_add_spec a b)).1

theorem checked_len_add_ok (a b : Std.Usize) :
    checked_len_add a b = ok (checkedLenAddRes a b) := by
  unfold checkedLenAddRes checkedLenAddVal
  by_cases h : a.val + b.val ≤ Usize.max
  · simp only [h, dite_cond_eq_true, if_true]
    exact (Classical.choose_spec ((checked_len_add_spec a b).1 h)).1
  · simp only [h, if_false]
    exact (checked_len_add_spec a b).2 (by omega)

theorem lenAddVal_val (a b : Std.Usize) (h : a.val + b.val ≤ Usize.max) :
    (lenAddVal a b).val = a.val + b.val :=
  (Classical.choose_spec (len_add_spec a b)).2 h

theorem checkedLenAddVal_val (a b : Std.Usize) (h : a.val + b.val ≤ Usize.max) :
    (checkedLenAddVal a b).val = a.val + b.val := by
  unfold checkedLenAddVal
  simp only [h, dite_cond_eq_true]
  exact (Classical.choose_spec ((checked_len_add_spec a b).1 h)).2

/-- When the sum fits, `checked_len_add` returns `Ok` of it. -/
theorem checkedLenAddRes_fits (a b : Std.Usize) (h : a.val + b.val ≤ Usize.max) :
    checkedLenAddRes a b = .Ok (checkedLenAddVal a b) := by
  simp [checkedLenAddRes, h]

/-- Rewrite `checkedLenAddRes a b` to `.Ok _` everywhere when the sum is provably within `Usize.max`. -/
macro "fits_rw" : tactic => `(tactic| try simp (disch := scalar_tac) only [checkedLenAddRes_fits] at *)

/-- `checked_len_add` returns `Ok r` only for the exact sum. -/
theorem checkedLenAddRes_ok (a b r : Std.Usize) (h : checkedLenAddRes a b = .Ok r) :
    r.val = a.val + b.val ∧ a.val + b.val ≤ Usize.max := by
  unfold checkedLenAddRes at h
  split at h
  · rename_i hf; cases h; exact ⟨checkedLenAddVal_val a b hf, hf⟩
  · cases h

@[spec]
theorem len_add_triple (a b : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ len_add a b ⦃ ⇓ r => ⌜ r = lenAddVal a b ⌝ ⦄ := by
  rw [len_add_ok]; mvcgen

@[spec]
theorem checked_len_add_triple (a b : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ checked_len_add a b ⦃ ⇓ r => ⌜ r = checkedLenAddRes a b ⌝ ⦄ := by
  rw [checked_len_add_ok]; mvcgen

/-- The hand translations (`Assumptions/FunsExternal.lean`) call the verbatim copy. -/
theorem Copied.checked_len_add_eq :
    Copied.checked_len_add = _root_.tls_codec.checked_len_add := rfl

@[spec]
theorem Copied.checked_len_add_triple (a b : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ Copied.checked_len_add a b ⦃ ⇓ r => ⌜ r = checkedLenAddRes a b ⌝ ⦄ := by
  rw [Copied.checked_len_add_eq, checked_len_add_ok]; mvcgen

/-! ### `pre.holds` hypotheses

No helper is needed: `hax_mvcgen [f, <crate defs called by the pre>]` introduces the
`(f.pre …).holds` hypothesis, runs `mvcgen` on it (hax's `hax_mvcgen at`) with the registered
`@[spec]` lemmas, and then runs `mvcgen` on the goal. -/

/-! ### `?` on `Result`

`x?` is extracted as `let cf ← branch x; match cf with | Continue v => … | Break res =>
from_residual T FromInst res`. `branch_tryCF_spec` states the result of `branch` as
`cf = tryCF x`, a plain def instead of a `match` (a `match` in a spec post is an anonymous
matcher, which no rewrite lemma can target). `mvcgen` then leaves, per `?`:
- in the `Continue v` branch, a hypothesis `Continue v = tryCF x`; `continue_eq_tryCF`
  turns it into `x = .Ok v` when a proof needs the callee's result (`simp only
  [continue_eq_tryCF] at *`);
- in the `Break res` branch, the hypothesis of the (global) `from_residual_spec`, as the VC
  `Break res = tryCF x → ∃ e, res = .Err e ∧ ⦃⌜True⌝⦄ FromInst.from e ⦃…⦄`, which `try_vcs`
  closes. -/

/-- The control flow of `x?`. -/
def tryCF {T E : Type} : core.result.Result T E →
    core.ops.control_flow.ControlFlow (core.result.Result core.convert.Infallible E) T
  | .Ok v => .Continue v
  | .Err e => .Break (.Err e)

/-- `branch`, with the result as `tryCF x`. `high`: wins over MissingSpecs' `branch_spec`. -/
@[spec high] theorem branch_tryCF_spec {T E : Type} (x : core.result.Result T E) :
    ⦃ ⌜ True ⌝ ⦄ core.result.Result.Insts.CoreOpsTry_traitTryTResultInfallibleE.branch x
    ⦃ ⇓ r => ⌜ r = tryCF x ⌝ ⦄ := by
  mvcgen [CoreModels.core.result.Result.Insts.CoreOpsTry_traitTryTResultInfallibleE.branch_spec]

theorem continue_eq_tryCF {T E : Type} {x : core.result.Result T E} {v : T} :
    (.Continue v = tryCF x) ↔ x = .Ok v := by
  cases x <;> simp [tryCF, eq_comm]

/-- The `Break` VC of `x?`: the residual is `Err e`, with `x = Err e`. -/
theorem try_break_vc {T E : Type} {x : core.result.Result T E}
    {res : core.result.Result core.convert.Infallible E} {P : E → Prop}
    (h : ∀ e, x = .Err e → P e) :
    .Break res = tryCF x → ∃ e, res = .Err e ∧ P e := by
  cases x <;> simp_all [tryCF]

/-- Close the `Break` VCs of `?` (see above). Other goals are left untouched: `apply
try_break_vc` fails at once on them. The optional list goes to the `mvcgen` that proves
the `From` triple: crate `From` impls to unfold, e.g.
`try_vcs [Error.Insts.CoreConvertFromTryFromIntError.from]`. The identity `From` needs nothing
(`From.Blanket.from_spec` is global). -/
syntax "try_vcs" (" [" Lean.Parser.Tactic.simpLemma,* "]")? : tactic
macro_rules
  | `(tactic| try_vcs) => `(tactic| try_vcs [])
  | `(tactic| try_vcs [$ts,*]) =>
    `(tactic| all_goals (first | (apply try_break_vc; intros; mvcgen [$ts,*]) | skip))

/-- Close the `Err` (`?` break) branches of a round-trip proof: the trait-level post of
`spec.X.post arg res` holds vacuously on `Err`. Other goals are left untouched. -/
syntax "close_err_branches " ident term:max : tactic
macro_rules
  | `(tactic| close_err_branches $post:ident $arg:term) =>
    `(tactic| all_goals (apply try_break_vc
                         intros
                         mvcgen
                         intro _
                         show (do let a ← ($post $arg (core.result.Result.Err _)); pure (a = true)).holds
                         simp only [$post:ident]
                         mvcgen
                         rename_i hne
                         intro h
                         exact absurd h hne))

/-- Close the `Err` (`?` break) branches of a round-trip proof whose post demands `Ok`
(`is_ok_and`): the hypotheses of such a branch contradict it (e.g. a total content spec
`∃ v, r = Ok v ∧ …` against `r = Err e`). Goals not closed this way are left untouched. -/
macro "close_err_absurd" : tactic =>
  `(tactic| all_goals (first | (apply try_break_vc; intro _ _; exfalso; simp_all; done) | skip))

/-! ### Scalar casts -/

/-- `usize as u64` is lossless (`usize` is at most 64 bits wide). -/
@[simp, scalar_tac_simps] theorem Usize.cast_U64_val_eq (x : Std.Usize) :
    (UScalar.cast .U64 x).val = x.val := by
  have := x.hBounds
  rcases System.Platform.numBits_eq with h | h <;> simp_all [UScalar.cast_val_eq] <;> omega

/-- Small numbers are not reduced modulo `Usize.size` (which is `2^32` or `2^64`). -/
@[simp, scalar_tac_simps] theorem Usize.mod_size_of_lt (n : Nat) (h : n < 2 ^ 32) :
    n % Usize.size = n := by
  apply Nat.mod_eq_of_lt
  rw [Usize.size_scalarTac_eq.2]
  rcases System.Platform.numBits_eq with h' | h' <;> rw [h'] <;> omega

/-- `isize::MAX as usize` is half of `usize::MAX` (rounded down): stated linearly for `omega`. -/
theorem Usize.hcast_Isize_MAX_val :
    (IScalar.hcast UScalarTy.Usize core.num.Isize.MAX).val * 2 + 1 = UScalar.max UScalarTy.Usize := by
  rw [IScalar.hcast_val_eq]
  have hM : (core.num.Isize.MAX).val = Isize.max := by simp [core.num.Isize.MAX]
  rw [hM]
  rcases System.Platform.numBits_eq with h | h <;>
    simp [Isize.max, UScalar.max, UScalarTy.numBits, Isize.numBits, IScalarTy.numBits, h]

/-! ### Indexing with a `usize`

`v[i]` goes through the generic `Index` specs of MissingSpecs, whose hypothesis is stated on
`get` (`∃ r, o = some r ∧ …`) and is not closed by `scalar_tac`. These direct specs have the
bound as their only hypothesis, so the VC is `i < len`. `high`: they must win over the generic ones. -/

/-- `v[i]` on a `Vec`, `i : usize` in bounds. -/
@[spec high] theorem alloc.vec.Vec.index_usize_spec {T : Type} (v : alloc.vec.Vec T) (i : Std.Usize)
    (h : i.val < v.val.length) :
    ⦃ ⌜ True ⌝ ⦄
    alloc.vec.Vec.Insts.CoreOpsIndexIndex.index (core.Usize.Insts.CoreSliceIndexSliceIndexSliceT T) v i
    ⦃ ⇓ r => ⌜ r = v.val[i.val] ⌝ ⦄ := by
  apply CoreModels.alloc.vec.Vec.Insts.CoreOpsIndexIndex.index_spec
  mvcgen
  simp_all [PostCond.ok]

/-! ### Specs of small shared functions -/

/-- `bytes_len` returns a length in `1..=8`, determined by the value (so two calls on the same
value agree). -/
@[spec] theorem varint.TlsVarInt.bytes_len_spec (self : varint.TlsVarInt) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.bytes_len self
    ⦃ ⇓ r => ⌜ 1 ≤ r.val ∧ r.val ≤ 8 ∧
               (self.val ≤ 63 → r.val = 1) ∧
               (63 < self.val → self.val ≤ 16383 → r.val = 2) ∧
               (16383 < self.val → self.val ≤ 1073741823 → r.val = 4) ∧
               (1073741823 < self.val → r.val = 8) ⌝ ⦄ := by
  mvcgen [varint.TlsVarInt.bytes_len] <;> scalar_tac

/-- `MAX_MLS_LEN` is `2^30 - 1`. -/
@[spec] theorem quic_vec.MAX_MLS_LEN_spec :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.MAX_MLS_LEN ⦃ ⇓ r => ⌜ r.val = 2 ^ 30 - 1 ⌝ ⦄ := by
  mvcgen [quic_vec.MAX_MLS_LEN] <;> scalar_tac

/-- `TlsVarInt::MAX` is `2^62 - 1`. -/
@[spec] theorem varint.TlsVarInt.MAX_spec :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.MAX ⦃ ⇓ r => ⌜ r.val = 2 ^ 62 - 1 ⌝ ⦄ := by
  mvcgen [varint.TlsVarInt.MAX] <;> scalar_tac

/-- `try_new` does not panic; it succeeds, returning its argument, iff the argument is at most `MAX`. -/
@[spec] theorem varint.TlsVarInt.try_new_spec (value : Std.U64) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.try_new value
    ⦃ ⇓ r => ⌜ match r with
                | .Ok v => v = value ∧ value.val ≤ 2 ^ 62 - 1
                | .Err e => e = Error.InvalidVectorLength ∧ 2 ^ 62 - 1 < value.val ⌝ ⦄ := by
  mvcgen [varint.TlsVarInt.try_new]
  all_goals exact ⟨trivial, by scalar_tac⟩

/-- `ContentLength::from_usize` does not panic; it succeeds, returning the value, iff the value is
below `2^30`. -/
@[spec] theorem quic_vec.ContentLength.from_usize_spec (value : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.ContentLength.from_usize value
    ⦃ ⇓ r => ⌜ match r with
                | .Ok c => c.val = value.val ∧ value.val ≤ 2 ^ 30 - 1
                | .Err _ => 2 ^ 30 - 1 < value.val ⌝ ⦄ := by
  mvcgen [quic_vec.ContentLength.from_usize, quic_vec.ContentLength.new,
    quic_vec.ContentLength.MAX, quic_vec.MAX_MLS_LEN_spec, varint.TlsVarInt.value,
    varint.TlsVarInt.MAX_spec]
  try_vcs [Error.Insts.CoreConvertFromTryFromIntError.from]
  · -- `new` fails: the value is above `MAX_MLS_LEN`
    rename_i _ h5 _ _ _ h4 r2 _ _ _ _ h2 _ _ _
    rw [continue_eq_tryCF] at h4 h2
    subst h5 h2
    simp only [core.result.Result.Ok.injEq] at h4
    subst h4
    scalar_tac
  · -- the `Ok` path: `value` went through `try_from` and `try_new` unchanged
    rename_i _ h5 _ _ _ h4 r2 h3 _ _ _ h2 _ _ _
    rw [continue_eq_tryCF] at h4 h2
    subst h5 h2
    simp only [core.result.Result.Ok.injEq] at h4
    subst h4
    obtain ⟨hv, _⟩ := h3
    subst hv
    scalar_tac
  · -- `try_new` fails: the value is above `2^62 - 1`
    rename_i _ h5 _ _ _ h4 _ h3 _ _ _ _ a _
    rw [continue_eq_tryCF] at h4
    subst h5 a
    simp only [core.result.Result.Ok.injEq] at h4
    subst h4
    obtain ⟨_, hb⟩ := h3
    intro _
    simp only [PostCond.ok]
    show 2 ^ 30 - 1 < value.val
    scalar_tac
  · -- `try_from` does not fail
    rename_i _ h _ _ _ _ a
    subst h
    cases a

/-- `to_vec` on a `u8` slice does not panic and returns a copy (`u8::clone` is the identity). -/
@[spec] theorem alloc.slice.Slice.to_vec_U8_spec (s : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ alloc.slice.Slice.to_vec core.U8.Insts.CoreCloneClone s
    ⦃ ⇓ r => ⌜ (r : Slice Std.U8) = s ⌝ ⦄ :=
  CoreModels.alloc.slice.Slice.to_vec_spec _ s CoreModels.core.U8.Insts.CoreCloneClone.clone_spec

/-- Number of bytes of the varint encoding of `v`. -/
def varint.lenOf (v : Nat) : Nat :=
  if v ≤ 63 then 1 else if v ≤ 16383 then 2 else if v ≤ 1073741823 then 4 else 8

/-- The 2-bit length prefix (in the top bits of the first byte) of a varint of `L` bytes. -/
def varint.pfx (L : Nat) : Nat := if L = 1 then 0 else if L = 2 then 64 else if L = 4 then 128 else 192

/-- The facts of `bytes_len_spec` determine the length: `lenOf`, one of `1, 2, 4, 8`. -/
theorem varint.lenOf_char (self : Std.U64) (r : Std.Usize)
    (h : 1 ≤ r.val ∧ r.val ≤ 8 ∧ (self.val ≤ 63 → r.val = 1) ∧
      (63 < self.val → self.val ≤ 16383 → r.val = 2) ∧
      (16383 < self.val → self.val ≤ 1073741823 → r.val = 4) ∧
      (1073741823 < self.val → r.val = 8)) :
    r.val = varint.lenOf self.val ∧ (r.val = 1 ∨ r.val = 2 ∨ r.val = 4 ∨ r.val = 8) := by
  unfold varint.lenOf
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := h
  split_ifs <;> omega

/-- The closure of `quic_vec::tls_serialize_bytes_len` returns a length in `1..=8`, namely `lenOf`. -/
@[spec] theorem quic_vec.tls_serialize_bytes_len.closure_call_once_spec
    (c : quic_vec.tls_serialize_bytes_len.closure) (a : quic_vec.ContentLength) :
    ⦃ ⌜ True ⌝ ⦄
    quic_vec.tls_serialize_bytes_len.closure.Insts.CoreOpsFunctionFnOnceTupleContentLengthUsize.call_once c a
    ⦃ ⇓ r => ⌜ 1 ≤ r.val ∧ r.val ≤ 8 ∧ r.val = varint.lenOf a.val ⌝ ⦄ := by
  mvcgen [quic_vec.tls_serialize_bytes_len.closure.Insts.CoreOpsFunctionFnOnceTupleContentLengthUsize.call_once]
  intro h1 h2 h3 h4 h5 h6
  exact ⟨h1, h2, (varint.lenOf_char _ _ ⟨h1, h2, h3, h4, h5, h6⟩).1⟩

/-- `Result::map` with the closure of `quic_vec::tls_serialize_bytes_len` and a plain
(non-schematic) post: an `Ok` input is mapped to an `Ok` length in `1..=8`, an `Err` is passed
through. (Specialised: a generic `P` is not inferred by `mvcgen`.) -/
@[spec] theorem quic_vec.tls_serialize_bytes_len.closure_map_spec
    (x : core.result.Result quic_vec.ContentLength Error) :
    ⦃ ⌜ True ⌝ ⦄
    core.result.Result.map
      quic_vec.tls_serialize_bytes_len.closure.Insts.CoreOpsFunctionFnOnceTupleContentLengthUsize x ()
    ⦃ ⇓ r => ⌜ (∀ t, x = .Ok t → ∃ u, r = .Ok u ∧ 1 ≤ u.val ∧ u.val ≤ 8 ∧ u.val = varint.lenOf t.val) ∧
               (∀ e, x = .Err e → r = .Err e) ⌝ ⦄ := by
  apply CoreModels.core.result.Result.map_spec
  · intro t ht; mvcgen [quic_vec.tls_serialize_bytes_len.closure_call_once_spec]
    intro h1 h2 h3
    subst ht
    refine ⟨fun t' h => ?_, fun e h => ?_⟩
    · obtain rfl := core.result.Result.Ok.inj h
      exact ⟨_, rfl, h1, h2, h3⟩
    · cases h
  · intro e he; subst he; simp [PostCond.ok]

/-- The error-mapping closure of `[u8; LEN]::tls_deserialize_bytes` does not panic. -/
@[spec] theorem arrays.DeserializeBytesArrayU8LEN.tls_deserialize_bytes.closure_call_once_spec
    {LEN : Std.Usize} (c : arrays.DeserializeBytesArrayU8LEN.tls_deserialize_bytes.closure LEN)
    (e : core.array.TryFromSliceError) :
    ⦃ ⌜ True ⌝ ⦄
    arrays.DeserializeBytesArrayU8LEN.tls_deserialize_bytes.closure.Insts.CoreOpsFunctionFnOnceTupleTryFromSliceErrorError.call_once
      c e
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  mvcgen [arrays.DeserializeBytesArrayU8LEN.tls_deserialize_bytes.closure.Insts.CoreOpsFunctionFnOnceTupleTryFromSliceErrorError.call_once]

/-- `[u8; LEN]::tls_deserialize_bytes` does not panic; on success it consumes exactly `LEN` bytes. -/
@[spec] theorem ArrayU8LEN.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_spec
    (LEN : Std.Usize) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ ArrayU8LEN.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes LEN bytes
    ⦃ ⇓ r => ⌜ ∀ v rem, r = .Ok (v, rem) → rem.val.length + LEN.val = bytes.val.length ⌝ ⦄ := by
  mvcgen [ArrayU8LEN.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes,
    core.option.Option.ok_or_spec, core.result.Result.map_err_spec]
  try_vcs
  · simp only [continue_eq_tryCF] at *
    have hle : LEN.val ≤ bytes.val.length := by grind [tryCF]
    intro h _
    obtain ⟨t, ht, hlen⟩ := h hle
    refine ⟨t, ht, ?_⟩
    mvcgen
    intro _ _ h
    simp only [core.result.Result.Ok.injEq, Prod.mk.injEq] at h
    have hl := congrArg List.length hlen
    simp only [List.length_drop] at hl
    scalar_tac
  · simp only [PostCond.ok]
    mvcgen
    try_vcs
    intros
    simp [PostCond.ok]
  · simp [PostCond.ok]


/-! ### `len` of the vector wrappers -/

/-- `TlsVecU8::len` is the length of the inner vector. -/
@[spec] theorem tls_vec.TlsVecU8.len_spec {T : Type} (self : tls_vec.TlsVecU8 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU8.len self ⦃ ⇓ r => ⌜ r.val = self.vec.val.length ⌝ ⦄ := by
  mvcgen [tls_vec.TlsVecU8.len]
  intro h; subst h; simp [Slice.len]

@[spec] theorem tls_vec.TlsByteVecU8.len_spec (self : tls_vec.TlsByteVecU8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU8.len self ⦃ ⇓ r => ⌜ r.val = self.vec.val.length ⌝ ⦄ := by
  mvcgen [tls_vec.TlsByteVecU8.len]
  intro h; subst h; simp [Slice.len]

@[spec] theorem tls_vec.SecretTlsVecU8.len_spec {T : Type} (zeroizeZeroizeInst : zeroize.Zeroize T)
    (self : tls_vec.SecretTlsVecU8 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU8.len zeroizeZeroizeInst self ⦃ ⇓ r => ⌜ r.val = self.vec.val.length ⌝ ⦄ := by
  mvcgen [tls_vec.SecretTlsVecU8.len]
  intro h; subst h; simp [Slice.len]

/-- `TlsVecU16::len` is the length of the inner vector. -/
@[spec] theorem tls_vec.TlsVecU16.len_spec {T : Type} (self : tls_vec.TlsVecU16 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU16.len self ⦃ ⇓ r => ⌜ r.val = self.vec.val.length ⌝ ⦄ := by
  mvcgen [tls_vec.TlsVecU16.len]
  intro h; subst h; simp [Slice.len]

@[spec] theorem tls_vec.TlsByteVecU16.len_spec (self : tls_vec.TlsByteVecU16) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU16.len self ⦃ ⇓ r => ⌜ r.val = self.vec.val.length ⌝ ⦄ := by
  mvcgen [tls_vec.TlsByteVecU16.len]
  intro h; subst h; simp [Slice.len]

@[spec] theorem tls_vec.SecretTlsVecU16.len_spec {T : Type} (zeroizeZeroizeInst : zeroize.Zeroize T)
    (self : tls_vec.SecretTlsVecU16 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU16.len zeroizeZeroizeInst self ⦃ ⇓ r => ⌜ r.val = self.vec.val.length ⌝ ⦄ := by
  mvcgen [tls_vec.SecretTlsVecU16.len]
  intro h; subst h; simp [Slice.len]

/-- `TlsVecU24::len` is the length of the inner vector. -/
@[spec] theorem tls_vec.TlsVecU24.len_spec {T : Type} (self : tls_vec.TlsVecU24 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU24.len self ⦃ ⇓ r => ⌜ r.val = self.vec.val.length ⌝ ⦄ := by
  mvcgen [tls_vec.TlsVecU24.len]
  intro h; subst h; simp [Slice.len]

@[spec] theorem tls_vec.TlsByteVecU24.len_spec (self : tls_vec.TlsByteVecU24) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU24.len self ⦃ ⇓ r => ⌜ r.val = self.vec.val.length ⌝ ⦄ := by
  mvcgen [tls_vec.TlsByteVecU24.len]
  intro h; subst h; simp [Slice.len]

@[spec] theorem tls_vec.SecretTlsVecU24.len_spec {T : Type} (zeroizeZeroizeInst : zeroize.Zeroize T)
    (self : tls_vec.SecretTlsVecU24 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU24.len zeroizeZeroizeInst self ⦃ ⇓ r => ⌜ r.val = self.vec.val.length ⌝ ⦄ := by
  mvcgen [tls_vec.SecretTlsVecU24.len]
  intro h; subst h; simp [Slice.len]

/-- `TlsVecU32::len` is the length of the inner vector. -/
@[spec] theorem tls_vec.TlsVecU32.len_spec {T : Type} (self : tls_vec.TlsVecU32 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU32.len self ⦃ ⇓ r => ⌜ r.val = self.vec.val.length ⌝ ⦄ := by
  mvcgen [tls_vec.TlsVecU32.len]
  intro h; subst h; simp [Slice.len]

@[spec] theorem tls_vec.TlsByteVecU32.len_spec (self : tls_vec.TlsByteVecU32) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU32.len self ⦃ ⇓ r => ⌜ r.val = self.vec.val.length ⌝ ⦄ := by
  mvcgen [tls_vec.TlsByteVecU32.len]
  intro h; subst h; simp [Slice.len]

@[spec] theorem tls_vec.SecretTlsVecU32.len_spec {T : Type} (zeroizeZeroizeInst : zeroize.Zeroize T)
    (self : tls_vec.SecretTlsVecU32 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU32.len zeroizeZeroizeInst self ⦃ ⇓ r => ⌜ r.val = self.vec.val.length ⌝ ⦄ := by
  mvcgen [tls_vec.SecretTlsVecU32.len]
  intro h; subst h; simp [Slice.len]

/-! ### `Vec::pop` length arithmetic -/

/-- Length arithmetic of the `pop` postconditions: `pop` removes the last element (if any), so the
new length is the old length minus `1` when an element was returned, and equal otherwise. -/
theorem pop_len_eq {α : Type} (l l' : List α) (o : Option α) (n m : Std.Usize)
    (r : UScalar UScalarTy.Usize)
    (ho : o = l.getLast?) (hl' : l' = l.dropLast) (hn : n.val = l.length) (hm : m.val = l'.length)
    (hr : r.val = n.val - (if o.isSome = true then 1#usize else 0#usize).val) : m = r := by
  subst ho hl'
  apply UScalar.eq_of_val_eq
  rcases l with _ | ⟨x, xs⟩
  · simp at hn hm hr ⊢
    omega
  · have hs : (List.getLast? (x :: xs)).isSome = true := by simp
    simp only [hs, if_true] at hr
    simp at hm hn hr
    omega

/-- `pop` returns an element iff the vector is non-empty. -/
theorem pop_isSome_eq {α : Type} (l : List α) (n : Std.Usize) (hn : n.val = l.length) :
    ((l.getLast?).isSome = true) = ¬ (decide (n = 0#usize) = true) := by
  rcases l with _ | ⟨x, xs⟩
  · have h0 : n = 0#usize := UScalar.eq_of_val_eq (by simpa using hn)
    simp [h0]
  · have h0 : n ≠ 0#usize := by
      intro h; subst h; simp at hn
    simp [h0]

/-- The amount `pop` subtracts from the length is at most the length. -/
theorem pop_sub_le {α : Type} (l : List α) (o : Option α) (n : Std.Usize)
    (ho : o = l.getLast?) (hn : n.val = l.length) :
    (if o.isSome = true then 1#usize else 0#usize).val ≤ n.val := by
  subst ho
  rcases l with _ | ⟨x, xs⟩
  · simp
  · have hs : (List.getLast? (x :: xs)).isSome = true := by simp
    simp only [hs, if_true]
    simp at hn ⊢
    omega

/-! ### FC closers -/

/-- Close the arithmetic VCs left by `mvcgen` on a post made of `len` calls: `decide`s become
props, `Slice.len` is unfolded, and `scalar_tac` finishes (also the `h_fail` panics, whose
hypotheses are contradictory). -/
syntax "fc_arith" : tactic
macro_rules
  | `(tactic| fc_arith) =>
    `(tactic| (all_goals (try simp only [decide_eq_true_eq, Slice.len] at *); all_goals scalar_tac))

/-! ### Partial triples with a trivial post -/

/-- A partial (`⇓?`) triple whose post is the constant `ok true` holds for any program: only
`ok` outcomes matter and the post cannot panic. -/
theorem partial_triple_ok_true {α : Type} (x : RustM α) (p : α → RustM Bool)
    (hp : ∀ a, p a = ok true) :
    ⦃ ⌜ True ⌝ ⦄ x ⦃ ⇓? a => ⌜ (p a).holds ⌝ ⦄ := by
  simp only [hp]
  cases x <;> simp [Std.Do.Triple, Std.Do.PostCond.mayThrow, RustM.holds]
    <;> simp [Std.Do.wp, Std.Do.PredTrans.apply]

/-- A partial (`⇓?`) triple from a statement about the `ok` outcomes only. -/
theorem partial_triple_of_ok {α : Type} {x : RustM α} {P : α → Prop}
    (h : ∀ r, x = ok r → P r) :
    ⦃ ⌜ True ⌝ ⦄ x ⦃ ⇓? r => ⌜ P r ⌝ ⦄ := by
  cases hx : x with
  | ok r =>
    have := h r hx
    simp [Std.Do.Triple, Std.Do.PostCond.mayThrow]
    simp [Std.Do.wp, Std.Do.PredTrans.apply, this]
  | fail e => simp [Std.Do.Triple, Std.Do.PostCond.mayThrow]; simp [Std.Do.wp, Std.Do.PredTrans.apply]
  | div => simp [Std.Do.Triple, Std.Do.PostCond.mayThrow]; simp [Std.Do.wp, Std.Do.PredTrans.apply]

/-- Converse: a partial (`⇓?`) triple gives its post on every `ok` outcome. -/
theorem ok_of_partial_triple {α : Type} {x : RustM α} {P : α → Prop} {r : α}
    (h : ⦃ ⌜ True ⌝ ⦄ x ⦃ ⇓? r => ⌜ P r ⌝ ⦄) (hr : x = ok r) : P r := by
  subst hr
  simpa [Std.Do.Triple, Std.Do.PostCond.mayThrow, Std.Do.wp, Std.Do.PredTrans.apply] using h

/-- A total triple with post `True` gives an `ok` value. -/
theorem triple_true_ok {α : Type} {m : RustM α}
    (h : ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓ _ => ⌜ True ⌝ ⦄) : ∃ v, m = .ok v := by
  cases m <;> simp [Triple, WP.wp, PredTrans.apply] at h ⊢


/-- A total triple from panic freedom and a partial triple. -/
theorem total_of_pf_partial {α : Type} {m : RustM α} {P : α → Prop}
    (hpf : ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓ _ => ⌜ True ⌝ ⦄) (h : ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓? r => ⌜ P r ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓ r => ⌜ P r ⌝ ⦄ := by
  obtain ⟨v, hv⟩ := triple_true_ok hpf
  have hP := ok_of_partial_triple h hv
  rw [hv]
  apply RustM.ok_spec
  exact hP

/-- Conjunction of the posts of two total triples. -/
theorem triple_and {α : Type} {m : RustM α} {P Q : α → Prop}
    (hP : ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓ r => ⌜ P r ⌝ ⦄) (hQ : ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓ r => ⌜ Q r ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓ r => ⌜ P r ∧ Q r ⌝ ⦄ := by
  obtain ⟨v, hv, hp⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp hP
  obtain ⟨w, hw, hq⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp hQ
  rw [hv] at hw
  cases hw
  rw [hv]
  apply RustM.ok_spec
  exact ⟨hp, hq⟩

/-- Weakening the post of a total triple. -/
theorem triple_post_mono {α : Type} {m : RustM α} {P Q : α → Prop}
    (h : ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓ r => ⌜ P r ⌝ ⦄) (hPQ : ∀ r, P r → Q r) :
    ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓ r => ⌜ Q r ⌝ ⦄ := by
  obtain ⟨v, hv, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp h
  rw [hv]
  apply RustM.ok_spec
  exact hPQ v hP


/-- A total triple is a partial one. -/
theorem partial_of_total {α : Type} {m : RustM α} {P : α → Prop}
    (h : ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓ r => ⌜ P r ⌝ ⦄) : ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓? r => ⌜ P r ⌝ ⦄ := by
  obtain ⟨v, hv, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp h
  exact partial_triple_of_ok fun r hr => by rw [hv] at hr; cases hr; exact hP

/-- A total triple gives panic freedom. -/
theorem pf_of_total {α : Type} {m : RustM α} {P : α → Prop}
    (h : ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓ r => ⌜ P r ⌝ ⦄) : ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  obtain ⟨v, hv, _⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp h
  rw [hv]
  apply RustM.ok_spec
  trivial

end tls_codec
