/- Missing core model specs, to upstream (hax `CoreModels`) once proved.
(Crate-independent. Only proofs need it:
imported by `Verification/Helpers/Base.lean`, not by the generated files.)

Hand-written (step 4, proof setup). Three kinds of entries:

1. Specs of the `format!` machinery. No axiom here: the one ASSUMED `fmt` spec
   (`FromUtf8Error`'s `Display`) lives in `Assumptions/FmtAssumptions.lean`.
2. Spec theorems for functions with a real definition (CoreModels, or a hand-filled
   def in `Assumptions/FunsExternal.lean`) that the *ready* obligations reach and that
   have no `@[spec]` lemma in hax / Aeneas. Each statement mirrors the model
   definition. Proved ones are `@[spec]`; `sorry`-ed ones are NOT (opt-in only, see
   below). None is `sorry`-ed.
3. A comment block listing the other signature-only `Assumptions/` axioms. They get
   no semantics here (deferred to steps 5–6).

How the list was obtained: `scripts/missing_specs.lean.in` (see NOTES.md) walks the
call graph of every `….spec` in `Extraction/Specs.lean` through the `Extraction`
modules, collects the external constants returning `RustM _`, and checks each
against the `@[spec]` triples and the `mvcgen` unfold set of the environment.
Instance records passed to generic functions were listed separately, and the
methods of those instances that have no spec are included too (section 2c).

Rule: proved ⇒ `@[spec]`, sorried ⇒ no attribute. The ASSUMED fmt axiom
(`FmtAssumptions.lean`) and every *proved* section-2 theorem are global `@[spec]`, so `mvcgen` uses
them without being told. The sorried theorems of section 2 carry no attribute, so
`mvcgen` does not see them unless a proof names them, and `#print axioms` /
`lean_verify` shows `sorryAx` only for proofs that actually use one:

    -- pass it to mvcgen for one call:
    mvcgen [f, CoreModels.core.option.Option.is_some_spec]
    -- or register it for one declaration:
    attribute [local spec] CoreModels.core.option.Option.is_some_spec in
    theorem X.spec.panic_freedom … := by mvcgen [f]; …

When a section-2 theorem is proved, add `@[spec]` to it (after checking with
`lean_verify` that it has no `sorryAx`); never tag a sorried one. Exceptions, proved but
untagged: `Result.map_spec` and `Slice.to_vec_spec` (schematic post or extra hypothesis;
and `Box.as_ref_spec`, left untagged so existing `mvcgen` calls are unchanged;
specialised `@[spec]` versions live in `Helpers.lean`). Also proved but untagged: the generic
`eq` specs that take `[DecidableEq T]` (`Option`, `Result`, `Slice`, `Pair`: tagging them made
`mvcgen` stall on `DecidableEq Error` in existing FC proofs), `U8.eq_decide_spec` (the form their
`heq` hypothesis takes; the existing proofs unfold the instance) and `next_Usize_some`-style
helpers. The exact `get`/`try_from` specs are `@[spec high]`: the weaker panic-freedom-sized
specs (declared first, same function) stay `@[spec]` for the existing PF/Helpers proofs, and
`high` makes `mvcgen` pick the exact one. `from_residual_spec` is tagged: its
hypothesis becomes the `Break` VC of `?`, closed by `try_vcs` (Helpers.lean).

Generic specs (section 2b) take the post as a schematic `Q : PostCond _ RustM.postShape`
(the pattern of hax's `RustM.ok_spec`), so that `mvcgen` leaves the callee's triple
as a verification condition. Beware: hax's `Hax.RustMPS` abbreviation is *not*
usable for this (it is `.except Error …`, while the instance is `.except (ULift Error) …`;
the elaborator accepts it but the kernel rejects the declaration).
-/
import Aeneas
import Hax
import TlsCodec.Assumptions.MissingCoreModels
import TlsCodec.Assumptions.FmtAssumptions
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do

set_option mvcgen.warning false
set_option linter.unusedVariables false

/-! ## 1. `format!`: proved, from one ASSUMED `Display` axiom (`FmtAssumptions.lean`)

`alloc.fmt.format` and `core.fmt.rt.Argument.new_display` are models
(`MissingCoreModels.lean`): `format` always succeeds, and `new_display` runs the argument's
`Display::fmt` and panics on `Err`, as `format!` does. So `format!` does not panic exactly
when the `fmt` of each argument returns `Ok`. For the arguments the crate formats:
- `usize`, `u8`: CoreModels bodies, which return `Ok` (proved below);
- `FromUtf8Error`: its `fmt` is a signature-only axiom (`MissingCoreModels.lean`), so that
  it returns `Ok` is ASSUMED (`FromUtf8Error.Insts.CoreFmtDisplay.fmt.ok_spec`,
  `FmtAssumptions.lean`);
- `io::Error` (`Debug`, via `new_debug`): no spec; its `fmt` may fail (`io::Error::Custom`),
  see `FmtAssumptions.lean`.
A `Display` instance whose `fmt` can fail gets no `@[spec]`, so a `format!` of it blocks the
panic-freedom proof instead of being assumed away. -/

namespace CoreModels

@[spec]
theorem alloc.fmt.format.no_fail_spec (args : core.fmt.Arguments) :
    ⦃ ⌜ True ⌝ ⦄ alloc.fmt.format args ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  unfold alloc.fmt.format; mvcgen

/-- `new_display` succeeds when the instance's `fmt` returns `Ok`. Untagged: the tagged
    per-instance versions below discharge the hypothesis. -/
theorem core.fmt.rt.Argument.new_display_spec
    {T : Type} (DisplayInst : core.fmt.Display T) (x : T)
    (h : ⦃ ⌜ True ⌝ ⦄ DisplayInst.fmt x () ⦃ ⇓ p => ⌜ p.1 = .Ok () ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ core.fmt.rt.Argument.new_display DisplayInst x ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  unfold core.fmt.rt.Argument.new_display
  mvcgen [h]
  simp_all

@[spec]
theorem core.fmt.rt.Argument.new_display_usize_spec (x : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ core.fmt.rt.Argument.new_display core.Usize.Insts.CoreFmtDisplay x
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  apply core.fmt.rt.Argument.new_display_spec
  unfold core.Usize.Insts.CoreFmtDisplay core.Usize.Insts.CoreFmtDisplay.fmt; mvcgen

@[spec]
theorem core.fmt.rt.Argument.new_display_u8_spec (x : Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ core.fmt.rt.Argument.new_display core.U8.Insts.CoreFmtDisplay x
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  apply core.fmt.rt.Argument.new_display_spec
  unfold core.U8.Insts.CoreFmtDisplay core.U8.Insts.CoreFmtDisplay.fmt; mvcgen

@[spec]
theorem core.fmt.rt.Argument.new_display_fromUtf8Error_spec (x : alloc.string.FromUtf8Error) :
    ⦃ ⌜ True ⌝ ⦄
    core.fmt.rt.Argument.new_display alloc.string.FromUtf8Error.Insts.CoreFmtDisplay x
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  core.fmt.rt.Argument.new_display_spec _ x
    (alloc.string.FromUtf8Error.Insts.CoreFmtDisplay.fmt.ok_spec x ())

/-! ## 2a. Missing specs: concrete functions (sorried, to be proved) -/

/-! ### `alloc::vec::Vec` -/

@[spec]
theorem alloc.vec.Vec.len_spec {T : Type} (v : alloc.vec.Vec T) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.len v ⦃ ⇓ r => ⌜ r = Aeneas.Std.Slice.len v ⌝ ⦄ := by
  mvcgen [alloc.vec.Vec.len]

@[spec]
theorem alloc.vec.Vec.is_empty_spec {T : Type} (v : alloc.vec.Vec T) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.is_empty v
    ⦃ ⇓ r => ⌜ r = decide (Aeneas.Std.Slice.len v = 0#usize) ⌝ ⦄ := by
  unfold alloc.vec.Vec.is_empty; mvcgen [rust_primitives.sequence.seq_len]

@[spec]
theorem alloc.vec.Vec.new_spec (T : Type) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.new T ⦃ ⇓ r => ⌜ (r : Slice T) = Aeneas.Std.Slice.new T ⌝ ⦄ := by
  unfold alloc.vec.Vec.new; mvcgen [rust_primitives.sequence.seq_empty]

@[spec]
theorem alloc.vec.Vec.push_spec {T : Type} (v : alloc.vec.Vec T) (x : T)
    (h : (v : Slice T).val.length < Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.push v x
    ⦃ ⇓ r => ⌜ (r : Slice T).val = (v : Slice T).val ++ [x] ⌝ ⦄ := by
  unfold alloc.vec.Vec.push rust_primitives.sequence.seq_push
  have : (v.val ++ [x]).length ≤ Usize.max := by simp; omega
  mvcgen [this]

@[spec]
theorem alloc.vec.Vec.pop_spec {T : Type} (v : alloc.vec.Vec T) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.pop v
    ⦃ ⇓ r => ⌜ r.1 = (v : Slice T).val.getLast? ∧
               (r.2 : Slice T).val = (v : Slice T).val.dropLast ⌝ ⦄ := by
  unfold alloc.vec.Vec.pop
  mvcgen
  · rename_i hpos r hr h1 hlt
    have hlen : (Slice.len v).val = v.val.length := by simp
    have hpos' : 0 < v.val.length := by scalar_tac
    have hr' : r.val = v.val.length - 1 := by scalar_tac
    refine ⟨?_, ?_⟩
    · simp [List.getLast?_eq_getElem?, hr']
    · rw [List.dropLast_eq_take, hr']
      simp
      omega
  · scalar_tac
  · scalar_tac
  · rename_i hpos
    have hlen : (Slice.len v).val = v.val.length := by simp
    have : v.val = [] := by
      rw [← List.length_eq_zero_iff]; scalar_tac
    simp [this]

@[spec]
theorem alloc.vec.Vec.remove_spec {T : Type} (v : alloc.vec.Vec T) (i : Std.Usize)
    (h : i.val < (v : Slice T).val.length) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.remove v i
    ⦃ ⇓ r => ⌜ r.1 = (v : Slice T).val[i.val] ∧
               (r.2 : Slice T).val = (v : Slice T).val.eraseIdx i.val ⌝ ⦄ := by
  unfold alloc.vec.Vec.remove
  mvcgen
  simp [List.eraseIdx_eq_take_drop_succ]

@[spec]
theorem alloc.vec.Vec.as_slice_spec {T : Type} (v : alloc.vec.Vec T) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.as_slice v ⦃ ⇓ r => ⌜ r = (v : Slice T) ⌝ ⦄ := by
  unfold alloc.vec.Vec.as_slice; mvcgen [rust_primitives.sequence.seq_to_slice]

@[spec]
theorem alloc.vec.Vec.Insts.CoreOpsDerefDerefSlice.deref_spec {T : Type} (v : alloc.vec.Vec T) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.CoreOpsDerefDerefSlice.deref v
    ⦃ ⇓ r => ⌜ r = (v : Slice T) ⌝ ⦄ := by
  unfold alloc.vec.Vec.Insts.CoreOpsDerefDerefSlice.deref
  exact alloc.vec.Vec.as_slice_spec v

/-- `Vec::extend` (hand-filled def in `Assumptions/MissingCoreModels.lean`) with a slice
    (`out.extend(slice)`): appends the slice, given room for it. -/
@[spec]
theorem alloc.vec.Vec.Insts.CoreIterTraitsCollectExtendSharedAT.extend_slice_spec
    {T : Type} (CopyInst : core.marker.Copy T) (v : alloc.vec.Vec T) (s : Slice T)
    (h : (v : Slice T).val.length + s.val.length ≤ Usize.max) :
    ⦃ ⌜ True ⌝ ⦄
    alloc.vec.Vec.Insts.CoreIterTraitsCollectExtendSharedAT.extend CopyInst
      (core.SharedASlice.Insts.CoreIterTraitsCollectIntoIteratorSharedATIter T) v s
    ⦃ ⇓ r => ⌜ (r : Slice T).val = (v : Slice T).val ++ s.val ⌝ ⦄ := by
  unfold alloc.vec.Vec.Insts.CoreIterTraitsCollectExtendSharedAT.extend
  simp only [core.SharedASlice.Insts.CoreIterTraitsCollectIntoIteratorSharedATIter.into_iter,
    core.slice.Slice.iter, rust_primitives.sequence.seq_from_slice]
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.loop.spec_decr_nat
    (fun p : core.slice.iter.Iter T × alloc.vec.Vec T => (p.1 : Slice T).val.length)
    (fun p : core.slice.iter.Iter T × alloc.vec.Vec T =>
      (p.2 : Slice T).val ++ (p.1 : Slice T).val = (v : Slice T).val ++ s.val)
  · rintro ⟨it, w⟩ hinv
    have hlen := congrArg List.length hinv
    simp only [List.length_append] at hlen hinv
    simp only [core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.next,
      rust_primitives.sequence.seq_len, rust_primitives.sequence.seq_remove,
      alloc.vec.Vec.push, rust_primitives.sequence.seq_push]
    by_cases hz : Slice.len it = 0#usize
    · have : (it : Slice T).val = [] := by
        rw [← List.length_eq_zero_iff]; scalar_tac
      simp_all
    · have hpos : 0 < (it : Slice T).val.length := by scalar_tac
      have hw : (w : Slice T).val.length < Usize.max := by omega
      simp [hz, hpos, hw]
      rw [← hinv, ← List.head_eq_getElem, List.cons_head_tail]
      exact List.ne_nil_of_length_pos hpos
  · simp

/-- `Default` for `Vec` (method of `alloc.vec.Vec.Insts.CoreDefaultDefault`, used by `mem::take`). -/
@[spec]
theorem alloc.vec.Vec.Insts.CoreDefaultDefault.default_spec (T : Type) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.CoreDefaultDefault.default T
    ⦃ ⇓ r => ⌜ (r : Slice T) = Aeneas.Std.Slice.new T ⌝ ⦄ := by
  unfold alloc.vec.Vec.Insts.CoreDefaultDefault.default; mvcgen

/-! ### `core::slice`, `str`, `AsRef` -/

@[spec]
theorem core.slice.Slice.len_spec {T : Type} (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ core.slice.Slice.len s ⦃ ⇓ r => ⌜ r = Aeneas.Std.Slice.len s ⌝ ⦄ := by
  unfold core.slice.Slice.len; mvcgen

@[spec]
theorem core.slice.Slice.is_empty_spec {T : Type} (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ core.slice.Slice.is_empty s
    ⦃ ⇓ r => ⌜ r = decide (Aeneas.Std.Slice.len s = 0#usize) ⌝ ⦄ := by
  unfold core.slice.Slice.is_empty; mvcgen
  rename_i h; subst h; rfl

@[spec]
theorem core.slice.Slice.iter_spec {T : Type} (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ core.slice.Slice.iter s ⦃ ⇓ r => ⌜ (r : Slice T) = s ⌝ ⦄ := by
  unfold core.slice.Slice.iter rust_primitives.sequence.seq_from_slice; mvcgen

@[spec]
theorem core.Slice.Insts.CoreConvertAsRefSlice.as_ref_spec {T : Type} (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ core.Slice.Insts.CoreConvertAsRefSlice.as_ref s ⦃ ⇓ r => ⌜ r = s ⌝ ⦄ := by
  unfold core.Slice.Insts.CoreConvertAsRefSlice.as_ref; mvcgen

@[spec]
theorem core.str.Str.as_bytes_spec (s : Str) :
    ⦃ ⌜ True ⌝ ⦄ core.str.Str.as_bytes s ⦃ ⇓ r => ⌜ r = s ⌝ ⦄ := by
  unfold core.str.Str.as_bytes; mvcgen

/-- Hand-filled def in `Assumptions/FunsExternal.lean`. -/
theorem alloc.Box.Insts.CoreConvertAsRef.as_ref_spec {T : Type} (x : T) :
    ⦃ ⌜ True ⌝ ⦄ alloc.Box.Insts.CoreConvertAsRef.as_ref x ⦃ ⇓ r => ⌜ r = x ⌝ ⦄ := by
  unfold alloc.Box.Insts.CoreConvertAsRef.as_ref; mvcgen

/-- `&[T]`'s `AsRef<[T]>` (the identity, through the `&T` blanket impl) is lawful. -/
theorem core.Shared0T.Insts.CoreConvertAsRef.slice_lawful {T : Type} :
    core.convert.AsRef.Lawful (Slice T) (Slice T)
      (core.Shared0T.Insts.CoreConvertAsRef (core.Slice.Insts.CoreConvertAsRefSlice T)) :=
  ⟨fun x => by
    mvcgen [core.Shared0T.Insts.CoreConvertAsRef, core.Slice.Insts.CoreConvertAsRefSlice.as_ref]⟩

/-- `slice::Iter::any` returns, for a closure that always returns. -/
theorem core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.any_spec {T F : Type}
    (FI : core.ops.function.FnMut F T Bool) (h : ∀ f x, ∃ b f', FI.call_mut f x = ok (b, f'))
    (it : core.slice.iter.Iter T) (f : F) :
    ⦃ ⌜ True ⌝ ⦄ core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.any FI it f
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  simp only [core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.any,
    core.iter.traits.iterator.Iterator.any.default, core.iter.traits.iterator.iter_any,
    core.iter.traits.iterator.iter_any_loop]
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.loop.spec_decr_nat (fun q : core.slice.iter.Iter T × F => q.1.val.length)
    (fun _ => True)
  · rintro ⟨i, g⟩ _
    simp only [core.iter.traits.iterator.iter_any_loop.body,
      core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.next,
      rust_primitives.sequence.seq_len, rust_primitives.sequence.seq_remove]
    by_cases hl : i.val.length = 0
    · have h0 : Aeneas.Std.Slice.len i = 0#usize := by scalar_tac
      simp [h0]
    · have h0 : Aeneas.Std.Slice.len i ≠ 0#usize := by scalar_tac
      obtain ⟨b, g', hg⟩ := h g (i.val[0]'(by omega))
      simp [h0, Nat.pos_of_ne_zero hl]
      simp only [hg, bind_tc_ok]
      cases b
      · simp; omega
      · simp
  · trivial

/-! ### Panic-freedom-sized specs for slice `get`/`try_from`

Weaker (shape `∀ t, o = some t → …`) than the exact specs below them. They are declared
BEFORE the exact specs so that, when both are `@[spec]`, `mvcgen` prefers the exact ones
(the most recently declared spec wins). They are used by the existing PF/Helpers proofs. -/

@[spec]
theorem core.ops.range.RangeToUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get_ok_spec
    {T : Type} [Inhabited T] (r : core.ops.range.RangeTo Std.Usize) (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ core.ops.range.RangeToUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get r s
    ⦃ ⇓ o => ⌜ ∀ t, o = some t → r.end.val ≤ s.val.length ∧ t.val.length = r.end.val ⌝ ⦄ := by
  mvcgen [core.ops.range.RangeToUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get,
    rust_primitives.slice.slice_length]
  · simp_all
  · exfalso; scalar_tac
  · simp

@[spec]
theorem core.ops.range.RangeFromUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get_some_spec
    {T : Type} [Inhabited T] (r : core.ops.range.RangeFrom Std.Usize) (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ core.ops.range.RangeFromUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get r s
    ⦃ ⇓ o => ⌜ r.start.val ≤ s.val.length →
        ∃ t, o = some t ∧ t.val.length = s.val.length - r.start.val ⌝ ⦄ := by
  mvcgen [core.ops.range.RangeFromUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get,
    rust_primitives.slice.slice_length]
  · obtain ⟨_, _, h, _⟩ := ‹∃ _, _›
    intro _; simp_all [Slice.len]
  · exfalso; scalar_tac
  · exfalso; scalar_tac
  · scalar_tac

@[spec]
theorem core.Array.Insts.CoreConvertTryFromShared0SliceTryFromSliceError.try_from_ok_spec
    {T : Type} [Inhabited T] (N : Std.Usize) (CopyInst : core.marker.Copy T) (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄
    core.Array.Insts.CoreConvertTryFromShared0SliceTryFromSliceError.try_from N CopyInst s
    ⦃ ⇓ r => ⌜ ∀ a, r = .Ok a → s.val.length = N.val ⌝ ⦄ := by
  mvcgen [core.Array.Insts.CoreConvertTryFromShared0SliceTryFromSliceError.try_from,
    rust_primitives.slice.slice_length]
  · mvcgen [convert.TryFromArrayShared0SliceTryFromSliceError.try_from.closure.Insts.CoreOpsFunctionFnMutTupleUsizeT.call_mut,
      rust_primitives.slice.slice_index]
    -- the index `k < N` fits in a `usize`, so `BitVec.ofNat` does not wrap
    exfalso
    have hN : N.val < 2 ^ System.Platform.numBits := N.hBounds
    rename_i hlen k hk hs
    unfold UScalar.val at hs
    simp [BitVec.toNat_ofNat] at hs
    rw [Nat.mod_eq_of_lt (by scalar_tac)] at hs
    scalar_tac
  · intros; simp_all [Slice.len]; scalar_tac
  · simp

/-- `TryFrom<&[T]> for [T; N]`: succeeds iff the lengths match. -/
@[spec high]
theorem core.Array.Insts.CoreConvertTryFromShared0SliceTryFromSliceError.try_from_spec
    {T : Type} [Inhabited T] (N : Std.Usize) (CopyInst : core.marker.Copy T) (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄
    core.Array.Insts.CoreConvertTryFromShared0SliceTryFromSliceError.try_from N CopyInst s
    ⦃ ⇓ r => ⌜ (s.val.length = N.val → ∃ a : Aeneas.Std.Array T N, r = .Ok a ∧ a.val = s.val) ∧
               (s.val.length ≠ N.val → r = .Err ()) ⌝ ⦄ := by
  have hcall : ∀ i (hi : i < s.val.length),
      convert.TryFromArrayShared0SliceTryFromSliceError.try_from.closure.Insts.CoreOpsFunctionFnMutTupleUsizeT.call_mut
        (N := N) CopyInst s ⟨BitVec.ofNat UScalarTy.Usize.numBits i⟩ = .ok (s.val[i], s) := by
    intro i hi
    have hb : s.val.length < 2 ^ UScalarTy.Usize.numBits := by
      have := s.property; have := Usize.max; scalar_tac
    unfold convert.TryFromArrayShared0SliceTryFromSliceError.try_from.closure.Insts.CoreOpsFunctionFnMutTupleUsizeT.call_mut
      rust_primitives.slice.slice_index Slice.index_usize
    have hv : (UScalar.mk (ty := .Usize) (BitVec.ofNat UScalarTy.Usize.numBits i)).val = i := by
      unfold UScalar.val
      simp only [BitVec.toNat_ofNat]
      exact Nat.mod_eq_of_lt (by omega)
    rw [Slice.getElem?_Usize_eq, hv, List.getElem?_eq_getElem hi]
    rfl
  unfold core.Array.Insts.CoreConvertTryFromShared0SliceTryFromSliceError.try_from
  mvcgen [rust_primitives.slice.slice_length]
  · rename_i h k hk
    have hl : s.val.length = N.val := by
      have : s.len.val = N.val := by rw [h]
      simpa using this
    rw [hcall k (by omega)]
    mvcgen
  · rename_i h a hc
    have hl : s.val.length = N.val := by
      have : s.len.val = N.val := by rw [h]
      simpa using this
    refine ⟨fun _ => ⟨a, rfl, ?_⟩, fun hne => absurd hl hne⟩
    apply List.ext_getElem
    · simp [hl]
    · intro i h1 h2
      have h3 := hc i (by omega)
      have h1' : i < s.val.length := by rw [hl]; simpa using h1
      rw [hcall i h1'] at h3
      have h4 := h3 trivial
      simp only [wp, PredTrans.apply] at h4
      exact h4.symm
  · rename_i h
    have hl : s.val.length ≠ N.val := by
      intro hl; apply h; apply UScalar.eq_of_val_eq; simpa using hl
    exact ⟨fun h' => absurd h' hl, fun _ => trivial⟩

/-! ### `fmt::Arguments::new`, `hint::must_use` (for `assert_written_bytes`) -/

@[spec]
theorem core.fmt.Arguments.new_spec {N M : Std.Usize} (t : Aeneas.Std.Array Std.U8 N)
    (a : Aeneas.Std.Array core.fmt.rt.Argument M) :
    ⦃ ⌜ True ⌝ ⦄ core.fmt.Arguments.new t a ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  unfold core.fmt.Arguments.new; mvcgen

@[spec]
theorem core.hint.must_use_spec {T : Type} (x : T) :
    ⦃ ⌜ True ⌝ ⦄ core.hint.must_use x ⦃ ⇓ r => ⌜ r = x ⌝ ⦄ := by
  unfold core.hint.must_use; mvcgen

/-! ### Integers -/

@[spec]
theorem core.num.U8.to_be_bytes_spec (x : Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ core.num.U8.to_be_bytes x
    ⦃ ⇓ r => ⌜ r = Aeneas.Std.core.num.U8.to_be_bytes x ⌝ ⦄ := by
  unfold core.num.U8.to_be_bytes; mvcgen

@[spec]
theorem core.num.U16.to_be_bytes_spec (x : Std.U16) :
    ⦃ ⌜ True ⌝ ⦄ core.num.U16.to_be_bytes x
    ⦃ ⇓ r => ⌜ r = Aeneas.Std.core.num.U16.to_be_bytes x ⌝ ⦄ := by
  unfold core.num.U16.to_be_bytes; mvcgen

@[spec]
theorem core.num.U32.to_be_bytes_spec (x : Std.U32) :
    ⦃ ⌜ True ⌝ ⦄ core.num.U32.to_be_bytes x
    ⦃ ⇓ r => ⌜ r = Aeneas.Std.core.num.U32.to_be_bytes x ⌝ ⦄ := by
  unfold core.num.U32.to_be_bytes; mvcgen

@[spec]
theorem core.num.U64.to_be_bytes_spec (x : Std.U64) :
    ⦃ ⌜ True ⌝ ⦄ core.num.U64.to_be_bytes x
    ⦃ ⇓ r => ⌜ r = Aeneas.Std.core.num.U64.to_be_bytes x ⌝ ⦄ := by
  unfold core.num.U64.to_be_bytes; mvcgen

@[spec]
theorem core.num.U8.from_be_bytes_spec (a : Aeneas.Std.Array Std.U8 1#usize) :
    ⦃ ⌜ True ⌝ ⦄ core.num.U8.from_be_bytes a
    ⦃ ⇓ r => ⌜ r = Aeneas.Std.core.num.U8.from_be_bytes a ⌝ ⦄ := by
  unfold core.num.U8.from_be_bytes rust_primitives.arithmetic.from_be_bytes_u8; mvcgen

@[spec]
theorem core.num.U16.from_be_bytes_spec (a : Aeneas.Std.Array Std.U8 2#usize) :
    ⦃ ⌜ True ⌝ ⦄ core.num.U16.from_be_bytes a
    ⦃ ⇓ r => ⌜ r = Aeneas.Std.core.num.U16.from_be_bytes a ⌝ ⦄ := by
  unfold core.num.U16.from_be_bytes rust_primitives.arithmetic.from_be_bytes_u16; mvcgen

@[spec]
theorem core.num.U32.from_be_bytes_spec (a : Aeneas.Std.Array Std.U8 4#usize) :
    ⦃ ⌜ True ⌝ ⦄ core.num.U32.from_be_bytes a
    ⦃ ⇓ r => ⌜ r = Aeneas.Std.core.num.U32.from_be_bytes a ⌝ ⦄ := by
  unfold core.num.U32.from_be_bytes rust_primitives.arithmetic.from_be_bytes_u32; mvcgen

@[spec]
theorem core.num.U64.from_be_bytes_spec (a : Aeneas.Std.Array Std.U8 8#usize) :
    ⦃ ⌜ True ⌝ ⦄ core.num.U64.from_be_bytes a
    ⦃ ⇓ r => ⌜ r = Aeneas.Std.core.num.U64.from_be_bytes a ⌝ ⦄ := by
  unfold core.num.U64.from_be_bytes rust_primitives.arithmetic.from_be_bytes_u64; mvcgen

@[spec]
theorem core.num.Usize.saturating_add_spec (x y : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ core.num.Usize.saturating_add x y
    ⦃ ⇓ r => ⌜ r = UScalar.saturating_add x y ⌝ ⦄ := by
  unfold core.num.Usize.saturating_add; mvcgen

@[spec]
theorem core.Usize.Insts.CoreConvertFromBool.from_spec (b : Bool) :
    ⦃ ⌜ True ⌝ ⦄ core.Usize.Insts.CoreConvertFromBool.from b
    ⦃ ⇓ r => ⌜ r = if b then 1#usize else 0#usize ⌝ ⦄ := by
  unfold core.Usize.Insts.CoreConvertFromBool.from; cases b <;> mvcgen

@[spec]
theorem core.Usize.Insts.CoreConvertFromU8.from_spec (x : Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ core.Usize.Insts.CoreConvertFromU8.from x
    ⦃ ⇓ r => ⌜ r = UScalar.cast .Usize x ⌝ ⦄ := by
  unfold core.Usize.Insts.CoreConvertFromU8.from; mvcgen

/-- `u64::try_from(usize)` never fails (`usize` is at most 64 bits wide). -/
@[spec]
theorem core.U64.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from_spec (x : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ core.U64.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from x
    ⦃ ⇓ r => ⌜ r = .Ok (UScalar.cast .U64 x) ⌝ ⦄ := by
  unfold core.U64.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from
  mvcgen
  all_goals simp_all  -- leaves only `x > cast Usize U64.MAX`, impossible as `numBits ≤ 64`
  have := x.hBounds
  rcases System.Platform.numBits_eq with h | h <;> simp_all [U64.rMax] <;> omega

/-- `usize::try_from(u64)` does not panic; an `Ok` keeps the value, and it is `Ok` whenever the value
fits in 32 bits (`usize` is at least 32 bits wide). -/
@[spec]
theorem core.Usize.Insts.CoreConvertTryFromU64TryFromIntError.try_from_spec (x : Std.U64) :
    ⦃ ⌜ True ⌝ ⦄ core.Usize.Insts.CoreConvertTryFromU64TryFromIntError.try_from x
    ⦃ ⇓ r => ⌜ (∀ y, r = .Ok y → y.val = x.val) ∧ (x.val ≤ 2 ^ 32 - 1 → ∃ y, r = .Ok y) ⌝ ⦄ := by
  unfold core.Usize.Insts.CoreConvertTryFromU64TryFromIntError.try_from
  mvcgen
  · refine ⟨fun y h => (nomatch h), fun hx => ?_⟩
    exfalso
    subst_vars
    simp only [Aeneas.Std.core.num.Usize.MAX] at *
    have := x.hBounds
    rcases System.Platform.numBits_eq with h | h <;>
      simp_all [Usize.max, UScalar.cast_val_eq, UScalarTy.numBits, Usize.numBits] <;> omega
  · refine ⟨fun y h => (nomatch h), fun hx => ?_⟩
    exfalso
    subst_vars
    simp only [Aeneas.Std.core.num.Usize.MIN] at *
    scalar_tac
  · subst_vars
    refine ⟨fun y h => ?_, fun hx => ⟨_, rfl⟩⟩
    obtain rfl := core.result.Result.Ok.inj h
    simp only [Aeneas.Std.core.num.Usize.MAX] at *
    have := x.hBounds
    rcases System.Platform.numBits_eq with h | h <;>
      simp_all [Usize.max, UScalar.cast_val_eq, UScalarTy.numBits, Usize.numBits] <;> omega

/-- `PartialEq for u8`, in the `decide` form that the generic `eq` specs (`Slice`, `Array`,
`Option`, …) take as hypothesis. Not tagged: the existing proofs unfold the instance. -/
theorem core.U8.Insts.CoreCmpPartialEqU8.eq_decide_spec (x y : Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ core.U8.Insts.CoreCmpPartialEqU8.eq x y ⦃ ⇓ r => ⌜ r = decide (x = y) ⌝ ⦄ := by
  simp only [core.U8.Insts.CoreCmpPartialEqU8]; mvcgen
  by_cases h : x = y <;> simp [h]

/-- `PartialEq for u64`, through the instance record (a projection, so it has no spec key). -/
@[spec]
theorem core.U64.Insts.CoreCmpPartialEqU64.eq_spec (x y : Std.U64) :
    ⦃ ⌜ True ⌝ ⦄ core.U64.Insts.CoreCmpPartialEqU64.eq x y ⦃ ⇓ r => ⌜ r = (x == y) ⌝ ⦄ := by
  simp only [core.U64.Insts.CoreCmpPartialEqU64]; mvcgen

/-! ### `Option` / `Result` (non-generic in the instance) -/

@[spec]
theorem core.option.Option.is_some_spec {T : Type} (o : core.option.Option T) :
    ⦃ ⌜ True ⌝ ⦄ core.option.Option.is_some o ⦃ ⇓ r => ⌜ r = o.isSome ⌝ ⦄ := by
  unfold core.option.Option.is_some; cases o <;> mvcgen

theorem core.option.Option.ok_or_spec {T E : Type} (o : core.option.Option T) (err : E) :
    ⦃ ⌜ True ⌝ ⦄ core.option.Option.ok_or o err
    ⦃ ⇓ r => ⌜ r = match o with
                  | some v => core.result.Result.Ok v
                  | none => core.result.Result.Err err ⌝ ⦄ := by
  unfold core.option.Option.ok_or; cases o <;> mvcgen

@[spec]
theorem core.result.Result.unwrap_or_spec {T E : Type} (x : core.result.Result T E) (d : T) :
    ⦃ ⌜ True ⌝ ⦄ core.result.Result.unwrap_or x d
    ⦃ ⇓ r => ⌜ r = match x with
                  | .Ok t => t
                  | .Err _ => d ⌝ ⦄ := by
  unfold core.result.Result.unwrap_or; cases x <;> mvcgen

@[spec]
theorem core.result.Result.is_err_spec {T E : Type} (x : core.result.Result T E) :
    ⦃ ⌜ True ⌝ ⦄ core.result.Result.is_err x
    ⦃ ⇓ r => ⌜ r = match x with
                  | .Ok _ => false
                  | .Err _ => true ⌝ ⦄ := by
  unfold core.result.Result.is_err; cases x <;> mvcgen

/-- `?` on a `Result` (the `Try::branch` abbrev of CoreModels unfolds to this). -/
@[spec]
theorem core.result.Result.Insts.CoreOpsTry_traitTryTResultInfallibleE.branch_spec {T E : Type}
    (x : core.result.Result T E) :
    ⦃ ⌜ True ⌝ ⦄ core.result.Result.Insts.CoreOpsTry_traitTryTResultInfallibleE.branch x
    ⦃ ⇓ r => ⌜ r = match x with
                  | .Ok v => core.ops.control_flow.ControlFlow.Continue v
                  | .Err e => core.ops.control_flow.ControlFlow.Break (.Err e) ⌝ ⦄ := by
  unfold core.result.Result.Insts.CoreOpsTry_traitTryTResultInfallibleE.branch; cases x <;> mvcgen

/-! ## 2b. Missing specs: generic in an instance (sorried, to be proved)

The callee's behaviour is a hypothesis. With a schematic `Q`, `mvcgen` turns it into a
new verification condition about the instance method. -/

@[spec]
theorem core.convert.Into.Blanket.into_spec {T U : Type} (FromInst : core.convert.From U T)
    (x : T) {Q : PostCond U RustM.postShape}
    (h : ⦃ ⌜ True ⌝ ⦄ FromInst.from x ⦃ Q ⦄) :
    ⦃ ⌜ True ⌝ ⦄ core.convert.Into.Blanket.into FromInst x ⦃ Q ⦄ := by
  unfold core.convert.Into.Blanket.into; exact h

@[spec]
theorem core.slice.Slice.get_spec {T I O : Type}
    (inst : core.slice.index.SliceIndex I (Slice T) O) (s : Slice T) (i : I)
    {Q : PostCond (core.option.Option O) RustM.postShape}
    (h : ⦃ ⌜ True ⌝ ⦄ inst.get i s ⦃ Q ⦄) :
    ⦃ ⌜ True ⌝ ⦄ core.slice.Slice.get inst s i ⦃ Q ⦄ := by
  unfold core.slice.Slice.get; exact h

/-- `s[i]`: succeeds when `get` returns `Some`. -/
@[spec]
theorem core.Slice.Insts.CoreOpsIndexIndex.index_spec {T I O : Type}
    (inst : core.slice.index.SliceIndex I (Slice T) O) (s : Slice T) (i : I)
    {Q : PostCond O RustM.postShape}
    (h : ⦃ ⌜ True ⌝ ⦄ inst.get i s ⦃ ⇓ o => ⌜ ∃ r, o = some r ∧ Aeneas.Std.PostCond.ok Q r ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ core.Slice.Insts.CoreOpsIndexIndex.index inst s i ⦃ Q ⦄ := by
  unfold core.Slice.Insts.CoreOpsIndexIndex.index
  mvcgen [h]
  · rename_i hh; obtain ⟨r, hr, hq⟩ := hh; cases hr; exact hq
  · simp

/-- `v[i]` on a `Vec`: indexes the underlying slice. -/
@[spec]
theorem alloc.vec.Vec.Insts.CoreOpsIndexIndex.index_spec {T I O : Type}
    (inst : core.slice.index.SliceIndex I (Slice T) O) (v : alloc.vec.Vec T) (i : I)
    {Q : PostCond O RustM.postShape}
    (h : ⦃ ⌜ True ⌝ ⦄ inst.get i v ⦃ ⇓ o => ⌜ ∃ r, o = some r ∧ Aeneas.Std.PostCond.ok Q r ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.CoreOpsIndexIndex.index inst v i ⦃ Q ⦄ := by
  unfold alloc.vec.Vec.Insts.CoreOpsIndexIndex.index
  mvcgen [alloc.vec.Vec.Insts.CoreOpsDerefDerefSlice.deref_spec,
    core.Slice.Insts.CoreOpsIndexIndex.index_spec]
  subst_vars; simpa [Triple] using h

/-- `&mut v[i]` on a `Vec`: the slice's `index_mut`, the write-back is unchanged. -/
@[spec]
theorem alloc.vec.Vec.Insts.CoreOpsIndexIndexMut.index_mut_spec {T I O : Type}
    (inst : core.slice.index.SliceIndex I (Slice T) O) (v : alloc.vec.Vec T) (i : I)
    {Q : PostCond (O × (O → alloc.vec.Vec T)) RustM.postShape}
    (h : ⦃ ⌜ True ⌝ ⦄ core.Slice.Insts.CoreOpsIndexIndexMut.index_mut inst v i ⦃ Q ⦄) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.CoreOpsIndexIndexMut.index_mut inst v i ⦃ Q ⦄ := by
  unfold alloc.vec.Vec.Insts.CoreOpsIndexIndexMut.index_mut
  mvcgen [rust_primitives.sequence.seq_to_slice_mut, h]

/-- Reached through `Vec`'s `index_mut` only. The model uses `get_unchecked_mut`. -/
@[spec]
theorem core.Slice.Insts.CoreOpsIndexIndexMut.index_mut_spec {T I O : Type}
    (inst : core.slice.index.SliceIndex I (Slice T) O) (s : Slice T) (i : I)
    {Q : PostCond (O × (O → Slice T)) RustM.postShape}
    (h : ⦃ ⌜ True ⌝ ⦄ inst.get_unchecked_mut i s ⦃ Q ⦄) :
    ⦃ ⌜ True ⌝ ⦄ core.Slice.Insts.CoreOpsIndexIndexMut.index_mut inst s i ⦃ Q ⦄ := by
  unfold core.Slice.Insts.CoreOpsIndexIndexMut.index_mut; exact h

/-- `a[i]` on an array: the slice `Index` instance on `a` as a slice. -/
@[spec]
theorem core.Array.Insts.CoreOpsIndexIndex.index_spec {T I O : Type} {N : Std.Usize}
    (inst : core.ops.index.Index (Slice T) I O) (a : Aeneas.Std.Array T N) (i : I)
    {Q : PostCond O RustM.postShape}
    (h : ⦃ ⌜ True ⌝ ⦄ inst.index (Aeneas.Std.Array.to_slice a) i ⦃ Q ⦄) :
    ⦃ ⌜ True ⌝ ⦄ core.Array.Insts.CoreOpsIndexIndex.index inst a i ⦃ Q ⦄ := by
  unfold core.Array.Insts.CoreOpsIndexIndex.index core.array.Array.as_slice
    rust_primitives.slice.array_as_slice
  mvcgen [h]

/-- `slice.to_vec()`: a copy, when `clone` is the identity (e.g. `Copy` types). -/
theorem alloc.slice.Slice.to_vec_spec {T : Type} (CloneInst : core.clone.Clone T)
    (s : Slice T)
    (hclone : ∀ x, ⦃ ⌜ True ⌝ ⦄ CloneInst.clone x ⦃ ⇓ y => ⌜ y = x ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ alloc.slice.Slice.to_vec CloneInst s ⦃ ⇓ r => ⌜ (r : Slice T) = s ⌝ ⦄ := by
  -- a total-correctness triple with a deterministic post pins down the `RustM` value
  have clone_eq : ∀ x, CloneInst.clone x = .ok x := by
    intro x
    have h := hclone x
    -- unfolds the triple: no `RustM` lemma yet characterises `⦃True⦄ x ⦃⇓ y => y = a⦄`
    cases hc : CloneInst.clone x <;> simp_all [Triple, wp, PredTrans.apply]
  have mapM_eq : ∀ l : List T, l.mapM CloneInst.clone = .ok l := by
    intro l
    induction l with
    | nil => rfl
    | cons x xs ih => simp [List.mapM_cons, clone_eq, ih]; rfl
  have hlen : s.val.length ≤ Usize.max := s.property
  unfold alloc.slice.Slice.to_vec alloc.slice.Dummy.to_vec
  simp [rust_primitives.sequence.seq_empty, rust_primitives.sequence.seq_extend, alloc.vec.from_seq,
    Slice.new, mapM_eq, hlen]
  mvcgen

/-- Hand-filled def in `Assumptions/FunsExternal.lean`. -/
@[spec]
theorem core.mem.take_spec {T : Type} (DefaultInst : core.default.Default T) (dest : T)
    {Q : PostCond (T × T) RustM.postShape}
    (h : ⦃ ⌜ True ⌝ ⦄ DefaultInst.default ⦃ ⇓ d => ⌜ Aeneas.Std.PostCond.ok Q (dest, d) ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ core.mem.take DefaultInst dest ⦃ Q ⦄ := by
  unfold core.mem.take
  mvcgen [h]

/-- `?` on a `Result`: converts the error with `From`. The `Ok` residual (unreachable in
Rust, `Infallible` is modelled as `Unit`) panics, so it is excluded by hypothesis. -/
@[spec]
theorem core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual_spec
    (T : Type) {E F : Type} (FromInst : core.convert.From F E)
    (res : core.result.Result core.convert.Infallible E)
    {Q : PostCond (core.result.Result T F) RustM.postShape}
    (h : ∃ e, res = .Err e ∧ ⦃ ⌜ True ⌝ ⦄ FromInst.from e ⦃ ⇓ f => ⌜ Aeneas.Std.PostCond.ok Q (.Err f) ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄
    core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual T FromInst res
    ⦃ Q ⦄ := by
  obtain ⟨e, rfl, h⟩ := h
  unfold core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
  mvcgen [h]

theorem core.result.Result.is_ok_and_spec {T E F : Type}
    (FnInst : core.ops.function.FnOnce F T Bool) (x : core.result.Result T E) (f : F)
    {Q : PostCond Bool RustM.postShape}
    (hok : ∀ t, x = .Ok t → ⦃ ⌜ True ⌝ ⦄ FnInst.call_once f t ⦃ Q ⦄)
    (herr : ∀ e, x = .Err e → Aeneas.Std.PostCond.ok Q false) :
    ⦃ ⌜ True ⌝ ⦄ core.result.Result.is_ok_and FnInst x f ⦃ Q ⦄ := by
  unfold core.result.Result.is_ok_and
  cases x with
  | Ok t => have h := hok t rfl; mvcgen [h]
  | Err e => have h := herr e rfl; mvcgen

theorem core.result.Result.map_spec {T E U F : Type}
    (FnInst : core.ops.function.FnOnce F T U) (x : core.result.Result T E) (op : F)
    {Q : PostCond (core.result.Result U E) RustM.postShape}
    (hok : ∀ t, x = .Ok t → ⦃ ⌜ True ⌝ ⦄ FnInst.call_once op t ⦃ ⇓ u => ⌜ Aeneas.Std.PostCond.ok Q (.Ok u) ⌝ ⦄)
    (herr : ∀ e, x = .Err e → Aeneas.Std.PostCond.ok Q (.Err e)) :
    ⦃ ⌜ True ⌝ ⦄ core.result.Result.map FnInst x op ⦃ Q ⦄ := by
  unfold core.result.Result.map
  cases x with
  | Ok t => have h := hok t rfl; mvcgen [h]
  | Err e => have h := herr e rfl; mvcgen

theorem core.result.Result.map_err_spec {T E F O : Type}
    (FnInst : core.ops.function.FnOnce O E F) (x : core.result.Result T E) (op : O)
    {Q : PostCond (core.result.Result T F) RustM.postShape}
    (hok : ∀ t, x = .Ok t → Aeneas.Std.PostCond.ok Q (.Ok t))
    (herr : ∀ e, x = .Err e → ⦃ ⌜ True ⌝ ⦄ FnInst.call_once op e ⦃ ⇓ f => ⌜ Aeneas.Std.PostCond.ok Q (.Err f) ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ core.result.Result.map_err FnInst x op ⦃ Q ⦄ := by
  unfold core.result.Result.map_err
  cases x with
  | Ok t => have h := hok t rfl; mvcgen [h]
  | Err e => have h := herr e rfl; mvcgen [h]

/-! Equality through `PartialEq` instances. Stated for instances that decide `=`, which
covers the concrete instances the obligations pass (integers, `()`, pairs, derived). -/

theorem core.option.Option.Insts.CoreCmpPartialEqOption.eq_spec {T : Type} [DecidableEq T]
    (inst : core.cmp.PartialEq T T) (a b : core.option.Option T)
    (heq : ∀ x y, ⦃ ⌜ True ⌝ ⦄ inst.eq x y ⦃ ⇓ r => ⌜ r = decide (x = y) ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ core.option.Option.Insts.CoreCmpPartialEqOption.eq inst a b
    ⦃ ⇓ r => ⌜ r = decide (a = b) ⌝ ⦄ := by
  unfold core.option.Option.Insts.CoreCmpPartialEqOption.eq
  cases a with
  | none => cases b <;> mvcgen
  | some x => cases b with
    | none => mvcgen
    | some y => have h := heq x y; mvcgen [h]; intro h; subst h; simp

theorem core.result.Result.Insts.CoreCmpPartialEqResult.eq_spec {T E : Type}
    [DecidableEq T] [DecidableEq E]
    (instT : core.cmp.PartialEq T T) (instE : core.cmp.PartialEq E E)
    (a b : core.result.Result T E)
    (heqT : ∀ x y, ⦃ ⌜ True ⌝ ⦄ instT.eq x y ⦃ ⇓ r => ⌜ r = decide (x = y) ⌝ ⦄)
    (heqE : ∀ x y, ⦃ ⌜ True ⌝ ⦄ instE.eq x y ⦃ ⇓ r => ⌜ r = decide (x = y) ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ core.result.Result.Insts.CoreCmpPartialEqResult.eq instT instE a b
    ⦃ ⇓ r => ⌜ r = true ↔ a = b ⌝ ⦄ := by
  unfold core.result.Result.Insts.CoreCmpPartialEqResult.eq
  cases a with
  | Ok x => cases b with
    | Ok y => have h := heqT x y; mvcgen [h]; intro h; subst h; simp
    | Err e => mvcgen; simp
  | Err e => cases b with
    | Ok y => mvcgen; simp
    | Err f => have h := heqE e f; mvcgen [h]; intro h; subst h; simp

/-- `@[reducible]` in CoreModels, but its body is a loop without a spec. -/
@[spec]
theorem core.Array.Insts.CoreCmpPartialEqArray.eq_spec {T : Type} {N : Std.Usize}
    [DecidableEq T] (inst : core.cmp.PartialEq T T) (a b : Aeneas.Std.Array T N)
    (heq : ∀ x y, ⦃ ⌜ True ⌝ ⦄ inst.eq x y ⦃ ⇓ r => ⌜ r = decide (x = y) ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ core.Array.Insts.CoreCmpPartialEqArray.eq inst a b
    ⦃ ⇓ r => ⌜ r = decide (a.val = b.val) ⌝ ⦄ := by
  have hbody : ∀ i : Std.Usize, i.val ≤ N.val ∧ (∀ j, j < i.val → a.val[j]? = b.val[j]?) →
      ⦃ ⌜ True ⌝ ⦄ core.Array.Insts.CoreCmpPartialEqArray.eq_loop.body inst a b i
      ⦃ ⇓ r => ⌜ match r with
        | .done y => y = decide (a.val = b.val)
        | .cont i' => (i'.val ≤ N.val ∧ ∀ j, j < i'.val → a.val[j]? = b.val[j]?) ∧
            N.val - i'.val < N.val - i.val ⌝ ⦄ := by
    intro i ⟨hiN, hinv⟩
    unfold core.Array.Insts.CoreCmpPartialEqArray.eq_loop.body
      rust_primitives.slice.array_index
    have hla : a.val.length = N.val := a.property
    have hlb : b.val.length = N.val := b.property
    have hsa : a.to_slice.length = N.val := by simp [Aeneas.Std.Array.to_slice, Slice.length, hla]
    have hsb : b.to_slice.length = N.val := by simp [Aeneas.Std.Array.to_slice, Slice.length, hlb]
    mvcgen [heq]
    · rename_i hi x hx y hy r hr hdec i' hi'
      obtain ⟨_, hxe⟩ := hx
      obtain ⟨_, hye⟩ := hy
      have hxy : x = y := by
        subst hr; simpa using hdec.symm
      have hai : a.val[i.val]? = some x := by
        simp [Aeneas.Std.Array.to_slice] at hxe; simp [hxe]
      have hbi : b.val[i.val]? = some y := by
        simp [Aeneas.Std.Array.to_slice] at hye; simp [hye]
      have hi1 : i'.val = i.val + 1 := by simp at hi'; scalar_tac
      refine ⟨⟨by scalar_tac, fun j hj => ?_⟩, by scalar_tac⟩
      by_cases hji : j < i.val
      · exact hinv j hji
      · have : j = i.val := by omega
        subst this; rw [hai, hbi, hxy]
    · scalar_tac
    · rename_i hi x hx y hy r hr hdec
      obtain ⟨_, hxe⟩ := hx
      obtain ⟨_, hye⟩ := hy
      have hai : a.val[i.val]? = some x := by
        simp [Aeneas.Std.Array.to_slice] at hxe; simp [hxe]
      have hbi : b.val[i.val]? = some y := by
        simp [Aeneas.Std.Array.to_slice] at hye; simp [hye]
      have hne : x ≠ y := by
        intro hxy; apply hr; rw [hdec]; simp [hxy]
      symm
      simp only [decide_eq_false_iff_not]
      intro hab
      apply hne
      rw [hab] at hai
      rw [hai] at hbi
      exact Option.some.inj hbi
    · scalar_tac
    · scalar_tac
    · rename_i hi
      symm
      simp only [decide_eq_true_eq]
      apply List.ext_getElem?
      intro j
      by_cases hj : j < i.val
      · exact hinv j hj
      · have h1 : a.val[j]? = none := by
          rw [List.getElem?_eq_none_iff]; scalar_tac
        have h2 : b.val[j]? = none := by
          rw [List.getElem?_eq_none_iff]; scalar_tac
        rw [h1, h2]
  unfold core.Array.Insts.CoreCmpPartialEqArray.eq core.Array.Insts.CoreCmpPartialEqArray.eq_loop
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.loop.spec_decr_nat (fun i : Std.Usize => N.val - i.val)
    (fun i : Std.Usize => i.val ≤ N.val ∧ ∀ j, j < i.val → a.val[j]? = b.val[j]?)
    (fun y => y = decide (a.val = b.val))
  · intro i hi
    obtain ⟨v, hv, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (hbody i hi)
    rw [hv, Aeneas.Std.WP.spec_ok]
    cases v with
    | done y => exact hP
    | cont i' => exact hP
  · exact ⟨by scalar_tac, fun j hj => by simp at hj⟩

/-- Method of `core.Pair.Insts.CoreCmpPartialEqPair` (passed to generic `eq`s). -/
theorem core.Pair.Insts.CoreCmpPartialEqPair.eq_spec {A B : Type} [DecidableEq A] [DecidableEq B]
    (instA : core.cmp.PartialEq A A) (instB : core.cmp.PartialEq B B) (a b : A × B)
    (heqA : ∀ x y, ⦃ ⌜ True ⌝ ⦄ instA.eq x y ⦃ ⇓ r => ⌜ r = decide (x = y) ⌝ ⦄)
    (heqB : ∀ x y, ⦃ ⌜ True ⌝ ⦄ instB.eq x y ⦃ ⇓ r => ⌜ r = decide (x = y) ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ core.Pair.Insts.CoreCmpPartialEqPair.eq instA instB a b
    ⦃ ⇓ r => ⌜ r = decide (a = b) ⌝ ⦄ := by
  unfold core.Pair.Insts.CoreCmpPartialEqPair.eq
  obtain ⟨a1, a2⟩ := a
  obtain ⟨b1, b2⟩ := b
  have h1 := heqA a1 b1
  have h2 := heqB a2 b2
  mvcgen [h1, h2]
  · rename_i r1 hr hd r2
    intro h; subst h
    have : a1 = b1 := by subst hr; simpa using hd.symm
    subst this; simp
  · rename_i r1 hr hd
    have : a1 ≠ b1 := fun e => hr (by rw [hd]; simp [e])
    simp [this]

/-! ## 2c. Missing specs: methods of concrete instances passed to generic code

These are reached through an instance record (e.g. `Usize`'s `SliceIndex` passed to
`Slice.get`), not by a direct call. -/

@[spec]
theorem core.Tuple.Insts.CoreCmpPartialEqTuple.eq_spec (x y : Unit) :
    ⦃ ⌜ True ⌝ ⦄ core.Tuple.Insts.CoreCmpPartialEqTuple.eq x y ⦃ ⇓ r => ⌜ r = true ⌝ ⦄ := by
  unfold core.Tuple.Insts.CoreCmpPartialEqTuple.eq; mvcgen

@[spec]
theorem core.U8.Insts.CoreCloneClone.clone_spec (x : Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ core.U8.Insts.CoreCloneClone.clone x ⦃ ⇓ r => ⌜ r = x ⌝ ⦄ := by
  unfold core.U8.Insts.CoreCloneClone.clone; mvcgen

@[spec]
theorem core.convert.From.Blanket.from_spec {T : Type} (x : T) :
    ⦃ ⌜ True ⌝ ⦄ core.convert.From.Blanket.from x ⦃ ⇓ r => ⌜ r = x ⌝ ⦄ := by
  unfold core.convert.From.Blanket.from; mvcgen

@[spec]
theorem core.Usize.Insts.CoreSliceIndexSliceIndexSliceT.get_spec {T : Type}
    (i : Std.Usize) (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ core.Usize.Insts.CoreSliceIndexSliceIndexSliceT.get i s
    ⦃ ⇓ r => ⌜ r = s.val[i.val]? ⌝ ⦄ := by
  unfold core.Usize.Insts.CoreSliceIndexSliceIndexSliceT.get
  mvcgen
  · obtain ⟨_, h⟩ := ‹∃ _, _›; simp [h]
  · exfalso; scalar_tac
  · simp_all [Slice.len]

@[spec]
theorem core.Usize.Insts.CoreSliceIndexSliceIndexSliceT.index_spec {T : Type}
    (i : Std.Usize) (s : Slice T) (h : i.val < s.val.length) :
    ⦃ ⌜ True ⌝ ⦄ core.Usize.Insts.CoreSliceIndexSliceIndexSliceT.index i s
    ⦃ ⇓ r => ⌜ r = s.val[i.val] ⌝ ⦄ := by
  unfold core.Usize.Insts.CoreSliceIndexSliceIndexSliceT.index
  mvcgen
  · obtain ⟨_, h⟩ := ‹∃ _, _›; exact h
  · exfalso; scalar_tac

/-- The write-back replaces element `i`. -/
@[spec]
theorem core.Usize.Insts.CoreSliceIndexSliceIndexSliceT.get_unchecked_mut_spec {T : Type}
    (i : Std.Usize) (s : Slice T) (h : i.val < s.val.length) :
    ⦃ ⌜ True ⌝ ⦄ core.Usize.Insts.CoreSliceIndexSliceIndexSliceT.get_unchecked_mut i s
    ⦃ ⇓ r => ⌜ r.1 = s.val[i.val] ∧ ∀ x, (r.2 x).val = s.val.set i.val x ⌝ ⦄ := by
  unfold core.Usize.Insts.CoreSliceIndexSliceIndexSliceT.get_unchecked_mut
  mvcgen
  · obtain ⟨_, h1, h2⟩ := ‹∃ _, _›
    subst h2
    exact ⟨h1, fun x => by simp [Slice.set, Slice.setAtNat]⟩
  · exfalso; scalar_tac

/-- `Range<usize>::next`: yields `start` and advances while `start < end`. -/
@[spec]
theorem core.ops.range.Range.Insts.CoreIterTraitsIteratorIterator.next_Usize_spec
    (it : core.ops.range.Range Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄
    core.ops.range.Range.Insts.CoreIterTraitsIteratorIterator.next
      core.Usize.Insts.CoreIterRangeStep it
    ⦃ ⇓ r => ⌜ (it.start.val < it.end.val →
                  r.1 = some it.start ∧ r.2.start.val = it.start.val + 1 ∧ r.2.end = it.end) ∧
               (¬ it.start.val < it.end.val → r = (none, it)) ⌝ ⦄ := by
  have key : ∀ x y : Nat, (match (match compare x y with
        | Ordering.lt => cmp.Ordering.Less
        | Ordering.eq => cmp.Ordering.Equal
        | Ordering.gt => cmp.Ordering.Greater) with
      | cmp.Ordering.Less => true
      | _ => false) = true ↔ x < y := by
    intro x y
    rcases Nat.lt_trichotomy x y with h | h | h
    · simp [Nat.compare_eq_lt.mpr h, h]
    · subst h; simp
    · simp [Nat.compare_eq_gt.mpr h, Nat.not_lt.mpr h.le]
  unfold core.ops.range.Range.Insts.CoreIterTraitsIteratorIterator.next core.IteratorRange.next
  simp only [core.Usize.Insts.CoreIterRangeStep, core.Usize.Insts.CoreCmpPartialOrdUsize,
    core.mkUPartialOrd, core.Usize.Insts.CoreCloneClone.clone,
    core.Usize.Insts.CoreIterRangeStep.forward_checked]
  mvcgen [core.convert.TryFromUTInfallible.Blanket.try_from, core.num.Usize.checked_add,
    core.num.Usize.overflowing_add]
  · rename_i hc r hr hov
    have hlt := (key _ _).mp hc
    subst hr
    have := UScalar.overflowing_add_eq it.start 1#usize
    have hmax := it.end.hBounds
    simp only [hov] at this
    split_ifs at this <;> scalar_tac
  · rename_i hc r hr hnov
    have hlt := (key _ _).mp hc
    subst hr
    have := UScalar.overflowing_add_eq it.start 1#usize
    have hmax := it.end.hBounds
    simp only [hnov] at this
    split_ifs at this with h1
    · scalar_tac
    · refine ⟨fun _ => ⟨trivial, by scalar_tac⟩, fun h => absurd hlt h⟩
  · rename_i hc
    refine ⟨fun h => ?_, fun _ => trivial⟩
    exact absurd ((key _ _).mpr h) hc

/-- Unpacking of `next_Usize_spec` when `next` returned `some i`. -/
theorem core.ops.range.Range.next_Usize_some
    (it : core.ops.range.Range Std.Usize) (r : Option Std.Usize × core.ops.range.Range Std.Usize)
    (i : Std.Usize) (hr : r.1 = some i)
    (h : (it.start.val < it.end.val →
            r.1 = some it.start ∧ r.2.start.val = it.start.val + 1 ∧ r.2.end = it.end) ∧
         (¬ it.start.val < it.end.val → r = (none, it))) :
    it.start.val < it.end.val ∧ i = it.start ∧ r.2.start.val = it.start.val + 1 ∧
      r.2.end = it.end := by
  by_cases hlt : it.start.val < it.end.val
  · obtain ⟨h1, h2, h3⟩ := h.1 hlt
    rw [h1] at hr
    exact ⟨hlt, (Option.some.inj hr).symm, h2, h3⟩
  · rw [h.2 hlt] at hr; simp at hr

theorem core.Slice.Insts.CoreCmpPartialEqSlice.eq_spec {T : Type} [DecidableEq T]
    (inst : core.cmp.PartialEq T T) (a b : Slice T)
    (heq : ∀ x y, ⦃ ⌜ True ⌝ ⦄ inst.eq x y ⦃ ⇓ r => ⌜ r = decide (x = y) ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ core.Slice.Insts.CoreCmpPartialEqSlice.eq inst a b
    ⦃ ⇓ r => ⌜ r = decide (a.val = b.val) ⌝ ⦄ := by
  have hbody : ∀ (it : core.ops.range.Range Std.Usize) (res : Bool),
      it.end.val = a.val.length → a.val.length = b.val.length →
      it.start.val ≤ it.end.val → (res = true ↔ ∀ j, j < it.start.val → a.val[j]? = b.val[j]?) →
      ⦃ ⌜ True ⌝ ⦄ core.Slice.Insts.CoreCmpPartialEqSlice.eq_loop.body inst a b it res
      ⦃ ⇓ r => ⌜ match r with
        | .done y => y = decide (a.val = b.val)
        | .cont (it', res') => (it'.end.val = a.val.length ∧ it'.start.val ≤ it'.end.val ∧
            (res' = true ↔ ∀ j, j < it'.start.val → a.val[j]? = b.val[j]?)) ∧
            it'.end.val - it'.start.val < it.end.val - it.start.val ⌝ ⦄ := by
    intro it res hend hlen hle hres
    unfold core.Slice.Insts.CoreCmpPartialEqSlice.eq_loop.body
    mvcgen [heq, core.ops.range.Range.Insts.CoreIterTraitsIteratorIterator.next_Usize_spec]
    · -- exhausted range
      rename_i r hr hnx
      by_cases hlt : it.start.val < it.end.val
      · rw [(hnx.1 hlt).1] at hr; simp at hr
      · have hse : it.start.val = it.end.val := by omega
        rcases Bool.eq_false_or_eq_true res with hr1 | hr1
        · rw [hr1]
          have hall := hres.mp hr1
          simp only [true_eq_decide_iff]
          apply List.ext_getElem?
          intro j
          by_cases hj : j < it.start.val
          · exact hall j hj
          · rw [List.getElem?_eq_none_iff.mpr (by omega), List.getElem?_eq_none_iff.mpr (by omega)]
        · rw [hr1]
          simp only [false_eq_decide_iff]
          intro hab'
          have : res = true := by
            apply hres.mpr; intro j _; rw [hab']
          rw [hr1] at this; simp at this
    · rename_i r i hi hres1 hnx x hx y hy c hc hdec
      obtain ⟨hlt, hii, hs, he⟩ := core.ops.range.Range.next_Usize_some it r i hi hnx
      subst hii
      have he' : r.2.end.val = it.end.val := by rw [he]
      obtain ⟨hxl, hxe⟩ := hx
      obtain ⟨hyl, hye⟩ := hy
      have hxy : x = y := by subst hc; simpa using hdec.symm
      have hall := hres.mp hres1
      refine ⟨⟨by omega, by omega, ⟨fun _ j hj => ?_, fun _ => trivial⟩⟩, by omega⟩
      by_cases hji : j < it.start.val
      · exact hall j hji
      · have hj : j = it.start.val := by omega
        subst hj
        rw [List.getElem?_eq_getElem (by scalar_tac), List.getElem?_eq_getElem (by scalar_tac)]
        simp [← hxe, ← hye, hxy]
    · rename_i r i hi hres1 hnx x hx y hy c hc hdec
      obtain ⟨hlt, hii, hs, he⟩ := core.ops.range.Range.next_Usize_some it r i hi hnx
      subst hii
      have he' : r.2.end.val = it.end.val := by rw [he]
      obtain ⟨hxl, hxe⟩ := hx
      obtain ⟨hyl, hye⟩ := hy
      have hne : x ≠ y := by
        intro hxy; apply hc; rw [hdec]; simp [hxy]
      refine ⟨⟨by omega, by omega, ⟨fun h => absurd h (by simp), fun hall => ?_⟩⟩, by omega⟩
      exfalso
      have := hall it.start.val (by omega)
      rw [List.getElem?_eq_getElem (by scalar_tac), List.getElem?_eq_getElem (by scalar_tac)] at this
      apply hne
      have h2 := Option.some.inj this
      rw [hxe, hye]; exact h2
    · rename_i r i hi hres1 hnx x hx hbl
      obtain ⟨hlt, hii, hs, he⟩ := core.ops.range.Range.next_Usize_some it r i hi hnx
      subst hii
      exfalso; simp only [Slice.length] at hbl; omega
    · rename_i r i hi hres1 hnx hal
      obtain ⟨hlt, hii, hs, he⟩ := core.ops.range.Range.next_Usize_some it r i hi hnx
      subst hii
      exfalso; simp only [Slice.length] at hal; omega
    · rename_i r i hi hres1 hnx
      obtain ⟨hlt, hii, hs, he⟩ := core.ops.range.Range.next_Usize_some it r i hi hnx
      subst hii
      have he' : r.2.end.val = it.end.val := by rw [he]
      refine ⟨⟨by omega, by omega, ⟨fun h => absurd h (by simp), fun hall => ?_⟩⟩, by omega⟩
      exfalso
      apply hres1
      apply hres.mpr
      intro j hj
      exact hall j (by omega)
  have hloop : ∀ (it : core.ops.range.Range Std.Usize) (res : Bool),
      it.end.val = a.val.length → a.val.length = b.val.length →
      it.start.val ≤ it.end.val → (res = true ↔ ∀ j, j < it.start.val → a.val[j]? = b.val[j]?) →
      ⦃ ⌜ True ⌝ ⦄ core.Slice.Insts.CoreCmpPartialEqSlice.eq_loop inst it a b res
      ⦃ ⇓ r => ⌜ r = decide (a.val = b.val) ⌝ ⦄ := by
    intro it res hend hlen hle hres
    unfold core.Slice.Insts.CoreCmpPartialEqSlice.eq_loop
    apply Aeneas.Std.WP.spec_to_mvcgen
    apply Aeneas.Std.loop.spec_decr_nat
      (fun p : core.ops.range.Range Std.Usize × Bool => p.1.end.val - p.1.start.val)
      (fun p : core.ops.range.Range Std.Usize × Bool => p.1.end.val = a.val.length ∧
        p.1.start.val ≤ p.1.end.val ∧
        (p.2 = true ↔ ∀ j, j < p.1.start.val → a.val[j]? = b.val[j]?))
      (fun y => y = decide (a.val = b.val))
    · rintro ⟨it', res'⟩ hp
      obtain ⟨hp1, hp2, hp3⟩ := hp
      obtain ⟨v, hv, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
        (hbody it' res' hp1 hlen hp2 hp3)
      show Aeneas.Std.WP.spec (core.Slice.Insts.CoreCmpPartialEqSlice.eq_loop.body inst a b it' res') _
      rw [hv, Aeneas.Std.WP.spec_ok]
      cases v with
      | done y => exact hP
      | cont q => exact hP
    · exact ⟨hend, hle, hres⟩
  unfold core.Slice.Insts.CoreCmpPartialEqSlice.eq
  mvcgen
  · rename_i r1 h1 r2 hne h2
    subst h1 h2
    symm
    simp only [decide_eq_false_iff_not]
    intro hab
    have : a.len = b.len := by
      apply UScalar.eq_of_val_eq; simp [Slice.len, hab]
    simp [this] at hne
  · rename_i r1 h1 r2 hne
    intro h2
    subst h1 h2
    have hl : a.val.length = b.val.length := by
      by_contra hn
      apply hne
      simp [Slice.len]
      intro h; apply hn; scalar_tac
    have := hloop { start := 0#usize, «end» := a.len } true (by simp [Slice.len]) hl
      (by simp [Slice.len]) (by simp)
    exact this trivial

/-- `<[u8]>::ends_with` decides "`needle` is a suffix of `s`" (the trait-level
    `DeserializeBytes` post). -/
@[spec]
theorem core.slice.Slice.ends_with_u8_spec (s needle : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ core.slice.Slice.ends_with core.U8.Insts.CoreCmpPartialEqU8 s needle
    ⦃ ⇓ r => ⌜ r = decide (needle.val <:+ s.val) ⌝ ⦄ := by
  have hs : ∀ a b : Slice Std.U8, ⦃ ⌜ True ⌝ ⦄
      core.Slice.Insts.CoreCmpPartialEqSlice.eq core.U8.Insts.CoreCmpPartialEqU8 a b
      ⦃ ⇓ r => ⌜ r = decide (a.val = b.val) ⌝ ⦄ := fun a b =>
    core.Slice.Insts.CoreCmpPartialEqSlice.eq_spec _ a b
      core.U8.Insts.CoreCmpPartialEqU8.eq_decide_spec
  unfold core.slice.Slice.ends_with core.slice.Slice.len
    rust_primitives.slice.slice_length rust_primitives.slice.slice_slice Slice.subslice
  mvcgen [hs]
  · rename_i r ha _ _ b
    intro hb; subst hb
    have hsl : s.len.val = s.val.length := by simp
    have hnl : needle.len.val = needle.val.length := by simp
    have hslice : List.slice r.val s.len.val s.val =
        s.val.drop (s.val.length - needle.val.length) := by
      rw [ha, hsl, hnl]; simp [List.slice]
    simp only [hslice, decide_eq_decide, List.suffix_iff_eq_drop]
    exact eq_comm
  · rename_i h; exfalso; apply h; scalar_tac
  · exfalso; scalar_tac
  · rename_i h
    simp only [false_eq_decide_iff]
    intro hsuf; apply h; have := hsuf.length_le; scalar_tac

theorem core.slice.Slice.ends_with_u8_eq (s needle : Slice Std.U8) :
    core.slice.Slice.ends_with core.U8.Insts.CoreCmpPartialEqU8 s needle =
      ok (decide (needle.val <:+ s.val)) := by
  obtain ⟨v, hv, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (core.slice.Slice.ends_with_u8_spec s needle)
  rw [hv, hP]

@[spec high]
theorem core.ops.range.RangeFromUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get_spec
    {T : Type} (r : core.ops.range.RangeFrom Std.Usize) (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ core.ops.range.RangeFromUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get r s
    ⦃ ⇓ o => ⌜ (r.start.val ≤ s.val.length → ∃ t : Slice T, o = some t ∧ t.val = s.val.drop r.start.val) ∧
               (s.val.length < r.start.val → o = none) ⌝ ⦄ := by
  unfold core.ops.range.RangeFromUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get
    rust_primitives.slice.slice_length rust_primitives.slice.slice_slice Slice.subslice
  mvcgen
  · rename_i h1 h2
    have hl : (s.len).val = s.val.length := by simp
    have hs : r.start.val ≤ s.val.length := by scalar_tac
    refine ⟨fun _ => ⟨_, rfl, ?_⟩, fun h => by scalar_tac⟩
    simp [List.slice, hl]
  · rename_i h1 h2
    exfalso; apply h2; have hl : (s.len).val = s.val.length := by simp
    scalar_tac
  · rename_i h1
    have hl : (s.len).val = s.val.length := by simp
    refine ⟨fun h => by scalar_tac, fun _ => trivial⟩

@[spec]
theorem core.ops.range.RangeFromUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.index_spec
    {T : Type} (r : core.ops.range.RangeFrom Std.Usize) (s : Slice T)
    (h : r.start.val ≤ s.val.length) :
    ⦃ ⌜ True ⌝ ⦄ core.ops.range.RangeFromUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.index r s
    ⦃ ⇓ t => ⌜ t.val = s.val.drop r.start.val ⌝ ⦄ := by
  unfold core.ops.range.RangeFromUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.index
    rust_primitives.slice.slice_length rust_primitives.slice.slice_slice Slice.subslice
  mvcgen
  · have hl : (s.len).val = s.val.length := by simp
    simp [List.slice, hl]
  · rename_i h2
    exfalso; apply h2; have hl : (s.len).val = s.val.length := by simp
    scalar_tac

@[spec high]
theorem core.ops.range.RangeToUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get_spec
    {T : Type} (r : core.ops.range.RangeTo Std.Usize) (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ core.ops.range.RangeToUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get r s
    ⦃ ⇓ o => ⌜ (r.end.val ≤ s.val.length → ∃ t : Slice T, o = some t ∧ t.val = s.val.take r.end.val) ∧
               (s.val.length < r.end.val → o = none) ⌝ ⦄ := by
  unfold core.ops.range.RangeToUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get
    rust_primitives.slice.slice_length rust_primitives.slice.slice_slice Slice.subslice
  mvcgen
  · rename_i h1 h2
    have hl : (s.len).val = s.val.length := by simp
    refine ⟨fun _ => ⟨_, rfl, ?_⟩, fun h => by scalar_tac⟩
    simp [List.slice]
  · rename_i h1 h2
    exfalso; apply h2; have hl : (s.len).val = s.val.length := by simp
    scalar_tac
  · rename_i h1
    have hl : (s.len).val = s.val.length := by simp
    refine ⟨fun h => by scalar_tac, fun _ => trivial⟩

@[spec]
theorem core.ops.range.RangeToUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.index_spec
    {T : Type} (r : core.ops.range.RangeTo Std.Usize) (s : Slice T)
    (h : r.end.val ≤ s.val.length) :
    ⦃ ⌜ True ⌝ ⦄ core.ops.range.RangeToUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.index r s
    ⦃ ⇓ t => ⌜ t.val = s.val.take r.end.val ⌝ ⦄ := by
  unfold core.ops.range.RangeToUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.index
    rust_primitives.slice.slice_slice Slice.subslice
  mvcgen
  rename_i h2
  exfalso; apply h2; scalar_tac

/-- `&mut s[start..]`: the suffix, with a write-back that overwrites the suffix and keeps the rest
(and the length). Reached through `Slice`'s `index_mut`. -/
@[spec]
theorem core.ops.range.RangeFromUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get_unchecked_mut_spec
    {T : Type} (r : core.ops.range.RangeFrom Std.Usize) (s : Slice T)
    (h : r.start.val ≤ s.val.length) :
    ⦃ ⌜ True ⌝ ⦄
    core.ops.range.RangeFromUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get_unchecked_mut r s
    ⦃ ⇓ p => ⌜ p.1.val = s.val.drop r.start.val ∧
               ∀ x : Slice T, (p.2 x).val = s.val.setSlice! r.start.val x.val ⌝ ⦄ := by
  unfold core.ops.range.RangeFromUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get_unchecked_mut
    rust_primitives.slice.slice_length rust_primitives.slice.slice_slice_mut Slice.subslice
  mvcgen
  · have hl' : (s.len).val = s.val.length := by simp
    refine ⟨?_, fun x => trivial⟩
    simp [List.slice, hl']
  · rename_i h2
    exfalso; apply h2
    have hl' : (s.len).val = s.val.length := by simp
    constructor <;> scalar_tac

/-- `&mut s[..end]`: the prefix, with a write-back that overwrites the prefix and keeps the rest
(and the length). Reached through `Slice`'s `index_mut`. -/
@[spec]
theorem core.ops.range.RangeToUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get_unchecked_mut_spec
    {T : Type} (r : core.ops.range.RangeTo Std.Usize) (s : Slice T)
    (h : r.end.val ≤ s.val.length) :
    ⦃ ⌜ True ⌝ ⦄
    core.ops.range.RangeToUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get_unchecked_mut r s
    ⦃ ⇓ p => ⌜ p.1.val = s.val.take r.end.val ∧
               ∀ x : Slice T, (p.2 x).val = s.val.setSlice! 0 x.val ⌝ ⦄ := by
  unfold core.ops.range.RangeToUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get_unchecked_mut
    rust_primitives.slice.slice_slice_mut Slice.subslice
  mvcgen
  · refine ⟨?_, fun x => rfl⟩
    simp [List.slice]
  · rename_i h2
    exfalso; apply h2; constructor <;> scalar_tac

@[spec]
theorem core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.get_spec
    {T : Type} (r : core.ops.range.RangeFull) (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.get r s
    ⦃ ⇓ o => ⌜ o = some s ⌝ ⦄ := by
  unfold core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.get; mvcgen

@[spec]
theorem core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.index_spec
    {T : Type} (r : core.ops.range.RangeFull) (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.index r s
    ⦃ ⇓ t => ⌜ t = s ⌝ ⦄ := by
  unfold core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.index; mvcgen

/-! ### `PartialEq.Lawful` of the core instances

The generated `RoundTrip.Lawful` glue needs `core.cmp.PartialEq.Lawful` for the core types the
crate instantiates (named `<instance>.Lawful`, as for the crate's own impls). Facts about the
CoreModels definitions: `eq` decides `HEq`, `ne` does not fail. -/

/-- A `PartialEq.Lawful` from `eq` deciding `=` and `ne` not failing. -/
theorem core.cmp.PartialEq.Lawful.of_eq_iff {T : Type} {inst : core.cmp.PartialEq T T}
    (heq : ∀ x y, ⦃ ⌜ True ⌝ ⦄ inst.eq x y ⦃ ⇓ r => ⌜ r = true ↔ x = y ⌝ ⦄)
    (hne : ∀ x y, ⦃ ⌜ True ⌝ ⦄ inst.ne x y ⦃ ⇓ _ => ⌜ True ⌝ ⦄) :
    core.cmp.PartialEq.Lawful T T inst where
  eq_spec x y := by simpa only [heq_iff_eq] using heq x y
  ne_spec := hne

/-- The `decide` form of `eq` (classical decidability), from a `PartialEq.Lawful`. -/
theorem core.cmp.PartialEq.Lawful.eq_decide {T : Type} {inst : core.cmp.PartialEq T T}
    (hl : core.cmp.PartialEq.Lawful T T inst) (x y : T) :
    ⦃ ⌜ True ⌝ ⦄ inst.eq x y
    ⦃ ⇓ r => ⌜ r = @decide (x = y) (Classical.propDecidable _) ⌝ ⦄ := by
  have h := hl.eq_spec x y
  mvcgen [h]
  intro hr
  rw [Bool.eq_iff_iff, hr]
  simp

theorem core.U8.Insts.CoreCmpPartialEqU8.Lawful :
    core.cmp.PartialEq.Lawful Std.U8 Std.U8 core.U8.Insts.CoreCmpPartialEqU8 :=
  .of_eq_iff (fun x y => by simp only [core.U8.Insts.CoreCmpPartialEqU8]; mvcgen; simp [beq_iff_eq])
    (fun x y => by simp only [core.U8.Insts.CoreCmpPartialEqU8]; mvcgen)

theorem core.U16.Insts.CoreCmpPartialEqU16.Lawful :
    core.cmp.PartialEq.Lawful Std.U16 Std.U16 core.U16.Insts.CoreCmpPartialEqU16 :=
  .of_eq_iff (fun x y => by simp only [core.U16.Insts.CoreCmpPartialEqU16]; mvcgen; simp [beq_iff_eq])
    (fun x y => by simp only [core.U16.Insts.CoreCmpPartialEqU16]; mvcgen)

theorem core.U32.Insts.CoreCmpPartialEqU32.Lawful :
    core.cmp.PartialEq.Lawful Std.U32 Std.U32 core.U32.Insts.CoreCmpPartialEqU32 :=
  .of_eq_iff (fun x y => by simp only [core.U32.Insts.CoreCmpPartialEqU32]; mvcgen; simp [beq_iff_eq])
    (fun x y => by simp only [core.U32.Insts.CoreCmpPartialEqU32]; mvcgen)

theorem core.U64.Insts.CoreCmpPartialEqU64.Lawful :
    core.cmp.PartialEq.Lawful Std.U64 Std.U64 core.U64.Insts.CoreCmpPartialEqU64 :=
  .of_eq_iff (fun x y => by simp only [core.U64.Insts.CoreCmpPartialEqU64]; mvcgen; simp [beq_iff_eq])
    (fun x y => by simp only [core.U64.Insts.CoreCmpPartialEqU64]; mvcgen)

theorem core.option.Option.Insts.CoreCmpPartialEqOption.Lawful {T : Type}
    (inst : core.cmp.PartialEq T T) (hl : core.cmp.PartialEq.Lawful T T inst) :
    core.cmp.PartialEq.Lawful (core.option.Option T) (core.option.Option T)
      (core.option.Option.Insts.CoreCmpPartialEqOption inst) := by
  classical
  have hs : ∀ a b, ⦃ ⌜ True ⌝ ⦄ core.option.Option.Insts.CoreCmpPartialEqOption.eq inst a b
      ⦃ ⇓ r => ⌜ r = true ↔ a = b ⌝ ⦄ := by
    intro a b
    have h := core.option.Option.Insts.CoreCmpPartialEqOption.eq_spec
      (inst := inst) (T := T) (a := a) (b := b) (fun x y => hl.eq_decide x y)
    mvcgen [h]
    intro hr; rw [hr]; simp
  refine .of_eq_iff hs fun a b => ?_
  have h := hs a b
  show ⦃ ⌜ True ⌝ ⦄ core.option.Option.Insts.CoreCmpPartialEqOption.ne inst a b ⦃ ⇓ _ => ⌜ True ⌝ ⦄
  unfold core.option.Option.Insts.CoreCmpPartialEqOption.ne
  mvcgen [h]

theorem core.Array.Insts.CoreCmpPartialEqArray.Lawful {T : Type} {N : Std.Usize}
    (inst : core.cmp.PartialEq T T) (hl : core.cmp.PartialEq.Lawful T T inst) :
    core.cmp.PartialEq.Lawful (Aeneas.Std.Array T N) (Aeneas.Std.Array T N)
      (core.Array.Insts.CoreCmpPartialEqArray N inst) := by
  classical
  have hs : ∀ a b : Aeneas.Std.Array T N, ⦃ ⌜ True ⌝ ⦄ core.Array.Insts.CoreCmpPartialEqArray.eq inst a b
      ⦃ ⇓ r => ⌜ r = true ↔ a = b ⌝ ⦄ := by
    intro a b
    have h := core.Array.Insts.CoreCmpPartialEqArray.eq_spec
      (inst := inst) (T := T) (N := N) (a := a) (b := b) (fun x y => hl.eq_decide x y)
    mvcgen [-core.Array.Insts.CoreCmpPartialEqArray.eq_spec, h]
    intro hr; rw [hr, decide_eq_true_iff]; exact ⟨Subtype.ext, congrArg Subtype.val⟩
  refine .of_eq_iff hs fun a b => ?_
  have h := hs a b
  show ⦃ ⌜ True ⌝ ⦄ core.Array.Insts.CoreCmpPartialEqArray.ne inst a b ⦃ ⇓ _ => ⌜ True ⌝ ⦄
  unfold core.Array.Insts.CoreCmpPartialEqArray.ne
  mvcgen [-core.Array.Insts.CoreCmpPartialEqArray.eq_spec, h]

end CoreModels

/-- Hand-filled def in `Assumptions/FunsExternal.lean` (root namespace). -/
theorem alloc.string.String.Insts.CoreCmpPartialEqString.eq_spec (a b : alloc.string.String) :
    ⦃ ⌜ True ⌝ ⦄ alloc.string.String.Insts.CoreCmpPartialEqString.eq a b
    ⦃ ⇓ r => ⌜ r = true ↔ a = b ⌝ ⦄ := by
  unfold alloc.string.String.Insts.CoreCmpPartialEqString.eq; mvcgen; simp

/-- `String`'s `PartialEq.Lawful`: `eq` decides `=`, `ne` is `!eq`. -/
theorem alloc.string.String.Insts.CoreCmpPartialEqString.Lawful :
    core.cmp.PartialEq.Lawful alloc.string.String alloc.string.String
      alloc.string.String.Insts.CoreCmpPartialEqString :=
  .of_eq_iff alloc.string.String.Insts.CoreCmpPartialEqString.eq_spec
    (fun a b => by
      have h := alloc.string.String.Insts.CoreCmpPartialEqString.eq_spec a b
      simp only [alloc.string.String.Insts.CoreCmpPartialEqString]
      mvcgen [h])

/-! ### `String` (hand-filled defs in `Assumptions/MissingCoreModels.lean`, root namespace)

`as_bytes`, `from_utf8` and `From<&str>` are stated with `utf8U8`, the UTF-8 encoding of
the string as `U8`s. -/

/-- The UTF-8 encoding of a string, as `U8`s (the bytes `as_bytes` returns). -/
def alloc.string.String.utf8U8 (s : alloc.string.String) : List Std.U8 :=
  s.toByteArray.data.toList.map fun b : UInt8 => (⟨b.toBitVec⟩ : Std.U8)

theorem alloc.string.String.utf8U8_length (s : alloc.string.String) :
    (alloc.string.String.utf8U8 s).length = s.toByteArray.size := by
  simp only [alloc.string.String.utf8U8, List.length_map, Array.length_toList]; rfl

/-- Bytes ↦ `U8`s ↦ bytes is the identity. -/
theorem alloc.string.String.map_ofBitVec_utf8U8 (s : alloc.string.String) :
    ((alloc.string.String.utf8U8 s).map fun b : Std.U8 => UInt8.ofBitVec b.bv).toArray
      = s.toByteArray.data := by
  simp [alloc.string.String.utf8U8, Function.comp_def]

theorem alloc.string.String.utf8U8_inj {s t : alloc.string.String}
    (h : alloc.string.String.utf8U8 s = alloc.string.String.utf8U8 t) : s = t := by
  have := congrArg (fun l : List Std.U8 => ByteArray.mk (l.map fun b => UInt8.ofBitVec b.bv).toArray) h
  simp only [alloc.string.String.map_ofBitVec_utf8U8] at this
  exact String.toByteArray_inj.mp this

theorem alloc.string.String.utf8U8_of_fromUTF8? {l : List Std.U8} {t : alloc.string.String}
    (h : String.fromUTF8? ⟨(l.map fun b : Std.U8 => UInt8.ofBitVec b.bv).toArray⟩ = some t) :
    alloc.string.String.utf8U8 t = l := by
  unfold String.fromUTF8? at h
  split at h
  · cases h
    simp [alloc.string.String.utf8U8, String.fromUTF8, Function.comp_def]
  · cases h

/-- `String.fromUTF8?` of the bytes of a string's `utf8U8` is that string. -/
theorem alloc.string.String.fromUTF8?_utf8U8 (t : alloc.string.String) :
    String.fromUTF8? ⟨((alloc.string.String.utf8U8 t).map fun b : Std.U8 => UInt8.ofBitVec b.bv).toArray⟩
      = some t := by
  rw [alloc.string.String.map_ofBitVec_utf8U8]
  unfold String.fromUTF8?
  rw [dif_pos t.isValidUTF8]
  rfl

@[spec]
theorem alloc.string.String.as_bytes_spec (s : alloc.string.String) :
    ⦃ ⌜ True ⌝ ⦄ alloc.string.String.as_bytes s
    ⦃ ⇓ r => ⌜ r.val = (alloc.string.String.utf8U8 s).take Usize.max ⌝ ⦄ := by
  unfold alloc.string.String.as_bytes; mvcgen

/-- `from_utf8` succeeds iff some string has exactly these bytes, and returns it. -/
@[spec]
theorem alloc.string.String.from_utf8_spec (v : alloc.vec.Vec Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ alloc.string.String.from_utf8 v
    ⦃ ⇓ r => ⌜ (∃ t, r = .Ok t ∧ alloc.string.String.utf8U8 t = v.val) ∨
               (r = .Err { bytes := v } ∧ ∀ t, alloc.string.String.utf8U8 t ≠ v.val) ⌝ ⦄ := by
  unfold alloc.string.String.from_utf8
  split
  · rename_i t ht
    mvcgen
    exact .inl ⟨t, rfl, alloc.string.String.utf8U8_of_fromUTF8? ht⟩
  · rename_i ht
    mvcgen
    refine .inr ⟨trivial, fun t heq => ?_⟩
    rw [← heq, alloc.string.String.fromUTF8?_utf8U8] at ht
    cases ht

/-- `String::from(&str)`, for a `Str` whose bytes are some string's UTF-8 encoding
    (every Rust `&str`, e.g. `toStr` literals). -/
@[spec]
theorem alloc.string.String.Insts.CoreConvertFromShared0Str.from_spec (s : Str)
    (h : ∃ t, alloc.string.String.utf8U8 t = s.val) :
    ⦃ ⌜ True ⌝ ⦄ alloc.string.String.Insts.CoreConvertFromShared0Str.from s
    ⦃ ⇓ r => ⌜ alloc.string.String.utf8U8 r = s.val ⌝ ⦄ := by
  obtain ⟨t, ht⟩ := h
  unfold alloc.string.String.Insts.CoreConvertFromShared0Str.from
  rw [← ht, alloc.string.String.fromUTF8?_utf8U8]
  mvcgen

/-! ## 3. The other `Assumptions/` axioms: listed

Signature-only (no spec; each is reached only on paths no obligation needs, or blocks the
obligations named in `PROOF_TARGETS.md`):

- `MissingCoreModels.lean`: `core.mem.size_of` (values fixed by the `size_of_*` axioms),
  `alloc.vec.Vec.Insts.CoreHashHash.hash`, `core.Array.Insts.CoreHashHash.hash`,
  `alloc.vec.Vec.Insts.CoreCmpOrd.cmp`,
  `alloc.vec.Vec.retain`, and the `….fmt` axioms of `FromUtf8Error`, `TryFromIntError`,
  `Infallible`, `io::Error` (`Debug`);
- `MissingThirdPartyModels.lean`: `zeroize.alloc.vec.Vec.Insts.ZeroizeZeroize.zeroize`;
- crate side (`FunsExternal.lean`): the crate `….fmt` axioms (incl. `SecretVLBytes` /
  `SecretVLByteVec` `Debug`) and `quic_vec.write_hex`.

ASSUMED specs / values (each in an `Assumptions/` file, docstring `ASSUMED`):

- `FmtAssumptions.lean`: `alloc.string.FromUtf8Error.Insts.CoreFmtDisplay.fmt.ok_spec`;
- `MissingCoreModels.lean`: the `core.mem.size_of_*` values;
- `CrateAssumptions.lean`: `core.mem.size_of_U24`, `append_bytes` (opaque) with
  `append_bytes_spec`, `numBits_eq_64`.

`len_add` / `checked_len_add` are extracted; their specs are theorems (`Helpers.lean`).
-/
