/- The hand-translated opaque bodies of `Assumptions/FunsExternal.lean`: the verbatim copies
`tls_codec.Copied.*` equal the extracted functions (by `rfl`), and the specs of the hand-translated
`get_content_lengths`.

Obligations: none directly; the bytes-path halves of `PanicFreedom.lean` /
`FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): ASSUMED `size_of`, `size_of_Usize`, `numBits_eq_64`;
2 signature-only stubs (`core.convert.Infallible.Insts.CoreFmtDebug.fmt`,
`core.num.error.TryFromIntError.Insts.CoreFmtDebug.fmt`). -/
import TlsCodec.Verification.Helpers.PrefixSer
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! ### Hand-translated opaque bodies (`Assumptions/FunsExternal.lean`)

`Assumptions/` is compiled before `Extraction/Funs.lean`, so the hand-written bodies of
`get_content_lengths`, `<&[T]>::tls_serialize_bytes` and `<Box<T>>::tls_deserialize_bytes`
call verbatim copies (`tls_codec.Copied.*`) of the crate functions they need. Each copy is
equal to its original; rewrite with these to reuse the originals' specs. -/

namespace Copied
theorem checked_alloc_len_eq : checked_alloc_len = _root_.tls_codec.checked_alloc_len := rfl
theorem U24.MAX_eq : U24.MAX = _root_.tls_codec.U24.MAX := by with_unfolding_all rfl
theorem Usize.Insts.CoreConvertFromU24_eq :
    Usize.Insts.CoreConvertFromU24 = _root_.tls_codec.Usize.Insts.CoreConvertFromU24 := by
  with_unfolding_all rfl
theorem U8.Insts.Tls_codecSize.tls_serialized_len_eq :
    U8.Insts.Tls_codecSize.tls_serialized_len =
      _root_.tls_codec.U8.Insts.Tls_codecSize.tls_serialized_len := rfl
theorem quic_vec.ContentLength.from_usize_eq :
    quic_vec.ContentLength.from_usize = _root_.tls_codec.quic_vec.ContentLength.from_usize := by
  with_unfolding_all rfl
theorem varint.TlsVarInt.bytes_len_eq :
    varint.TlsVarInt.bytes_len = _root_.tls_codec.varint.TlsVarInt.bytes_len := rfl
theorem varint.TlsVarInt.write_bytes_eq :
    varint.TlsVarInt.write_bytes = _root_.tls_codec.varint.TlsVarInt.write_bytes := by
  with_unfolding_all rfl
theorem varint.TlsVarInt.write_bytes_eq_of_le (self : varint.TlsVarInt) (buf : Slice Std.U8)
    (_hv : self.val ≤ 2 ^ 62 - 1) :
    varint.TlsVarInt.write_bytes self buf = _root_.tls_codec.varint.TlsVarInt.write_bytes self buf := by
  rw [varint.TlsVarInt.write_bytes_eq]
end Copied

/-- `write_bytes_spec_le` for the copy. -/
theorem Copied.varint.TlsVarInt.write_bytes_spec (self : varint.TlsVarInt) (buf : Slice Std.U8)
    (hv : self.val ≤ 2 ^ 62 - 1) :
    ⦃ ⌜ True ⌝ ⦄ Copied.varint.TlsVarInt.write_bytes self buf
    ⦃ ⇓ r => ⌜ (buf.val.length < varint.lenOf self.val →
                  r = (.Err Error.InvalidVectorLength, buf)) ∧
               (varint.lenOf self.val ≤ buf.val.length →
                  (∃ l : Std.Usize, r.1 = .Ok l ∧ l.val = varint.lenOf self.val) ∧
                  r.2.val.length = buf.val.length) ⌝ ⦄ := by
  rw [Copied.varint.TlsVarInt.write_bytes_eq_of_le self buf hv]
  exact varint.TlsVarInt.write_bytes_spec_le self buf hv

/-! ### Specs of the hand-translated `get_content_lengths` -/

/-- `Vec` deref and `slice::iter` are the identity (re-packed, so the result is type-correct at
instance transparency and `bind_tc_ok` can fire after `erw`). -/
theorem deref_vec_ok {T : Type} (v : alloc.vec.Vec T) :
    alloc.vec.Vec.Insts.CoreOpsDerefDerefSlice.deref v = RustM.ok (⟨v.val, v.property⟩ : Slice T) := rfl
theorem slice_iter_ok {T : Type} (s : Slice T) :
    core.slice.Slice.iter s = RustM.ok (⟨s.val, s.property⟩ : core.slice.iter.Iter T) := rfl

/-- A `loop` that walks a slice iterator and adds `c` to an accumulator per element (the
`try_fold` of the length sums in the hand-translated bodies). `hbody`: one step. -/
theorem loop_len_sum_spec {T : Type} (c : Std.Usize) (it : core.slice.iter.Iter T) (acc : Std.Usize)
    (body : core.slice.iter.Iter T × Std.Usize →
      RustM (ControlFlow (core.slice.iter.Iter T × Std.Usize) (core.result.Result Std.Usize Error)))
    (h : acc.val + c.val * (it : Slice T).val.length ≤ Usize.max)
    (hbody : ∀ (it' : core.slice.iter.Iter T) (a : Std.Usize),
      a.val + c.val * (it' : Slice T).val.length ≤ Usize.max →
      ⦃ ⌜ True ⌝ ⦄ body (it', a)
      ⦃ ⇓ r => ⌜ match r with
        | .done y => y = .Ok a ∧ (it' : Slice T).val.length = 0
        | .cont p => p.2.val = a.val + c.val ∧ (p.1 : Slice T).val.length + 1 = (it' : Slice T).val.length ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ loop body (it, acc)
    ⦃ ⇓ r => ⌜ ∃ v : Std.Usize, r = .Ok v ∧ v.val = acc.val + c.val * (it : Slice T).val.length ⌝ ⦄ := by
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.loop.spec_decr_nat
    (fun p : core.slice.iter.Iter T × Std.Usize => (p.1 : Slice T).val.length)
    (fun p => p.2.val + c.val * (p.1 : Slice T).val.length = acc.val + c.val * (it : Slice T).val.length)
  · rintro ⟨it', a⟩ hinv
    have hb := Aeneas.Std.WP.exists_imp_spec
      (Aeneas.Std.WP.triple_iff_exists_ok.mp (hbody it' a (by simp only at hinv; omega)))
    apply Aeneas.Std.WP.spec_mono hb
    intro r hr
    simp only at hinv
    cases r with
    | done y =>
      obtain ⟨rfl, hl⟩ := hr
      exact ⟨a, rfl, by rw [hl] at hinv; omega⟩
    | cont p =>
      obtain ⟨ha, hl⟩ := hr
      refine ⟨?_, by simp only; omega⟩
      rw [← hl, Nat.mul_succ] at hinv
      omega
  · simp

/-- Sequencing through a total step: if `x` returns with `P`, any post of `x >>= f` follows from
the posts of `f` on the `P` values (for `⇓` and `⇓?` alike). -/
theorem triple_bind_of_total {α β : Type} {x : RustM α} {f : α → RustM β} {P : α → Prop}
    {Q : Std.Do.PostCond β (Std.Do.PostShape.except (ULift Std.Error) (Std.Do.PostShape.except PUnit.{1} Std.Do.PostShape.pure))}
    (hx : ⦃ ⌜ True ⌝ ⦄ x ⦃ ⇓ r => ⌜ P r ⌝ ⦄) (hf : ∀ r, P r → ⦃ ⌜ True ⌝ ⦄ f r ⦃ Q ⦄) :
    ⦃ ⌜ True ⌝ ⦄ (x >>= f) ⦃ Q ⦄ := by
  obtain ⟨a, rfl, ha⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp hx
  simpa using hf a ha

/-- `hbody` obligation of `loop_len_sum_spec` for the `try_fold` loop of `get_content_lengths`.
The loop body is the same for every `TlsByteVecU*` width. (It cannot be stated as a lemma: the
restated body gets different `match` auxiliary definitions and `exact` fails, so the script is shared as a macro.) -/
macro "glen_hbody" : tactic => `(tactic| (
  intro it a ha
  mvcgen [core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.next,
    Copied.U8.Insts.Tls_codecSize.tls_serialized_len, checked_len_add_triple, tls_codec.Copied.checked_len_add_triple]
  all_goals (fits_rw; simp_all [tryCF, -List.length_eq_zero_iff]; try first | scalar_tac | (have := checkedLenAddVal_val a 1#usize (by scalar_tac); scalar_tac))))

/-- `hk` continuation of the `get_content_lengths` proofs for the plain-`MAX` widths: `max` is the
`core.num.U*.MAX` constant, `rmax` the matching `U*.rMax`, `w` the prefix width. -/
macro "glen_hk " max:term:max rmax:term:max w:term:max : tactic => `(tactic| (
  rintro r ⟨v, rfl, hv⟩
  mvcgen [checked_len_add_triple, tls_codec.Copied.checked_len_add_triple]
  all_goals (simp_all [tryCF, $max:term, $rmax:term]; try fits_rw; try simp_all [tryCF])
  all_goals try (intro h; split at h <;> simp_all)
  all_goals try (mvcgen [core.convert.From.Blanket.from_spec]; try simp [PostCond.ok])
  all_goals first | scalar_tac | (have := checkedLenAddVal_val v $w (by scalar_tac); scalar_tac)))

/-- `get_content_lengths` of a `TlsByteVecU8` never fails (an over-long vector gives `Err`); an `Ok` result is `(len + 1, len)` with `len ≤ 255`. -/
theorem tls_vec.TlsByteVecU8.get_content_lengths_char (self : tls_vec.TlsByteVecU8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU8.get_content_lengths self
    ⦃ ⇓ r => ⌜ ∀ p : Std.Usize × Std.Usize, r = .Ok p → p.2.val = self.vec.val.length ∧
        p.1.val = self.vec.val.length + 1 ∧ self.vec.val.length ≤ 255 ⌝ ⦄ := by
  unfold tls_vec.TlsByteVecU8.get_content_lengths
  simp only [deref_vec_ok, slice_iter_ok]
  erw [bind_tc_ok, bind_tc_ok]
  refine triple_bind_of_total (loop_len_sum_spec 1#usize _ 0#usize _ ?hlen ?hbody) ?hk
  case hlen => scalar_tac
  case hk => glen_hk core.num.U8.MAX U8.rMax 1#usize
  case hbody => glen_hbody


/-- `get_content_lengths` of a `TlsByteVecU16` never fails (an over-long vector gives `Err`); an `Ok` result is `(len + 2, len)` with `len ≤ 65535`. -/
theorem tls_vec.TlsByteVecU16.get_content_lengths_char (self : tls_vec.TlsByteVecU16) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU16.get_content_lengths self
    ⦃ ⇓ r => ⌜ ∀ p : Std.Usize × Std.Usize, r = .Ok p → p.2.val = self.vec.val.length ∧
        p.1.val = self.vec.val.length + 2 ∧ self.vec.val.length ≤ 65535 ⌝ ⦄ := by
  unfold tls_vec.TlsByteVecU16.get_content_lengths
  simp only [deref_vec_ok, slice_iter_ok]
  erw [bind_tc_ok, bind_tc_ok]
  refine triple_bind_of_total (loop_len_sum_spec 1#usize _ 0#usize _ ?hlen ?hbody) ?hk
  case hlen => scalar_tac
  case hk => glen_hk core.num.U16.MAX U16.rMax 2#usize
  case hbody => glen_hbody



/-- `get_content_lengths` of a `TlsByteVecU32` never fails (an over-long vector gives `Err`); an `Ok` result is `(len + 4, len)` with `len ≤ 2^32 - 1`. -/
theorem tls_vec.TlsByteVecU32.get_content_lengths_char (self : tls_vec.TlsByteVecU32) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU32.get_content_lengths self
    ⦃ ⇓ r => ⌜ ∀ p : Std.Usize × Std.Usize, r = .Ok p → p.2.val = self.vec.val.length ∧
        p.1.val = self.vec.val.length + 4 ∧ self.vec.val.length ≤ 4294967295 ⌝ ⦄ := by
  unfold tls_vec.TlsByteVecU32.get_content_lengths
  simp only [deref_vec_ok, slice_iter_ok]
  erw [bind_tc_ok, bind_tc_ok]
  refine triple_bind_of_total (loop_len_sum_spec 1#usize _ 0#usize _ ?hlen ?hbody) ?hk
  case hlen => scalar_tac
  case hk => have := numBits_eq_64; glen_hk core.num.U32.MAX U32.rMax 4#usize
  case hbody => glen_hbody


/-- The bytes of `U24::MAX`. -/
theorem U24.MAX_val : U24.MAX.val = [255#u8, 255#u8, 255#u8] := by
  unfold U24.MAX
  simp [Std.Array.repeat]

/-- `get_content_lengths` of a `TlsByteVecU24` never fails (an over-long vector gives `Err`); an `Ok` result is `(len + 3, len)` with `len ≤ 2^24 - 1`. -/
theorem tls_vec.TlsByteVecU24.get_content_lengths_char (self : tls_vec.TlsByteVecU24) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU24.get_content_lengths self
    ⦃ ⇓ r => ⌜ ∀ p : Std.Usize × Std.Usize, r = .Ok p → p.2.val = self.vec.val.length ∧
        p.1.val = self.vec.val.length + 3 ∧ self.vec.val.length ≤ 16777215 ⌝ ⦄ := by
  unfold tls_vec.TlsByteVecU24.get_content_lengths
  simp only [deref_vec_ok, slice_iter_ok]
  erw [bind_tc_ok, bind_tc_ok]
  refine triple_bind_of_total (loop_len_sum_spec 1#usize _ 0#usize _ ?hlen ?hbody) ?hk
  case hlen => scalar_tac
  case hk =>
    rintro r ⟨v, rfl, hv⟩
    have hmax : ∀ y : Std.Usize, (∀ b0 b1 b2 : Std.U8, U24.MAX.val = [b0, b1, b2] →
        y.val = b0.val * 65536 + b1.val * 256 + b2.val) → y.val = 16777215 := by
      intro y h
      have := h 255#u8 255#u8 255#u8 U24.MAX_val
      simpa using this
    simp only [Copied.Usize.Insts.CoreConvertFromU24_eq, Copied.U24.MAX_eq]
    mvcgen [checked_len_add_triple, tls_codec.Copied.checked_len_add_triple, core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U24_content,
      core.result.Result.unwrap_ok_spec]
    try_vcs
    · obtain ⟨y, hy, -⟩ := ‹∃ y, _ = core.result.Result.Ok y ∧ _›
      exact ⟨y, hy⟩
    · obtain ⟨y, hy, hh⟩ := ‹∃ y, _ = core.result.Result.Ok y ∧ _›
      have hr := hmax y hh
      clear hmax hh
      simp_all [tryCF, -List.length_eq_zero_iff]
    · obtain ⟨y, hy, hh⟩ := ‹∃ y, _ = core.result.Result.Ok y ∧ _›
      have hr := hmax y hh
      clear hmax hh
      simp_all [tryCF, -List.length_eq_zero_iff]
      fits_rw
      simp_all
      have := checkedLenAddVal_val v 3#usize (by scalar_tac)
      scalar_tac
    · intro _
      clear hmax
      simp [PostCond.ok]
  case hbody => glen_hbody

end tls_codec
