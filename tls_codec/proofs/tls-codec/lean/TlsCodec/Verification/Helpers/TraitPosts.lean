/- Trait-level posts of the bytes path: `DeserializeBytes::tls_deserialize_exact_bytes` (trait
default), the `tls_deserialize_bytes` / `tls_serialize_bytes` posts from a characterization of the
result, and the length part of the `tls_deserialize_bytes` post.

Obligations: none directly; the bytes-path halves of `PanicFreedom.lean` /
`FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): nothing ASSUMED. -/
import TlsCodec.Verification.Helpers.SliceSer
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! ### `DeserializeBytes::tls_deserialize_exact_bytes` (trait default) -/

/-- The default `tls_deserialize_exact_bytes` does not fail when `tls_deserialize_bytes` does not. -/
theorem DeserializeBytes.exact_default_pf {Self : Type} (inst : DeserializeBytes Self)
    (h : ∀ b, ⦃ ⌜ True ⌝ ⦄ inst.tls_deserialize_bytes b ⦃ ⇓ _ => ⌜ True ⌝ ⦄)
    (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ DeserializeBytes.tls_deserialize_exact_bytes.default inst bytes
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  have hb := h bytes
  mvcgen [DeserializeBytes.tls_deserialize_exact_bytes.default, hb]
  rename_i r _ residual _
  intro hx
  cases r <;> simp only [tls_codec.tryCF, reduceCtorEq, core.ops.control_flow.ControlFlow.Break.injEq] at hx
  subst hx
  refine ⟨_, rfl, ?_⟩
  mvcgen

/-- The default `tls_deserialize_exact_bytes` meets its post given the post of
`tls_deserialize_bytes` (on the `ok` outcomes). -/
theorem DeserializeBytes.exact_default_fc {Self : Type} (inst : DeserializeBytes Self)
    (bytes : Slice Std.U8)
    (h : ⦃ ⌜ True ⌝ ⦄ inst.tls_deserialize_bytes bytes
      ⦃ ⇓? res => ⌜ (DeserializeBytes.tls_deserialize_bytes.post inst.SizeInst inst bytes res).holds ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ DeserializeBytes.tls_deserialize_exact_bytes.default inst bytes
    ⦃ ⇓? res => ⌜ (DeserializeBytes.tls_deserialize_exact_bytes.post inst.SizeInst inst bytes res).holds ⌝ ⦄ := by
  apply partial_triple_of_ok
  intro r hr
  unfold DeserializeBytes.tls_deserialize_exact_bytes.default at hr
  have hl : ∀ (rem : Slice Std.U8), core.slice.Slice.len rem = ok (Slice.len rem) := by
    intro rem; unfold core.slice.Slice.len; rfl
  cases hd : inst.tls_deserialize_bytes bytes with
  | ok r0 =>
    have hp := ok_of_partial_triple h hd
    rw [hd] at hr
    cases r0 with
    | Err e =>
      simp [core.result.Result.Insts.CoreOpsTry_traitTry.branch,
        core.result.Result.Insts.CoreOpsTry_traitTryTResultInfallibleE.branch,
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual,
        core.convert.From.Blanket.from] at hr
      subst hr
      simp [DeserializeBytes.tls_deserialize_exact_bytes.post, core.result.Result.is_err, RustM.holds]
      mvcgen
    | Ok p =>
      obtain ⟨o, rem⟩ := p
      simp [core.result.Result.Insts.CoreOpsTry_traitTry.branch,
        core.result.Result.Insts.CoreOpsTry_traitTryTResultInfallibleE.branch,
        core.slice.Slice.is_empty, hl] at hr
      by_cases h0 : Slice.len rem = 0#usize
      · rw [if_pos h0] at hr
        have := ok.inj hr
        subst this
        simp only [DeserializeBytes.tls_deserialize_bytes.post, core.result.Result.is_err,
          core.result.Result.is_ok_and,
          __9.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairSelf_SharedSliceU8Bool,
          __9.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairSelf_SharedSliceU8Bool.call_once,
          DeserializeBytes.tls_deserialize_exact_bytes.post,
          __10.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleSelf_Bool,
          __10.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleSelf_Bool.call_once, hl,
          core.slice.Slice.ends_with_u8_eq] at hp ⊢
        have hz : (↑rem : List U8).length = 0 := by
          have := congrArg UScalar.val h0
          simpa [Slice.len] using this
        have hsuf : (↑rem : List U8) <:+ ↑bytes := by
          rw [List.eq_nil_of_length_eq_zero hz]; exact List.nil_suffix
        cases hL : inst.SizeInst.tls_serialized_len o with
        | ok i2 =>
          simp [hL, hz, hsuf] at hp ⊢
          rw [h0] at hp
          have h1 : (0#usize + i2 : RustM Usize) = ok i2 := by
            have := Aeneas.Std.UScalar.add_equiv (0#usize) i2
            cases hc : (0#usize + i2 : RustM Usize) with
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
          simp [h1] at hp
          exact hp
        | fail e => simp [hL, hz, hsuf, RustM.holds] at hp ⊢; exact hp
        | div => simp [hL, hz, hsuf, RustM.holds] at hp ⊢; exact hp
      · rw [if_neg h0] at hr
        have := ok.inj hr
        subst this
        simp [DeserializeBytes.tls_deserialize_exact_bytes.post, core.result.Result.is_err, RustM.holds]
        mvcgen
  | fail e => rw [hd] at hr; simp at hr
  | div => rw [hd] at hr; simp at hr

/-! ### Trait-level `tls_deserialize_bytes` post from a characterization of the result -/

/-- An `Err` result meets the trait-level post of `tls_deserialize_bytes`. -/
theorem DeserializeBytes.post_err {Self : Type} (SizeInst : Size Self) (inst : DeserializeBytes Self)
    (bytes : Slice Std.U8) (e : Error) :
    (DeserializeBytes.tls_deserialize_bytes.post SizeInst inst bytes (.Err e)).holds := by
  simp [DeserializeBytes.tls_deserialize_bytes.post, core.result.Result.is_err, RustM.holds]
  mvcgen

/-- An `Ok (v, rem)` result meets the trait-level post of `tls_deserialize_bytes` when the size
of `v` is `n`, `rem.len + n = bytes.len` and `rem` is a suffix of `bytes`. -/
theorem DeserializeBytes.post_ok {Self : Type} (SizeInst : Size Self) (inst : DeserializeBytes Self)
    (bytes : Slice Std.U8) (v : Self) (rem : Slice Std.U8) (n : Std.Usize)
    (hn : SizeInst.tls_serialized_len v = ok n)
    (hrem : rem.val.length + n.val = bytes.val.length)
    (hsuf : rem.val <:+ bytes.val) :
    (DeserializeBytes.tls_deserialize_bytes.post SizeInst inst bytes (.Ok (v, rem))).holds := by
  have hl : ∀ (s : Slice Std.U8), core.slice.Slice.len s = ok (Slice.len s) := by
    intro s; unfold core.slice.Slice.len; rfl
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
  simp only [DeserializeBytes.tls_deserialize_bytes.post, core.result.Result.is_err,
    core.result.Result.is_ok_and,
    __9.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairSelf_SharedSliceU8Bool.call_once,
    hl, core.slice.Slice.ends_with_u8_eq]
  simp [hn, hadd, RustM.holds, hsuf]
  have hle : (rem.val.length ≤ bytes.val.length) := by omega
  simp only [hle, if_true]
  mvcgen

/-- `String::tls_serialized_len` for a string of at most `2^30 - 1` bytes: the byte length plus its
varint prefix length (as for `<&[u8]>::tls_serialized_len`). -/
theorem alloc.string.String.size_char (t : alloc.string.String)
    (h : (alloc.string.String.utf8U8 t).length ≤ 2 ^ 30 - 1) :
    ⦃ ⌜ True ⌝ ⦄ alloc.string.String.Insts.Tls_codecSize.tls_serialized_len t
    ⦃ ⇓ r => ⌜ r.val = (alloc.string.String.utf8U8 t).length +
        varint.lenOf (alloc.string.String.utf8U8 t).length ⌝ ⦄ := by
  mvcgen [alloc.string.String.Insts.Tls_codecSize.tls_serialized_len, Shared0Slice.size_U8_char]
  rename_i s hs _
  intro hr
  have htake : List.take Usize.max t.utf8U8 = t.utf8U8 := List.take_of_length_le (by scalar_tac)
  rw [htake] at hs
  rw [hr, hs, if_pos h]

/-! ### Trait-level `tls_serialize_bytes` post from a characterization of the result -/

/-- An `Err` result meets the trait-level post of `tls_serialize_bytes`. -/
theorem SerializeBytes.post_err {Self : Type} (SizeInst : Size Self) (inst : SerializeBytes Self)
    (self_ : Self) (e : Error) :
    (SerializeBytes.tls_serialize_bytes.post SizeInst inst self_ (.Err e)).holds := by
  simp [SerializeBytes.tls_serialize_bytes.post, core.result.Result.is_err, RustM.holds]
  mvcgen

/-- An `Ok out` result meets the trait-level post of `tls_serialize_bytes` when the size of `self_`
is `n` and `out.len = n`. -/
theorem SerializeBytes.post_ok {Self : Type} (SizeInst : Size Self) (inst : SerializeBytes Self)
    (self_ : Self) (out : alloc.vec.Vec Std.U8) (n : Std.Usize)
    (hn : SizeInst.tls_serialized_len self_ = ok n)
    (hout : (out : Slice Std.U8).val.length = n.val) :
    (SerializeBytes.tls_serialize_bytes.post SizeInst inst self_ (.Ok out)).holds := by
  have hl : alloc.vec.Vec.len out = ok (Slice.len (out : Slice Std.U8)) := by
    obtain ⟨l, hl, hl'⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (alloc.vec.Vec.len_spec out)
    rw [hl, hl']
  simp only [SerializeBytes.tls_serialize_bytes.post, core.result.Result.is_err,
    core.result.Result.is_ok_and,
    __6.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.call_once, hl, hn]
  have he : Slice.len (out : Slice Std.U8) = n := by
    apply UScalar.eq_of_val_eq
    simpa [Slice.len_val, Slice.length] using hout
  simp [he, RustM.holds]
  mvcgen

/-- `String::tls_serialized_len` never panics and is positive. -/
theorem alloc.string.String.size_pos (t : alloc.string.String) :
    ⦃ ⌜ True ⌝ ⦄ alloc.string.String.Insts.Tls_codecSize.tls_serialized_len t
    ⦃ ⇓ r => ⌜ 0 < r.val ⌝ ⦄ := by
  mvcgen [alloc.string.String.Insts.Tls_codecSize.tls_serialized_len, Shared0Slice.size_U8_char]
  rename_i s _ _
  intro h
  have : 1 ≤ varint.lenOf s.val.length := by
    unfold varint.lenOf; split_ifs <;> omega
  split_ifs at h with hc <;> omega

/-- `Vec<T>::tls_serialized_len` is positive when the element size does not fail. -/
theorem alloc.vec.Vec.size_pos {T : Type} (SizeInst : Size T)
    (SizeInstLawful : Size.Lawful T SizeInst) (self_ : alloc.vec.Vec T) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.Tls_codecSize.tls_serialized_len SizeInst self_
    ⦃ ⇓ r => ⌜ 0 < r.val ⌝ ⦄ := by
  have hl := Shared0Slice.size_pos SizeInst SizeInstLawful
  mvcgen [alloc.vec.Vec.Insts.Tls_codecSize.tls_serialized_len, hl]

/-- `TlsVarInt::tls_serialized_len` is the minimal varint length. -/
theorem varint.TlsVarInt.size_char (v : varint.TlsVarInt) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.Insts.Tls_codecSize.tls_serialized_len v
    ⦃ ⇓ r => ⌜ r.val = varint.lenOf v.val ⌝ ⦄ := by
  mvcgen [varint.TlsVarInt.Insts.Tls_codecSize.tls_serialized_len, varint.TlsVarInt.bytes_len_spec]
  intro h1 h2 h3 h4 h5 h6
  exact (varint.lenOf_char _ _ ⟨h1, h2, h3, h4, h5, h6⟩).1

/-- A trait `pre` that is `ok true` holds (the shape `(do let a ← pre; pure (a = true)).holds` of the
`Lawful` hypotheses): `have hs := fun x => I.m_spec x (pre_holds_of_ok_true rfl)`. -/
theorem pre_holds_of_ok_true {m : RustM Bool} (h : m = ok true) :
    (do let a ← m; pure (a = true) : RustM Prop).holds := by
  subst h
  unfold RustM.holds
  mvcgen

/-- `RustM.holds` of a pure proposition. -/
theorem holds_ok_iff {p : Prop} : (ok p : RustM Prop).holds ↔ p := by
  unfold RustM.holds
  constructor
  · intro h; exact h trivial
  · intro hp; mvcgen

/-- Converse of `SerializeBytes.post_ok`: an `Ok out` meeting the trait-level post of
`tls_serialize_bytes` has the length given by `tls_serialized_len`. -/
theorem SerializeBytes.post_ok_elim {Self : Type} (SizeInst : Size Self) (inst : SerializeBytes Self)
    (self_ : Self) (out : alloc.vec.Vec Std.U8)
    (h : (SerializeBytes.tls_serialize_bytes.post SizeInst inst self_ (.Ok out)).holds) :
    ∃ n, SizeInst.tls_serialized_len self_ = ok n ∧ (out : Slice Std.U8).val.length = n.val := by
  have hl : alloc.vec.Vec.len out = ok (Slice.len (out : Slice Std.U8)) := by
    obtain ⟨l, hl, hl'⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (alloc.vec.Vec.len_spec out)
    rw [hl, hl']
  simp only [SerializeBytes.tls_serialize_bytes.post, core.result.Result.is_err,
    core.result.Result.is_ok_and,
    __6.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.call_once, hl] at h
  cases hn : SizeInst.tls_serialized_len self_ with
  | ok n =>
    refine ⟨n, rfl, ?_⟩
    simp only [hn] at h
    have h2 : decide (Slice.len out = n) = true := holds_ok_iff.mp h
    have h3 := of_decide_eq_true h2
    have := congrArg UScalar.val h3
    simpa [Slice.len_val, Slice.length] using this
  | fail e =>
    exfalso
    have := h trivial
    simp [hn] at this
    simp [Std.Do.wp, Std.Do.PredTrans.apply] at this
  | div =>
    exfalso
    have := h trivial
    simp [hn] at this
    simp [Std.Do.wp, Std.Do.PredTrans.apply] at this

/-- An `Ok (v, rem)` meeting the trait-level post of `tls_deserialize_bytes` has `rem` a suffix
of `bytes`. -/
theorem DeserializeBytes.post_ok_suffix {Self : Type} (SizeInst : Size Self)
    (inst : DeserializeBytes Self) (bytes : Slice Std.U8) (v : Self) (rem : Slice Std.U8)
    (h : (DeserializeBytes.tls_deserialize_bytes.post SizeInst inst bytes (.Ok (v, rem))).holds) :
    rem.val <:+ bytes.val := by
  have hl : ∀ (s : Slice Std.U8), core.slice.Slice.len s = ok (Slice.len s) := by
    intro s; unfold core.slice.Slice.len; rfl
  by_contra hsuf
  have hpost : DeserializeBytes.tls_deserialize_bytes.post SizeInst inst bytes (.Ok (v, rem))
      = ok false := by
    simp only [DeserializeBytes.tls_deserialize_bytes.post, core.result.Result.is_err,
      core.result.Result.is_ok_and,
      __9.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairSelf_SharedSliceU8Bool.call_once,
      hl, core.slice.Slice.ends_with_u8_eq, hsuf, decide_false, Aeneas.Std.bind_tc_ok]
    split <;> simp_all
  rw [hpost] at h
  exact absurd (holds_ok_iff.mp h) (by simp)

/-- Converse of `DeserializeBytes.post_ok`: an `Ok (v, rem)` meeting the trait-level post of
`tls_deserialize_bytes` has `rem.len + size v = bytes.len`. -/
theorem DeserializeBytes.post_ok_elim {Self : Type} (SizeInst : Size Self) (inst : DeserializeBytes Self)
    (bytes : Slice Std.U8) (v : Self) (rem : Slice Std.U8)
    (h : (DeserializeBytes.tls_deserialize_bytes.post SizeInst inst bytes (.Ok (v, rem))).holds) :
    ∃ n, SizeInst.tls_serialized_len v = ok n ∧ rem.val.length + n.val = bytes.val.length := by
  have hl : ∀ (s : Slice Std.U8), core.slice.Slice.len s = ok (Slice.len s) := by
    intro s; unfold core.slice.Slice.len; rfl
  have hsuf := DeserializeBytes.post_ok_suffix SizeInst inst bytes v rem h
  simp only [DeserializeBytes.tls_deserialize_bytes.post, core.result.Result.is_err,
    core.result.Result.is_ok_and,
    __9.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairSelf_SharedSliceU8Bool.call_once,
    hl, core.slice.Slice.ends_with_u8_eq, hsuf, decide_true, Aeneas.Std.bind_tc_ok,
    if_true] at h
  cases hn : SizeInst.tls_serialized_len v with
  | ok n =>
    refine ⟨n, rfl, ?_⟩
    simp [hn, hsuf] at h
    by_cases hle : (rem.val.length ≤ bytes.val.length)
    · simp only [hle, if_true] at h
      cases hadd : (rem.len + n : RustM Std.Usize) with
      | ok z =>
        have hz := (Aeneas.Std.UScalar.add_equiv (Slice.len rem) n)
        rw [hadd] at hz
        obtain ⟨_, hz, _⟩ := hz
        simp only [hadd, hsuf, if_true] at h
        have h2 : decide (z = Slice.len bytes) = true := holds_ok_iff.mp h
        have h3 := congrArg UScalar.val (of_decide_eq_true h2)
        simp only [Slice.len_val, Slice.length] at hz h3 ⊢
        omega
      | fail e =>
        exfalso
        have := h trivial
        simp [hadd, hsuf] at this
        simp [Std.Do.wp, Std.Do.PredTrans.apply] at this
      | div =>
        exfalso
        have := h trivial
        simp [hadd, hsuf] at this
        simp [Std.Do.wp, Std.Do.PredTrans.apply] at this
    · exfalso
      simp only [hle, if_false] at h
      have := holds_ok_iff.mp h
      simp at this
  | fail e =>
    exfalso
    have := h trivial
    simp [hn] at this
    by_cases hle : (rem.val.length ≤ bytes.val.length) <;> simp [hle, hsuf, Std.Do.wp, Std.Do.PredTrans.apply] at this
  | div =>
    exfalso
    have := h trivial
    simp [hn] at this
    by_cases hle : (rem.val.length ≤ bytes.val.length) <;> simp [hle, hsuf, Std.Do.wp, Std.Do.PredTrans.apply] at this

/-! ### The length part of the trait-level `tls_deserialize_bytes` post

`post_len` is the trait-level post without its suffix clause (`bytes.ends_with(remainder)`);
`post_of_len` / `fc_of_len` rebuild the full post from it and
a suffix fact, so proofs that reason about the length post keep their shape. -/

/-- The length clause of the `tls_deserialize_bytes` post (closure body). -/
def DeserializeBytes.PostLen.call_once {Self : Type} (SizeInst : Size Self)
    (c : Slice Std.U8) (tupled_args : Self × Slice Std.U8) : RustM Bool := do
  let (value, remainder) := tupled_args
  let i ← core.slice.Slice.len remainder
  let i1 ← core.slice.Slice.len c
  if i <= i1
  then
    let i2 ← SizeInst.tls_serialized_len value
    let i3 ← i + i2
    ok (i3 = i1)
  else ok false

@[reducible]
def DeserializeBytes.PostLen.inst {Self : Type} (SizeInst : Size Self) :
    core.ops.function.FnOnce (Slice Std.U8) (Self × Slice Std.U8) Bool :=
  { call_once := DeserializeBytes.PostLen.call_once SizeInst }

/-- The trait-level `tls_deserialize_bytes` post without its suffix clause. -/
@[reducible]
def DeserializeBytes.post_len {Self : Type} (SizeInst : Size Self) (_inst : DeserializeBytes Self)
    (bytes : Slice Std.U8) (res : core.result.Result (Self × Slice Std.U8) Error) : RustM Bool := do
  let b ← core.result.Result.is_err res
  if b
  then ok true
  else core.result.Result.is_ok_and (DeserializeBytes.PostLen.inst SizeInst) res bytes

/-- The trait-level post from its length part and the suffix fact. -/
theorem DeserializeBytes.post_of_len {Self : Type} (SizeInst : Size Self) (inst : DeserializeBytes Self)
    (bytes : Slice Std.U8) (r : core.result.Result (Self × Slice Std.U8) Error)
    (h : (DeserializeBytes.post_len SizeInst inst bytes r).holds)
    (hs : ∀ v rem, r = .Ok (v, rem) → rem.val <:+ bytes.val) :
    (DeserializeBytes.tls_deserialize_bytes.post SizeInst inst bytes r).holds := by
  cases r with
  | Err e => exact DeserializeBytes.post_err _ _ _ _
  | Ok p =>
    obtain ⟨v, rem⟩ := p
    have hsuf := hs v rem rfl
    have hpost : DeserializeBytes.tls_deserialize_bytes.post SizeInst inst bytes (.Ok (v, rem)) =
        DeserializeBytes.post_len SizeInst inst bytes (.Ok (v, rem)) := by
      simp only [DeserializeBytes.tls_deserialize_bytes.post, DeserializeBytes.post_len,
        core.result.Result.is_err, core.result.Result.is_ok_and,
        __9.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairSelf_SharedSliceU8Bool.call_once,
        DeserializeBytes.PostLen.call_once, core.slice.Slice.ends_with_u8_eq, hsuf, decide_true,
        Aeneas.Std.bind_tc_ok, if_true]
      simp [hsuf]
    rw [hpost]; exact h

/-- `post_of_len` for partial triples. -/
theorem DeserializeBytes.fc_of_len {Self : Type} (SizeInst : Size Self) (inst : DeserializeBytes Self)
    (bytes : Slice Std.U8) {m : RustM (core.result.Result (Self × Slice Std.U8) Error)}
    (h : ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓? r => ⌜ (DeserializeBytes.post_len SizeInst inst bytes r).holds ⌝ ⦄)
    (hs : ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓ r => ⌜ ∀ v rem, r = .Ok (v, rem) → rem.val <:+ bytes.val ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓? r => ⌜ (DeserializeBytes.tls_deserialize_bytes.post SizeInst inst bytes r).holds ⌝ ⦄ := by
  apply partial_triple_of_ok
  intro r hr
  exact DeserializeBytes.post_of_len SizeInst inst bytes r
    (ok_of_partial_triple (x := m) (r := r)
      (P := fun r => (DeserializeBytes.post_len SizeInst inst bytes r).holds) h hr)
    (ok_of_partial_triple (x := m) (r := r) (partial_of_total hs) hr)

/-- A list whose byte values end with those of `a` has `a` as a suffix. -/
theorem suffix_of_map_val {a b : List Std.U8} {A : List Nat}
    (h : b.map (·.val) = A ++ a.map (·.val)) : a <:+ b := by
  have hinj : Function.Injective (fun x : Std.U8 => x.val) := fun x y hxy => UScalar.eq_of_val_eq hxy
  have h2 : (b.drop A.length).map (·.val) = a.map (·.val) := by
    rw [List.map_drop, h, List.drop_left]
  have h3 : b.drop A.length = a := (List.map_injective_iff.mpr hinj) h2
  rw [← h3]; exact List.drop_suffix _ _

end tls_codec
