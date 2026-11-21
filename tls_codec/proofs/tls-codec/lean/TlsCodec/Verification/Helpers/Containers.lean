/- Generic containers of the bytes path: `Option<T>` serialization, the sizes of `Option` / pairs /
triples, `Box<T>` (erased), pairs and triples.

Obligations: none directly; the bytes-path halves of `PanicFreedom.lean` /
`FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): ASSUMED `size_of`, `size_of_U8`. -/
import TlsCodec.Verification.Helpers.TraitPosts
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! ### `Option<T>` serialization, generic over `T` -/

/-- Behaviour of `Option<T>::tls_serialize_bytes` from the trait contracts of `T`: never fails to
terminate, and an `Ok out` is `[0]` for `None` and `1 :: v` for `Some e`, with `v` of the size of `e`. -/
theorem Option_serialize_char {T : Type} (inst : SerializeBytes T)
    (hlaw : SerializeBytes.Lawful T inst) (o : core.option.Option T) :
    ⦃ ⌜ True ⌝ ⦄ core.option.Option.Insts.Tls_codecSerializeBytes.tls_serialize_bytes inst o
    ⦃ ⇓ r => ⌜ (∀ out, r = .Ok out →
        (o = .None ∧ (out : Slice Std.U8).val = [0#u8]) ∨
        ∃ (e : T) (n : Std.Usize) (v : List Std.U8), o = .Some e ∧ inst.SizeInst.tls_serialized_len e = ok n ∧
          v.length = n.val ∧ (out : Slice Std.U8).val = 1#u8 :: v) ∧
        (o = .None → ∃ out, r = .Ok out) ⌝ ⦄ := by
  have hsz := hlaw.SizeInstLawful.tls_serialized_len_spec
  have hs := fun x => hlaw.tls_serialize_bytes_spec x (pre_holds_of_ok_true rfl)
  cases o with
  | none =>
    mvcgen [core.option.Option.Insts.Tls_codecSerializeBytes.tls_serialize_bytes,
      alloc.slice.Slice.into_vec_spec]
    refine ⟨?_, ⟨_, rfl⟩⟩
    intro out hout
    have hout' := core.result.Result.Ok.inj hout
    subst hout'
    refine Or.inl ⟨trivial, ?_⟩
    rename_i hr
    simp [hr, Std.Array.to_slice]
    rfl
  | some e =>
    obtain ⟨n, hn, -⟩ := (Aeneas.Std.WP.triple_iff_exists_ok).1
      (hsz e (pre_holds_of_ok_true rfl))
    mvcgen [core.option.Option.Insts.Tls_codecSerializeBytes.tls_serialize_bytes, hn, hs,
      checked_alloc_len_ok, alloc.vec.Vec.with_capacity, alloc.vec.Vec.append,
      rust_primitives.sequence.seq_concat]
    try_vcs
    all_goals (try simp only [continue_eq_tryCF] at *)
    all_goals (try (intros; simp [PostCond.ok]; done))
    · rename_i _ _ _ _ _ _ hr3 _
      subst hr3
      simp [Slice.new]
      scalar_tac
    · rename_i r5 hchk cf0 val x1 r3 hr3 out1 hout1 r1 hpost cf1 val1 x2 comb hlen hcv hr1
      refine ⟨?_, by simp⟩
      intro out hout
      have hout' := core.result.Result.Ok.inj hout
      subst hout' hr1
      obtain ⟨n', hn', hl⟩ := SerializeBytes.post_ok_elim _ _ _ _ hpost
      have hnn := ok.inj (hn.symm.trans hn')
      subst hnn
      subst hr3
      refine Or.inr ⟨e, n, val1.val, rfl, hn, hl, ?_⟩
      simp [comb, hout1, Slice.new]
    · rename_i r5 hchk cf0 val x1 r3 hr3 out1 hout1 r1 hpost cf1 val1 x2 comb hlen hcv hr1
      exfalso
      subst hr1
      obtain ⟨n', hn', hl⟩ := SerializeBytes.post_ok_elim _ _ _ _ hpost
      have hnn := ok.inj (hn.symm.trans hn')
      subst hnn
      have h1 := hchk val hcv
      subst hr3
      apply hlen
      simp only [comb, hout1, List.length_append, hl]
      simp [Slice.new]
      scalar_tac

/-- Behaviour of `Option<T>::tls_deserialize_bytes` from the trait contracts of `T`: never fails to
terminate, and an `Ok (v, rem)` consumed a `0` tag (`None`) or a `1` tag followed by an `e` of size
`n` (`Some e`), the rest of the input being `rem`. -/
theorem Option_deserialize_char {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ core.option.Option.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes inst bytes
    ⦃ ⇓ r => ⌜ ∀ v rem, r = .Ok (v, rem) → ∃ l,
        (bytes.val = 0#u8 :: l ∧ v = .None ∧ rem.val = l) ∨
        (bytes.val = 1#u8 :: l ∧ ∃ (e : T) (n : Std.Usize), v = .Some e ∧
          inst.SizeInst.tls_serialized_len e = ok n ∧ rem.val.length + n.val = l.length ∧
          rem.val <:+ l) ⌝ ⦄ := by
  have hd := fun b => hlaw.tls_deserialize_bytes_spec b (pre_holds_of_ok_true rfl)
  mvcgen [core.option.Option.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes,
    U8_deserialize_char, hd]
  try_vcs
  all_goals (try simp only [continue_eq_tryCF] at *)
  all_goals (try (intros; simp [PostCond.ok]; done))
  · rename_i r1 hP cf p hx hz hr1
    intro v rem hv
    obtain ⟨l, hb, hp2⟩ := U8_deserialize_ok hP (continue_eq_tryCF.2 hr1)
    rw [hz] at hb
    simp only [core.result.Result.Ok.injEq, Prod.mk.injEq] at hv
    obtain ⟨rfl, rfl⟩ := hv
    exact ⟨l, Or.inl ⟨hb, rfl, hp2⟩⟩
  · rename_i r1 hP cf p hx hz r2 hpost cf2 p2 hx2 hr1 hr2
    intro v rem hv
    obtain ⟨l, hb, hp2⟩ := U8_deserialize_ok hP (continue_eq_tryCF.2 hr1)
    rw [hz] at hb
    obtain ⟨e, rem2⟩ := p2
    subst hr2
    obtain ⟨n, hn, hl⟩ := DeserializeBytes.post_ok_elim _ _ _ _ _ hpost
    simp only [core.result.Result.Ok.injEq, Prod.mk.injEq] at hv
    obtain ⟨rfl, rfl⟩ := hv
    have hs := DeserializeBytes.post_ok_suffix _ _ _ _ _ hpost
    exact ⟨l, Or.inr ⟨hb, e, n, rfl, hn, by rw [← hp2]; exact hl, by rw [← hp2]; exact hs⟩⟩
  · intro v rem hv
    exact absurd hv (by simp)

/-! ### Sizes of `Option` / pairs / triples (the `len_add`s of the extracted `tls_serialized_len`) -/

theorem Option_size_none {T : Type} (S : Size T) :
    core.option.Option.Insts.Tls_codecSize.tls_serialized_len S .None = ok (lenAddVal 1#usize 0#usize) := by
  simp [core.option.Option.Insts.Tls_codecSize.tls_serialized_len, len_add_ok]

theorem Option_size_some {T : Type} (S : Size T) (e : T) (n : Std.Usize)
    (h : S.tls_serialized_len e = ok n) :
    core.option.Option.Insts.Tls_codecSize.tls_serialized_len S (.Some e) = ok (lenAddVal 1#usize n) := by
  simp [core.option.Option.Insts.Tls_codecSize.tls_serialized_len, len_add_ok, h]

theorem Pair_size {T U : Type} (S : Size T) (S1 : Size U) (a : T) (b : U) (n1 n2 : Std.Usize)
    (h1 : S.tls_serialized_len a = ok n1) (h2 : S1.tls_serialized_len b = ok n2) :
    Pair.Insts.Tls_codecSize.tls_serialized_len S S1 (a, b) = ok (lenAddVal n1 n2) := by
  simp [Pair.Insts.Tls_codecSize.tls_serialized_len, len_add_ok, h1, h2]

theorem TupleTUV_size {T U V : Type} (S : Size T) (S1 : Size U) (S2 : Size V) (a : T) (b : U) (c : V)
    (n1 n2 n3 : Std.Usize) (h1 : S.tls_serialized_len a = ok n1) (h2 : S1.tls_serialized_len b = ok n2)
    (h3 : S2.tls_serialized_len c = ok n3) :
    TupleTUV.Insts.Tls_codecSize.tls_serialized_len S S1 S2 (a, b, c) =
      ok (lenAddVal (lenAddVal n1 n2) n3) := by
  simp [TupleTUV.Insts.Tls_codecSize.tls_serialized_len, len_add_ok, h1, h2, h3]

/-- `<[T]>::first`: the head of the contents. -/
theorem core.slice.Slice.first_spec {T : Type} (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ core.slice.Slice.first s ⦃ ⇓ r => ⌜ r = s.val.head? ⌝ ⦄ := by
  mvcgen [core.slice.Slice.first, rust_primitives.slice.slice_index, Slice.index_usize]
  · rename_i hb hd
    have h0 : s.val.length = 0 := by
      have := congrArg UScalar.val (of_decide_eq_true (hd ▸ hb))
      simpa [Slice.len_val, Slice.length] using this
    simp [List.length_eq_zero_iff.mp h0]
  · rename_i hb hd hg
    exfalso
    apply hb
    rw [hd]
    rw [Slice.getElem?_Usize_eq] at hg
    replace hg : s.val[0]? = none := hg
    have h0 : s.val = [] := by
      cases hs : s.val with
      | nil => rfl
      | cons y l => rw [hs] at hg; simp at hg
    simp [Slice.len, h0]
    rfl
  · rename_i hb hd x hg
    rw [Slice.getElem?_Usize_eq] at hg
    replace hg : s.val[0]? = some x := hg
    cases hs : s.val with
    | nil => rw [hs] at hg; simp at hg
    | cons y l => rw [hs] at hg; simp_all

/-- `Option<&u8>::eq`: `decide` of equality. -/
theorem Option_U8_eq_spec (a b : core.option.Option Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ core.option.Option.Insts.CoreCmpPartialEqOption.eq
      (core.Shared1A.Insts.CoreCmpPartialEqShared0B core.U8.Insts.CoreCmpPartialEqU8) a b
    ⦃ ⇓ r => ⌜ r = decide (a = b) ⌝ ⦄ := by
  apply core.option.Option.Insts.CoreCmpPartialEqOption.eq_spec
  intro x y
  exact core.U8.Insts.CoreCmpPartialEqU8.eq_decide_spec x y

/-! ### `Box<T>` (erased: `Box<T>` is `T`) -/

theorem Box_size {T : Type} (S : Size T) (x : T) (n : Std.Usize) (h : S.tls_serialized_len x = ok n) :
    Box.Insts.Tls_codecSize.tls_serialized_len S x = ok n := by
  simp [Box.Insts.Tls_codecSize.tls_serialized_len, alloc.Box.Insts.CoreConvertAsRef.as_ref, h]

theorem Box_serialize_eq {T : Type} (inst : SerializeBytes T) (x : T) :
    Box.Insts.Tls_codecSerializeBytes.tls_serialize_bytes inst x = inst.tls_serialize_bytes x := by
  simp [Box.Insts.Tls_codecSerializeBytes.tls_serialize_bytes, alloc.Box.Insts.CoreConvertAsRef.as_ref]

theorem Box_deserialize_eq {T : Type} (inst : DeserializeBytes T) (bytes : Slice Std.U8) :
    Box.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes inst bytes = inst.tls_deserialize_bytes bytes := by
  unfold Box.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
  cases h : inst.tls_deserialize_bytes bytes with
  | ok r => cases r with
    | Ok p => obtain ⟨v, r1⟩ := p; simp
    | Err e => simp
  | fail e => simp
  | div => simp

/-! ### Pairs and triples -/

/-- `(T, U)::tls_deserialize_bytes`, from the trait contracts of `T` and `U`. -/
theorem Pair_deserialize_char {T U : Type} (inst : DeserializeBytes T) (inst1 : DeserializeBytes U)
    (hlaw : DeserializeBytes.Lawful T inst) (hlaw1 : DeserializeBytes.Lawful U inst1)
    (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ Pair.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes inst inst1 bytes
    ⦃ ⇓ r => ⌜ ∀ a b rem, r = .Ok ((a, b), rem) → ∃ n1 n2 : Std.Usize,
        inst.SizeInst.tls_serialized_len a = ok n1 ∧ inst1.SizeInst.tls_serialized_len b = ok n2 ∧
        rem.val.length + n2.val + n1.val = bytes.val.length ∧ rem.val <:+ bytes.val ⌝ ⦄ := by
  have hd := fun b => hlaw.tls_deserialize_bytes_spec b (pre_holds_of_ok_true rfl)
  have hd1 := fun b => hlaw1.tls_deserialize_bytes_spec b (pre_holds_of_ok_true rfl)
  mvcgen [Pair.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes, hd, hd1]
  try_vcs
  all_goals (try simp only [continue_eq_tryCF] at *)
  all_goals (try (intros; simp [PostCond.ok]; done))
  rename_i r1 h1 cf p x r2 h2 cf2 p2 x2 hr1 hr2
  intro a b rem hv
  obtain ⟨p1a, p1r⟩ := p
  obtain ⟨p2a, p2r⟩ := p2
  subst hr1 hr2
  obtain ⟨n1, hn1, hl1⟩ := DeserializeBytes.post_ok_elim _ _ _ _ _ h1
  obtain ⟨n2, hn2, hl2⟩ := DeserializeBytes.post_ok_elim _ _ _ _ _ h2
  simp only [core.result.Result.Ok.injEq, Prod.mk.injEq] at hv
  obtain ⟨⟨rfl, rfl⟩, rfl⟩ := hv
  have hs1 := DeserializeBytes.post_ok_suffix _ _ _ _ _ h1
  have hs2 := DeserializeBytes.post_ok_suffix _ _ _ _ _ h2
  dsimp only at hl2 hs2
  exact ⟨n1, n2, hn1, hn2, by omega, hs2.trans hs1⟩

/-- `(T, U, V)::tls_deserialize_bytes`, from the trait contracts of `T`, `U` and `V`. -/
theorem TupleTUV_deserialize_char {T U V : Type} (inst : DeserializeBytes T)
    (inst1 : DeserializeBytes U) (inst2 : DeserializeBytes V)
    (hlaw : DeserializeBytes.Lawful T inst) (hlaw1 : DeserializeBytes.Lawful U inst1)
    (hlaw2 : DeserializeBytes.Lawful V inst2) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ TupleTUV.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes inst inst1 inst2 bytes
    ⦃ ⇓ r => ⌜ ∀ a b c rem, r = .Ok ((a, b, c), rem) → ∃ n1 n2 n3 : Std.Usize,
        inst.SizeInst.tls_serialized_len a = ok n1 ∧ inst1.SizeInst.tls_serialized_len b = ok n2 ∧
        inst2.SizeInst.tls_serialized_len c = ok n3 ∧
        rem.val.length + n3.val + n2.val + n1.val = bytes.val.length ∧ rem.val <:+ bytes.val ⌝ ⦄ := by
  have hd := fun b => hlaw.tls_deserialize_bytes_spec b (pre_holds_of_ok_true rfl)
  have hd1 := fun b => hlaw1.tls_deserialize_bytes_spec b (pre_holds_of_ok_true rfl)
  have hd2 := fun b => hlaw2.tls_deserialize_bytes_spec b (pre_holds_of_ok_true rfl)
  mvcgen [TupleTUV.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes, hd, hd1, hd2]
  try_vcs
  all_goals (try simp only [continue_eq_tryCF] at *)
  all_goals (try (intros; simp [PostCond.ok]; done))
  rename_i r1 h1 cf p x r2 h2 cf2 p2 x2 r3 h3 cf3 p3 x3 hr1 hr2 hr3
  intro a b c rem hv
  obtain ⟨p1a, p1r⟩ := p
  obtain ⟨p2a, p2r⟩ := p2
  obtain ⟨p3a, p3r⟩ := p3
  subst hr1 hr2 hr3
  obtain ⟨n1, hn1, hl1⟩ := DeserializeBytes.post_ok_elim _ _ _ _ _ h1
  obtain ⟨n2, hn2, hl2⟩ := DeserializeBytes.post_ok_elim _ _ _ _ _ h2
  obtain ⟨n3, hn3, hl3⟩ := DeserializeBytes.post_ok_elim _ _ _ _ _ h3
  simp only [core.result.Result.Ok.injEq, Prod.mk.injEq] at hv
  obtain ⟨⟨rfl, rfl, rfl⟩, rfl⟩ := hv
  have hs1 := DeserializeBytes.post_ok_suffix _ _ _ _ _ h1
  have hs2 := DeserializeBytes.post_ok_suffix _ _ _ _ _ h2
  have hs3 := DeserializeBytes.post_ok_suffix _ _ _ _ _ h3
  dsimp only at hl2 hl3 hs2 hs3
  exact ⟨n1, n2, n3, hn1, hn2, hn3, by omega, (hs3.trans hs2).trans hs1⟩

end tls_codec
