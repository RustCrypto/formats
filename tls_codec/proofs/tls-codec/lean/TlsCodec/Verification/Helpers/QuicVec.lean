/- `Vec<T>` (quic_vec, varint length prefix) on the bytes path, and `Slice::to_vec` with a
non-failing `clone`.

Obligations: none directly; the bytes-path halves of `PanicFreedom.lean` /
`FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): ASSUMED `size_of`, `size_of_U8`; `native_decide`
(1). -/
import TlsCodec.Verification.Helpers.TlsVecDe
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! #### `Vec<T>` (quic_vec) -/

/-- The size of a slice: the size fold of its elements (from `0`), plus the length prefix
(none above the `2^30 - 1` bound). -/
theorem Shared0Slice.size_rel {T : Type} (S : Size T) (hl : Size.Lawful T S) (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ Shared0Slice.Insts.Tls_codecSize.tls_serialized_len S s
    ⦃ ⇓ r => ⌜ ∃ c ll, SizeFoldRel S 0#usize s.val c ∧ r = lenAddVal c ll ∧
        ll.val = (if c.val ≤ 2 ^ 30 - 1 then varint.lenOf c.val else 0) ⌝ ⦄ := by
  have hcall : ∀ c a e n, S.tls_serialized_len e = ok n →
      (quic_vec.SizeShared0Slice.tls_serialized_len.closure.Insts.CoreOpsFunctionFnMutPairUsizeSharedTUsize
        S).call_mut c (a, e) = ok (lenAddVal a n, c) := by
    intro c a e n hn
    simp [quic_vec.SizeShared0Slice.tls_serialized_len.closure.Insts.CoreOpsFunctionFnMutPairUsizeSharedTUsize.call_mut, hn, len_add_ok]
  have hf := size_fold_rel S (Size.lawful_ok S hl) _ hcall
  mvcgen [Shared0Slice.Insts.Tls_codecSize.tls_serialized_len, hf,
    Shared0Slice.size_closure_map_spec, len_add_triple]
  rename_i it hit c hrel rc hrc rm hrm ll hll r
  intro h
  subst hit
  refine ⟨c, ll, hrel, h, ?_⟩
  cases rc with
  | Ok c' =>
    obtain ⟨u, rfl, hul⟩ := hrm.1 c' rfl
    simp only at hll hrc
    subst hll
    rw [if_pos hrc.2, hul, hrc.1]
  | Err e =>
    obtain rfl := hrm.2 e rfl
    simp only at hll hrc
    subst hll
    rw [if_neg (by omega)]
    rfl

/-- The size of a `Vec<T>`: as `Shared0Slice.size_rel`. -/
theorem alloc.vec.Vec.size_rel {T : Type} (S : Size T) (hl : Size.Lawful T S) (v : alloc.vec.Vec T) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.Tls_codecSize.tls_serialized_len S v
    ⦃ ⇓ r => ⌜ ∃ c ll, SizeFoldRel S 0#usize v.val c ∧ r = lenAddVal c ll ∧
        ll.val = (if c.val ≤ 2 ^ 30 - 1 then varint.lenOf c.val else 0) ⌝ ⦄ := by
  have h := Shared0Slice.size_rel S hl
  mvcgen [alloc.vec.Vec.Insts.Tls_codecSize.tls_serialized_len, h]
  intro h; subst_vars; exact h

theorem ByteArray_toList_loop (bs : ByteArray) : ∀ (n i : Nat) (r : List UInt8), bs.size - i = n →
    ByteArray.toList.loop bs i r = r.reverse ++ bs.data.toList.drop i := by
  intro n
  induction n with
  | zero =>
    intro i r h
    rw [ByteArray.toList.loop]
    have : ¬ i < bs.size := by omega
    simp [this]
    omega
  | succ n ih =>
    intro i r h
    rw [ByteArray.toList.loop]
    have hi : i < bs.size := by omega
    simp only [hi, if_true]
    rw [ih (i+1) _ (by omega)]
    have hi' : i < bs.data.toList.length := by simpa using hi
    have hi2 : i < bs.data.size := hi
    have : bs.get! i = bs.data.toList[i] := by
      simp [ByteArray.get!]
      exact getElem!_pos bs.data i hi2
    rw [this]
    simp [List.drop_eq_getElem_cons hi']

theorem ByteArray_toList_eq (bs : ByteArray) : bs.toList = bs.data.toList := by
  unfold ByteArray.toList
  rw [ByteArray_toList_loop bs bs.size 0 [] (by omega)]
  simp

/-- The bytes of a `toStr` literal are the UTF-8 encoding of some string (so `String::from(&str)`
of a literal has a spec). -/
theorem toStr_utf8 (s : String) (h : s.toByteArray.size ≤ U32.max) :
    ∃ t, alloc.string.String.utf8U8 t = (toStr s h).val := by
  refine ⟨s, ?_⟩
  simp only [alloc.string.String.utf8U8, toStr]
  rw [ByteArray_toList_eq]
  apply List.map_congr_left
  intro b _
  apply UScalar.eq_of_val_eq
  simp

theorem alloc.vec.Vec.deserialize_bytes_loop_body_char {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (length : Std.Usize) (N : Nat) {B : List Std.U8}
    (hN : N ≤ Usize.max)
    (result : alloc.vec.Vec T) (remainder : Slice Std.U8) (read : Std.Usize)
    (hinv : DesLoopInv inst.SizeInst 0#usize N B result.val remainder read) :
    ⦃ ⌜ True ⌝ ⦄
    alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop.body inst length remainder
      result read
    ⦃ ⇓ r => ⌜ match r with
      | .done (rem, res, rd, fl) => fl = core.option.Option.None →
          (∃ s, SizeFoldRel inst.SizeInst 0#usize res.val s ∧ s.val + rem.val.length = N) ∧
          rd.val + rem.val.length = N ∧ rem.val <:+ B
      | .cont (rem, res, rd) => DesLoopInv inst.SizeInst 0#usize N B res.val rem rd ∧
          rem.val.length < remainder.val.length ⌝ ⦄ := by
  have hd := fun b => hlaw.tls_deserialize_bytes_spec b (pre_holds_of_ok_true rfl)
  obtain ⟨hres, ⟨s, hs, hsN⟩, hr, hB⟩ := hinv
  mvcgen [alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop.body, hd,
    core.convert.Into.Blanket.into]
  case vc1.h =>
    rename_i hlt r p hx hpost r2 h2 r1 h1 r0 ha hb
    scalar_tac
  case vc2.h => exact toStr_utf8 _ _
  case vc3 => intro h; cases h
  case vc4.hQ =>
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
  case vc5.h_fail =>
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
  case vc6.h_fail =>
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
  case vc7 => intro h; cases h
  case vc8.hQ => exact ⟨⟨s, hs, hsN⟩, by simpa using hr, hB⟩

theorem alloc.vec.Vec.deserialize_bytes_loop_char {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (length : Std.Usize) (N : Nat) {B : List Std.U8}
    (hN : N ≤ Usize.max)
    (result : alloc.vec.Vec T) (remainder : Slice Std.U8) (read : Std.Usize)
    (hinv : DesLoopInv inst.SizeInst 0#usize N B result.val remainder read) :
    ⦃ ⌜ True ⌝ ⦄
    alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop inst remainder length
      result read
    ⦃ ⇓ r => ⌜ r.2.2.2 = core.option.Option.None →
        (∃ s, SizeFoldRel inst.SizeInst 0#usize r.2.1.val s ∧ s.val + r.1.val.length = N) ∧
        r.2.2.1.val + r.1.val.length = N ∧ r.1.val <:+ B ⌝ ⦄ := by
  unfold alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.loop.spec_decr_nat
    (fun p : Slice Std.U8 × alloc.vec.Vec T × Std.Usize => p.1.val.length)
    (fun p => DesLoopInv inst.SizeInst 0#usize N B p.2.1.val p.1 p.2.2)
  · rintro ⟨rem, res, rd⟩ h
    obtain ⟨v, hv, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (alloc.vec.Vec.deserialize_bytes_loop_body_char inst hlaw length N hN res rem rd h)
    dsimp only
    rw [hv]
    refine (Aeneas.Std.WP.spec_ok v).mpr ?_
    cases v with
    | done y => exact hP
    | cont x => exact hP
  · exact hinv

/-- The size of a `Vec<T>` whose size fold is `c` (when the sum does not overflow). -/
theorem alloc.vec.Vec.size_ok {T : Type} (S : Size T) (hl : Size.Lawful T S) (v : alloc.vec.Vec T)
    (c : Std.Usize) (hrel : SizeFoldRel S 0#usize v.val c)
    (hc : c.val + (if c.val ≤ 2 ^ 30 - 1 then varint.lenOf c.val else 0) ≤ Usize.max) :
    ∃ n, alloc.vec.Vec.Insts.Tls_codecSize.tls_serialized_len S v = ok n ∧
      n.val = c.val + (if c.val ≤ 2 ^ 30 - 1 then varint.lenOf c.val else 0) := by
  obtain ⟨r, hr, c', ll, hrel', hr', hll⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (alloc.vec.Vec.size_rel S hl v)
  have := hrel.functional hrel'
  subst this
  refine ⟨r, hr, ?_⟩
  rw [hr', lenAddVal_val _ _ (by rw [hll]; exact hc), hll]

/-- `Vec<T>::tls_deserialize_bytes` from the trait contract of `T`. -/
theorem alloc.vec.Vec.deserialize_bytes_char {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes inst bytes
    ⦃ ⇓ r => ⌜ ∀ v rem, r = .Ok (v, rem) → ∃ n,
        alloc.vec.Vec.Insts.Tls_codecSize.tls_serialized_len inst.SizeInst v = ok n ∧
        rem.val.length + n.val = bytes.val.length ∧ rem.val <:+ bytes.val ⌝ ⦄ := by
  have hl := fun (result : alloc.vec.Vec T) (remainder : Slice Std.U8) (length read : Std.Usize)
      (hinv : DesLoopInv inst.SizeInst 0#usize remainder.val.length remainder.val result.val
        remainder read) =>
    alloc.vec.Vec.deserialize_bytes_loop_char inst hlaw length remainder.val.length
      (by have := remainder.property; scalar_tac) result remainder read hinv
  mvcgen [alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes,
    quic_vec.ContentLength.deserialize_char_suffix, varint.TlsVarInt.value, hl,
    alloc.vec.Vec.new_spec, core.hint.must_use_spec]
  try_vcs
  all_goals (try simp only [continue_eq_tryCF] at *)
  all_goals (try (intro _ _ h; cases h; done))
  all_goals (try (intros; simp [PostCond.ok]; done))
  all_goals (try (exfalso; simp_all; done))
  case vc1 =>
    rename_i r0 hP r1 p hx r2 htf r3 val hx2 hv0 rv hrv hr0 hr2
    intro v rem h
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj (core.result.Result.Ok.inj h)
    have hp := hP.1 p.1 p.2 hr0
    have hps := hP.2 p.1 p.2 hr0
    have hy := htf.1 val hr2
    have hv : val.val = 0 := by rw [hv0]; rfl
    have hrel : SizeFoldRel inst.SizeInst 0#usize rv.val 0#usize := by
      rw [hrv]; simp [Slice.new]; exact .nil _
    obtain ⟨n, hn, hnv⟩ := alloc.vec.Vec.size_ok inst.SizeInst hlaw.SizeInstLawful rv 0#usize hrel
      (by simp [varint.lenOf]; scalar_tac)
    refine ⟨n, hn, ?_, hps⟩
    have h0 : varint.lenOf 0 = 1 := by simp [varint.lenOf]
    simp [h0] at hnv
    have := hp.2
    rw [show p.1.val = 0 by omega, h0] at this
    omega
  case vc2.hinv =>
    rename_i r0 hP r1 p hx r2 htf r3 val hx2 hv0 rv hrv hr0 hr2
    refine ⟨by simp [hrv, Slice.new], ⟨0#usize, ?_, by simp⟩, by simp, List.suffix_refl _⟩
    rw [hrv]; simp [Slice.new]; exact .nil _
  case vc4 =>
    rename_i r0 hP r1 p hx r2 htf r3 val hx2 hnz rv hrv res hnone hne hpost hr0 hr2
    intro v rem h
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj (core.result.Result.Ok.inj h)
    have hp := hP.1 p.1 p.2 hr0
    have hps := hP.2 p.1 p.2 hr0
    have hy := htf.1 val hr2
    obtain ⟨⟨s, hs, hsN⟩, hrd, hsB⟩ := hpost hnone
    have hrv' : res.2.2.1.val = val.val := by simpa using hne
    have hsv : s.val = p.1.val := by
      rw [hrv'] at hrd
      omega
    have hb : bytes.val.length ≤ Usize.max := by have := bytes.property; scalar_tac
    have hle : p.1.val ≤ 2 ^ 30 - 1 := hp.1
    obtain ⟨n, hn, hnv⟩ := alloc.vec.Vec.size_ok inst.SizeInst hlaw.SizeInstLawful res.2.1 s hs
      (by rw [if_pos (by omega), hsv]; have := hp.2; omega)
    refine ⟨n, hn, ?_, hsB.trans hps⟩
    rw [if_pos (by omega), hsv] at hnv
    have := hp.2
    omega

/-- The trait method of `Vec<T>` does not fail. -/
theorem alloc.vec.Vec.trait_pf {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄
      (alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes inst) bytes
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  obtain ⟨v, hv, _⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (alloc.vec.Vec.deserialize_bytes_char inst hlaw bytes)
  rw [hv]
  apply RustM.ok_spec
  trivial

/-- Functional correctness of the trait method of `Vec<T>` (trait-level post). -/
theorem alloc.vec.Vec.trait_fc {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄
      (alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes inst) bytes
    ⦃ ⇓? res => ⌜ (DeserializeBytes.tls_deserialize_bytes.post
        (alloc.vec.Vec.Insts.Tls_codecDeserializeBytes inst).SizeInst
        (alloc.vec.Vec.Insts.Tls_codecDeserializeBytes inst) bytes res).holds ⌝ ⦄ :=
  DeserializeBytes.fc_of_char (alloc.vec.Vec.Insts.Tls_codecSize inst.SizeInst)
    (alloc.vec.Vec.Insts.Tls_codecDeserializeBytes inst) bytes _
    (alloc.vec.Vec.deserialize_bytes_char inst hlaw bytes)


/-! ### `Slice::to_vec` with a non-failing `clone` -/

/-- `to_vec` does not fail when `clone` does not, and preserves the length. -/
theorem alloc.slice.Slice.to_vec_len {T : Type} (inst : core.clone.Clone T)
    (hc : ∀ x, ⦃ ⌜ True ⌝ ⦄ inst.clone x ⦃ ⇓ _ => ⌜ True ⌝ ⦄) (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ alloc.slice.Slice.to_vec inst s
    ⦃ ⇓ r => ⌜ (r : Slice T).val.length = s.val.length ⌝ ⦄ := by
  have mapM_ok : ∀ l : List T, ∃ l', l.mapM inst.clone = .ok l' ∧ l'.length = l.length := by
    intro l
    induction l with
    | nil => exact ⟨[], rfl, rfl⟩
    | cons x xs ih =>
      obtain ⟨y, hy⟩ := triple_true_ok (hc x)
      obtain ⟨l', hl', hlen⟩ := ih
      refine ⟨y :: l', ?_, by simp [hlen]⟩
      simp [List.mapM_cons, hy, hl']; rfl
  have hlen : s.val.length ≤ Usize.max := s.property
  obtain ⟨l', hl', hlen'⟩ := mapM_ok s.val
  unfold alloc.slice.Slice.to_vec alloc.slice.Dummy.to_vec
  simp [rust_primitives.sequence.seq_empty, rust_primitives.sequence.seq_extend, alloc.vec.from_seq,
    Slice.new, hl']
  rw [dif_pos (by omega)]
  mvcgen

end tls_codec
