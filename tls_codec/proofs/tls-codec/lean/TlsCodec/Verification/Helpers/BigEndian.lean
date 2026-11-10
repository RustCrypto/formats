/- Big-endian byte round trips: integer → bytes → integer and bytes → integer → bytes, for the
fixed-width integers (`u8` … `u64`, `U24`).

Obligations: none directly; the bytes-path halves of `PanicFreedom.lean` /
`FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): ASSUMED `size_of`, `size_of_U16`, `size_of_U24`,
`size_of_U32`, `size_of_U64`, `size_of_U8`. -/
import TlsCodec.Verification.Helpers.Base
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! ### Big-endian byte round trips -/

theorem fromBEBytes_toBEBytes_toNat {w : ℕ} (h : w % 8 = 0) (b : BitVec w) :
    (BitVec.fromBEBytes b.toBEBytes).toNat = b.toNat := by
  unfold BitVec.fromBEBytes BitVec.toBEBytes
  rw [BitVec.toNat_cast, List.reverse_reverse]
  have := congrArg BitVec.toNat (BitVec.fromLEBytes_toLEBytes h b)
  simpa using this

/-- Generic step: bytes made from a `BitVec` through `UScalar.mk` and read back through `U8.bv`. -/
theorem fromBEBytes_map_mk_toNat {w : ℕ} (h : w % 8 = 0) (b : BitVec w) :
    (BitVec.fromBEBytes (List.map U8.bv (List.map (@UScalar.mk UScalarTy.U8) b.toBEBytes))).toNat
      = b.toNat := by
  have key : List.map U8.bv (List.map (@UScalar.mk UScalarTy.U8) b.toBEBytes) = b.toBEBytes := by
    have hid : (U8.bv ∘ @UScalar.mk UScalarTy.U8) = id := rfl
    rw [List.map_map, hid, List.map_id]
  rw [key]
  exact fromBEBytes_toBEBytes_toNat h b

theorem U8_from_be_bytes_to_be_bytes (x : Std.U8) :
    Aeneas.Std.core.num.U8.from_be_bytes (Aeneas.Std.core.num.U8.to_be_bytes x) = x := by
  apply UScalar.eq_of_val_eq
  have h := fromBEBytes_map_mk_toNat (by decide : 8 % 8 = 0) x.bv
  unfold Aeneas.Std.core.num.U8.from_be_bytes Aeneas.Std.core.num.U8.to_be_bytes
  unfold UScalar.val
  rw [BitVec.toNat_cast]
  exact h

theorem U16_from_be_bytes_to_be_bytes (x : Std.U16) :
    Aeneas.Std.core.num.U16.from_be_bytes (Aeneas.Std.core.num.U16.to_be_bytes x) = x := by
  apply UScalar.eq_of_val_eq
  have h := fromBEBytes_map_mk_toNat (by decide : 16 % 8 = 0) x.bv
  unfold Aeneas.Std.core.num.U16.from_be_bytes Aeneas.Std.core.num.U16.to_be_bytes
  unfold UScalar.val
  rw [BitVec.toNat_cast]
  exact h

theorem U32_from_be_bytes_to_be_bytes (x : Std.U32) :
    Aeneas.Std.core.num.U32.from_be_bytes (Aeneas.Std.core.num.U32.to_be_bytes x) = x := by
  apply UScalar.eq_of_val_eq
  have h := fromBEBytes_map_mk_toNat (by decide : 32 % 8 = 0) x.bv
  unfold Aeneas.Std.core.num.U32.from_be_bytes Aeneas.Std.core.num.U32.to_be_bytes
  unfold UScalar.val
  rw [BitVec.toNat_cast]
  exact h

theorem U64_from_be_bytes_to_be_bytes (x : Std.U64) :
    Aeneas.Std.core.num.U64.from_be_bytes (Aeneas.Std.core.num.U64.to_be_bytes x) = x := by
  apply UScalar.eq_of_val_eq
  have h := fromBEBytes_map_mk_toNat (by decide : 64 % 8 = 0) x.bv
  unfold Aeneas.Std.core.num.U64.from_be_bytes Aeneas.Std.core.num.U64.to_be_bytes
  unfold UScalar.val
  rw [BitVec.toNat_cast]
  exact h

/-! The other direction: bytes → integer → bytes is the identity. -/

theorem toLEBytes_fromLEBytes (l : List Byte) : (BitVec.fromLEBytes l).toLEBytes = l := by
  apply List.ext_getElem
  · simp only [BitVec.toLEBytes_length]; omega
  · intro i h1 h2
    rw [Byte.eq_iff]
    intro j hj
    have := BitVec.toLEBytes_getElem!_testBit (BitVec.fromLEBytes l) i j hj
    have e1 := List.Inhabited_getElem_eq_getElem! (BitVec.fromLEBytes l).toLEBytes i h1
    have e2 := List.Inhabited_getElem_eq_getElem! l i h2
    rw [← e1] at this
    rw [this, BitVec.fromLEBytes_getElem!]
    have h3 : (8 * i + j) / 8 = i := by omega
    have h4 : (8 * i + j) % 8 = j := by omega
    rw [h3, h4, ← e2]

theorem toBEBytes_cast {n m : ℕ} (x : BitVec n) (h : n = m) :
    (x.cast h).toBEBytes = x.toBEBytes := by
  subst h; rfl

theorem toBEBytes_fromBEBytes (l : List Byte) : (BitVec.fromBEBytes l).toBEBytes = l := by
  unfold BitVec.fromBEBytes BitVec.toBEBytes
  have : ∀ {n m : ℕ} (x : BitVec n) (h : n = m), (x.cast h).toLEBytes = x.toLEBytes := by
    intro n m x h; subst h; rfl
  rw [this, toLEBytes_fromLEBytes, List.reverse_reverse]

theorem be_bytes_roundtrip (l : List Std.U8) {m : ℕ} (h : 8 * (List.map U8.bv l).length = m) :
    List.map (@UScalar.mk UScalarTy.U8)
      (BitVec.toBEBytes (BitVec.cast h (BitVec.fromBEBytes (List.map U8.bv l)))) = l := by
  rw [toBEBytes_cast, toBEBytes_fromBEBytes, List.map_map]
  have hid : ((@UScalar.mk UScalarTy.U8) ∘ U8.bv) = id := rfl
  rw [hid, List.map_id]

theorem U8_to_be_bytes_from_be_bytes (a : Aeneas.Std.Array Std.U8 1#usize) :
    Aeneas.Std.core.num.U8.to_be_bytes (Aeneas.Std.core.num.U8.from_be_bytes a) = a := by
  apply Subtype.ext
  have ha : a.val.length = 1 := by simpa using a.property
  unfold Aeneas.Std.core.num.U8.to_be_bytes Aeneas.Std.core.num.U8.from_be_bytes
  exact be_bytes_roundtrip a.val (by simp [ha])

theorem U16_to_be_bytes_from_be_bytes (a : Aeneas.Std.Array Std.U8 2#usize) :
    Aeneas.Std.core.num.U16.to_be_bytes (Aeneas.Std.core.num.U16.from_be_bytes a) = a := by
  apply Subtype.ext
  have ha : a.val.length = 2 := by simpa using a.property
  unfold Aeneas.Std.core.num.U16.to_be_bytes Aeneas.Std.core.num.U16.from_be_bytes
  exact be_bytes_roundtrip a.val (by simp [ha])

theorem U32_to_be_bytes_from_be_bytes (a : Aeneas.Std.Array Std.U8 4#usize) :
    Aeneas.Std.core.num.U32.to_be_bytes (Aeneas.Std.core.num.U32.from_be_bytes a) = a := by
  apply Subtype.ext
  have ha : a.val.length = 4 := by simpa using a.property
  unfold Aeneas.Std.core.num.U32.to_be_bytes Aeneas.Std.core.num.U32.from_be_bytes
  exact be_bytes_roundtrip a.val (by simp [ha])

theorem U64_to_be_bytes_from_be_bytes (a : Aeneas.Std.Array Std.U8 8#usize) :
    Aeneas.Std.core.num.U64.to_be_bytes (Aeneas.Std.core.num.U64.from_be_bytes a) = a := by
  apply Subtype.ext
  have ha : a.val.length = 8 := by simpa using a.property
  unfold Aeneas.Std.core.num.U64.to_be_bytes Aeneas.Std.core.num.U64.from_be_bytes
  exact be_bytes_roundtrip a.val (by simp [ha])

/-- `Option::ok_or` result is `Ok v`: the option was `some v`. -/
theorem ok_or_eq_ok {α E : Type} {o : core.option.Option α} {e : E}
    {r : core.result.Result α E} {v : α}
    (h : r = match o with | some x => .Ok x | none => .Err e) (hv : r = .Ok v) : o = some v := by
  subst h
  cases o with
  | none => cases hv
  | some x => simp only [core.result.Result.Ok.injEq] at hv; rw [hv]

/-- `Option::ok_or` result is an `Err`: the option was `none`. -/
theorem ok_or_eq_err {α E : Type} {o : core.option.Option α} {e e' : E}
    {r : core.result.Result α E}
    (h : r = match o with | some x => .Ok x | none => .Err e) (hv : r = .Err e') :
    o = none ∧ e' = e := by
  subst h
  cases o with
  | none => simp only [core.result.Result.Err.injEq] at hv; exact ⟨rfl, hv.symm⟩
  | some x => cases hv

/-- Exact behaviour of `u8::tls_deserialize_bytes`. -/
theorem U8_deserialize_char (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ U8.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ (1 ≤ bytes.val.length → ∃ (a : Aeneas.Std.Array Std.U8 1#usize) (t : Slice Std.U8),
          a.val = bytes.val.take 1 ∧ t.val = bytes.val.drop 1 ∧
          r = .Ok (Aeneas.Std.core.num.U8.from_be_bytes a, t)) ∧
        (bytes.val.length < 1 → r = .Err Error.EndOfStream) ⌝ ⦄ := by
  mvcgen [U8.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes,
    core.option.Option.ok_or_spec, core.result.Result.map_err_spec, core.mem.size_of_U8,
    primitives.DeserializeBytesU8.tls_deserialize_bytes.closure.Insts.CoreOpsFunctionFnOnceTupleTryFromSliceErrorError.call_once]
  try_vcs
  all_goals (try simp only [continue_eq_tryCF] at *)
  · rename_i o1 hs1 res1 hr1 cf1 v1 hcf1 tf hs3 t hteq cf2 v2 hcf2 b hb o2 hs2 res2 hr2 cf3 v3 hcf3 hv1 hv2 hv3
    have ho1 := ok_or_eq_ok hr1 hv1
    by_cases hl : 1 ≤ bytes.val.length
    · obtain ⟨t1, ho1', ht1⟩ := hs1.1 (by scalar_tac)
      rw [ho1] at ho1'
      have hv1t := Option.some.inj ho1'
      subst hv1t
      have hlen1 : v1.val.length = 1 := by rw [ht1]; simp [hl]
      obtain ⟨a0, hta0, ha0⟩ := hs3.1 (by scalar_tac)
      rw [hteq] at hta0
      have h1 := core.result.Result.Ok.inj hta0
      have h2 := core.result.Result.Ok.inj hv2
      obtain ⟨t2, ho2', ht2⟩ := hs2.1 (by scalar_tac)
      have ho2 := ok_or_eq_ok hr2 hv3
      rw [ho2] at ho2'
      have hv3t := Option.some.inj ho2'
      subst hv3t
      refine ⟨fun _ => ⟨v2, v3, ?_, ht2, ?_⟩, fun h => absurd h (by omega)⟩
      · rw [← h2, h1, ha0, ht1]; rfl
      · rw [hb]
    · exfalso
      have := hs1.2 (by scalar_tac)
      rw [ho1] at this
      cases this
  · rename_i o1 hs1 res1 hr1 cf1 v1 hcf1 tf hs3 t hteq cf2 v2 hcf2 b hb o2 hs2 res2 hr2 cf3 resid hcf3 e hres2 r hv1 hv2
    exfalso
    have ho1 := ok_or_eq_ok hr1 hv1
    have hl : 1 ≤ bytes.val.length := by
      by_contra hn
      have := hs1.2 (by scalar_tac)
      rw [ho1] at this
      cases this
    obtain ⟨t2, ho2', ht2⟩ := hs2.1 (by scalar_tac)
    obtain ⟨ho2, _⟩ := ok_or_eq_err hr2 hres2
    rw [ho2] at ho2'
    cases ho2'
  · rename_i o1 hs1 res1 hr1 cf1 v1 hcf1 tf hs3 e hte hv1
    exfalso
    have ho1 := ok_or_eq_ok hr1 hv1
    have hl : 1 ≤ bytes.val.length := by
      by_contra hn
      have := hs1.2 (by scalar_tac)
      rw [ho1] at this
      cases this
    obtain ⟨t1, ho1', ht1⟩ := hs1.1 (by scalar_tac)
    rw [ho1] at ho1'
    have hv1t := Option.some.inj ho1'
    subst hv1t
    have hlen1 : v1.val.length = 1 := by rw [ht1]; simp [hl]
    obtain ⟨a0, hta0, ha0⟩ := hs3.1 (by scalar_tac)
    rw [hte] at hta0
    cases hta0
  · rename_i o1 hs1 res1 hr1 cf1 resid hcf1 e hres1 r
    intro hre
    obtain ⟨ho1, he⟩ := ok_or_eq_err hr1 hres1
    have hl : bytes.val.length < 1 := by
      by_contra hn
      obtain ⟨t1, ho1', _⟩ := hs1.1 (by scalar_tac)
      rw [ho1] at ho1'
      cases ho1'
    subst hre
    subst he
    exact ⟨fun h => absurd h (by omega), fun _ => rfl⟩

/-- Exact behaviour of `u16::tls_deserialize_bytes`. -/
theorem U16_deserialize_char (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ U16.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ (2 ≤ bytes.val.length → ∃ (a : Aeneas.Std.Array Std.U8 2#usize) (t : Slice Std.U8),
          a.val = bytes.val.take 2 ∧ t.val = bytes.val.drop 2 ∧
          r = .Ok (Aeneas.Std.core.num.U16.from_be_bytes a, t)) ∧
        (bytes.val.length < 2 → r = .Err Error.EndOfStream) ⌝ ⦄ := by
  mvcgen [U16.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes,
    core.option.Option.ok_or_spec, core.result.Result.map_err_spec, core.mem.size_of_U16,
    primitives.DeserializeBytesU16.tls_deserialize_bytes.closure.Insts.CoreOpsFunctionFnOnceTupleTryFromSliceErrorError.call_once]
  try_vcs
  all_goals (try simp only [continue_eq_tryCF] at *)
  · rename_i o1 hs1 res1 hr1 cf1 v1 hcf1 tf hs3 t hteq cf2 v2 hcf2 b hb o2 hs2 res2 hr2 cf3 v3 hcf3 hv1 hv2 hv3
    have ho1 := ok_or_eq_ok hr1 hv1
    by_cases hl : 2 ≤ bytes.val.length
    · obtain ⟨t1, ho1', ht1⟩ := hs1.1 (by scalar_tac)
      rw [ho1] at ho1'
      have hv1t := Option.some.inj ho1'
      subst hv1t
      have hlen1 : v1.val.length = 2 := by rw [ht1]; simp [hl]
      obtain ⟨a0, hta0, ha0⟩ := hs3.1 (by scalar_tac)
      rw [hteq] at hta0
      have h1 := core.result.Result.Ok.inj hta0
      have h2 := core.result.Result.Ok.inj hv2
      obtain ⟨t2, ho2', ht2⟩ := hs2.1 (by scalar_tac)
      have ho2 := ok_or_eq_ok hr2 hv3
      rw [ho2] at ho2'
      have hv3t := Option.some.inj ho2'
      subst hv3t
      refine ⟨fun _ => ⟨v2, v3, ?_, ht2, ?_⟩, fun h => absurd h (by omega)⟩
      · rw [← h2, h1, ha0, ht1]; rfl
      · rw [hb]
    · exfalso
      have := hs1.2 (by scalar_tac)
      rw [ho1] at this
      cases this
  · rename_i o1 hs1 res1 hr1 cf1 v1 hcf1 tf hs3 t hteq cf2 v2 hcf2 b hb o2 hs2 res2 hr2 cf3 resid hcf3 e hres2 r hv1 hv2
    exfalso
    have ho1 := ok_or_eq_ok hr1 hv1
    have hl : 2 ≤ bytes.val.length := by
      by_contra hn
      have := hs1.2 (by scalar_tac)
      rw [ho1] at this
      cases this
    obtain ⟨t2, ho2', ht2⟩ := hs2.1 (by scalar_tac)
    obtain ⟨ho2, _⟩ := ok_or_eq_err hr2 hres2
    rw [ho2] at ho2'
    cases ho2'
  · rename_i o1 hs1 res1 hr1 cf1 v1 hcf1 tf hs3 e hte hv1
    exfalso
    have ho1 := ok_or_eq_ok hr1 hv1
    have hl : 2 ≤ bytes.val.length := by
      by_contra hn
      have := hs1.2 (by scalar_tac)
      rw [ho1] at this
      cases this
    obtain ⟨t1, ho1', ht1⟩ := hs1.1 (by scalar_tac)
    rw [ho1] at ho1'
    have hv1t := Option.some.inj ho1'
    subst hv1t
    have hlen1 : v1.val.length = 2 := by rw [ht1]; simp [hl]
    obtain ⟨a0, hta0, ha0⟩ := hs3.1 (by scalar_tac)
    rw [hte] at hta0
    cases hta0
  · rename_i o1 hs1 res1 hr1 cf1 resid hcf1 e hres1 r
    intro hre
    obtain ⟨ho1, he⟩ := ok_or_eq_err hr1 hres1
    have hl : bytes.val.length < 2 := by
      by_contra hn
      obtain ⟨t1, ho1', _⟩ := hs1.1 (by scalar_tac)
      rw [ho1] at ho1'
      cases ho1'
    subst hre
    subst he
    exact ⟨fun h => absurd h (by omega), fun _ => rfl⟩

/-- Exact behaviour of `u32::tls_deserialize_bytes`. -/
theorem U32_deserialize_char (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ U32.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ (4 ≤ bytes.val.length → ∃ (a : Aeneas.Std.Array Std.U8 4#usize) (t : Slice Std.U8),
          a.val = bytes.val.take 4 ∧ t.val = bytes.val.drop 4 ∧
          r = .Ok (Aeneas.Std.core.num.U32.from_be_bytes a, t)) ∧
        (bytes.val.length < 4 → r = .Err Error.EndOfStream) ⌝ ⦄ := by
  mvcgen [U32.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes,
    core.option.Option.ok_or_spec, core.result.Result.map_err_spec, core.mem.size_of_U32,
    primitives.DeserializeBytesU32.tls_deserialize_bytes.closure.Insts.CoreOpsFunctionFnOnceTupleTryFromSliceErrorError.call_once]
  try_vcs
  all_goals (try simp only [continue_eq_tryCF] at *)
  · rename_i o1 hs1 res1 hr1 cf1 v1 hcf1 tf hs3 t hteq cf2 v2 hcf2 b hb o2 hs2 res2 hr2 cf3 v3 hcf3 hv1 hv2 hv3
    have ho1 := ok_or_eq_ok hr1 hv1
    by_cases hl : 4 ≤ bytes.val.length
    · obtain ⟨t1, ho1', ht1⟩ := hs1.1 (by scalar_tac)
      rw [ho1] at ho1'
      have hv1t := Option.some.inj ho1'
      subst hv1t
      have hlen1 : v1.val.length = 4 := by rw [ht1]; simp [hl]
      obtain ⟨a0, hta0, ha0⟩ := hs3.1 (by scalar_tac)
      rw [hteq] at hta0
      have h1 := core.result.Result.Ok.inj hta0
      have h2 := core.result.Result.Ok.inj hv2
      obtain ⟨t2, ho2', ht2⟩ := hs2.1 (by scalar_tac)
      have ho2 := ok_or_eq_ok hr2 hv3
      rw [ho2] at ho2'
      have hv3t := Option.some.inj ho2'
      subst hv3t
      refine ⟨fun _ => ⟨v2, v3, ?_, ht2, ?_⟩, fun h => absurd h (by omega)⟩
      · rw [← h2, h1, ha0, ht1]; rfl
      · rw [hb]
    · exfalso
      have := hs1.2 (by scalar_tac)
      rw [ho1] at this
      cases this
  · rename_i o1 hs1 res1 hr1 cf1 v1 hcf1 tf hs3 t hteq cf2 v2 hcf2 b hb o2 hs2 res2 hr2 cf3 resid hcf3 e hres2 r hv1 hv2
    exfalso
    have ho1 := ok_or_eq_ok hr1 hv1
    have hl : 4 ≤ bytes.val.length := by
      by_contra hn
      have := hs1.2 (by scalar_tac)
      rw [ho1] at this
      cases this
    obtain ⟨t2, ho2', ht2⟩ := hs2.1 (by scalar_tac)
    obtain ⟨ho2, _⟩ := ok_or_eq_err hr2 hres2
    rw [ho2] at ho2'
    cases ho2'
  · rename_i o1 hs1 res1 hr1 cf1 v1 hcf1 tf hs3 e hte hv1
    exfalso
    have ho1 := ok_or_eq_ok hr1 hv1
    have hl : 4 ≤ bytes.val.length := by
      by_contra hn
      have := hs1.2 (by scalar_tac)
      rw [ho1] at this
      cases this
    obtain ⟨t1, ho1', ht1⟩ := hs1.1 (by scalar_tac)
    rw [ho1] at ho1'
    have hv1t := Option.some.inj ho1'
    subst hv1t
    have hlen1 : v1.val.length = 4 := by rw [ht1]; simp [hl]
    obtain ⟨a0, hta0, ha0⟩ := hs3.1 (by scalar_tac)
    rw [hte] at hta0
    cases hta0
  · rename_i o1 hs1 res1 hr1 cf1 resid hcf1 e hres1 r
    intro hre
    obtain ⟨ho1, he⟩ := ok_or_eq_err hr1 hres1
    have hl : bytes.val.length < 4 := by
      by_contra hn
      obtain ⟨t1, ho1', _⟩ := hs1.1 (by scalar_tac)
      rw [ho1] at ho1'
      cases ho1'
    subst hre
    subst he
    exact ⟨fun h => absurd h (by omega), fun _ => rfl⟩

/-- Exact behaviour of `u64::tls_deserialize_bytes`. -/
theorem U64_deserialize_char (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ U64.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ (8 ≤ bytes.val.length → ∃ (a : Aeneas.Std.Array Std.U8 8#usize) (t : Slice Std.U8),
          a.val = bytes.val.take 8 ∧ t.val = bytes.val.drop 8 ∧
          r = .Ok (Aeneas.Std.core.num.U64.from_be_bytes a, t)) ∧
        (bytes.val.length < 8 → r = .Err Error.EndOfStream) ⌝ ⦄ := by
  mvcgen [U64.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes,
    core.option.Option.ok_or_spec, core.result.Result.map_err_spec, core.mem.size_of_U64,
    primitives.DeserializeBytesU64.tls_deserialize_bytes.closure.Insts.CoreOpsFunctionFnOnceTupleTryFromSliceErrorError.call_once]
  try_vcs
  all_goals (try simp only [continue_eq_tryCF] at *)
  · rename_i o1 hs1 res1 hr1 cf1 v1 hcf1 tf hs3 t hteq cf2 v2 hcf2 b hb o2 hs2 res2 hr2 cf3 v3 hcf3 hv1 hv2 hv3
    have ho1 := ok_or_eq_ok hr1 hv1
    by_cases hl : 8 ≤ bytes.val.length
    · obtain ⟨t1, ho1', ht1⟩ := hs1.1 (by scalar_tac)
      rw [ho1] at ho1'
      have hv1t := Option.some.inj ho1'
      subst hv1t
      have hlen1 : v1.val.length = 8 := by rw [ht1]; simp [hl]
      obtain ⟨a0, hta0, ha0⟩ := hs3.1 (by scalar_tac)
      rw [hteq] at hta0
      have h1 := core.result.Result.Ok.inj hta0
      have h2 := core.result.Result.Ok.inj hv2
      obtain ⟨t2, ho2', ht2⟩ := hs2.1 (by scalar_tac)
      have ho2 := ok_or_eq_ok hr2 hv3
      rw [ho2] at ho2'
      have hv3t := Option.some.inj ho2'
      subst hv3t
      refine ⟨fun _ => ⟨v2, v3, ?_, ht2, ?_⟩, fun h => absurd h (by omega)⟩
      · rw [← h2, h1, ha0, ht1]; rfl
      · rw [hb]
    · exfalso
      have := hs1.2 (by scalar_tac)
      rw [ho1] at this
      cases this
  · rename_i o1 hs1 res1 hr1 cf1 v1 hcf1 tf hs3 t hteq cf2 v2 hcf2 b hb o2 hs2 res2 hr2 cf3 resid hcf3 e hres2 r hv1 hv2
    exfalso
    have ho1 := ok_or_eq_ok hr1 hv1
    have hl : 8 ≤ bytes.val.length := by
      by_contra hn
      have := hs1.2 (by scalar_tac)
      rw [ho1] at this
      cases this
    obtain ⟨t2, ho2', ht2⟩ := hs2.1 (by scalar_tac)
    obtain ⟨ho2, _⟩ := ok_or_eq_err hr2 hres2
    rw [ho2] at ho2'
    cases ho2'
  · rename_i o1 hs1 res1 hr1 cf1 v1 hcf1 tf hs3 e hte hv1
    exfalso
    have ho1 := ok_or_eq_ok hr1 hv1
    have hl : 8 ≤ bytes.val.length := by
      by_contra hn
      have := hs1.2 (by scalar_tac)
      rw [ho1] at this
      cases this
    obtain ⟨t1, ho1', ht1⟩ := hs1.1 (by scalar_tac)
    rw [ho1] at ho1'
    have hv1t := Option.some.inj ho1'
    subst hv1t
    have hlen1 : v1.val.length = 8 := by rw [ht1]; simp [hl]
    obtain ⟨a0, hta0, ha0⟩ := hs3.1 (by scalar_tac)
    rw [hte] at hta0
    cases hta0
  · rename_i o1 hs1 res1 hr1 cf1 resid hcf1 e hres1 r
    intro hre
    obtain ⟨ho1, he⟩ := ok_or_eq_err hr1 hres1
    have hl : bytes.val.length < 8 := by
      by_contra hn
      obtain ⟨t1, ho1', _⟩ := hs1.1 (by scalar_tac)
      rw [ho1] at ho1'
      cases ho1'
    subst hre
    subst he
    exact ⟨fun h => absurd h (by omega), fun _ => rfl⟩

/-- Exact behaviour of `u8::tls_serialize_bytes`: never fails, returns the big-endian bytes. -/
@[spec] theorem U8_serialize_char (x : Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ U8.Insts.Tls_codecSerializeBytes.tls_serialize_bytes x
    ⦃ ⇓ r => ⌜ ∃ v : alloc.vec.Vec Std.U8, r = .Ok v ∧
        (v : Slice Std.U8).val = (Aeneas.Std.core.num.U8.to_be_bytes x).val ⌝ ⦄ := by
  mvcgen [U8.Insts.Tls_codecSerializeBytes.tls_serialize_bytes,
    Shared0U8.Insts.Tls_codecSerializeBytes.tls_serialize_bytes]
  exact ⟨_, rfl, by simp [Aeneas.Std.Array.to_slice, *]⟩

/-- Exact behaviour of `u16::tls_serialize_bytes`: never fails, returns the big-endian bytes. -/
@[spec] theorem U16_serialize_char (x : Std.U16) :
    ⦃ ⌜ True ⌝ ⦄ U16.Insts.Tls_codecSerializeBytes.tls_serialize_bytes x
    ⦃ ⇓ r => ⌜ ∃ v : alloc.vec.Vec Std.U8, r = .Ok v ∧
        (v : Slice Std.U8).val = (Aeneas.Std.core.num.U16.to_be_bytes x).val ⌝ ⦄ := by
  mvcgen [U16.Insts.Tls_codecSerializeBytes.tls_serialize_bytes,
    Shared0U16.Insts.Tls_codecSerializeBytes.tls_serialize_bytes]
  exact ⟨_, rfl, by simp [Aeneas.Std.Array.to_slice, *]⟩

/-- Exact behaviour of `u32::tls_serialize_bytes`: never fails, returns the big-endian bytes. -/
@[spec] theorem U32_serialize_char (x : Std.U32) :
    ⦃ ⌜ True ⌝ ⦄ U32.Insts.Tls_codecSerializeBytes.tls_serialize_bytes x
    ⦃ ⇓ r => ⌜ ∃ v : alloc.vec.Vec Std.U8, r = .Ok v ∧
        (v : Slice Std.U8).val = (Aeneas.Std.core.num.U32.to_be_bytes x).val ⌝ ⦄ := by
  mvcgen [U32.Insts.Tls_codecSerializeBytes.tls_serialize_bytes,
    Shared0U32.Insts.Tls_codecSerializeBytes.tls_serialize_bytes]
  exact ⟨_, rfl, by simp [Aeneas.Std.Array.to_slice, *]⟩

/-- Exact behaviour of `u64::tls_serialize_bytes`: never fails, returns the big-endian bytes. -/
@[spec] theorem U64_serialize_char (x : Std.U64) :
    ⦃ ⌜ True ⌝ ⦄ U64.Insts.Tls_codecSerializeBytes.tls_serialize_bytes x
    ⦃ ⇓ r => ⌜ ∃ v : alloc.vec.Vec Std.U8, r = .Ok v ∧
        (v : Slice Std.U8).val = (Aeneas.Std.core.num.U64.to_be_bytes x).val ⌝ ⦄ := by
  mvcgen [U64.Insts.Tls_codecSerializeBytes.tls_serialize_bytes,
    Shared0U64.Insts.Tls_codecSerializeBytes.tls_serialize_bytes]
  exact ⟨_, rfl, by simp [Aeneas.Std.Array.to_slice, *]⟩

/-- The body of the closures of the `*_decode_encode` posts:
`bytes.get(..consumed) == Some(out.as_slice())`. -/
def prefixCheck (c : Slice Std.U8) (tupled_args : (alloc.vec.Vec Std.U8) × Std.Usize) :
    RustM Bool := do
  let (out, consumed) := tupled_args
  let o ← core.slice.Slice.get
    (core.ops.range.RangeToUsize.Insts.CoreSliceIndexSliceIndexSliceSlice Std.U8) c
    { «end» := consumed }
  let s ← alloc.vec.Vec.as_slice out
  core.option.Option.Insts.CoreCmpPartialEqOption.eq
    (core.Shared1A.Insts.CoreCmpPartialEqShared0B
    (core.Slice.Insts.CoreCmpPartialEqSlice core.U8.Insts.CoreCmpPartialEqU8))
    o (core.option.Option.Some s)

theorem prefixCheck_spec (c : Slice Std.U8) (out : alloc.vec.Vec Std.U8) (consumed : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ prefixCheck c (out, consumed)
    ⦃ ⇓ r => ⌜ r = true ↔ (consumed.val ≤ c.val.length ∧ c.val.take consumed.val = out.val) ⌝ ⦄ := by
  unfold prefixCheck
  have hs := core.Slice.Insts.CoreCmpPartialEqSlice.eq_spec core.U8.Insts.CoreCmpPartialEqU8
    (heq := core.U8.Insts.CoreCmpPartialEqU8.eq_decide_spec)
  have hdec : ∀ x y : Slice Std.U8, decide (x = y) = decide (x.val = y.val) := by
    intro x y
    have : x = y ↔ x.val = y.val := ⟨fun h => by rw [h], fun h => Subtype.ext h⟩
    simp only [this]
  have hs1 : ∀ x y : Slice Std.U8, ⦃ ⌜ True ⌝ ⦄
      (core.Shared1A.Insts.CoreCmpPartialEqShared0B
        (core.Slice.Insts.CoreCmpPartialEqSlice core.U8.Insts.CoreCmpPartialEqU8)).eq x y
      ⦃ ⇓ r => ⌜ r = decide (x = y) ⌝ ⦄ := by
    intro x y
    rw [hdec]
    exact hs x y
  mvcgen [core.option.Option.Insts.CoreCmpPartialEqOption.eq_spec, hs1]
  rename_i o ho s hs' r
  intro hr
  subst hr hs'
  rw [decide_eq_true_iff]
  constructor
  · intro h
    by_cases hle : consumed.val ≤ c.val.length
    · obtain ⟨t, rfl, ht⟩ := ho.1 hle
      have := Option.some.inj h
      subst this
      exact ⟨hle, ht.symm⟩
    · have := ho.2 (by omega)
      rw [this] at h
      cases h
  · rintro ⟨hle, htk⟩
    obtain ⟨t, rfl, ht⟩ := ho.1 hle
    congr 1
    exact Subtype.ext (ht.trans htk)

/-- Exact behaviour of `U24::tls_deserialize_bytes`. -/
theorem U24_deserialize_char (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ U24.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ (3 ≤ bytes.val.length → ∃ (a : Aeneas.Std.Array Std.U8 3#usize) (t : Slice Std.U8),
          a.val = bytes.val.take 3 ∧ t.val = bytes.val.drop 3 ∧
          r = .Ok (a, t)) ∧
        (bytes.val.length < 3 → r = .Err Error.EndOfStream) ⌝ ⦄ := by
  mvcgen [U24.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes,
    core.option.Option.ok_or_spec, core.result.Result.map_err_spec, core.mem.size_of_U24, U24.from_be_bytes,
    primitives.DeserializeBytesU24.tls_deserialize_bytes.closure.Insts.CoreOpsFunctionFnOnceTupleTryFromSliceErrorError.call_once]
  try_vcs
  all_goals (try simp only [continue_eq_tryCF] at *)
  · rename_i o1 hs1 res1 hr1 cf1 v1 hcf1 tf hs3 t hteq cf2 v2 hcf2 o2 hs2 res2 hr2 cf3 v3 hcf3 hv1 hv2 hv3
    have ho1 := ok_or_eq_ok hr1 hv1
    by_cases hl : 3 ≤ bytes.val.length
    · obtain ⟨t1, ho1', ht1⟩ := hs1.1 (by scalar_tac)
      rw [ho1] at ho1'
      have hv1t := Option.some.inj ho1'
      subst hv1t
      have hlen1 : v1.val.length = 3 := by rw [ht1]; simp [hl]
      obtain ⟨a0, hta0, ha0⟩ := hs3.1 (by scalar_tac)
      rw [hteq] at hta0
      have h1 := core.result.Result.Ok.inj hta0
      have h2 := core.result.Result.Ok.inj hv2
      obtain ⟨t2, ho2', ht2⟩ := hs2.1 (by scalar_tac)
      have ho2 := ok_or_eq_ok hr2 hv3
      rw [ho2] at ho2'
      have hv3t := Option.some.inj ho2'
      subst hv3t
      refine ⟨fun _ => ⟨v2, v3, ?_, ht2, ?_⟩, fun h => absurd h (by omega)⟩
      · rw [← h2, h1, ha0, ht1]; rfl
      · rfl
    · exfalso
      have := hs1.2 (by scalar_tac)
      rw [ho1] at this
      cases this
  · rename_i o1 hs1 res1 hr1 cf1 v1 hcf1 tf hs3 t hteq cf2 v2 hcf2 o2 hs2 res2 hr2 cf3 resid hcf3 e hres2 r hv1 hv2
    exfalso
    have ho1 := ok_or_eq_ok hr1 hv1
    have hl : 3 ≤ bytes.val.length := by
      by_contra hn
      have := hs1.2 (by scalar_tac)
      rw [ho1] at this
      cases this
    obtain ⟨t2, ho2', ht2⟩ := hs2.1 (by scalar_tac)
    obtain ⟨ho2, _⟩ := ok_or_eq_err hr2 hres2
    rw [ho2] at ho2'
    cases ho2'
  · rename_i o1 hs1 res1 hr1 cf1 v1 hcf1 tf hs3 e hte hv1
    exfalso
    have ho1 := ok_or_eq_ok hr1 hv1
    have hl : 3 ≤ bytes.val.length := by
      by_contra hn
      have := hs1.2 (by scalar_tac)
      rw [ho1] at this
      cases this
    obtain ⟨t1, ho1', ht1⟩ := hs1.1 (by scalar_tac)
    rw [ho1] at ho1'
    have hv1t := Option.some.inj ho1'
    subst hv1t
    have hlen1 : v1.val.length = 3 := by rw [ht1]; simp [hl]
    obtain ⟨a0, hta0, ha0⟩ := hs3.1 (by scalar_tac)
    rw [hte] at hta0
    cases hta0
  · rename_i o1 hs1 res1 hr1 cf1 resid hcf1 e hres1 r
    intro hre
    obtain ⟨ho1, he⟩ := ok_or_eq_err hr1 hres1
    have hl : bytes.val.length < 3 := by
      by_contra hn
      obtain ⟨t1, ho1', _⟩ := hs1.1 (by scalar_tac)
      rw [ho1] at ho1'
      cases ho1'
    subst hre
    subst he
    exact ⟨fun h => absurd h (by omega), fun _ => rfl⟩


/-- Exact behaviour of `[u8; LEN]::tls_deserialize_bytes`. -/
theorem ArrayU8LEN_deserialize_char (LEN : Std.Usize) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ ArrayU8LEN.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes LEN bytes
    ⦃ ⇓ r => ⌜ (LEN.val ≤ bytes.val.length → ∃ (a : Aeneas.Std.Array Std.U8 LEN) (t : Slice Std.U8),
          a.val = bytes.val.take LEN.val ∧ t.val = bytes.val.drop LEN.val ∧
          r = .Ok (a, t)) ∧
        (bytes.val.length < LEN.val → r = .Err Error.EndOfStream) ⌝ ⦄ := by
  unfold ArrayU8LEN.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
  mvcgen [
    arrays.DeserializeBytesArrayU8LEN.tls_deserialize_bytes.closure.Insts.CoreOpsFunctionFnOnceTupleTryFromSliceErrorError.call_once,
    core.option.Option.ok_or_spec, core.result.Result.map_err_spec, core.Slice.Insts.CoreOpsIndexIndex.index_spec,
    core.ops.range.RangeFromUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get_spec]
  try_vcs
  all_goals (try simp only [continue_eq_tryCF] at *)
  · rename_i o1 hs1 res1 hr1 cf1 v1 hcf1 tf hs3 t hteq cf2 v2 hcf2 o2 hv1 hv2
    intro hs2a hs2b
    have ho1 := ok_or_eq_ok hr1 hv1
    by_cases hl : LEN.val ≤ bytes.val.length
    · obtain ⟨t1, ho1', ht1⟩ := hs1.1 hl
      rw [ho1] at ho1'
      have hv1t := Option.some.inj ho1'
      subst hv1t
      have hlen1 : v1.val.length = LEN.val := by rw [ht1]; simp [hl]
      obtain ⟨a0, hta0, ha0⟩ := hs3.1 hlen1
      rw [hteq] at hta0
      have h1 := core.result.Result.Ok.inj hta0
      have h2 := core.result.Result.Ok.inj hv2
      obtain ⟨t2, ho2, ht2⟩ := hs2a hl
      refine ⟨t2, ho2, ?_⟩
      simp only [PostCond.ok]
      mvcgen
      refine ⟨fun _ => ⟨v2, t2, ?_, ht2, rfl⟩, fun h => absurd h (by omega)⟩
      rw [← h2, h1, ha0, ht1]
    · exfalso
      have := hs1.2 (by omega)
      rw [ho1] at this
      cases this
  · rename_i o1 hs1 res1 hr1 cf1 v1 hcf1 tf hs3 e hte r hv1
    exfalso
    have ho1 := ok_or_eq_ok hr1 hv1
    have hl : LEN.val ≤ bytes.val.length := by
      by_contra hn
      have := hs1.2 (by omega)
      rw [ho1] at this
      cases this
    obtain ⟨t1, ho1', ht1⟩ := hs1.1 hl
    rw [ho1] at ho1'
    have hv1t := Option.some.inj ho1'
    subst hv1t
    have hlen1 : v1.val.length = LEN.val := by rw [ht1]; simp [hl]
    obtain ⟨a0, hta0, ha0⟩ := hs3.1 hlen1
    rw [hte] at hta0
    cases hta0
  · rename_i o1 hs1 res1 hr1 cf1 resid hcf1 e hres1 r
    intro hre
    obtain ⟨ho1, he⟩ := ok_or_eq_err hr1 hres1
    have hl : bytes.val.length < LEN.val := by
      by_contra hn
      obtain ⟨t1, ho1', _⟩ := hs1.1 (by omega)
      rw [ho1] at ho1'
      cases ho1'
    subst hre
    subst he
    exact ⟨fun h => absurd h (by omega), fun _ => rfl⟩

/-- Exact behaviour of `U24::tls_serialize_bytes`: never fails, returns the three bytes. -/
@[spec] theorem U24_serialize_char (x : U24) :
    ⦃ ⌜ True ⌝ ⦄ U24.Insts.Tls_codecSerializeBytes.tls_serialize_bytes x
    ⦃ ⇓ r => ⌜ ∃ v : alloc.vec.Vec Std.U8, r = .Ok v ∧ (v : Slice Std.U8).val = x.val ⌝ ⦄ := by
  mvcgen [U24.Insts.Tls_codecSerializeBytes.tls_serialize_bytes,
    Shared0U24.Insts.Tls_codecSerializeBytes.tls_serialize_bytes, U24.to_be_bytes]
  exact ⟨_, rfl, by simp [Aeneas.Std.Array.to_slice, *]⟩

theorem U24_eq_spec (x y : U24) :
    ⦃ ⌜ True ⌝ ⦄ U24.Insts.CoreCmpPartialEqU24.eq x y
    ⦃ ⇓ r => ⌜ r = decide (x.val = y.val) ⌝ ⦄ := by
  unfold U24.Insts.CoreCmpPartialEqU24.eq
  exact core.Array.Insts.CoreCmpPartialEqArray.eq_spec _ x y
    core.U8.Insts.CoreCmpPartialEqU8.eq_decide_spec

/-- Exact behaviour of `[u8; LEN]::tls_serialize_bytes`: never fails, returns the bytes. -/
@[spec] theorem ArrayU8LEN_serialize_char {LEN : Std.Usize} (x : Aeneas.Std.Array Std.U8 LEN) :
    ⦃ ⌜ True ⌝ ⦄ ArrayU8LEN.Insts.Tls_codecSerializeBytes.tls_serialize_bytes x
    ⦃ ⇓ r => ⌜ ∃ v : alloc.vec.Vec Std.U8, r = .Ok v ∧ (v : Slice Std.U8).val = x.val ⌝ ⦄ := by
  mvcgen [ArrayU8LEN.Insts.Tls_codecSerializeBytes.tls_serialize_bytes]
  exact ⟨_, rfl, by simp [Aeneas.Std.Array.to_slice, *]⟩

/-- `==` on `[u8; N]`. -/
@[spec high] theorem Array_U8_eq_spec {N : Std.Usize} (a b : Aeneas.Std.Array Std.U8 N) :
    ⦃ ⌜ True ⌝ ⦄ core.Array.Insts.CoreCmpPartialEqArray.eq core.U8.Insts.CoreCmpPartialEqU8 a b
    ⦃ ⇓ r => ⌜ r = decide (a.val = b.val) ⌝ ⦄ :=
  core.Array.Insts.CoreCmpPartialEqArray.eq_spec _ a b core.U8.Insts.CoreCmpPartialEqU8.eq_decide_spec

end tls_codec
