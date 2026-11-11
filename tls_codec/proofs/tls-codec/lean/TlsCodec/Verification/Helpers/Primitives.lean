/- `Option<u16>`, `copy_from_slice`, and `usize::from_be_bytes` of a `U24`.

Obligations: none directly; the bytes-path halves of `PanicFreedom.lean` /
`FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): ASSUMED `size_of`, `size_of_U16`, `size_of_U8`,
`size_of_Usize`. -/
import TlsCodec.Verification.Helpers.VarIntWrite
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! ### `Option<u16>` -/

/-- `Box<[T]>::into_vec`: the identity on the contents. -/
theorem alloc.slice.Slice.into_vec_spec {T : Type} (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ alloc.slice.Slice.into_vec s ⦃ ⇓ r => ⌜ (r : Slice T) = s ⌝ ⦄ := by
  unfold alloc.slice.Slice.into_vec alloc.slice.Dummy.into_vec
    rust_primitives.sequence.seq_from_boxed_slice alloc.vec.from_seq
  mvcgen

/-- Exact behaviour of `Option<u16>::tls_serialize_bytes`: never fails, `0` or `1` followed by the
big-endian bytes. -/
theorem Option_U16_serialize_char (o : core.option.Option Std.U16) :
    ⦃ ⌜ True ⌝ ⦄ core.option.Option.Insts.Tls_codecSerializeBytes.tls_serialize_bytes
      U16.Insts.Tls_codecSerializeBytes o
    ⦃ ⇓ r => ⌜ ∃ v : alloc.vec.Vec Std.U8, r = .Ok v ∧
        (v : Slice Std.U8).val = (match o with
          | .none => [0#u8]
          | .some x => 1#u8 :: (Aeneas.Std.core.num.U16.to_be_bytes x).val) ⌝ ⦄ := by
  cases o with
  | none =>
    mvcgen [core.option.Option.Insts.Tls_codecSerializeBytes.tls_serialize_bytes,
      alloc.slice.Slice.into_vec_spec]
    refine ⟨_, rfl, ?_⟩
    simp_all [Std.Array.to_slice]
    rfl
  | some x =>
    mvcgen [core.option.Option.Insts.Tls_codecSerializeBytes.tls_serialize_bytes,
      U16.Insts.Tls_codecSize.tls_serialized_len, core.mem.size_of_U16, checked_alloc_len,
      checked_capacity, alloc.vec.Vec.with_capacity, alloc.vec.Vec.append,
      rust_primitives.sequence.seq_concat]
    · rename_i sat hsat hgt cf resid hx
      intro _
      exfalso
      have := Usize.hcast_Isize_MAX_val
      have h3 := Usize_saturating_add_val 2#usize 1#usize (by scalar_tac)
      rw [← hsat] at h3
      scalar_tac
    · rename_i sat hsat hle cf val hx hcf v hv
      subst hv
      have h0 : (Slice.new U8).val.length = 0 := rfl
      rw [h0]
      scalar_tac
    · rename_i sat hsat hle cf val hx hcf v0 hv0 v1 hv1 res hres cf1 val1 hx1 hcf1 comb hlen
      obtain ⟨v, rfl, hv⟩ := hres
      rw [continue_eq_tryCF, core.result.Result.Ok.injEq] at hcf1
      subst hcf1
      subst hv0
      refine ⟨⟨comb, hlen⟩, rfl, ?_⟩
      show comb = _
      simp only [comb, hv1, hv]
      rfl
    · rename_i sat hsat hle cf val hx hcf v0 hv0 v1 hv1 res hres cf1 val1 hx1 hcf1 comb hlen
      obtain ⟨v, rfl, hv⟩ := hres
      rw [continue_eq_tryCF, core.result.Result.Ok.injEq] at hcf1
      subst hcf1
      subst hv0
      have h2 : v.val.length = 2 := by
        rw [hv]; simpa using (Aeneas.Std.core.num.U16.to_be_bytes x).property
      exfalso; apply hlen
      simp only [comb, hv1, List.length_append, h2]
      simp [Slice.new]
      scalar_tac
    · rename_i sat hsat hle cf val hx hcf v0 hv0 v1 hv1 res hres cf1 resid hx1
      obtain ⟨v, rfl, hv⟩ := hres
      intro hb
      simp only [tryCF, reduceCtorEq] at hb
    · rename_i sat hsat hle cf resid hx
      intro hb
      simp only [tryCF, reduceCtorEq] at hb

theorem U8_to_be_bytes_val (x : Std.U8) : (Aeneas.Std.core.num.U8.to_be_bytes x).val = [x] := by
  unfold Aeneas.Std.core.num.U8.to_be_bytes
  simp [BitVec.toBEBytes]
  rw [BitVec.toLEBytes.eq_def]
  simp
  rw [BitVec.toLEBytes.eq_def]
  simp

theorem U8_from_be_bytes_of_val (a : Aeneas.Std.Array Std.U8 1#usize) (b : Std.U8)
    (h : a.val = [b]) : Aeneas.Std.core.num.U8.from_be_bytes a = b := by
  have h1 := U8_to_be_bytes_from_be_bytes a
  have h2 := congrArg Subtype.val h1
  rw [U8_to_be_bytes_val, h] at h2
  exact List.singleton_inj.mp h2

/-- Consequences of a successful `?` on the result of `u8::tls_deserialize_bytes`. -/
theorem U8_deserialize_ok {bytes : Slice Std.U8} {r : core.result.Result (Std.U8 × Slice Std.U8) Error}
    {p : Std.U8 × Slice Std.U8}
    (hP : (1 ≤ bytes.val.length → ∃ (a : Aeneas.Std.Array Std.U8 1#usize) (t : Slice Std.U8),
          a.val = bytes.val.take 1 ∧ t.val = bytes.val.drop 1 ∧
          r = .Ok (Aeneas.Std.core.num.U8.from_be_bytes a, t)) ∧
        (bytes.val.length < 1 → r = .Err Error.EndOfStream))
    (hcf : core.ops.control_flow.ControlFlow.Continue p = tryCF r) :
    ∃ l, bytes.val = p.1 :: l ∧ p.2.val = l := by
  rw [continue_eq_tryCF] at hcf
  have hl : 1 ≤ bytes.val.length := by
    by_contra hn
    rw [hP.2 (by omega)] at hcf
    cases hcf
  obtain ⟨a, t, ha, ht, hr⟩ := hP.1 hl
  rw [hr, core.result.Result.Ok.injEq] at hcf
  subst hcf
  cases hb : bytes.val with
  | nil => rw [hb] at hl; simp at hl
  | cons b l =>
    rw [hb] at ha ht
    simp only [List.take_succ_cons, List.take_zero, List.drop_succ_cons, List.drop_zero] at ha ht
    refine ⟨l, ?_, ht⟩
    simp only [U8_from_be_bytes_of_val a b ha]

/-- Consequences of a successful `?` on the result of `u16::tls_deserialize_bytes`. -/
theorem U16_deserialize_ok {s : Slice Std.U8} {r : core.result.Result (Std.U16 × Slice Std.U8) Error}
    {p : Std.U16 × Slice Std.U8}
    (hP : (2 ≤ s.val.length → ∃ (a : Aeneas.Std.Array Std.U8 2#usize) (t : Slice Std.U8),
          a.val = s.val.take 2 ∧ t.val = s.val.drop 2 ∧
          r = .Ok (Aeneas.Std.core.num.U16.from_be_bytes a, t)) ∧
        (s.val.length < 2 → r = .Err Error.EndOfStream))
    (hcf : core.ops.control_flow.ControlFlow.Continue p = tryCF r) :
    2 ≤ s.val.length ∧ ∃ (a : Aeneas.Std.Array Std.U8 2#usize) (t : Slice Std.U8),
      a.val = s.val.take 2 ∧ t.val = s.val.drop 2 ∧ p = (Aeneas.Std.core.num.U16.from_be_bytes a, t) := by
  rw [continue_eq_tryCF] at hcf
  have hl : 2 ≤ s.val.length := by
    by_contra hn
    rw [hP.2 (by omega)] at hcf
    cases hcf
  obtain ⟨a, t, ha, ht, hr⟩ := hP.1 hl
  rw [hr, core.result.Result.Ok.injEq] at hcf
  exact ⟨hl, a, t, ha, ht, hcf.symm⟩

/-- Exact behaviour of `Option<u16>::tls_deserialize_bytes`. -/
theorem Option_U16_deserialize_char (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ core.option.Option.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
      U16.Insts.Tls_codecDeserializeBytes bytes
    ⦃ ⇓ r => ⌜ (∀ l, bytes.val = 0#u8 :: l → ∃ t : Slice Std.U8, t.val = l ∧ r = .Ok (.none, t)) ∧
        (∀ l, bytes.val = 1#u8 :: l → 2 ≤ l.length →
          ∃ (a : Aeneas.Std.Array Std.U8 2#usize) (t : Slice Std.U8), a.val = l.take 2 ∧
            t.val = l.drop 2 ∧
            r = .Ok (.some (Aeneas.Std.core.num.U16.from_be_bytes a), t)) ∧
        (∀ v t, r = .Ok (v, t) →
          (∃ l, bytes.val = 0#u8 :: l ∧ v = .none ∧ t.val = l) ∨
          (∃ (a : Aeneas.Std.Array Std.U8 2#usize) (l : List Std.U8), bytes.val = 1#u8 :: (a.val ++ l) ∧
            v = .some (Aeneas.Std.core.num.U16.from_be_bytes a) ∧ t.val = l)) ⌝ ⦄ := by
  mvcgen [core.option.Option.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes,
    U8_deserialize_char, U16_deserialize_char]
  · rename_i r1 hP cf p hx hz hcf
    obtain ⟨l, hb, hp2⟩ := U8_deserialize_ok hP hcf
    rw [hz] at hb
    refine ⟨fun l' hl' => ?_, fun l' hl' _ => ?_, fun v t hv => ?_⟩
    · rw [hb] at hl'
      have := (List.cons.inj hl').2
      exact ⟨p.2, by rw [hp2, this], rfl⟩
    · rw [hb] at hl'
      exact absurd (List.cons.inj hl').1 (by decide)
    · simp only [core.result.Result.Ok.injEq, Prod.mk.injEq] at hv
      obtain ⟨hv1, hv2⟩ := hv
      subst hv1 hv2
      exact Or.inl ⟨l, hb, rfl, hp2⟩
  · rename_i r1 hP cf p hx hz hcf r2 hP2 cf2 p2 hx2 hcf2
    obtain ⟨l, hb, hp2⟩ := U8_deserialize_ok hP hcf
    obtain ⟨hl2, a, t, ha, ht, hp⟩ := U16_deserialize_ok hP2 hcf2
    rw [hz] at hb
    subst hp
    refine ⟨fun l' hl' => ?_, fun l' hl' hl2' => ?_, fun v t' hv => ?_⟩
    · rw [hb] at hl'
      exact absurd (List.cons.inj hl').1 (by decide)
    · rw [hb] at hl'
      have hll := (List.cons.inj hl').2
      subst hll
      rw [hp2] at ha ht
      exact ⟨a, t, ha, ht, rfl⟩
    · simp only [core.result.Result.Ok.injEq, Prod.mk.injEq] at hv
      obtain ⟨hv1, hv2⟩ := hv
      subst hv1 hv2
      refine Or.inr ⟨a, l.drop 2, ?_, rfl, ?_⟩
      · rw [hb, ha, hp2, List.take_append_drop]
        rfl
      · rw [ht, hp2]
  · rename_i r1 hP cf p hx hz hcf r2 hP2 cf2 resid hx2
    obtain ⟨l, hb, hp2⟩ := U8_deserialize_ok hP hcf
    rw [hz] at hb
    apply try_break_vc
    intro e he
    mvcgen
    intro hre
    subst hre
    simp only [PostCond.ok]
    refine ⟨fun l' hl' => ?_, fun l' hl' hl2' => ?_, fun v t hv => ?_⟩
    · rw [hb] at hl'
      exact absurd (List.cons.inj hl').1 (by decide)
    · rw [hb] at hl'
      have hll := (List.cons.inj hl').2
      subst hll
      rw [hp2] at hP2
      obtain ⟨a, t, _, _, hr⟩ := hP2.1 hl2'
      rw [he] at hr
      cases hr
    · cases hv
  · rename_i r1 hP cf p hx n h0 h1 hn hcf a1 a2 s1 s2 hs
    obtain ⟨l, hb, hp2⟩ := U8_deserialize_ok hP hcf
    refine ⟨fun l' hl' => ?_, fun l' hl' _ => ?_, fun v t hv => ?_⟩
    · rw [hb, hn] at hl'
      exact absurd (List.cons.inj hl').1 h0
    · rw [hb, hn] at hl'
      exact absurd (List.cons.inj hl').1 h1
    · cases hv
  · rename_i r1 hP cf resid hx
    apply try_break_vc
    intro e he
    mvcgen
    intro hre
    subst hre
    simp only [PostCond.ok]
    have hlen : bytes.val.length < 1 := by
      by_contra hn
      obtain ⟨a, t, _, _, hr⟩ := hP.1 (by omega)
      rw [he] at hr
      cases hr
    refine ⟨fun l' hl' => ?_, fun l' hl' hl2' => ?_, fun v t hv => ?_⟩
    · rw [hl'] at hlen; simp at hlen
    · rw [hl'] at hlen; simp at hlen
    · cases hv

/-! ### `copy_from_slice` -/

/-- Cloning a `u8` list is the identity. -/
theorem mapM_clone_U8 (l : List Std.U8) :
    l.mapM core.U8.Insts.CoreCloneClone.clone = ok l := by
  induction l with
  | nil => rfl
  | cons x xs ih =>
    rw [List.mapM_cons, ih]
    rfl

/-- `dest.copy_from_slice(src)` on `u8`: if it returns, the lengths agree and the result is `src`.
Partial: it panics when the lengths differ. -/
theorem core.slice.Slice.copy_from_slice_U8_spec (s src : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ core.slice.Slice.copy_from_slice core.U8.Insts.CoreMarkerCopy s src
    ⦃ ⇓? r => ⌜ s.val.length = src.val.length ∧ r.val = src.val ⌝ ⦄ := by
  apply partial_triple_of_ok
  intro r hr
  unfold core.slice.Slice.copy_from_slice rust_primitives.slice.slice_clone_from_slice at hr
  split at hr
  · rename_i hlen
    split at hr
    · rename_i cloned hcl
      rw [mapM_clone_U8] at hcl
      have : src.val = cloned := by injection hcl
      cases hr
      exact ⟨hlen, this.symm⟩
    · rename_i e hcl
      rw [mapM_clone_U8] at hcl
      cases hcl
    · rename_i hcl
      rw [mapM_clone_U8] at hcl
      cases hcl
  · cases hr

/-- Total version of `copy_from_slice_U8_spec`: with equal lengths, the call does not panic.
Not tagged `@[spec]` (extra hypothesis). -/
theorem core.slice.Slice.copy_from_slice_U8_total (s src : Slice Std.U8)
    (h : s.val.length = src.val.length) :
    ⦃ ⌜ True ⌝ ⦄ core.slice.Slice.copy_from_slice core.U8.Insts.CoreMarkerCopy s src
    ⦃ ⇓ r => ⌜ r.val = src.val ⌝ ⦄ := by
  unfold core.slice.Slice.copy_from_slice rust_primitives.slice.slice_clone_from_slice
  rw [if_pos h]
  split
  · rename_i cloned hcl
    rw [mapM_clone_U8] at hcl
    have : src.val = cloned := by injection hcl
    apply RustM.ok_spec
    exact this.symm
  · rename_i e hcl
    rw [mapM_clone_U8] at hcl
    cases hcl
  · rename_i hcl
    rw [mapM_clone_U8] at hcl
    cases hcl

/-- `size_of::<usize>()` returns `numBits / 8`. -/
theorem core.mem.size_of_Usize_spec :
    ⦃ ⌜ True ⌝ ⦄ core.mem.size_of Std.Usize
    ⦃ ⇓ n => ⌜ n.val * 8 = System.Platform.numBits ⌝ ⦄ := by
  obtain ⟨n, hn, h8⟩ := core.mem.size_of_Usize
  rw [hn]
  mvcgen

/-! ### `usize::from_be_bytes` of a `U24` -/

/-- One step of `BitVec.fromLEBytes`, on the value. -/
theorem setWidth_or_shift_toNat {n w : Nat} (h : w = n + 8) (b : BitVec 8) (x : BitVec n) :
    (BitVec.setWidth w b ||| BitVec.setWidth w x <<< 8).toNat = b.toNat + 256 * x.toNat := by
  subst h
  have hb := b.isLt
  have hx := x.isLt
  have hpow : 2 ^ (n + 8) = 2 ^ n * 256 := by rw [Nat.pow_add]
  rw [BitVec.toNat_or, BitVec.toNat_shiftLeft, BitVec.toNat_setWidth, BitVec.toNat_setWidth]
  have h1 : b.toNat % 2 ^ (n + 8) = b.toNat := Nat.mod_eq_of_lt (by
    have : 256 ≤ 2 ^ (n + 8) := by rw [hpow]; have : 1 ≤ 2 ^ n := Nat.one_le_two_pow; omega
    omega)
  have h2 : x.toNat % 2 ^ (n + 8) = x.toNat := Nat.mod_eq_of_lt (by omega)
  have h3 : (x.toNat <<< 8) % 2 ^ (n + 8) = x.toNat <<< 8 := Nat.mod_eq_of_lt (by
    rw [Nat.shiftLeft_eq]; omega)
  rw [h1, h2, h3, Nat.or_comm, ← Nat.shiftLeft_add_eq_or_of_lt (by omega) x.toNat, Nat.shiftLeft_eq]
  omega

/-- Value of a little-endian byte string. -/
theorem fromLEBytes_toNat : ∀ (l : List (BitVec 8)),
    (BitVec.fromLEBytes l).toNat = l.foldr (fun b acc => b.toNat + 256 * acc) 0
  | [] => by simp [BitVec.fromLEBytes.eq_1]
  | b :: t => by
    rw [BitVec.fromLEBytes.eq_2, setWidth_or_shift_toNat (by simp; omega), fromLEBytes_toNat t]
    rfl

/-- Value of eight big-endian bytes whose first five are zero. -/
theorem fromBEBytes_zero5_toNat (b0 b1 b2 : BitVec 8) :
    (BitVec.fromBEBytes [0#8, 0#8, 0#8, 0#8, 0#8, b0, b1, b2]).toNat =
      b0.toNat * 65536 + b1.toNat * 256 + b2.toNat := by
  unfold BitVec.fromBEBytes
  rw [BitVec.toNat_cast, fromLEBytes_toNat]
  simp [List.foldr]
  omega

/-- The `usize` read back from `[0,0,0,0,0,b0,b1,b2]` (64-bit platform). -/
theorem usize_from_zero5_val (b0 b1 b2 : Std.U8) (h64 : System.Platform.numBits = 64) :
    (UScalar.mk (ty := UScalarTy.Usize) (BitVec.setWidth UScalarTy.Usize.numBits
      (BitVec.fromBEBytes (List.map U8.bv [0#u8, 0#u8, 0#u8, 0#u8, 0#u8, b0, b1, b2])))).val =
      b0.val * 65536 + b1.val * 256 + b2.val := by
  have hb0 : b0.bv.toNat < 256 := b0.bv.isLt
  have hb1 : b1.bv.toNat < 256 := b1.bv.isLt
  have hb2 : b2.bv.toNat < 256 := b2.bv.isLt
  have h1 := fromBEBytes_zero5_toNat b0.bv b1.bv b2.bv
  have hnb : UScalarTy.Usize.numBits = 64 := h64
  show (BitVec.setWidth UScalarTy.Usize.numBits
      (BitVec.fromBEBytes (List.map U8.bv [0#u8, 0#u8, 0#u8, 0#u8, 0#u8, b0, b1, b2]))).toNat =
    b0.bv.toNat * 65536 + b1.bv.toNat * 256 + b2.bv.toNat
  rw [BitVec.toNat_setWidth, hnb]
  have h2 : (BitVec.fromBEBytes (List.map U8.bv [0#u8, 0#u8, 0#u8, 0#u8, 0#u8, b0, b1, b2])).toNat =
      b0.bv.toNat * 65536 + b1.bv.toNat * 256 + b2.bv.toNat := h1
  rw [h2]
  apply Nat.mod_eq_of_lt
  omega

end tls_codec
