/- `TlsVarInt::tls_deserialize_bytes`: the decoding loop, its panic freedom and its result.

Obligations: none directly; the bytes-path halves of `PanicFreedom.lean` /
`FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): ASSUMED `size_of`, `size_of_U8`. -/
import TlsCodec.Verification.Helpers.Primitives
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! ### `TlsVarInt::tls_deserialize_bytes` -/

/-- `calculate_value` never fails: `Ok (v, len)` with `v < 64` and `len` one of `1, 2, 4, 8`. -/
theorem varint.calculate_value_char (byte : Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ varint.calculate_value byte
    ⦃ ⇓ r => ⌜ ∃ v l : Std.Usize, r = .Ok (v, l) ∧ v.val < 64 ∧
        (l.val = 1 ∨ l.val = 2 ∨ l.val = 4 ∨ l.val = 8) ⌝ ⦄ := by
  have := System.Platform.numBits_eq
  have hand : (byte &&& 63#u8).val < 64 := by
    have h := Nat.and_le_right (n := byte.val) (m := 63)
    have : (byte &&& 63#u8).val = byte.val &&& 63 := by simp
    omega
  mvcgen [varint.calculate_value, varint.TlsVarInt.MAX_LOG]
  · exfalso; scalar_tac
  · exact ⟨_, _, rfl, by scalar_tac, by simp⟩
  · exact ⟨_, _, rfl, by scalar_tac, by simp⟩
  · exact ⟨_, _, rfl, by scalar_tac, by simp⟩
  · exact ⟨_, _, rfl, by scalar_tac, by simp⟩
  · exfalso; scalar_tac
  · exfalso; scalar_tac

/-- `calculate_value` on contents: the value is the low 6 bits and the length encodes the top 2 bits
(`pfx l = byte / 64 * 64`). -/
theorem varint.calculate_value_content (byte : Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ varint.calculate_value byte
    ⦃ ⇓ r => ⌜ ∃ v l : Std.Usize, r = .Ok (v, l) ∧ v.val = byte.val % 64 ∧
        (l.val = 1 ∨ l.val = 2 ∨ l.val = 4 ∨ l.val = 8) ∧ varint.pfx l.val = byte.val / 64 * 64 ⌝ ⦄ := by
  have := System.Platform.numBits_eq
  have hand : (byte &&& 63#u8).val = byte.val % 64 := by
    have : (byte &&& 63#u8).val = byte.val &&& 63 := by simp
    rw [this]; exact Nat.and_two_pow_sub_one_eq_mod byte.val 6
  have hc8 : ∀ x : Std.U8, (UScalar.cast UScalarTy.Usize x).val = x.val := by
    intro x
    have hx : x.val < 256 := by scalar_tac
    rw [UScalar.cast_val_eq]
    apply Nat.mod_eq_of_lt
    exact lt_of_lt_of_le hx (by rcases this with h | h <;> simp [UScalarTy.Usize_numBits_eq, h])
  mvcgen [varint.calculate_value, varint.TlsVarInt.MAX_LOG]
  · exfalso; scalar_tac
  · rename_i rv hrv rb ha1 ha2 ha3 rl hrl hu hle hgt hl
    have : rl.val = byte.val / 64 := by rw [hrl, hc8, ha1, Nat.shiftRight_eq_div_pow]; rfl
    refine ⟨_, _, rfl, by rw [hrv, hc8, hand], by simp, ?_⟩
    simp [varint.pfx]; omega
  · rename_i rv hrv rb ha1 ha2 ha3 rl hrl hu hle hgt hl
    have : rl.val = byte.val / 64 := by rw [hrl, hc8, ha1, Nat.shiftRight_eq_div_pow]; rfl
    refine ⟨_, _, rfl, by rw [hrv, hc8, hand], by simp, ?_⟩
    simp [varint.pfx]; omega
  · rename_i rv hrv rb ha1 ha2 ha3 rl hrl hu hle hgt hl
    have : rl.val = byte.val / 64 := by rw [hrl, hc8, ha1, Nat.shiftRight_eq_div_pow]; rfl
    refine ⟨_, _, rfl, by rw [hrv, hc8, hand], by simp, ?_⟩
    simp [varint.pfx]; omega
  · rename_i rv hrv rb ha1 ha2 ha3 rl hrl hu hle hgt hl
    have : rl.val = byte.val / 64 := by rw [hrl, hc8, ha1, Nat.shiftRight_eq_div_pow]; rfl
    refine ⟨_, _, rfl, by rw [hrv, hc8, hand], by simp, ?_⟩
    simp [varint.pfx]; omega
  · exfalso; scalar_tac
  · exfalso; scalar_tac

/-- Arithmetic of one step `value ← (value << 8) + byte` of the varint decoder. -/
theorem varint.step_bound (v b i : Nat) (hi : 1 ≤ i) (hi8 : i + 1 ≤ 8) (hv : v < 2 ^ (8 * i - 2))
    (hb : b < 256) :
    (v <<< 8) % 2 ^ 64 = v * 256 ∧ v * 256 + b < 2 ^ (8 * (i + 1) - 2) ∧ v * 256 + b < 2 ^ 64 := by
  have e : 2 ^ (8 * (i + 1) - 2) = 2 ^ (8 * i - 2) * 256 := by
    have : 8 * (i + 1) - 2 = (8 * i - 2) + 8 := by omega
    rw [this, Nat.pow_add]
  have hle : 2 ^ (8 * (i + 1) - 2) ≤ 2 ^ 62 := Nat.pow_le_pow_right (by norm_num) (by omega)
  have hsh : v <<< 8 = v * 256 := by rw [Nat.shiftLeft_eq]
  have hlt : v * 256 + b < 2 ^ (8 * (i + 1) - 2) := by rw [e]; omega
  have h62 : (2:Nat) ^ 62 < 2 ^ 64 := by norm_num
  have hlt64 : v * 256 + b < 2 ^ 64 := Nat.lt_of_lt_of_le hlt (le_trans hle h62.le)
  refine ⟨?_, hlt, hlt64⟩
  rw [hsh]; apply Nat.mod_eq_of_lt; exact Nat.lt_of_le_of_lt (Nat.le_add_right _ _) hlt64

/-- `u64::from(u8)` is the widening cast. -/
@[spec] theorem core.U64.Insts.CoreConvertFromU8.from_spec (x : Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ core.U64.Insts.CoreConvertFromU8.from x
    ⦃ ⇓ r => ⌜ r.val = x.val ⌝ ⦄ := by
  unfold core.U64.Insts.CoreConvertFromU8.from; mvcgen

/-- One iteration of the `TlsVarInt::tls_deserialize_bytes` loop. -/
theorem varint.deserialize_loop.body_spec (len : Std.Usize) (remainder : Slice Std.U8)
    (value : Std.U64) (i : Std.Usize) (hi : 1 ≤ i.val) (hil : i.val ≤ len.val) (hl : len.val ≤ 8)
    (hv : value.val < 2 ^ (8 * i.val - 2)) :
    ⦃ ⌜ True ⌝ ⦄
    varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop.body len remainder value i
    ⦃ ⇓ r => ⌜ match r with
      | .done (r', v', f) => (f = core.option.Option.None → i = len ∧ r' = remainder ∧ v' = value)
      | .cont (r', v', i') => r'.val.length + 1 = remainder.val.length ∧ i'.val = i.val + 1 ∧
          i'.val ≤ len.val ∧ v'.val < 2 ^ (8 * i'.val - 2) ⌝ ⦄ := by
  unfold varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop.body
  mvcgen [U8_deserialize_char]
  · rename_i hlt r0 p hr hP r3 h3 h3b h3c r2 h2 r1 h1 r h0
    have hb := varint.step_bound value.val r2.val i.val hi (by scalar_tac) hv (by scalar_tac)
    have hrl : 1 ≤ remainder.val.length := by
      by_contra hn
      have := hP.2 (by omega)
      cases this
    obtain ⟨a, t, ha, ht, hpt⟩ := hP.1 hrl
    have hp2 : p.2 = t := (congrArg Prod.snd (core.result.Result.Ok.inj hpt)).trans rfl
    rw [hp2, ht]
    simp only [List.length_drop]
    have h1' : (1#usize).val = 1 := by simp
    refine ⟨by omega, by scalar_tac, by scalar_tac, ?_⟩
    have : r.val = i.val + 1 := by scalar_tac
    rw [this]
    scalar_tac
  · rename_i hlt r0 p hr hP r3 h3 h3b h3c r2 h2 r1 h1 hov
    exfalso
    have hb := varint.step_bound value.val r2.val i.val hi (by scalar_tac) hv (by scalar_tac)
    scalar_tac
  · rename_i hlt r0 p hr hP r3 h3 h3b h3c r2 h2 hov
    exfalso
    have hb := varint.step_bound value.val r2.val i.val hi (by scalar_tac) hv (by scalar_tac)
    scalar_tac
  · intro h; cases h
  · apply UScalar.eq_of_val_eq; scalar_tac

/-- One iteration of the `TlsVarInt::tls_deserialize_bytes` loop, on contents. -/
theorem varint.deserialize_loop.body_content (len : Std.Usize) (remainder : Slice Std.U8)
    (value : Std.U64) (i : Std.Usize) (hi : 1 ≤ i.val) (hil : i.val ≤ len.val) (hl : len.val ≤ 8)
    (hv : value.val < 2 ^ (8 * i.val - 2)) :
    ⦃ ⌜ True ⌝ ⦄
    varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop.body len remainder value i
    ⦃ ⇓ r => ⌜ match r with
      | .done (r', v', f) => (f = core.option.Option.None → i = len ∧ r' = remainder ∧ v' = value)
      | .cont (r', v', i') => r'.val.length + 1 = remainder.val.length ∧ i'.val = i.val + 1 ∧
          i'.val ≤ len.val ∧ v'.val < 2 ^ (8 * i'.val - 2) ∧
          ∃ b : Std.U8, remainder.val = b :: r'.val ∧ v'.val = value.val * 256 + b.val ⌝ ⦄ := by
  unfold varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop.body
  mvcgen [U8_deserialize_char]
  · rename_i hlt r0 p hr hP r3 h3 h3b h3c r2 h2 r1 h1 r h0
    have hb := varint.step_bound value.val r2.val i.val hi (by scalar_tac) hv (by scalar_tac)
    have hrl : 1 ≤ remainder.val.length := by
      by_contra hn
      have := hP.2 (by omega)
      cases this
    obtain ⟨a, t, ha, ht, hpt⟩ := hP.1 hrl
    have hp2 : p.2 = t := (congrArg Prod.snd (core.result.Result.Ok.inj hpt)).trans rfl
    rw [hp2, ht]
    simp only [List.length_drop]
    have h1' : (1#usize).val = 1 := by simp
    refine ⟨by omega, by scalar_tac, by scalar_tac, ?_, ?_⟩
    · have : r.val = i.val + 1 := by scalar_tac
      rw [this]
      scalar_tac
    · have hpp := core.result.Result.Ok.inj hpt
      cases hbr : remainder.val with
      | nil => rw [hbr] at hrl; simp at hrl
      | cons b l =>
        rw [hbr] at ha
        simp only [List.take_succ_cons, List.take_zero] at ha
        have hp1 : p.1 = b := by rw [hpp]; exact U8_from_be_bytes_of_val a b ha
        refine ⟨b, by simp, ?_⟩
        have h64 : U64.size = 2 ^ 64 := by simp [U64.size, U64.numBits]
        have h8 : (8#i32).toNat = 8 := rfl
        rw [h1, h3, h2, hp1, h64, h8]
        have := hb.1
        simp only [Nat.shiftLeft_eq] at this ⊢
        omega
  · rename_i hlt r0 p hr hP r3 h3 h3b h3c r2 h2 r1 h1 hov
    exfalso
    have hb := varint.step_bound value.val r2.val i.val hi (by scalar_tac) hv (by scalar_tac)
    scalar_tac
  · rename_i hlt r0 p hr hP r3 h3 h3b h3c r2 h2 hov
    exfalso
    have hb := varint.step_bound value.val r2.val i.val hi (by scalar_tac) hv (by scalar_tac)
    scalar_tac
  · intro h; cases h
  · apply UScalar.eq_of_val_eq; scalar_tac

/-- The `TlsVarInt::tls_deserialize_bytes` loop: it never panics; without failure it consumes
`len - i` bytes and the value stays below `2^(8*len-2)`. -/
theorem varint.deserialize_loop_spec (remainder : Slice Std.U8) (len : Std.Usize) (value : Std.U64)
    (i : Std.Usize) (hi : 1 ≤ i.val) (hil : i.val ≤ len.val) (hl : len.val ≤ 8)
    (hv : value.val < 2 ^ (8 * i.val - 2)) :
    ⦃ ⌜ True ⌝ ⦄
    varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop remainder len value i
    ⦃ ⇓ r => ⌜ r.2.2 = core.option.Option.None →
        r.1.val.length + len.val = remainder.val.length + i.val ∧
        r.2.1.val < 2 ^ (8 * len.val - 2) ⌝ ⦄ := by
  unfold varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.loop.spec_decr_nat
    (fun x : Slice Std.U8 × Std.U64 × Std.Usize => len.val - x.2.2.val)
    (fun x : Slice Std.U8 × Std.U64 × Std.Usize =>
      1 ≤ x.2.2.val ∧ x.2.2.val ≤ len.val ∧ x.2.1.val < 2 ^ (8 * x.2.2.val - 2) ∧
      x.1.val.length + x.2.2.val = remainder.val.length + i.val)
    (fun y : Slice Std.U8 × Std.U64 × (core.option.Option Error) => y.2.2 = core.option.Option.None →
        y.1.val.length + len.val = remainder.val.length + i.val ∧
        y.2.1.val < 2 ^ (8 * len.val - 2))
  · rintro ⟨b, v, j⟩ ⟨hj1, hjl, hjv, hjr⟩
    dsimp only at hj1 hjl hjv hjr
    obtain ⟨r, hr, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (varint.deserialize_loop.body_spec len b v j hj1 hjl hl hjv)
    dsimp only
    rw [hr, Aeneas.Std.WP.spec_ok]
    cases r with
    | done y =>
      obtain ⟨r', v', f⟩ := y
      intro hf
      obtain ⟨h1, h2, h3⟩ := hP hf
      subst h2; subst h3
      have : j.val = len.val := by rw [h1]
      dsimp only at hjv hjr ⊢
      refine ⟨by omega, ?_⟩
      rw [← this]; exact hjv
    | cont x =>
      obtain ⟨b', v', j'⟩ := x
      obtain ⟨h1, h2, h3, h4⟩ := hP
      dsimp only at h1 h2 h3 h4 ⊢
      refine ⟨⟨by omega, h3, h4, by omega⟩, by omega⟩
  · exact ⟨hi, hil, hv, rfl⟩

/-- The `TlsVarInt::tls_deserialize_bytes` loop, on contents: without failure it consumes `len - i`
bytes and folds them (big-endian) into the value. -/
theorem varint.deserialize_loop_content (remainder : Slice Std.U8) (len : Std.Usize)
    (value : Std.U64) (i : Std.Usize) (hi : 1 ≤ i.val) (hil : i.val ≤ len.val) (hl : len.val ≤ 8)
    (hv : value.val < 2 ^ (8 * i.val - 2)) :
    ⦃ ⌜ True ⌝ ⦄
    varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop remainder len value i
    ⦃ ⇓ r => ⌜ r.2.2 = core.option.Option.None → len.val - i.val ≤ remainder.val.length ∧
        r.1.val = remainder.val.drop (len.val - i.val) ∧
        r.2.1.val = (remainder.val.take (len.val - i.val)).foldl (fun a b => a * 256 + b.val) value.val ⌝ ⦄ := by
  unfold varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.loop.spec_decr_nat
    (fun x : Slice Std.U8 × Std.U64 × Std.Usize => len.val - x.2.2.val)
    (fun x : Slice Std.U8 × Std.U64 × Std.Usize =>
      1 ≤ x.2.2.val ∧ i.val ≤ x.2.2.val ∧ x.2.2.val ≤ len.val ∧ x.2.1.val < 2 ^ (8 * x.2.2.val - 2) ∧
      x.2.2.val - i.val ≤ remainder.val.length ∧ x.1.val = remainder.val.drop (x.2.2.val - i.val) ∧
      x.2.1.val = (remainder.val.take (x.2.2.val - i.val)).foldl (fun a b => a * 256 + b.val) value.val)
    (fun y : Slice Std.U8 × Std.U64 × (core.option.Option Error) => y.2.2 = core.option.Option.None →
        len.val - i.val ≤ remainder.val.length ∧ y.1.val = remainder.val.drop (len.val - i.val) ∧
        y.2.1.val = (remainder.val.take (len.val - i.val)).foldl (fun a b => a * 256 + b.val) value.val)
  · rintro ⟨b, v, j⟩ ⟨hj1, hij, hjl, hjv, hjlen, hjb, hjv'⟩
    dsimp only at hj1 hij hjl hjv hjlen hjb hjv'
    obtain ⟨r, hr, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (varint.deserialize_loop.body_content len b v j hj1 hjl hl hjv)
    dsimp only
    rw [hr, Aeneas.Std.WP.spec_ok]
    cases r with
    | done y =>
      obtain ⟨r', v', f⟩ := y
      intro hf
      obtain ⟨h1, h2, h3⟩ := hP hf
      subst h2; subst h3
      have : j.val = len.val := by rw [h1]
      rw [← this]
      exact ⟨hjlen, hjb, hjv'⟩
    | cont x =>
      obtain ⟨b', v', j'⟩ := x
      obtain ⟨h1, h2, h3, h4, c, hc, hvc⟩ := hP
      dsimp only at h1 h2 h3 h4 hc hvc ⊢
      refine ⟨⟨by omega, by omega, h3, h4, ?_, ?_, ?_⟩, by omega⟩
      · rw [hjb] at hc
        have := congrArg List.length hc
        simp only [List.length_drop, List.length_cons] at this
        omega
      · rw [hjb] at hc
        rw [show j'.val - i.val = (j.val - i.val) + 1 by omega, ← List.drop_drop, hc]
        rfl
      · rw [hjb] at hc
        rw [show j'.val - i.val = (j.val - i.val) + 1 by omega, List.take_add, hc, List.foldl_append,
          ← hjv']
        simp [hvc]
  · exact ⟨hi, le_refl _, hil, hv, by simp, by simp, by simp⟩

/-- `check_min_len` succeeds iff the value is at most `MAX` and the length is the minimal one. -/
theorem varint.check_min_len_char (value : Std.U64) (len : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ varint.check_min_len value len
    ⦃ ⇓ r => ⌜ r = .Ok () → value.val ≤ 2 ^ 62 - 1 ∧ len.val = varint.lenOf value.val ⌝ ⦄ := by
  mvcgen [varint.check_min_len]
  · intro h; cases h
  · rename_i r2 hr2 cf val1 hx hcf r hne hr
    rw [continue_eq_tryCF] at hcf
    rw [hcf] at hr2
    obtain ⟨hv1, hle⟩ := hr2
    subst hv1
    have hc := varint.lenOf_char _ _ hr
    have hrl : r.val = len.val := by simpa using hne
    exact ⟨hle, by rw [← hrl]; exact hc.1⟩
  · try_vcs
    intro _ h; cases h

/-- `check_min_len` succeeds on a value at most `MAX` and its minimal length. -/
theorem varint.check_min_len_total (value : Std.U64) (len : Std.Usize)
    (hv : value.val ≤ 2 ^ 62 - 1) (hl : len.val = varint.lenOf value.val) :
    ⦃ ⌜ True ⌝ ⦄ varint.check_min_len value len ⦃ ⇓ r => ⌜ r = .Ok () ⌝ ⦄ := by
  mvcgen [varint.check_min_len]
  · rename_i r1 hP cf v hx hcf r hne hr
    rw [continue_eq_tryCF] at hcf
    rw [hcf] at hP
    obtain ⟨rfl, -⟩ := hP
    have h := varint.lenOf_char _ _ hr
    have hne' : r ≠ len := by simpa using hne
    exact absurd (UScalar.eq_of_val_eq (by omega)) hne'
  · rename_i r1 hP cf resid hx
    intro hb
    exfalso
    cases r1 with
    | Ok v => simp [tryCF] at hb
    | Err e => omega

/-- A successful `u8::tls_deserialize_bytes` consumes exactly one byte. -/
theorem U8_deserialize_len {bytes : Slice Std.U8} {r : core.result.Result (Std.U8 × Slice Std.U8) Error}
    {p : Std.U8 × Slice Std.U8}
    (hP : (1 ≤ bytes.val.length → ∃ (a : Aeneas.Std.Array Std.U8 1#usize) (t : Slice Std.U8),
          a.val = bytes.val.take 1 ∧ t.val = bytes.val.drop 1 ∧
          r = .Ok (Aeneas.Std.core.num.U8.from_be_bytes a, t)) ∧
        (bytes.val.length < 1 → r = .Err Error.EndOfStream))
    (h : r = .Ok p) : bytes.val.length = p.2.val.length + 1 := by
  have hl : 1 ≤ bytes.val.length := by
    by_contra hn
    rw [hP.2 (by omega)] at h
    cases h
  obtain ⟨a, t, _, ht, hr⟩ := hP.1 hl
  rw [hr] at h
  have h2 := congrArg Prod.snd (core.result.Result.Ok.inj h)
  simp only at h2
  rw [← h2, ht]
  simp only [List.length_drop]
  omega

/-- Facts about the `Ok` result of `calculate_value_char`. -/
theorem varint.calculate_value_ok {r : core.result.Result (Std.Usize × Std.Usize) Error}
    {val : Std.Usize × Std.Usize}
    (hvl : ∃ v l : Std.Usize, r = .Ok (v, l) ∧ v.val < 64 ∧
        (l.val = 1 ∨ l.val = 2 ∨ l.val = 4 ∨ l.val = 8))
    (h : r = .Ok val) :
    val.1.val < 64 ∧ 1 ≤ val.2.val ∧ val.2.val ≤ 8 := by
  obtain ⟨v, l, h1, h2, h3⟩ := hvl
  rw [h1] at h
  have := core.result.Result.Ok.inj h
  subst this
  refine ⟨h2, ?_, ?_⟩ <;> simp only <;> omega

/-- Content-level `calculate_value` result gives the plain one. -/
theorem varint.calculate_value_content_char {byte : Std.U8} {r : core.result.Result (Std.Usize × Std.Usize) Error}
    (h : ∃ v l : Std.Usize, r = .Ok (v, l) ∧ v.val = byte.val % 64 ∧
        (l.val = 1 ∨ l.val = 2 ∨ l.val = 4 ∨ l.val = 8) ∧ varint.pfx l.val = byte.val / 64 * 64) :
    ∃ v l : Std.Usize, r = .Ok (v, l) ∧ v.val < 64 ∧
        (l.val = 1 ∨ l.val = 2 ∨ l.val = 4 ∨ l.val = 8) := by
  obtain ⟨v, l, h1, h2, h3, _⟩ := h
  exact ⟨v, l, h1, by omega, h3⟩

/-- Closes the arithmetic VCs of the varint decoder (the loop's preconditions, from the first
byte): instantiates `calculate_value_ok` on the hypotheses of the right shape (plain or content
form, found by `assumption`, not by name or position), substitutes the `Ok` equations, then
`scalar_tac`. -/
macro "varint_vc_arith" : tactic => `(tactic| (
  first
    | have := varint.calculate_value_ok (by assumption) (by assumption)
    | have := varint.calculate_value_ok (varint.calculate_value_content_char (by assumption))
        (by assumption)
  subst_vars
  simp only [core.result.Result.Ok.injEq] at *
  subst_vars
  scalar_tac))

/-- `TlsVarInt::tls_deserialize_bytes` never panics; on success the value is at most `MAX` and the
remainder is the input minus the minimal encoding of the value. -/
theorem varint.TlsVarInt.deserialize_char (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ (v : varint.TlsVarInt) (t : Slice Std.U8), r = .Ok (v, t) →
        v.val ≤ 2 ^ 62 - 1 ∧ t.val.length + varint.lenOf v.val = bytes.val.length ⌝ ⦄ := by
  mvcgen [varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes,
    U8_deserialize_char, varint.calculate_value_char, varint.check_min_len_char,
    varint.deserialize_loop_spec, core.result.Result.map_err_spec,
    varint.DeserializeBytesTlsVarInt.tls_deserialize_bytes.closure.Insts.CoreOpsFunctionFnOnceTupleTryFromIntErrorError.call_once]
  try_vcs
  all_goals (try simp only [continue_eq_tryCF] at *)
  · varint_vc_arith
  · varint_vc_arith
  · varint_vc_arith
  · rename_i r0 hP r1 p x1 r2 hvl r3 val x2 r4 hcast t ha r5 val1 x3 rl xn hloop r6 hchk r7 u x4 hr0 hr2 hr4 hr6
    intro v t' hvt
    have hvt' := core.result.Result.Ok.inj hvt
    have hc := hchk hr6
    have hlp := (hloop xn).1
    have hb := U8_deserialize_len hP hr0
    obtain ⟨hv, ht⟩ := Prod.mk.inj hvt'
    subst hv; subst ht
    have h1 : (1#usize).val = 1 := by simp
    refine ⟨hc.1, ?_⟩
    rw [← hc.2]
    omega
  · intro _ v t h; cases h
  · intro v t h; cases h
  · rename_i r0 hP r1 p x1 r2 hvl r3 val x2 r4 hcast e ha hr0 hr2
    exfalso
    rw [hcast] at ha
    cases ha
  · intro _ v t h; cases h
  · intro _ v t h; cases h

/-- `TlsVarInt::tls_deserialize_bytes` on contents: on success the input is `b0 :: l`, the length
`L` is the minimal one for the value and matches the prefix of `b0`, and the value is the big-endian
fold of the low 6 bits of `b0` and the next `L - 1` bytes. -/
theorem varint.TlsVarInt.deserialize_content (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ (v : varint.TlsVarInt) (t : Slice Std.U8), r = .Ok (v, t) →
        ∃ (b0 : Std.U8) (l : List Std.U8) (L : Nat), bytes.val = b0 :: l ∧
          (L = 1 ∨ L = 2 ∨ L = 4 ∨ L = 8) ∧ L = varint.lenOf v.val ∧ varint.pfx L = b0.val / 64 * 64 ∧
          L - 1 ≤ l.length ∧ t.val = l.drop (L - 1) ∧
          v.val = (l.take (L - 1)).foldl (fun a b => a * 256 + b.val) (b0.val % 64) ∧
          v.val ≤ 2 ^ 62 - 1 ⌝ ⦄ := by
  mvcgen [varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes,
    U8_deserialize_char, varint.calculate_value_content, varint.check_min_len_char,
    varint.deserialize_loop_content, core.result.Result.map_err_spec,
    varint.DeserializeBytesTlsVarInt.tls_deserialize_bytes.closure.Insts.CoreOpsFunctionFnOnceTupleTryFromIntErrorError.call_once]
  try_vcs
  all_goals (try simp only [continue_eq_tryCF] at *)
  · varint_vc_arith
  · varint_vc_arith
  · varint_vc_arith
  · rename_i r0 hP r1 p x1 r2 hvl r3 val x2 r4 hcast t ha r5 val1 x3 rl xn hloop r6 hchk r7 u x4 hr0 hr2 hr4 hr6
    intro v t' hvt
    obtain ⟨hv, ht⟩ := Prod.mk.inj (core.result.Result.Ok.inj hvt)
    subst hv; subst ht
    obtain ⟨l, hbl, hp2⟩ := U8_deserialize_ok hP (by rw [hr0]; rfl)
    obtain ⟨v0, l0, h1, h2, h3, h4⟩ := hvl
    rw [hr2] at h1
    have hval := core.result.Result.Ok.inj h1
    subst hval
    have hc := hchk hr6
    have hlp := hloop xn
    have e1 := core.result.Result.Ok.inj (hcast.symm.trans ha)
    have e2 := core.result.Result.Ok.inj hr4
    have hv1 : val1.val = p.1.val % 64 := by
      rw [← e2, ← e1, UScalar.cast_val_eq]
      have : v0.val < 64 := by omega
      simp only [UScalarTy.U64_numBits_eq]
      exact (Nat.mod_eq_of_lt (by omega)).trans h2
    have h1' : (1#usize).val = 1 := by simp
    obtain ⟨hl1, hl2, hl3⟩ := hlp
    simp only [hp2, h1', hv1] at hl1 hl2 hl3
    have hcl : l0.val = lenOf rl.2.1.val := hc.2
    exact ⟨p.1, l, l0.val, hbl, h3, hcl, h4, hl1, hl2, hl3, hc.1⟩
  · intro _ v t h; cases h
  · intro v t h; cases h
  · rename_i r0 hP r1 p x1 r2 hvl r3 val x2 r4 hcast e ha hr0 hr2
    exfalso
    rw [hcast] at ha
    cases ha
  · intro _ v t h; cases h
  · intro _ v t h; cases h

/-- `ContentLength::tls_deserialize_bytes` never panics; on success the value is at most `2^30 - 1`
(RFC 9420 2.1.2) and the remainder is the input minus the minimal varint encoding of the value. -/
theorem quic_vec.ContentLength.deserialize_char (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.ContentLength.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ (v : quic_vec.ContentLength) (t : Slice Std.U8), r = .Ok (v, t) →
        v.val ≤ 2 ^ 30 - 1 ∧ t.val.length + varint.lenOf v.val = bytes.val.length ⌝ ⦄ := by
  mvcgen [quic_vec.ContentLength.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes,
    varint.TlsVarInt.deserialize_char, quic_vec.ContentLength.new, varint.TlsVarInt.value,
    quic_vec.ContentLength.MAX, quic_vec.MAX_MLS_LEN_spec]
  try_vcs
  all_goals (try simp only [continue_eq_tryCF] at *)
  · intro _ v t h; cases h
  · rename_i r0 hP r1 p x1 r2 h2 h1 r3 val x2 hr0 hval
    have hv := core.result.Result.Ok.inj hval
    have hb : p.1.val ≤ 2 ^ 30 - 1 := by scalar_tac
    subst hv
    intro v t hvt
    obtain ⟨hv1, ht⟩ := Prod.mk.inj (core.result.Result.Ok.inj hvt)
    subst hv1; subst ht
    exact ⟨hb, (hP p.1 p.2 hr0).2⟩
  · intro _ v t h; cases h

/-- `TlsVarInt::tls_deserialize_bytes`: the remainder is a suffix of the input
(from `deserialize_content`). -/
theorem varint.TlsVarInt.deserialize_suffix (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ (v : varint.TlsVarInt) (t : Slice Std.U8), r = .Ok (v, t) →
        t.val <:+ bytes.val ⌝ ⦄ := by
  apply triple_post_mono (varint.TlsVarInt.deserialize_content bytes)
  intro r h v t hr
  obtain ⟨b0, l, L, hb, -, -, -, -, ht, -⟩ := h v t hr
  rw [ht, hb]
  exact (List.drop_suffix _ _).trans (List.suffix_cons _ _)

/-- `ContentLength::tls_deserialize_bytes`: the remainder is a suffix of the input. -/
theorem quic_vec.ContentLength.deserialize_suffix (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.ContentLength.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ (v : quic_vec.ContentLength) (t : Slice Std.U8), r = .Ok (v, t) →
        t.val <:+ bytes.val ⌝ ⦄ := by
  have hv := triple_and (varint.TlsVarInt.deserialize_char bytes)
    (varint.TlsVarInt.deserialize_suffix bytes)
  mvcgen [quic_vec.ContentLength.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes,
    hv, quic_vec.ContentLength.new, varint.TlsVarInt.value,
    quic_vec.ContentLength.MAX, quic_vec.MAX_MLS_LEN_spec]
  try_vcs
  all_goals (try simp only [continue_eq_tryCF] at *)
  all_goals (try (intro _ v t h; cases h; done))
  all_goals (try (intro v t h; cases h; done))
  rename_i r0 hP r1 p x1 r2 h2 h1 r3 val x2 hr0 hval
  have hv := core.result.Result.Ok.inj hval
  subst hv
  intro v t hvt
  obtain ⟨hv1, ht⟩ := Prod.mk.inj (core.result.Result.Ok.inj hvt)
  subst hv1; subst ht
  exact hP.2 p.1 p.2 hr0

/-- `ContentLength::tls_deserialize_bytes`, char and suffix together. -/
theorem quic_vec.ContentLength.deserialize_char_suffix (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.ContentLength.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ (∀ (v : quic_vec.ContentLength) (t : Slice Std.U8), r = .Ok (v, t) →
        v.val ≤ 2 ^ 30 - 1 ∧ t.val.length + varint.lenOf v.val = bytes.val.length) ∧
      ∀ (v : quic_vec.ContentLength) (t : Slice Std.U8), r = .Ok (v, t) →
        t.val <:+ bytes.val ⌝ ⦄ :=
  triple_and (quic_vec.ContentLength.deserialize_char bytes)
    (quic_vec.ContentLength.deserialize_suffix bytes)

/-- `tls_serialize_bytes_len` of a slice of length at most `2^30 - 1` (the MLS bound) is the length
plus the minimal varint length prefix. -/
theorem quic_vec.tls_serialize_bytes_len_char (bytes : Slice Std.U8)
    (h : bytes.val.length ≤ 2 ^ 30 - 1) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.tls_serialize_bytes_len bytes
    ⦃ ⇓ r => ⌜ r.val = bytes.val.length + varint.lenOf bytes.val.length ⌝ ⦄ := by
  mvcgen [quic_vec.tls_serialize_bytes_len, CoreModels.core.slice.Slice.len_spec]
  · rename_i n hn rc hrc r2 hr2 r1 hr1 r3 hr3
    have hl : n.val = bytes.val.length := by subst hn; simp [Slice.len]
    cases rc with
    | Ok c =>
      obtain ⟨hc, _⟩ := hrc
      obtain ⟨u, hu, _, _, hul⟩ := hr2.1 c rfl
      subst hu
      simp only at hr1
      subst hr1
      rw [hul] at hr3
      have hcl : c.val = bytes.val.length := by omega
      rw [← hcl]
      scalar_tac
    | Err e => omega
  · rename_i n hn rc hrc r2 hr2 r1 hr1 hov
    have hl : n.val = bytes.val.length := by subst hn; simp [Slice.len]
    cases rc with
    | Ok c =>
      obtain ⟨hc, _⟩ := hrc
      obtain ⟨u, hu, h1, h8, hul⟩ := hr2.1 c rfl
      subst hu
      simp only at hr1
      subst hr1
      scalar_tac
    | Err e => omega

/-- `tls_serialize_bytes_len` never panics and is positive, whatever the length (the prefix, or the
length itself when `from_usize` fails). -/
theorem quic_vec.tls_serialize_bytes_len_pos (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.tls_serialize_bytes_len bytes ⦃ ⇓ r => ⌜ 0 < r.val ⌝ ⦄ := by
  mvcgen [quic_vec.tls_serialize_bytes_len, CoreModels.core.slice.Slice.len_spec]
  · rename_i n hn rc hrc r2 hr2 r1 hr1 r3 hr3
    cases rc with
    | Ok c =>
      obtain ⟨u, hu, h1, h8, hul⟩ := hr2.1 c rfl
      subst hu
      simp only at hr1
      subst hr1
      scalar_tac
    | Err e =>
      obtain rfl := hr2.2 e rfl
      simp only at hr1
      subst hr1
      scalar_tac
  · rename_i n hn rc hrc r2 hr2 r1 hr1 hov
    cases rc with
    | Ok c =>
      obtain ⟨u, hu, h1, h8, hul⟩ := hr2.1 c rfl
      subst hu
      simp only at hr1
      subst hr1
      scalar_tac
    | Err e =>
      obtain rfl := hr2.2 e rfl
      simp only at hr1
      subst hr1
      scalar_tac

/-- `VLBytes::tls_serialized_len` never panics and is positive. -/
theorem quic_vec.VLBytes.size_pos (self : quic_vec.VLBytes) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLBytes.Insts.Tls_codecSize.tls_serialized_len self
    ⦃ ⇓ r => ⌜ 0 < r.val ⌝ ⦄ := by
  mvcgen [quic_vec.VLBytes.Insts.Tls_codecSize.tls_serialized_len, quic_vec.VLBytes.as_slice,
    quic_vec.VLBytes.impl.vec, quic_vec.tls_serialize_bytes_len_pos]

/-- `VLBytes::tls_deserialize_bytes` never panics; on success the payload is at most `2^30 - 1` bytes
and the remainder is the input minus the varint length prefix and the payload. -/
theorem quic_vec.VLBytes.deserialize_char (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLBytes.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ (v : quic_vec.VLBytes) (t : Slice Std.U8), r = .Ok (v, t) →
        v.vec.val.length ≤ 2 ^ 30 - 1 ∧
        t.val.length + (v.vec.val.length + varint.lenOf v.vec.val.length) = bytes.val.length ⌝ ⦄ := by
  mvcgen [quic_vec.VLBytes.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes,
    quic_vec.ContentLength.deserialize_char, varint.TlsVarInt.value, quic_vec.VLBytes.new,
    core.option.Option.ok_or_spec, core.Slice.Insts.CoreOpsIndexIndex.index_spec,
    alloc.vec.Vec.new_spec, core.hint.must_use_spec]
  try_vcs
  all_goals (try simp only [continue_eq_tryCF] at *)
  · rename_i r0 hP r1 p x1 r2 htf r3 val x2 hv0 rv hrv h3 h5
    intro v t h
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj (core.result.Result.Ok.inj h)
    have hl := (hP p.1 p.2 h3).2
    have hy := htf.1 val h5
    have hv : val.val = 0 := by rw [hv0]; rfl
    have hrl : rv.val.length = 0 := by rw [hrv]; simp [Slice.new]
    have hlen : varint.lenOf p.1.val = 1 := by
      have : p.1.val = 0 := by omega
      rw [this]; simp [varint.lenOf]
    refine ⟨by simp only; omega, ?_⟩
    simp only
    rw [hrl]
    have h0 : varint.lenOf 0 = 1 := by simp [varint.lenOf]
    omega
  · rename_i r0 hP r1 p x1 r2 htf r3 val x2 hv0 o ho rr vec hrr hok rv hrv ro h3 h5
    intro hd hn
    have hb := (hP p.1 p.2 h3)
    have hy := htf.1 val h5
    have hvl : val.val ≤ p.2.val.length := by
      by_contra hc
      rw [ho.2 (by omega)] at hok
      cases hok
    obtain ⟨t, ht, ht'⟩ := ho.1 hvl
    rw [ht] at hok
    have hvec := core.result.Result.Ok.inj hok.symm
    obtain ⟨t2, h2, h2'⟩ := hd hvl
    refine ⟨t2, h2, ?_⟩
    simp only [PostCond.ok]
    mvcgen
    intro v t h
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj (core.result.Result.Ok.inj h)
    have hrl : rv.val.length = val.val := by
      rw [hrv, ← hvec, ht']; simp only [List.length_take]; omega
    have hl2 : t2.val.length = p.2.val.length - val.val := by rw [h2']; simp
    show rv.val.length ≤ 2 ^ 30 - 1 ∧
      t2.val.length + (rv.val.length + varint.lenOf rv.val.length) = bytes.val.length
    rw [hrl, hl2, hy]
    refine ⟨by omega, ?_⟩
    omega
  · intro v t h; cases h
  · exfalso
    rename_i r0 hP r1 p x1 r2 htf r3 residual x2 e hr2 h3
    have hb := (hP p.1 p.2 h3)
    obtain ⟨y, hy⟩ := htf.2 (by omega)
    rw [hy] at hr2
    cases hr2
  · intro _ v t h; cases h

/-- `VLBytes::tls_serialized_len` of a payload of at most `2^30 - 1` bytes is the payload length plus
the minimal varint length prefix. -/
theorem quic_vec.VLBytes.serialized_len_char (self : quic_vec.VLBytes)
    (h : self.vec.val.length ≤ 2 ^ 30 - 1) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLBytes.Insts.Tls_codecSize.tls_serialized_len self
    ⦃ ⇓ r => ⌜ r.val = self.vec.val.length + varint.lenOf self.vec.val.length ⌝ ⦄ := by
  mvcgen [quic_vec.VLBytes.Insts.Tls_codecSize.tls_serialized_len, quic_vec.VLBytes.as_slice,
    quic_vec.VLBytes.impl.vec, quic_vec.tls_serialize_bytes_len_char]
  · intro hr; subst_vars; exact hr
  · intro hr; subst_vars; exact h

/-- `VLByteVec::tls_deserialize_bytes` never panics; on success the payload is at most `2^30 - 1` bytes
and the remainder is the input minus the varint length prefix and the payload. -/
theorem quic_vec.VLByteVec.deserialize_char (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLByteVec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ (v : quic_vec.VLByteVec) (t : Slice Std.U8), r = .Ok (v, t) →
        v.vec.val.length ≤ 2 ^ 30 - 1 ∧
        t.val.length + (v.vec.val.length + varint.lenOf v.vec.val.length) = bytes.val.length ⌝ ⦄ := by
  mvcgen [quic_vec.VLByteVec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes,
    quic_vec.ContentLength.deserialize_char, varint.TlsVarInt.value, quic_vec.VLByteVec.new,
    core.option.Option.ok_or_spec, core.Slice.Insts.CoreOpsIndexIndex.index_spec,
    alloc.vec.Vec.new_spec, core.hint.must_use_spec]
  try_vcs
  all_goals (try simp only [continue_eq_tryCF] at *)
  · rename_i r0 hP r1 p x1 r2 htf r3 val x2 hv0 rv hrv h3 h5
    intro v t h
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj (core.result.Result.Ok.inj h)
    have hl := (hP p.1 p.2 h3).2
    have hy := htf.1 val h5
    have hv : val.val = 0 := by rw [hv0]; rfl
    have hrl : rv.val.length = 0 := by rw [hrv]; simp [Slice.new]
    have hlen : varint.lenOf p.1.val = 1 := by
      have : p.1.val = 0 := by omega
      rw [this]; simp [varint.lenOf]
    refine ⟨by simp only; omega, ?_⟩
    simp only
    rw [hrl]
    have h0 : varint.lenOf 0 = 1 := by simp [varint.lenOf]
    omega
  · rename_i r0 hP r1 p x1 r2 htf r3 val x2 hv0 o ho rr vec hrr hok rv hrv ro h3 h5
    intro hd hn
    have hb := (hP p.1 p.2 h3)
    have hy := htf.1 val h5
    have hvl : val.val ≤ p.2.val.length := by
      by_contra hc
      rw [ho.2 (by omega)] at hok
      cases hok
    obtain ⟨t, ht, ht'⟩ := ho.1 hvl
    rw [ht] at hok
    have hvec := core.result.Result.Ok.inj hok.symm
    obtain ⟨t2, h2, h2'⟩ := hd hvl
    refine ⟨t2, h2, ?_⟩
    simp only [PostCond.ok]
    mvcgen
    intro v t h
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj (core.result.Result.Ok.inj h)
    have hrl : rv.val.length = val.val := by
      rw [hrv, ← hvec, ht']; simp only [List.length_take]; omega
    have hl2 : t2.val.length = p.2.val.length - val.val := by rw [h2']; simp
    show rv.val.length ≤ 2 ^ 30 - 1 ∧
      t2.val.length + (rv.val.length + varint.lenOf rv.val.length) = bytes.val.length
    rw [hrl, hl2, hy]
    refine ⟨by omega, ?_⟩
    omega
  · intro v t h; cases h
  · exfalso
    rename_i r0 hP r1 p x1 r2 htf r3 residual x2 e hr2 h3
    have hb := (hP p.1 p.2 h3)
    obtain ⟨y, hy⟩ := htf.2 (by omega)
    rw [hy] at hr2
    cases hr2
  · intro _ v t h; cases h

/-- `VLByteVec::tls_serialized_len` of a payload of at most `2^30 - 1` bytes is the payload length plus
the minimal varint length prefix. -/
theorem quic_vec.VLByteVec.serialized_len_char (self : quic_vec.VLByteVec)
    (h : self.vec.val.length ≤ 2 ^ 30 - 1) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLByteVec.Insts.Tls_codecSize.tls_serialized_len self
    ⦃ ⇓ r => ⌜ r.val = self.vec.val.length + varint.lenOf self.vec.val.length ⌝ ⦄ := by
  mvcgen [quic_vec.VLByteVec.Insts.Tls_codecSize.tls_serialized_len, quic_vec.VLByteVec.as_slice,
    quic_vec.VLByteVec.impl.vec, quic_vec.tls_serialize_bytes_len_char]
  · intro hr; subst_vars; exact hr
  · intro hr; subst_vars; exact h

end tls_codec
