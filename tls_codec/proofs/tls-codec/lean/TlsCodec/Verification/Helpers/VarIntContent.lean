/- Contents of the varint codec: the bytes `TlsVarInt::write_bytes` writes, the arithmetic of the
encoding (big-endian digits), and the trait contracts of `u16`.

Obligations: none directly; the bytes-path halves of `PanicFreedom.lean` /
`FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): ASSUMED `size_of`, `size_of_U16`. -/
import TlsCodec.Verification.Helpers.SliceSerGen
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! ### Content of `TlsVarInt::write_bytes` -/

/-- One iteration of the `write_bytes` loops, on contents: byte `i-1` is OR-ed with the low byte
of `value`, which is shifted by 8. -/
theorem varint.TlsVarInt.write_bytes_loop0.body_content (bytes : Slice Std.U8) (value : Std.U64)
    (i : Std.Usize) (h : i.val ≤ bytes.val.length) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.write_bytes_loop0.body bytes value i
    ⦃ ⇓ r => ⌜ match r with
      | .done y => i.val = 0 ∧ y = bytes
      | .cont (b', v', i') => 0 < i.val ∧ i'.val = i.val - 1 ∧ v'.val = value.val / 256 ∧
          b'.val.length = bytes.val.length ∧ ∀ k, (b'.val[k]?).map (·.val) = (bytes.val[k]?).map
            (fun x => if k = i.val - 1 then x.val ||| (value.val % 256) else x.val) ⌝ ⦄ := by
  unfold varint.TlsVarInt.write_bytes_loop0.body
  mvcgen
  · rename_i i1 hi1 hge i2 hi2 i3 hi3 i4 hi4 i5 hi5 s hlt hs v hv1 hv2 hlt8
    obtain ⟨hx, hi4v⟩ := hi4
    have h3 : i3.val = value.val % 256 := by
      subst hi3
      have h255 : value.val &&& 255 = value.val % 256 := Nat.and_two_pow_sub_one_eq_mod value.val 8
      have : i2.val = value.val &&& 255 := by simpa using hi2.1
      simp [UScalar.cast_val_eq, this, h255]
    have h5 : i5.val = i4.val ||| value.val % 256 := by rw [hi5.1]; simp [← h3]
    refine ⟨by scalar_tac, by scalar_tac, ?_, ?_, ?_⟩
    · rw [hv1]; simp [Nat.shiftRight_eq_div_pow]
    · rw [hs]; simp [Slice.set, Slice.setAtNat]
    · intro k
      subst hs
      have hk : (i1.val : ℕ) = i.val - 1 := by scalar_tac
      have h5' : i5.val = (bytes.val[i1.val]'hx).val ||| value.val % 256 := by rw [h5, hi4v]
      by_cases hkk : k = i1.val
      · subst hkk
        simp [Slice.set, Slice.setAtNat, List.getElem?_set, hx, h5']
        rw [← hk]; simp [hx]
      · simp [Slice.set, Slice.setAtNat, List.getElem?_set, hkk, Ne.symm hkk, hk ▸ hkk]
  · exfalso; scalar_tac
  · exfalso; scalar_tac
  · exfalso; scalar_tac
  · scalar_tac

/-- The `write_bytes` loops, on contents: bytes `0..i` get OR-ed with the bytes of `value`
(big-endian, the last one at index `i-1`). -/
theorem varint.TlsVarInt.write_bytes_loop0_content (bytes : Slice Std.U8) (value : Std.U64)
    (i : Std.Usize) (h : i.val ≤ bytes.val.length) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.write_bytes_loop0 bytes value i
    ⦃ ⇓ r => ⌜ r.val.length = bytes.val.length ∧ ∀ k, (r.val[k]?).map (·.val) =
        (bytes.val[k]?).map (fun x => if k < i.val
          then x.val ||| ((value.val >>> (8 * (i.val - 1 - k))) % 256) else x.val) ⌝ ⦄ := by
  unfold varint.TlsVarInt.write_bytes_loop0
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.loop.spec_decr_nat
    (fun x : Slice Std.U8 × Std.U64 × Std.Usize => x.2.2.val)
    (fun x : Slice Std.U8 × Std.U64 × Std.Usize =>
      x.2.2.val ≤ i.val ∧ x.1.val.length = bytes.val.length ∧
      x.2.1.val = value.val >>> (8 * (i.val - x.2.2.val)) ∧
      ∀ k, (x.1.val[k]?).map (·.val) = (bytes.val[k]?).map (fun y => if x.2.2.val ≤ k ∧ k < i.val
          then y.val ||| ((value.val >>> (8 * (i.val - 1 - k))) % 256) else y.val))
    (fun y : Slice Std.U8 => y.val.length = bytes.val.length ∧ ∀ k, (y.val[k]?).map (·.val) =
        (bytes.val[k]?).map (fun x => if k < i.val
          then x.val ||| ((value.val >>> (8 * (i.val - 1 - k))) % 256) else x.val))
  · rintro ⟨b, v, j⟩ ⟨hji, hb, hv, hk⟩
    dsimp only at hji hb hv hk
    obtain ⟨r, hr, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (varint.TlsVarInt.write_bytes_loop0.body_content b v j (by omega))
    dsimp only
    rw [hr, Aeneas.Std.WP.spec_ok]
    cases r with
    | done y =>
      obtain ⟨hj0, rfl⟩ := hP
      refine ⟨hb, fun k => ?_⟩
      rw [hk k]
      have : (j.val ≤ k ∧ k < i.val) ↔ k < i.val := by omega
      simp only [this]
    | cont x =>
      obtain ⟨b', v', j'⟩ := x
      obtain ⟨hj, hj', hv', hl', hk'⟩ := hP
      dsimp only at hj hj' hv' hl' hk' ⊢
      refine ⟨⟨by omega, hl'.trans hb, ?_, fun k => ?_⟩, by omega⟩
      · rw [hv', hv, Nat.shiftRight_eq_div_pow, Nat.shiftRight_eq_div_pow, Nat.div_div_eq_div_mul,
          show 8 * (i.val - j'.val) = 8 * (i.val - j.val) + 8 by omega, Nat.pow_add]
      · have hk1 := hk k
        rw [hk' k]
        rcases hy : bytes.val[k]? with _ | y
        · simp [hy] at hk1 ⊢
          simp [hk1]
        · rcases hx : b.val[k]? with _ | x
          · simp [hx, hy] at hk1
          · simp [hx, hy] at hk1 ⊢
            by_cases hkj : k = j.val - 1
            · have h1 : ¬ (j.val ≤ k ∧ k < i.val) := by omega
              have h2 : j'.val ≤ k ∧ k < i.val := by omega
              simp only [h1, if_false] at hk1
              simp only [h2, hkj, if_true, hk1, and_self]
              have h3 : j'.val ≤ j.val - 1 ∧ j.val - 1 < i.val := by omega
              rw [if_pos h3, hv, show i.val - 1 - (j.val - 1) = i.val - j.val by omega]
            · have h1 : (j.val ≤ k ∧ k < i.val) ↔ (j'.val ≤ k ∧ k < i.val) := by omega
              simp [hkj, hk1, h1]
  · refine ⟨le_refl _, rfl, by simp, fun k => ?_⟩
    have : ¬ (i.val ≤ k ∧ k < i.val) := by omega
    simp [this]

theorem varint.TlsVarInt.write_bytes_loop1_content (bytes : Slice Std.U8) (value : Std.U64)
    (i : Std.Usize) (h : i.val ≤ bytes.val.length) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.write_bytes_loop1 bytes value i
    ⦃ ⇓ r => ⌜ r.val.length = bytes.val.length ∧ ∀ k, (r.val[k]?).map (·.val) =
        (bytes.val[k]?).map (fun x => if k < i.val
          then x.val ||| ((value.val >>> (8 * (i.val - 1 - k))) % 256) else x.val) ⌝ ⦄ := by
  have := varint.TlsVarInt.write_bytes_loop0_content bytes value i h
  unfold varint.TlsVarInt.write_bytes_loop1 varint.TlsVarInt.write_bytes_loop1.body
  unfold varint.TlsVarInt.write_bytes_loop0 varint.TlsVarInt.write_bytes_loop0.body at this
  exact this

theorem varint.TlsVarInt.write_bytes_loop2_content (bytes : Slice Std.U8) (value : Std.U64)
    (i : Std.Usize) (h : i.val ≤ bytes.val.length) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.write_bytes_loop2 bytes value i
    ⦃ ⇓ r => ⌜ r.val.length = bytes.val.length ∧ ∀ k, (r.val[k]?).map (·.val) =
        (bytes.val[k]?).map (fun x => if k < i.val
          then x.val ||| ((value.val >>> (8 * (i.val - 1 - k))) % 256) else x.val) ⌝ ⦄ := by
  have := varint.TlsVarInt.write_bytes_loop0_content bytes value i h
  unfold varint.TlsVarInt.write_bytes_loop2 varint.TlsVarInt.write_bytes_loop2.body
  unfold varint.TlsVarInt.write_bytes_loop0 varint.TlsVarInt.write_bytes_loop0.body at this
  exact this

theorem varint.TlsVarInt.write_bytes_loop3_content (bytes : Slice Std.U8) (value : Std.U64)
    (i : Std.Usize) (h : i.val ≤ bytes.val.length) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.write_bytes_loop3 bytes value i
    ⦃ ⇓ r => ⌜ r.val.length = bytes.val.length ∧ ∀ k, (r.val[k]?).map (·.val) =
        (bytes.val[k]?).map (fun x => if k < i.val
          then x.val ||| ((value.val >>> (8 * (i.val - 1 - k))) % 256) else x.val) ⌝ ⦄ := by
  have := varint.TlsVarInt.write_bytes_loop0_content bytes value i h
  unfold varint.TlsVarInt.write_bytes_loop3 varint.TlsVarInt.write_bytes_loop3.body
  unfold varint.TlsVarInt.write_bytes_loop0 varint.TlsVarInt.write_bytes_loop0.body at this
  exact this

/-- List-level assembly of `write_bytes`: write the prefix byte `u` at index 0 of the first `L`
bytes, OR the value bytes in (`rr`), and write the result back at index 0. -/
theorem varint.write_bytes_assemble (buf rr : List Std.U8) (L value : Nat) (u : Std.U8)
    (hL : 1 ≤ L ∧ L ≤ buf.length) (hrr : rr.length = L ∧ ∀ k, (rr[k]?).map (·.val) =
      (((buf.take L).set 0 u)[k]?).map (fun x => if k < L
        then x.val ||| ((value >>> (8 * (L - 1 - k))) % 256) else x.val)) :
    (buf.setSlice! 0 rr).length = buf.length ∧ ∀ k, ((buf.setSlice! 0 rr)[k]?).map (·.val) =
      (buf[k]?).map (fun x => if k < L then
        (if k = 0 then u.val else x.val) ||| ((value >>> (8 * (L - 1 - k))) % 256) else x.val) := by
  obtain ⟨hlen, hk⟩ := hrr
  refine ⟨by simp, fun k => ?_⟩
  by_cases hkL : k < L
  · rw [List.setSlice!_getElem?_middle _ _ _ _ ⟨by omega, by omega, by omega⟩]
    have := hk k
    simp only [Nat.sub_zero]
    rw [this]
    simp [List.getElem?_set, List.getElem?_take, hkL, show k < buf.length by omega]
    by_cases h0 : k = 0
    · subst h0; simp
    · simp [h0, Ne.symm h0]
  · rw [List.setSlice!_getElem?_suffix _ _ _ _ (by omega)]
    simp [hkL]

/-- `vec![x; len]` for `u8`, content: `len` copies of `x`. -/
theorem alloc.vec.from_elem_U8_content (item : Std.U8) (len : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.from_elem core.U8.Insts.CoreCloneClone item len
    ⦃ ⇓ r => ⌜ (r : Slice Std.U8).val = List.replicate len.val item ⌝ ⦄ := by
  unfold alloc.vec.from_elem rust_primitives.sequence.seq_create
  mvcgen
  · rename_i h
    simp [Slice.new, h]
  · rename_i hne cl hcl comb hle
    rw [mapM_clone_replicate_U8] at hcl
    cases hcl
    have : (List.replicate (len.val - 1) item) ++ [item] = List.replicate len.val item := by
      rw [← List.replicate_succ']; congr 1; omega
    simpa [comb] using this
  · rename_i hne cl hcl comb hle
    have hl := List.mapM_RustM_length hcl
    simp only [List.length_replicate] at hl
    exfalso; apply hle
    simp only [comb, List.length_append, List.length_singleton, hl]
    scalar_tac
  · rename_i hne e hcl
    rw [mapM_clone_replicate_U8] at hcl
    cases hcl
  · rename_i hne hcl
    rw [mapM_clone_replicate_U8] at hcl
    cases hcl

/-- One successful branch of `write_bytes` on contents (`len` is the encoded length, `n` the literal
the branch matched on, `u` the prefix byte). -/
theorem varint.write_bytes_case (self : varint.TlsVarInt) (buf : Slice Std.U8) (len n : Std.Usize)
    (hL : len.val = varint.lenOf self.val) (hn : n.val = len.val)
    (hle : len.val ≤ buf.val.length) (hlc : len.val = 1 ∨ len.val = 2 ∨ len.val = 4 ∨ len.val = 8)
    (p : Slice Std.U8 × (Slice Std.U8 → Slice Std.U8))
    (hp : p.1.val = buf.val.take len.val ∧ ∀ x, (p.2 x).val = buf.val.setSlice! 0 x.val)
    (u : Std.U8) (hu : u.val = varint.pfx len.val) (s s2 : Slice Std.U8)
    (hs : s = p.1.set 0#usize u)
    (hl2 : s2.val.length = s.val.length ∧ ∀ k, (s2.val[k]?).map (·.val) =
      (s.val[k]?).map (fun x => if k < n.val
        then x.val ||| ((self.val >>> (8 * (n.val - 1 - k))) % 256) else x.val)) :
    (p.2 s2).val.length = buf.val.length ∧ ∀ k, ((p.2 s2).val[k]?).map (·.val) =
      (buf.val[k]?).map (fun x => if k < varint.lenOf self.val then
        (if k = 0 then varint.pfx (varint.lenOf self.val) else x.val) |||
          ((self.val >>> (8 * (varint.lenOf self.val - 1 - k))) % 256) else x.val) := by
  rw [hp.2 s2]
  rw [hn] at hl2
  have hs' : s.val = (buf.val.take len.val).set 0 u := by
    rw [hs, ← hp.1]; simp [Slice.set, Slice.setAtNat]
  have hlen1 : 1 ≤ len.val := by omega
  have := varint.write_bytes_assemble buf.val s2.val len.val self.val u ⟨hlen1, hle⟩
    ⟨by rw [hl2.1, hs']; simp; omega, fun k => by rw [hl2.2 k, hs']⟩
  rw [← hL] at *
  rw [hu] at this
  exact this

/-- Content of `TlsVarInt::write_bytes` on a buffer of at least the encoded length: the first
`L = lenOf value` bytes are the big-endian bytes of `value`, OR-ed into the (existing) buffer, with
the length prefix `pfx L` in place of the old first byte; the rest is untouched. -/
theorem varint.TlsVarInt.write_bytes_content (self : varint.TlsVarInt) (buf : Slice Std.U8)
    (h : self.val ≤ 2 ^ 62 - 1 ∧ varint.lenOf self.val ≤ buf.val.length) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.write_bytes self buf
    ⦃ ⇓ r => ⌜ (∃ l : Std.Usize, r.1 = .Ok l ∧ l.val = varint.lenOf self.val) ∧
        r.2.val.length = buf.val.length ∧ ∀ k, (r.2.val[k]?).map (·.val) =
        (buf.val[k]?).map (fun x => if k < varint.lenOf self.val then
          (if k = 0 then varint.pfx (varint.lenOf self.val) else x.val) |||
            ((self.val >>> (8 * (varint.lenOf self.val - 1 - k))) % 256) else x.val) ⌝ ⦄ := by
  obtain ⟨hv, h⟩ := h
  mvcgen [varint.TlsVarInt.write_bytes, varint.TlsVarInt.write_bytes_loop0_content,
    varint.TlsVarInt.write_bytes_loop1_content, varint.TlsVarInt.write_bytes_loop2_content,
    varint.TlsVarInt.write_bytes_loop3_content]
  · exfalso; scalar_tac -- `value > MAX`
  · rename_i len hlc blen hlt hbl
    have hc := varint.lenOf_char _ _ hlc
    exfalso; scalar_tac
  · rename_i len hlc blen hnlt hbl
    scalar_tac
  -- len = 1
  · rename_i len hlc blen hnlt hbl p hx hp s hlt hs
    have hc := varint.lenOf_char _ _ hlc
    have h2 : p.1.val.length = len.val := by rw [hp.1]; apply slice_take_length; scalar_tac
    have h3 : s.length = p.1.length := by rw [hs]; simp [Slice.set, Slice.setAtNat, Slice.length]
    scalar_tac
  · rename_i len hlc blen hnlt hbl p hx hp s hlt hs s2 buf1 hl2
    have hc := varint.lenOf_char _ _ hlc
    have hle : len.val ≤ buf.val.length := by scalar_tac
    refine ⟨⟨_, rfl, ?_⟩, ?_⟩
    · scalar_tac
    · exact varint.write_bytes_case self buf len _ hc.1 (by simp; omega) hle hc.2 p hp 0#u8
        (by simp [varint.pfx, hx]) s s2 hs hl2
  · rename_i len hlc blen hnlt hbl p hx hp ha
    have hc := varint.lenOf_char _ _ hlc
    have h2 : p.1.val.length = len.val := by rw [hp.1]; apply slice_take_length; scalar_tac
    exfalso; scalar_tac
  -- len = 2
  · rename_i len hlc blen hnlt hbl p hx hp s hlt hs
    have hc := varint.lenOf_char _ _ hlc
    have h2 : p.1.val.length = len.val := by rw [hp.1]; apply slice_take_length; scalar_tac
    have h3 : s.length = p.1.length := by rw [hs]; simp [Slice.set, Slice.setAtNat, Slice.length]
    scalar_tac
  · rename_i len hlc blen hnlt hbl p hx hp s hlt hs s2 buf1 hl2
    have hc := varint.lenOf_char _ _ hlc
    have hle : len.val ≤ buf.val.length := by scalar_tac
    refine ⟨⟨_, rfl, ?_⟩, ?_⟩
    · scalar_tac
    · exact varint.write_bytes_case self buf len _ hc.1 (by simp; omega) hle hc.2 p hp 64#u8
        (by simp [varint.pfx, hx]) s s2 hs hl2
  · rename_i len hlc blen hnlt hbl p hx hp ha
    have hc := varint.lenOf_char _ _ hlc
    have h2 : p.1.val.length = len.val := by rw [hp.1]; apply slice_take_length; scalar_tac
    exfalso; scalar_tac
  -- len = 4
  · rename_i len hlc blen hnlt hbl p hx hp s hlt hs
    have hc := varint.lenOf_char _ _ hlc
    have h2 : p.1.val.length = len.val := by rw [hp.1]; apply slice_take_length; scalar_tac
    have h3 : s.length = p.1.length := by rw [hs]; simp [Slice.set, Slice.setAtNat, Slice.length]
    scalar_tac
  · rename_i len hlc blen hnlt hbl p hx hp s hlt hs s2 buf1 hl2
    have hc := varint.lenOf_char _ _ hlc
    have hle : len.val ≤ buf.val.length := by scalar_tac
    refine ⟨⟨_, rfl, ?_⟩, ?_⟩
    · scalar_tac
    · exact varint.write_bytes_case self buf len _ hc.1 (by simp; omega) hle hc.2 p hp 128#u8
        (by simp [varint.pfx, hx]) s s2 hs hl2
  · rename_i len hlc blen hnlt hbl p hx hp ha
    have hc := varint.lenOf_char _ _ hlc
    have h2 : p.1.val.length = len.val := by rw [hp.1]; apply slice_take_length; scalar_tac
    exfalso; scalar_tac
  -- len = 8
  · rename_i len hlc blen hnlt hbl p hx hp s hlt hs
    have hc := varint.lenOf_char _ _ hlc
    have h2 : p.1.val.length = len.val := by rw [hp.1]; apply slice_take_length; scalar_tac
    have h3 : s.length = p.1.length := by rw [hs]; simp [Slice.set, Slice.setAtNat, Slice.length]
    scalar_tac
  · rename_i len hlc blen hnlt hbl p hx hp s hlt hs s2 buf1 hl2
    have hc := varint.lenOf_char _ _ hlc
    have hle : len.val ≤ buf.val.length := by scalar_tac
    refine ⟨⟨_, rfl, ?_⟩, ?_⟩
    · scalar_tac
    · exact varint.write_bytes_case self buf len _ hc.1 (by simp; omega) hle hc.2 p hp 192#u8
        (by simp [varint.pfx, hx]) s s2 hs hl2
  · rename_i len hlc blen hnlt hbl p hx hp ha
    have hc := varint.lenOf_char _ _ hlc
    have h2 : p.1.val.length = len.val := by rw [hp.1]; apply slice_take_length; scalar_tac
    exfalso; scalar_tac
  · rename_i len hlc blen hnlt hbl p n h1 h2 h4 h8 hx hp a1 a2
    have hc := varint.lenOf_char _ _ hlc
    have e1 : n ≠ 1 := h1
    have e2 : n ≠ 2 := h2
    have e4 : n ≠ 4 := h4
    have e8 : n ≠ 8 := h8
    exfalso; omega

/-- `write_bytes_content` for the copy. -/
theorem Copied.varint.TlsVarInt.write_bytes_content (self : varint.TlsVarInt) (buf : Slice Std.U8)
    (h : self.val ≤ 2 ^ 62 - 1 ∧ varint.lenOf self.val ≤ buf.val.length) :
    ⦃ ⌜ True ⌝ ⦄ Copied.varint.TlsVarInt.write_bytes self buf
    ⦃ ⇓ r => ⌜ (∃ l : Std.Usize, r.1 = .Ok l ∧ l.val = varint.lenOf self.val) ∧
        r.2.val.length = buf.val.length ∧ ∀ k, (r.2.val[k]?).map (·.val) =
        (buf.val[k]?).map (fun x => if k < varint.lenOf self.val then
          (if k = 0 then varint.pfx (varint.lenOf self.val) else x.val) |||
            ((self.val >>> (8 * (varint.lenOf self.val - 1 - k))) % 256) else x.val) ⌝ ⦄ := by
  have := _root_.tls_codec.varint.TlsVarInt.write_bytes_content self buf h
  rwa [← Copied.varint.TlsVarInt.write_bytes_eq_of_le self buf h.1] at this

/-! ### Arithmetic of the varint encoding (big-endian digits) -/

/-- Big-endian bytes of `v` on `n` digits. -/
def varint.digits (n v : Nat) : List Nat :=
  (List.range n).map (fun k => (v >>> (8 * (n - 1 - k))) % 256)

theorem varint.digits_succ (n v : Nat) :
    varint.digits (n + 1) v = ((v >>> (8 * n)) % 256) :: varint.digits n v := by
  unfold varint.digits
  rw [List.range_succ_eq_map, List.map_cons, List.map_map]
  congr 1
  apply List.map_congr_left
  intro k _
  simp only [Function.comp]
  congr 3
  omega

theorem varint.foldl_digits (n v a : Nat) :
    (varint.digits n v).foldl (fun a b => a * 256 + b) a = a * 256 ^ n + v % 256 ^ n := by
  induction n generalizing a with
  | zero => simp [varint.digits, Nat.mod_one]
  | succ n ih =>
    rw [varint.digits_succ, List.foldl_cons, ih, Nat.shiftRight_eq_div_pow, pow_succ, Nat.mod_mul]
    have h2 : 2 ^ (8 * n) = 256 ^ n := by rw [pow_mul]; norm_num
    rw [h2]
    ring

/-- Big-endian value of a list of digits. -/
def varint.D (xs : List Nat) : Nat := xs.foldl (fun a b => a * 256 + b) 0

theorem varint.foldl_eq (xs : List Nat) (a : Nat) :
    xs.foldl (fun a b => a * 256 + b) a = a * 256 ^ xs.length + varint.D xs := by
  induction xs generalizing a with
  | nil => simp [varint.D]
  | cons x xs ih =>
    have hD : varint.D (x :: xs) = xs.foldl (fun a b => a * 256 + b) (0 * 256 + x) := rfl
    rw [List.foldl_cons, ih, hD, ih]
    simp only [List.length_cons, pow_succ]
    ring

theorem varint.D_cons (x : Nat) (xs : List Nat) :
    varint.D (x :: xs) = x * 256 ^ xs.length + varint.D xs := by
  have hD : varint.D (x :: xs) = xs.foldl (fun a b => a * 256 + b) (0 * 256 + x) := rfl
  rw [hD, varint.foldl_eq]; simp

theorem varint.D_lt (xs : List Nat) (h : ∀ x ∈ xs, x < 256) : varint.D xs < 256 ^ xs.length := by
  induction xs with
  | nil => simp [varint.D]
  | cons x xs ih =>
    rw [varint.D_cons, List.length_cons, pow_succ]
    have hx := h x (by simp)
    have := ih (fun y hy => h y (by simp [hy]))
    have h1 : (x + 1) * 256 ^ xs.length ≤ 256 * 256 ^ xs.length := Nat.mul_le_mul_right _ hx
    nlinarith

theorem varint.D_inj (xs ys : List Nat) (hl : xs.length = ys.length) (hx : ∀ x ∈ xs, x < 256)
    (hy : ∀ y ∈ ys, y < 256) (h : varint.D xs = varint.D ys) : xs = ys := by
  induction xs generalizing ys with
  | nil => cases ys with
    | nil => rfl
    | cons y ys => simp at hl
  | cons x xs ih =>
    cases ys with
    | nil => simp at hl
    | cons y ys =>
      have hl' : xs.length = ys.length := by simpa using hl
      rw [varint.D_cons, varint.D_cons, hl'] at h
      have h1 := varint.D_lt xs (fun z hz => hx z (by simp [hz]))
      have h2 := varint.D_lt ys (fun z hz => hy z (by simp [hz]))
      rw [hl'] at h1
      have hxy : x = y := by
        rcases lt_trichotomy x y with hlt | heq | hgt
        · have : (x + 1) * 256 ^ ys.length ≤ y * 256 ^ ys.length := Nat.mul_le_mul_right _ hlt
          nlinarith
        · exact heq
        · have : (y + 1) * 256 ^ ys.length ≤ x * 256 ^ ys.length := Nat.mul_le_mul_right _ hgt
          nlinarith
      subst hxy
      have : varint.D xs = varint.D ys := by omega
      rw [ih ys hl' (fun z hz => hx z (by simp [hz])) (fun z hz => hy z (by simp [hz])) this]

/-- Byte `k` of the varint encoding of `v`: the big-endian byte of `v`, with the length prefix
OR-ed into the first one. -/
def varint.encByte (v k : Nat) : Nat :=
  (if k = 0 then varint.pfx (varint.lenOf v) else 0) ||| ((v >>> (8 * (varint.lenOf v - 1 - k))) % 256)

/-- The bytes of the varint encoding of `v`. -/
def varint.encList (v : Nat) : List Nat := (List.range (varint.lenOf v)).map (varint.encByte v)

theorem varint.lenOf_mem (v : Nat) :
    varint.lenOf v = 1 ∨ varint.lenOf v = 2 ∨ varint.lenOf v = 4 ∨ varint.lenOf v = 8 := by
  unfold varint.lenOf; split_ifs <;> simp

theorem varint.lenOf_pos (v : Nat) : 1 ≤ varint.lenOf v := by
  rcases varint.lenOf_mem v with h | h | h | h <;> omega

theorem varint.encList_eq (v : Nat) :
    varint.encList v = (varint.pfx (varint.lenOf v) ||| ((v >>> (8 * (varint.lenOf v - 1))) % 256)) ::
      varint.digits (varint.lenOf v - 1) v := by
  have hpos := varint.lenOf_pos v
  obtain ⟨n, hn⟩ : ∃ n, varint.lenOf v = n + 1 := ⟨varint.lenOf v - 1, by omega⟩
  unfold varint.encList
  rw [hn, List.range_succ_eq_map, List.map_cons, List.map_map]
  simp only [Nat.add_sub_cancel]
  rw [varint.digits]
  congr 1
  · simp [varint.encByte, hn]
  · apply List.map_congr_left
    intro k _
    simp [varint.encByte, hn]
    rw [show n - (k + 1) = n - 1 - k by omega]

theorem varint.top_lt (v : Nat) (h : v ≤ 2 ^ 62 - 1) : v >>> (8 * (varint.lenOf v - 1)) < 64 := by
  rw [Nat.shiftRight_eq_div_pow]
  unfold varint.lenOf
  split_ifs <;> simp <;> omega

theorem varint.or_small (L t : Nat) (hL : L = 1 ∨ L = 2 ∨ L = 4 ∨ L = 8) (ht : t < 64) :
    varint.pfx L ||| t = varint.pfx L + t := by
  have h0 : ∀ t < 64, 0 ||| t = 0 + t := by decide
  have h1 : ∀ t < 64, 64 ||| t = 64 + t := by decide
  have h2 : ∀ t < 64, 128 ||| t = 128 + t := by decide
  have h3 : ∀ t < 64, 192 ||| t = 192 + t := by decide
  rcases hL with rfl | rfl | rfl | rfl
  · simpa [varint.pfx] using h0 t ht
  · simpa [varint.pfx] using h1 t ht
  · simpa [varint.pfx] using h2 t ht
  · simpa [varint.pfx] using h3 t ht

theorem varint.pfx_inj (L L' : Nat) (hL : L = 1 ∨ L = 2 ∨ L = 4 ∨ L = 8)
    (hL' : L' = 1 ∨ L' = 2 ∨ L' = 4 ∨ L' = 8) (h : varint.pfx L = varint.pfx L') : L = L' := by
  rcases hL with rfl | rfl | rfl | rfl <;> rcases hL' with rfl | rfl | rfl | rfl <;>
    simp_all [varint.pfx]

theorem varint.pfx_mem (L : Nat) (hL : L = 1 ∨ L = 2 ∨ L = 4 ∨ L = 8) :
    varint.pfx L = 0 ∨ varint.pfx L = 64 ∨ varint.pfx L = 128 ∨ varint.pfx L = 192 := by
  rcases hL with rfl | rfl | rfl | rfl <;> simp [varint.pfx]

/-- Decoding the encoding: the first byte has the length prefix, and folding its low 6 bits with
the other bytes gives back the value. -/
theorem varint.encList_dec (v : Nat) (h : v ≤ 2 ^ 62 - 1) :
    ∃ e0 tl, varint.encList v = e0 :: tl ∧ e0 / 64 * 64 = varint.pfx (varint.lenOf v) ∧
      tl.length = varint.lenOf v - 1 ∧ (∀ x ∈ e0 :: tl, x < 256) ∧
      varint.D ((e0 % 64) :: tl) = v := by
  have hL := varint.lenOf_mem v
  have htop := varint.top_lt v h
  set L := varint.lenOf v with hLdef
  have hm : (v >>> (8 * (L - 1))) % 256 = v >>> (8 * (L - 1)) := Nat.mod_eq_of_lt (by omega)
  have hor := varint.or_small L _ hL htop
  have hp := varint.pfx_mem L hL
  refine ⟨_, _, varint.encList_eq v, ?_, ?_, ?_, ?_⟩
  · rw [hm, hor]; omega
  · show (varint.digits (L - 1) v).length = L - 1
    simp [varint.digits]
  · intro x hx
    rw [hm, hor] at hx
    simp only [List.mem_cons] at hx
    rcases hx with rfl | hx
    · omega
    · simp only [varint.digits, List.mem_map] at hx
      obtain ⟨k, _, rfl⟩ := hx
      exact Nat.mod_lt _ (by norm_num)
  · rw [hm, hor]
    have e : (varint.pfx L + v >>> (8 * (L - 1))) % 64 = v >>> (8 * (L - 1)) := by omega
    rw [e, varint.D, List.foldl_cons, varint.foldl_digits]
    have hlt : v < 2 ^ (8 * (L - 1)) * 64 := by
      rw [Nat.shiftRight_eq_div_pow] at htop
      have := Nat.div_lt_iff_lt_mul (Nat.two_pow_pos (8 * (L - 1))) |>.mp htop
      rw [Nat.mul_comm]; exact this
    have h256 : (256 : Nat) ^ (L - 1) = 2 ^ (8 * (L - 1)) := by rw [pow_mul]; norm_num
    rw [Nat.shiftRight_eq_div_pow, ← h256, Nat.zero_mul, Nat.zero_add, Nat.mul_comm]
    exact Nat.div_add_mod v _

/-- Canonical encoding (decode then encode): what the decoder reads is the encoding of the value. -/
theorem varint.enc_of_dec (b0 : Nat) (l : List Nat) (L v : Nat) (hv : v ≤ 2 ^ 62 - 1)
    (hb0 : b0 < 256) (hl : ∀ x ∈ l, x < 256) (hL : L = varint.lenOf v)
    (hpfx : varint.pfx L = b0 / 64 * 64) (hle : L - 1 ≤ l.length)
    (hval : v = (l.take (L - 1)).foldl (fun a b => a * 256 + b) (b0 % 64)) :
    b0 :: l.take (L - 1) = varint.encList v := by
  obtain ⟨e0, tl, he, he0, htl, hlt, hD⟩ := varint.encList_dec v hv
  rw [he]
  have hlen : (b0 % 64 :: l.take (L - 1)).length = (e0 % 64 :: tl).length := by
    simp [htl, hL]; omega
  have hDeq : varint.D (b0 % 64 :: l.take (L - 1)) = varint.D (e0 % 64 :: tl) := by
    rw [hD, varint.D_cons, hval, varint.foldl_eq]
  have hall1 : ∀ x ∈ b0 % 64 :: l.take (L - 1), x < 256 := by
    intro x hx
    simp only [List.mem_cons] at hx
    rcases hx with rfl | hx
    · omega
    · exact hl x (List.mem_of_mem_take hx)
  have hall2 : ∀ x ∈ e0 % 64 :: tl, x < 256 := by
    intro x hx
    simp only [List.mem_cons] at hx
    rcases hx with rfl | hx
    · omega
    · exact hlt x (by simp [hx])
  have := varint.D_inj _ _ hlen hall1 hall2 hDeq
  simp only [List.cons.injEq] at this
  rw [← hL] at he0
  have hb : b0 = e0 := by omega
  rw [hb, this.2]

/-- Round trip (encode then decode): decoding the encoding of `v` returns `v`, consuming it all. -/
theorem varint.dec_of_enc (b0 : Nat) (l : List Nat) (L v v' : Nat) (hv : v ≤ 2 ^ 62 - 1)
    (hc : b0 :: l = varint.encList v) (hL : L = 1 ∨ L = 2 ∨ L = 4 ∨ L = 8)
    (hpfx : varint.pfx L = b0 / 64 * 64)
    (hval : v' = (l.take (L - 1)).foldl (fun a b => a * 256 + b) (b0 % 64)) :
    L = varint.lenOf v ∧ l.length = L - 1 ∧ v' = v := by
  obtain ⟨e0, tl, he, he0, htl, hlt, hD⟩ := varint.encList_dec v hv
  rw [he] at hc
  obtain ⟨rfl, rfl⟩ := List.cons.inj hc
  have hLL : L = varint.lenOf v :=
    varint.pfx_inj _ _ hL (varint.lenOf_mem v) (hpfx.trans he0)
  have hl : l.length = L - 1 := by rw [htl, hLL]
  refine ⟨hLL, hl, ?_⟩
  rw [hval, List.take_of_length_le (by omega), ← hD, varint.D_cons, varint.foldl_eq]

/-- Content of `TlsVarInt::tls_serialize_bytes` on a value at most `MAX`: returns the `lenOf` bytes
`encByte`. -/
theorem varint.TlsVarInt.serialize_content (self : varint.TlsVarInt)
    (hv : self.val ≤ 2 ^ 62 - 1) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.Insts.Tls_codecSerializeBytes.tls_serialize_bytes self
    ⦃ ⇓ r => ⌜ ∃ v : alloc.vec.Vec Std.U8, r = .Ok v ∧
        (v : Slice Std.U8).val.map (·.val) =
          (List.range (varint.lenOf self.val)).map (varint.encByte self.val) ⌝ ⦄ := by
  mvcgen [varint.TlsVarInt.Insts.Tls_codecSerializeBytes.tls_serialize_bytes,
    varint.TlsVarInt.bytes_len_spec, alloc.vec.from_elem_U8_content,
    varint.TlsVarInt.write_bytes_content, alloc.vec.Vec.Insts.CoreOpsDerefDerefMutSlice.deref_mut,
    alloc.vec.Vec.as_mut_slice, rust_primitives.sequence.seq_to_slice_mut]
  · rename_i len hlc vec hvl back
    have hc := varint.lenOf_char _ _ hlc
    rw [hvl]; simp; omega
  · rename_i len hlc vec hvl back wr hwr cf val hx byt hcf
    have hc := varint.lenOf_char _ _ hlc
    obtain ⟨_, _, hk⟩ := hwr
    refine ⟨_, rfl, ?_⟩
    show wr.2.val.map (·.val) = _
    apply List.ext_getElem?
    intro k
    have hk' := hk k
    rw [List.getElem?_map, hk', hvl, List.getElem?_replicate, List.getElem?_map]
    by_cases hkL : k < varint.lenOf self.val
    · have hkl : k < len.val := by omega
      rw [List.getElem?_range hkL]
      simp [hkL, hkl, varint.encByte]
    · have hkl : ¬ k < len.val := by omega
      rw [List.getElem?_eq_none (by simp; omega)]
      simp [hkL, hkl]
  · rename_i len hlc vec hvl back wr hwr cf resid hx
    obtain ⟨⟨l, hl, _⟩, _⟩ := hwr
    intro hb
    rw [hl] at hb
    simp only [tryCF, reduceCtorEq] at hb


/-! ### Trait contracts of `u16`

The `Lawful` structures of `u16` (the generic `Vec<T>` results take them as hypotheses). -/

theorem U16.size_lawful : Size.Lawful Std.U16 U16.Insts.Tls_codecSize :=
  ⟨fun x _ => by
    obtain ⟨v, hv, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (show ⦃ ⌜ True ⌝ ⦄ U16.Insts.Tls_codecSize.tls_serialized_len x ⦃ ⇓ _ => ⌜ True ⌝ ⦄ by
        mvcgen [U16.Insts.Tls_codecSize.tls_serialized_len])
    show ⦃ ⌜ True ⌝ ⦄ U16.Insts.Tls_codecSize.tls_serialized_len x
      ⦃ ⇓ r => ⌜ (Size.tls_serialized_len.post U16.Insts.Tls_codecSize x r).holds ⌝ ⦄
    rw [hv]
    apply RustM.ok_spec
    unfold Size.tls_serialized_len.post
    mvcgen⟩

theorem U16.serialize_lawful : SerializeBytes.Lawful Std.U16 U16.Insts.Tls_codecSerializeBytes where
  SizeInstLawful := U16.size_lawful
  tls_serialize_bytes_spec x _ := by
    apply triple_post_mono (U16_serialize_char x)
    rintro r ⟨v, rfl, hv⟩
    refine SerializeBytes.post_ok _ _ _ v 2#usize rfl ?_
    rw [hv]; simpa using (Aeneas.Std.core.num.U16.to_be_bytes x).property

theorem U16.deserialize_post (b : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ U16.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes b
    ⦃ ⇓ r => ⌜ (DeserializeBytes.tls_deserialize_bytes.post U16.Insts.Tls_codecSize
        U16.Insts.Tls_codecDeserializeBytes b r).holds ⌝ ⦄ := by
  apply triple_post_mono (U16_deserialize_char b)
  intro r hP
  by_cases hl : 2 ≤ b.val.length
  · obtain ⟨a, t, ha, ht, rfl⟩ := hP.1 hl
    refine DeserializeBytes.post_ok _ _ _ _ _ 2#usize rfl ?_ (by rw [ht]; exact List.drop_suffix _ _)
    simp [ht]; omega
  · rw [hP.2 (by omega)]
    exact DeserializeBytes.post_err _ _ _ _

theorem U16.deserialize_lawful :
    DeserializeBytes.Lawful Std.U16 U16.Insts.Tls_codecDeserializeBytes where
  SizeInstLawful := U16.size_lawful
  tls_deserialize_bytes_spec b _ := U16.deserialize_post b
  tls_deserialize_exact_bytes_spec b _ :=
    total_of_pf_partial
      (DeserializeBytes.exact_default_pf U16.Insts.Tls_codecDeserializeBytes
        (fun b => pf_of_total (U16.deserialize_post b)) b)
      (DeserializeBytes.exact_default_fc U16.Insts.Tls_codecDeserializeBytes b
        (partial_of_total (U16.deserialize_post b)))

end tls_codec
