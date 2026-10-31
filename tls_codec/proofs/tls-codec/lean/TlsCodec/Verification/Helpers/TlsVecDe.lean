/- Per-width instances of `TlsVecGen` (`TlsVecU*`, `SecretTlsVecU*`), and their function and
trait-level specs.

Obligations: none directly; the bytes-path halves of `PanicFreedom.lean` /
`FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): ASSUMED `size_of`, `size_of_U16`, `size_of_U24`,
`size_of_U32`, `size_of_U8`, `size_of_Usize`, `numBits_eq_64`; 2 signature-only stubs
(`core.convert.Infallible.Insts.CoreFmtDebug.fmt`,
`core.num.error.TryFromIntError.Insts.CoreFmtDebug.fmt`); `native_decide` (1). -/
import TlsCodec.Verification.Helpers.TlsByteVecDe
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! #### `TlsVecU8` -/
@[spec] theorem tls_vec.TlsVecU8.push_spec {T : Type} (self : tls_vec.TlsVecU8 T) (x : T)
    (h : self.vec.val.length < Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU8.push self x ⦃ ⇓ r => ⌜ r.vec.val = self.vec.val ++ [x] ⌝ ⦄ :=
  TlsVecGen.push_spec _ tls_vec.TlsVecU8.mk (fun _ => rfl) self x h

/-- The size of a `TlsVecU8` is the size fold of its elements, starting at the prefix width. -/
theorem tls_vec.TlsVecU8.size_rel {T : Type} (S : Size T) (hl : Size.Lawful T S)
    (self : tls_vec.TlsVecU8 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU8.tls_serialized_length S self
    ⦃ ⇓ r => ⌜ SizeFoldRel S 1#usize self.vec.val r ⌝ ⦄ :=
  TlsVecGen.serLen_rel S hl tls_vec.TlsVecU8.as_slice
    (fun x => alloc.vec.Vec.Insts.CoreOpsDerefDerefSlice.deref_spec x.vec) _ (fun _ _ _ => rfl) () 1#usize self

/-- `TlsVecU8::tls_serialized_length` does not fail when the element size does not. -/
theorem tls_vec.TlsVecU8.tls_serialized_length_pf {T : Type} (SizeInst : Size T)
    (SizeInstLawful : Size.Lawful T SizeInst) (self_ : tls_vec.TlsVecU8 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU8.tls_serialized_length SizeInst self_ ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  pf_of_total (tls_vec.TlsVecU8.size_rel SizeInst SizeInstLawful self_)

/-- `TlsVecU8::deserialize_bytes` is the generic one (rfl modulo the message literal). -/
theorem tls_vec.TlsVecU8.deserialize_bytes_eq {T : Type} :
    ∃ (M : Std.Usize) (pieces : Aeneas.Std.Array Std.U8 M), ∀ (inst : DeserializeBytes T),
      tls_vec.TlsVecU8.deserialize_bytes inst =
      TlsVecGen.deser tls_vec.TlsVecU8.mk U8.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
        (core.convert.TryFromTUInfallible.Blanket.try_from
          (core.convert.Into.Blanket core.Usize.Insts.CoreConvertFromU8))
        core.convert.Infallible.Insts.CoreFmtDebug (tls_vec.TlsVecU8.deserialize_bytes_loop inst) pieces := by
  apply Exists.intro; apply Exists.intro; intro inst; funext bytes
  unfold tls_vec.TlsVecU8.deserialize_bytes TlsVecGen.deser
  congr 1; funext v; congr 1; funext r; congr 1; funext cf; cases cf <;> rfl

/-- `TlsVecU8::deserialize_bytes` from the trait contract of `T`: never fails to terminate, and an `Ok`
result accounts for the whole input (`rem.len + size v = bytes.len`). -/
theorem tls_vec.TlsVecU8.deserialize_bytes_char {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU8.deserialize_bytes inst bytes
    ⦃ ⇓ r => ⌜ ∀ v rem, r = .Ok (v, rem) → ∃ n,
        tls_vec.TlsVecU8.Insts.Tls_codecSize.tls_serialized_len inst.SizeInst v = ok n ∧
        rem.val.length + n.val = bytes.val.length ∧ rem.val <:+ bytes.val ⌝ ⦄ := by
  obtain ⟨_, _, h⟩ := tls_vec.TlsVecU8.deserialize_bytes_eq (T := T)
  rw [h]
  exact TlsVecGen.deser_char inst.SizeInst _ _ (fun _ => rfl) _ 1#usize
    (tls_vec.TlsVecU8.size_rel inst.SizeInst hlaw.SizeInstLawful) _
    (TlsVecGen.prefix_len 1#usize 1 (by simp) U8_deserialize_char) _
    (TlsVecGen.conv_ok core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U8_spec) _ _
    (fun N _ hN _ _ len _ hinv => TlsVecGen.loop_char _ _ tls_vec.TlsVecU8.push_spec inst len _ rfl
      hlaw 1#usize N hN _ _ _ hinv) _ bytes

/-- Functional correctness of `TlsVecU8::deserialize_bytes` (function-level post). -/
theorem tls_vec.TlsVecU8.deserialize_bytes_fc {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU8.deserialize_bytes inst bytes
    ⦃ ⇓? res => ⌜ (tls_vec.TlsVecU8.deserialize_bytes.post inst bytes res).holds ⌝ ⦄ :=
  TlsVecGen.fc_of_char _ bytes (tls_vec.TlsVecU8.deserialize_bytes_char inst hlaw bytes)

/-- `TlsVecU8::deserialize_bytes` does not fail. -/
theorem tls_vec.TlsVecU8.deserialize_bytes_pf {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU8.deserialize_bytes inst bytes ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  pf_of_total (tls_vec.TlsVecU8.deserialize_bytes_char inst hlaw bytes)


/-! #### `TlsVecU16` -/
@[spec] theorem tls_vec.TlsVecU16.push_spec {T : Type} (self : tls_vec.TlsVecU16 T) (x : T)
    (h : self.vec.val.length < Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU16.push self x ⦃ ⇓ r => ⌜ r.vec.val = self.vec.val ++ [x] ⌝ ⦄ :=
  TlsVecGen.push_spec _ tls_vec.TlsVecU16.mk (fun _ => rfl) self x h

/-- The size of a `TlsVecU16` is the size fold of its elements, starting at the prefix width. -/
theorem tls_vec.TlsVecU16.size_rel {T : Type} (S : Size T) (hl : Size.Lawful T S)
    (self : tls_vec.TlsVecU16 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU16.tls_serialized_length S self
    ⦃ ⇓ r => ⌜ SizeFoldRel S 2#usize self.vec.val r ⌝ ⦄ :=
  TlsVecGen.serLen_rel S hl tls_vec.TlsVecU16.as_slice
    (fun x => alloc.vec.Vec.Insts.CoreOpsDerefDerefSlice.deref_spec x.vec) _ (fun _ _ _ => rfl) () 2#usize self

/-- `TlsVecU16::tls_serialized_length` does not fail when the element size does not. -/
theorem tls_vec.TlsVecU16.tls_serialized_length_pf {T : Type} (SizeInst : Size T)
    (SizeInstLawful : Size.Lawful T SizeInst) (self_ : tls_vec.TlsVecU16 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU16.tls_serialized_length SizeInst self_ ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  pf_of_total (tls_vec.TlsVecU16.size_rel SizeInst SizeInstLawful self_)

/-- `TlsVecU16::deserialize_bytes` is the generic one (rfl modulo the message literal). -/
theorem tls_vec.TlsVecU16.deserialize_bytes_eq {T : Type} :
    ∃ (M : Std.Usize) (pieces : Aeneas.Std.Array Std.U8 M), ∀ (inst : DeserializeBytes T),
      tls_vec.TlsVecU16.deserialize_bytes inst =
      TlsVecGen.deser tls_vec.TlsVecU16.mk U16.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
        (core.convert.TryFromTUInfallible.Blanket.try_from
          (core.convert.Into.Blanket core.Usize.Insts.CoreConvertFromU16))
        core.convert.Infallible.Insts.CoreFmtDebug (tls_vec.TlsVecU16.deserialize_bytes_loop inst) pieces := by
  apply Exists.intro; apply Exists.intro; intro inst; funext bytes
  unfold tls_vec.TlsVecU16.deserialize_bytes TlsVecGen.deser
  congr 1; funext v; congr 1; funext r; congr 1; funext cf; cases cf <;> rfl

/-- `TlsVecU16::deserialize_bytes` from the trait contract of `T`: never fails to terminate, and an `Ok`
result accounts for the whole input (`rem.len + size v = bytes.len`). -/
theorem tls_vec.TlsVecU16.deserialize_bytes_char {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU16.deserialize_bytes inst bytes
    ⦃ ⇓ r => ⌜ ∀ v rem, r = .Ok (v, rem) → ∃ n,
        tls_vec.TlsVecU16.Insts.Tls_codecSize.tls_serialized_len inst.SizeInst v = ok n ∧
        rem.val.length + n.val = bytes.val.length ∧ rem.val <:+ bytes.val ⌝ ⦄ := by
  obtain ⟨_, _, h⟩ := tls_vec.TlsVecU16.deserialize_bytes_eq (T := T)
  rw [h]
  exact TlsVecGen.deser_char inst.SizeInst _ _ (fun _ => rfl) _ 2#usize
    (tls_vec.TlsVecU16.size_rel inst.SizeInst hlaw.SizeInstLawful) _
    (TlsVecGen.prefix_len 2#usize 2 (by simp) U16_deserialize_char) _
    (TlsVecGen.conv_ok core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U16_spec) _ _
    (fun N _ hN _ _ len _ hinv => TlsVecGen.loop_char _ _ tls_vec.TlsVecU16.push_spec inst len _ rfl
      hlaw 2#usize N hN _ _ _ hinv) _ bytes

/-- Functional correctness of `TlsVecU16::deserialize_bytes` (function-level post). -/
theorem tls_vec.TlsVecU16.deserialize_bytes_fc {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU16.deserialize_bytes inst bytes
    ⦃ ⇓? res => ⌜ (tls_vec.TlsVecU16.deserialize_bytes.post inst bytes res).holds ⌝ ⦄ :=
  TlsVecGen.fc_of_char _ bytes (tls_vec.TlsVecU16.deserialize_bytes_char inst hlaw bytes)

/-- `TlsVecU16::deserialize_bytes` does not fail. -/
theorem tls_vec.TlsVecU16.deserialize_bytes_pf {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU16.deserialize_bytes inst bytes ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  pf_of_total (tls_vec.TlsVecU16.deserialize_bytes_char inst hlaw bytes)


/-! #### `TlsVecU32` -/
@[spec] theorem tls_vec.TlsVecU32.push_spec {T : Type} (self : tls_vec.TlsVecU32 T) (x : T)
    (h : self.vec.val.length < Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU32.push self x ⦃ ⇓ r => ⌜ r.vec.val = self.vec.val ++ [x] ⌝ ⦄ :=
  TlsVecGen.push_spec _ tls_vec.TlsVecU32.mk (fun _ => rfl) self x h

/-- The size of a `TlsVecU32` is the size fold of its elements, starting at the prefix width. -/
theorem tls_vec.TlsVecU32.size_rel {T : Type} (S : Size T) (hl : Size.Lawful T S)
    (self : tls_vec.TlsVecU32 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU32.tls_serialized_length S self
    ⦃ ⇓ r => ⌜ SizeFoldRel S 4#usize self.vec.val r ⌝ ⦄ :=
  TlsVecGen.serLen_rel S hl tls_vec.TlsVecU32.as_slice
    (fun x => alloc.vec.Vec.Insts.CoreOpsDerefDerefSlice.deref_spec x.vec) _ (fun _ _ _ => rfl) () 4#usize self

/-- `TlsVecU32::tls_serialized_length` does not fail when the element size does not. -/
theorem tls_vec.TlsVecU32.tls_serialized_length_pf {T : Type} (SizeInst : Size T)
    (SizeInstLawful : Size.Lawful T SizeInst) (self_ : tls_vec.TlsVecU32 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU32.tls_serialized_length SizeInst self_ ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  pf_of_total (tls_vec.TlsVecU32.size_rel SizeInst SizeInstLawful self_)

/-- `TlsVecU32::deserialize_bytes` is the generic one (rfl modulo the message literal). -/
theorem tls_vec.TlsVecU32.deserialize_bytes_eq {T : Type} :
    ∃ (M : Std.Usize) (pieces : Aeneas.Std.Array Std.U8 M), ∀ (inst : DeserializeBytes T),
      tls_vec.TlsVecU32.deserialize_bytes inst =
      TlsVecGen.deser tls_vec.TlsVecU32.mk U32.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
        core.Usize.Insts.CoreConvertTryFromU32TryFromIntError.try_from
        core.num.error.TryFromIntError.Insts.CoreFmtDebug (tls_vec.TlsVecU32.deserialize_bytes_loop inst) pieces := by
  apply Exists.intro; apply Exists.intro; intro inst; funext bytes
  unfold tls_vec.TlsVecU32.deserialize_bytes TlsVecGen.deser
  congr 1; funext v; congr 1; funext r; congr 1; funext cf; cases cf <;> rfl

/-- `TlsVecU32::deserialize_bytes` from the trait contract of `T`: never fails to terminate, and an `Ok`
result accounts for the whole input (`rem.len + size v = bytes.len`). -/
theorem tls_vec.TlsVecU32.deserialize_bytes_char {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU32.deserialize_bytes inst bytes
    ⦃ ⇓ r => ⌜ ∀ v rem, r = .Ok (v, rem) → ∃ n,
        tls_vec.TlsVecU32.Insts.Tls_codecSize.tls_serialized_len inst.SizeInst v = ok n ∧
        rem.val.length + n.val = bytes.val.length ∧ rem.val <:+ bytes.val ⌝ ⦄ := by
  obtain ⟨_, _, h⟩ := tls_vec.TlsVecU32.deserialize_bytes_eq (T := T)
  rw [h]
  exact TlsVecGen.deser_char inst.SizeInst _ _ (fun _ => rfl) _ 4#usize
    (tls_vec.TlsVecU32.size_rel inst.SizeInst hlaw.SizeInstLawful) _
    (TlsVecGen.prefix_len 4#usize 4 (by simp) U32_deserialize_char) _
    (TlsVecGen.conv_ok core.Usize.Insts.CoreConvertTryFromU32TryFromIntError.try_from_spec) _ _
    (fun N _ hN _ _ len _ hinv => TlsVecGen.loop_char _ _ tls_vec.TlsVecU32.push_spec inst len _ rfl
      hlaw 4#usize N hN _ _ _ hinv) _ bytes

/-- Functional correctness of `TlsVecU32::deserialize_bytes` (function-level post). -/
theorem tls_vec.TlsVecU32.deserialize_bytes_fc {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU32.deserialize_bytes inst bytes
    ⦃ ⇓? res => ⌜ (tls_vec.TlsVecU32.deserialize_bytes.post inst bytes res).holds ⌝ ⦄ :=
  TlsVecGen.fc_of_char _ bytes (tls_vec.TlsVecU32.deserialize_bytes_char inst hlaw bytes)

/-- `TlsVecU32::deserialize_bytes` does not fail. -/
theorem tls_vec.TlsVecU32.deserialize_bytes_pf {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU32.deserialize_bytes inst bytes ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  pf_of_total (tls_vec.TlsVecU32.deserialize_bytes_char inst hlaw bytes)


/-! #### `SecretTlsVecU8` -/

@[spec] theorem tls_vec.SecretTlsVecU8.push_spec {T : Type} (z : zeroize.Zeroize T) (self : tls_vec.SecretTlsVecU8 T) (x : T)
    (h : self.vec.val.length < Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU8.push z self x ⦃ ⇓ r => ⌜ r.vec.val = self.vec.val ++ [x] ⌝ ⦄ :=
  TlsVecGen.push_spec _ tls_vec.SecretTlsVecU8.mk (fun _ => rfl) self x h

/-- The size of a `SecretTlsVecU8` is the size fold of its elements, starting at the prefix width. -/
theorem tls_vec.SecretTlsVecU8.size_rel {T : Type} (S : Size T) (z : zeroize.Zeroize T) (hl : Size.Lawful T S)
    (self : tls_vec.SecretTlsVecU8 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU8.tls_serialized_length S z self
    ⦃ ⇓ r => ⌜ SizeFoldRel S 1#usize self.vec.val r ⌝ ⦄ :=
  TlsVecGen.serLen_rel S hl (tls_vec.SecretTlsVecU8.as_slice z)
    (fun x => alloc.vec.Vec.Insts.CoreOpsDerefDerefSlice.deref_spec x.vec) _ (fun _ _ _ => rfl) () 1#usize self

/-- `SecretTlsVecU8::tls_serialized_length` does not fail when the element size does not. -/
theorem tls_vec.SecretTlsVecU8.tls_serialized_length_pf {T : Type} (SizeInst : Size T)
    (zeroizeZeroizeInst : zeroize.Zeroize T)
    (SizeInstLawful : Size.Lawful T SizeInst) (self_ : tls_vec.SecretTlsVecU8 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU8.tls_serialized_length SizeInst zeroizeZeroizeInst self_ ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  pf_of_total (tls_vec.SecretTlsVecU8.size_rel SizeInst zeroizeZeroizeInst SizeInstLawful self_)

/-- `SecretTlsVecU8::deserialize_bytes` is the generic one (rfl modulo the message literal). -/
theorem tls_vec.SecretTlsVecU8.deserialize_bytes_eq {T : Type} :
    ∃ (M : Std.Usize) (pieces : Aeneas.Std.Array Std.U8 M), ∀ (inst : DeserializeBytes T) (z : zeroize.Zeroize T),
      tls_vec.SecretTlsVecU8.deserialize_bytes inst z =
      TlsVecGen.deser tls_vec.SecretTlsVecU8.mk U8.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
        (core.convert.TryFromTUInfallible.Blanket.try_from
          (core.convert.Into.Blanket core.Usize.Insts.CoreConvertFromU8))
        core.convert.Infallible.Insts.CoreFmtDebug (tls_vec.SecretTlsVecU8.deserialize_bytes_loop inst z) pieces := by
  apply Exists.intro; apply Exists.intro; intro inst z; funext bytes
  unfold tls_vec.SecretTlsVecU8.deserialize_bytes TlsVecGen.deser
  congr 1; funext v; congr 1; funext r; congr 1; funext cf; cases cf <;> rfl

/-- `SecretTlsVecU8::deserialize_bytes` from the trait contract of `T`: never fails to terminate, and an `Ok`
result accounts for the whole input (`rem.len + size v = bytes.len`). -/
theorem tls_vec.SecretTlsVecU8.deserialize_bytes_char {T : Type} (inst : DeserializeBytes T)
    (z : zeroize.Zeroize T) (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU8.deserialize_bytes inst z bytes
    ⦃ ⇓ r => ⌜ ∀ v rem, r = .Ok (v, rem) → ∃ n,
        tls_vec.SecretTlsVecU8.Insts.Tls_codecSize.tls_serialized_len z inst.SizeInst v = ok n ∧
        rem.val.length + n.val = bytes.val.length ∧ rem.val <:+ bytes.val ⌝ ⦄ := by
  obtain ⟨_, _, h⟩ := tls_vec.SecretTlsVecU8.deserialize_bytes_eq (T := T)
  rw [h]
  exact TlsVecGen.deser_char inst.SizeInst _ _ (fun _ => rfl) _ 1#usize
    (tls_vec.SecretTlsVecU8.size_rel inst.SizeInst z hlaw.SizeInstLawful) _
    (TlsVecGen.prefix_len 1#usize 1 (by simp) U8_deserialize_char) _
    (TlsVecGen.conv_ok core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U8_spec) _ _
    (fun N _ hN _ _ len _ hinv => TlsVecGen.loop_char _ _ (tls_vec.SecretTlsVecU8.push_spec z) inst len _ rfl
      hlaw 1#usize N hN _ _ _ hinv) _ bytes

/-- Functional correctness of `SecretTlsVecU8::deserialize_bytes` (function-level post). -/
theorem tls_vec.SecretTlsVecU8.deserialize_bytes_fc {T : Type} (inst : DeserializeBytes T)
    (z : zeroize.Zeroize T) (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU8.deserialize_bytes inst z bytes
    ⦃ ⇓? res => ⌜ (tls_vec.SecretTlsVecU8.deserialize_bytes.post inst z bytes res).holds ⌝ ⦄ :=
  TlsVecGen.fc_of_char _ bytes (tls_vec.SecretTlsVecU8.deserialize_bytes_char inst z hlaw bytes)

/-- `SecretTlsVecU8::deserialize_bytes` does not fail. -/
theorem tls_vec.SecretTlsVecU8.deserialize_bytes_pf {T : Type} (inst : DeserializeBytes T)
    (z : zeroize.Zeroize T) (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU8.deserialize_bytes inst z bytes ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  pf_of_total (tls_vec.SecretTlsVecU8.deserialize_bytes_char inst z hlaw bytes)

/-! #### `SecretTlsVecU16` -/

@[spec] theorem tls_vec.SecretTlsVecU16.push_spec {T : Type} (z : zeroize.Zeroize T) (self : tls_vec.SecretTlsVecU16 T) (x : T)
    (h : self.vec.val.length < Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU16.push z self x ⦃ ⇓ r => ⌜ r.vec.val = self.vec.val ++ [x] ⌝ ⦄ :=
  TlsVecGen.push_spec _ tls_vec.SecretTlsVecU16.mk (fun _ => rfl) self x h

/-- The size of a `SecretTlsVecU16` is the size fold of its elements, starting at the prefix width. -/
theorem tls_vec.SecretTlsVecU16.size_rel {T : Type} (S : Size T) (z : zeroize.Zeroize T) (hl : Size.Lawful T S)
    (self : tls_vec.SecretTlsVecU16 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU16.tls_serialized_length S z self
    ⦃ ⇓ r => ⌜ SizeFoldRel S 2#usize self.vec.val r ⌝ ⦄ :=
  TlsVecGen.serLen_rel S hl (tls_vec.SecretTlsVecU16.as_slice z)
    (fun x => alloc.vec.Vec.Insts.CoreOpsDerefDerefSlice.deref_spec x.vec) _ (fun _ _ _ => rfl) () 2#usize self

/-- `SecretTlsVecU16::tls_serialized_length` does not fail when the element size does not. -/
theorem tls_vec.SecretTlsVecU16.tls_serialized_length_pf {T : Type} (SizeInst : Size T)
    (zeroizeZeroizeInst : zeroize.Zeroize T)
    (SizeInstLawful : Size.Lawful T SizeInst) (self_ : tls_vec.SecretTlsVecU16 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU16.tls_serialized_length SizeInst zeroizeZeroizeInst self_ ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  pf_of_total (tls_vec.SecretTlsVecU16.size_rel SizeInst zeroizeZeroizeInst SizeInstLawful self_)

/-- `SecretTlsVecU16::deserialize_bytes` is the generic one (rfl modulo the message literal). -/
theorem tls_vec.SecretTlsVecU16.deserialize_bytes_eq {T : Type} :
    ∃ (M : Std.Usize) (pieces : Aeneas.Std.Array Std.U8 M), ∀ (inst : DeserializeBytes T) (z : zeroize.Zeroize T),
      tls_vec.SecretTlsVecU16.deserialize_bytes inst z =
      TlsVecGen.deser tls_vec.SecretTlsVecU16.mk U16.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
        (core.convert.TryFromTUInfallible.Blanket.try_from
          (core.convert.Into.Blanket core.Usize.Insts.CoreConvertFromU16))
        core.convert.Infallible.Insts.CoreFmtDebug (tls_vec.SecretTlsVecU16.deserialize_bytes_loop inst z) pieces := by
  apply Exists.intro; apply Exists.intro; intro inst z; funext bytes
  unfold tls_vec.SecretTlsVecU16.deserialize_bytes TlsVecGen.deser
  congr 1; funext v; congr 1; funext r; congr 1; funext cf; cases cf <;> rfl

/-- `SecretTlsVecU16::deserialize_bytes` from the trait contract of `T`: never fails to terminate, and an `Ok`
result accounts for the whole input (`rem.len + size v = bytes.len`). -/
theorem tls_vec.SecretTlsVecU16.deserialize_bytes_char {T : Type} (inst : DeserializeBytes T)
    (z : zeroize.Zeroize T) (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU16.deserialize_bytes inst z bytes
    ⦃ ⇓ r => ⌜ ∀ v rem, r = .Ok (v, rem) → ∃ n,
        tls_vec.SecretTlsVecU16.Insts.Tls_codecSize.tls_serialized_len z inst.SizeInst v = ok n ∧
        rem.val.length + n.val = bytes.val.length ∧ rem.val <:+ bytes.val ⌝ ⦄ := by
  obtain ⟨_, _, h⟩ := tls_vec.SecretTlsVecU16.deserialize_bytes_eq (T := T)
  rw [h]
  exact TlsVecGen.deser_char inst.SizeInst _ _ (fun _ => rfl) _ 2#usize
    (tls_vec.SecretTlsVecU16.size_rel inst.SizeInst z hlaw.SizeInstLawful) _
    (TlsVecGen.prefix_len 2#usize 2 (by simp) U16_deserialize_char) _
    (TlsVecGen.conv_ok core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U16_spec) _ _
    (fun N _ hN _ _ len _ hinv => TlsVecGen.loop_char _ _ (tls_vec.SecretTlsVecU16.push_spec z) inst len _ rfl
      hlaw 2#usize N hN _ _ _ hinv) _ bytes

/-- Functional correctness of `SecretTlsVecU16::deserialize_bytes` (function-level post). -/
theorem tls_vec.SecretTlsVecU16.deserialize_bytes_fc {T : Type} (inst : DeserializeBytes T)
    (z : zeroize.Zeroize T) (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU16.deserialize_bytes inst z bytes
    ⦃ ⇓? res => ⌜ (tls_vec.SecretTlsVecU16.deserialize_bytes.post inst z bytes res).holds ⌝ ⦄ :=
  TlsVecGen.fc_of_char _ bytes (tls_vec.SecretTlsVecU16.deserialize_bytes_char inst z hlaw bytes)

/-- `SecretTlsVecU16::deserialize_bytes` does not fail. -/
theorem tls_vec.SecretTlsVecU16.deserialize_bytes_pf {T : Type} (inst : DeserializeBytes T)
    (z : zeroize.Zeroize T) (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU16.deserialize_bytes inst z bytes ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  pf_of_total (tls_vec.SecretTlsVecU16.deserialize_bytes_char inst z hlaw bytes)

/-! #### `SecretTlsVecU32` -/

@[spec] theorem tls_vec.SecretTlsVecU32.push_spec {T : Type} (z : zeroize.Zeroize T) (self : tls_vec.SecretTlsVecU32 T) (x : T)
    (h : self.vec.val.length < Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU32.push z self x ⦃ ⇓ r => ⌜ r.vec.val = self.vec.val ++ [x] ⌝ ⦄ :=
  TlsVecGen.push_spec _ tls_vec.SecretTlsVecU32.mk (fun _ => rfl) self x h

/-- The size of a `SecretTlsVecU32` is the size fold of its elements, starting at the prefix width. -/
theorem tls_vec.SecretTlsVecU32.size_rel {T : Type} (S : Size T) (z : zeroize.Zeroize T) (hl : Size.Lawful T S)
    (self : tls_vec.SecretTlsVecU32 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU32.tls_serialized_length S z self
    ⦃ ⇓ r => ⌜ SizeFoldRel S 4#usize self.vec.val r ⌝ ⦄ :=
  TlsVecGen.serLen_rel S hl (tls_vec.SecretTlsVecU32.as_slice z)
    (fun x => alloc.vec.Vec.Insts.CoreOpsDerefDerefSlice.deref_spec x.vec) _ (fun _ _ _ => rfl) () 4#usize self

/-- `SecretTlsVecU32::tls_serialized_length` does not fail when the element size does not. -/
theorem tls_vec.SecretTlsVecU32.tls_serialized_length_pf {T : Type} (SizeInst : Size T)
    (zeroizeZeroizeInst : zeroize.Zeroize T)
    (SizeInstLawful : Size.Lawful T SizeInst) (self_ : tls_vec.SecretTlsVecU32 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU32.tls_serialized_length SizeInst zeroizeZeroizeInst self_ ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  pf_of_total (tls_vec.SecretTlsVecU32.size_rel SizeInst zeroizeZeroizeInst SizeInstLawful self_)

/-- `SecretTlsVecU32::deserialize_bytes` is the generic one (rfl modulo the message literal). -/
theorem tls_vec.SecretTlsVecU32.deserialize_bytes_eq {T : Type} :
    ∃ (M : Std.Usize) (pieces : Aeneas.Std.Array Std.U8 M), ∀ (inst : DeserializeBytes T) (z : zeroize.Zeroize T),
      tls_vec.SecretTlsVecU32.deserialize_bytes inst z =
      TlsVecGen.deser tls_vec.SecretTlsVecU32.mk U32.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
        core.Usize.Insts.CoreConvertTryFromU32TryFromIntError.try_from
        core.num.error.TryFromIntError.Insts.CoreFmtDebug (tls_vec.SecretTlsVecU32.deserialize_bytes_loop inst z) pieces := by
  apply Exists.intro; apply Exists.intro; intro inst z; funext bytes
  unfold tls_vec.SecretTlsVecU32.deserialize_bytes TlsVecGen.deser
  congr 1; funext v; congr 1; funext r; congr 1; funext cf; cases cf <;> rfl

/-- `SecretTlsVecU32::deserialize_bytes` from the trait contract of `T`: never fails to terminate, and an `Ok`
result accounts for the whole input (`rem.len + size v = bytes.len`). -/
theorem tls_vec.SecretTlsVecU32.deserialize_bytes_char {T : Type} (inst : DeserializeBytes T)
    (z : zeroize.Zeroize T) (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU32.deserialize_bytes inst z bytes
    ⦃ ⇓ r => ⌜ ∀ v rem, r = .Ok (v, rem) → ∃ n,
        tls_vec.SecretTlsVecU32.Insts.Tls_codecSize.tls_serialized_len z inst.SizeInst v = ok n ∧
        rem.val.length + n.val = bytes.val.length ∧ rem.val <:+ bytes.val ⌝ ⦄ := by
  obtain ⟨_, _, h⟩ := tls_vec.SecretTlsVecU32.deserialize_bytes_eq (T := T)
  rw [h]
  exact TlsVecGen.deser_char inst.SizeInst _ _ (fun _ => rfl) _ 4#usize
    (tls_vec.SecretTlsVecU32.size_rel inst.SizeInst z hlaw.SizeInstLawful) _
    (TlsVecGen.prefix_len 4#usize 4 (by simp) U32_deserialize_char) _
    (TlsVecGen.conv_ok core.Usize.Insts.CoreConvertTryFromU32TryFromIntError.try_from_spec) _ _
    (fun N _ hN _ _ len _ hinv => TlsVecGen.loop_char _ _ (tls_vec.SecretTlsVecU32.push_spec z) inst len _ rfl
      hlaw 4#usize N hN _ _ _ hinv) _ bytes

/-- Functional correctness of `SecretTlsVecU32::deserialize_bytes` (function-level post). -/
theorem tls_vec.SecretTlsVecU32.deserialize_bytes_fc {T : Type} (inst : DeserializeBytes T)
    (z : zeroize.Zeroize T) (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU32.deserialize_bytes inst z bytes
    ⦃ ⇓? res => ⌜ (tls_vec.SecretTlsVecU32.deserialize_bytes.post inst z bytes res).holds ⌝ ⦄ :=
  TlsVecGen.fc_of_char _ bytes (tls_vec.SecretTlsVecU32.deserialize_bytes_char inst z hlaw bytes)

/-- `SecretTlsVecU32::deserialize_bytes` does not fail. -/
theorem tls_vec.SecretTlsVecU32.deserialize_bytes_pf {T : Type} (inst : DeserializeBytes T)
    (z : zeroize.Zeroize T) (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU32.deserialize_bytes inst z bytes ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  pf_of_total (tls_vec.SecretTlsVecU32.deserialize_bytes_char inst z hlaw bytes)

/-! #### `TlsVecU24` -/

@[spec] theorem tls_vec.TlsVecU24.push_spec {T : Type} (self : tls_vec.TlsVecU24 T) (x : T)
    (h : self.vec.val.length < Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU24.push self x ⦃ ⇓ r => ⌜ r.vec.val = self.vec.val ++ [x] ⌝ ⦄ :=
  TlsVecGen.push_spec _ tls_vec.TlsVecU24.mk (fun _ => rfl) self x h

/-- The size of a `TlsVecU24` is the size fold of its elements, starting at the prefix width. -/
theorem tls_vec.TlsVecU24.size_rel {T : Type} (S : Size T) (hl : Size.Lawful T S)
    (self : tls_vec.TlsVecU24 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU24.tls_serialized_length S self
    ⦃ ⇓ r => ⌜ SizeFoldRel S 3#usize self.vec.val r ⌝ ⦄ :=
  TlsVecGen.serLen_rel S hl tls_vec.TlsVecU24.as_slice
    (fun x => alloc.vec.Vec.Insts.CoreOpsDerefDerefSlice.deref_spec x.vec) _ (fun _ _ _ => rfl) () 3#usize self

/-- `TlsVecU24::tls_serialized_length` does not fail when the element size does not. -/
theorem tls_vec.TlsVecU24.tls_serialized_length_pf {T : Type} (SizeInst : Size T)
    (SizeInstLawful : Size.Lawful T SizeInst) (self_ : tls_vec.TlsVecU24 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU24.tls_serialized_length SizeInst self_ ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  pf_of_total (tls_vec.TlsVecU24.size_rel SizeInst SizeInstLawful self_)

/-- `TlsVecU24::deserialize_bytes` is the generic one (rfl modulo the message literal). -/
theorem tls_vec.TlsVecU24.deserialize_bytes_eq {T : Type} :
    ∃ (M : Std.Usize) (pieces : Aeneas.Std.Array Std.U8 M), ∀ (inst : DeserializeBytes T),
      tls_vec.TlsVecU24.deserialize_bytes inst =
      TlsVecGen.deser tls_vec.TlsVecU24.mk U24.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
        (core.convert.TryFromTUInfallible.Blanket.try_from
          (core.convert.Into.Blanket Usize.Insts.CoreConvertFromU24))
        core.convert.Infallible.Insts.CoreFmtDebug (tls_vec.TlsVecU24.deserialize_bytes_loop inst) pieces := by
  apply Exists.intro; apply Exists.intro; intro inst; funext bytes
  unfold tls_vec.TlsVecU24.deserialize_bytes TlsVecGen.deser
  congr 1; funext v; congr 1; funext r; congr 1; funext cf; cases cf <;> rfl

/-- `TlsVecU24::deserialize_bytes` from the trait contract of `T`: never fails to terminate, and an `Ok`
result accounts for the whole input (`rem.len + size v = bytes.len`). -/
theorem tls_vec.TlsVecU24.deserialize_bytes_char {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU24.deserialize_bytes inst bytes
    ⦃ ⇓ r => ⌜ ∀ v rem, r = .Ok (v, rem) → ∃ n,
        tls_vec.TlsVecU24.Insts.Tls_codecSize.tls_serialized_len inst.SizeInst v = ok n ∧
        rem.val.length + n.val = bytes.val.length ∧ rem.val <:+ bytes.val ⌝ ⦄ := by
  obtain ⟨_, _, h⟩ := tls_vec.TlsVecU24.deserialize_bytes_eq (T := T)
  rw [h]
  exact TlsVecGen.deser_char inst.SizeInst _ _ (fun _ => rfl) _ 3#usize
    (tls_vec.TlsVecU24.size_rel inst.SizeInst hlaw.SizeInstLawful) _
    (TlsVecGen.prefix_len 3#usize 3 (by simp) U24_deserialize_char) _
    (core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U24_ok) _ _
    (fun N _ hN _ _ len _ hinv => TlsVecGen.loop_char _ _ tls_vec.TlsVecU24.push_spec inst len _ rfl
      hlaw 3#usize N hN _ _ _ hinv) _ bytes

/-- Functional correctness of `TlsVecU24::deserialize_bytes` (function-level post). -/
theorem tls_vec.TlsVecU24.deserialize_bytes_fc {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU24.deserialize_bytes inst bytes
    ⦃ ⇓? res => ⌜ (tls_vec.TlsVecU24.deserialize_bytes.post inst bytes res).holds ⌝ ⦄ :=
  TlsVecGen.fc_of_char _ bytes (tls_vec.TlsVecU24.deserialize_bytes_char inst hlaw bytes)

/-- `TlsVecU24::deserialize_bytes` does not fail. -/
theorem tls_vec.TlsVecU24.deserialize_bytes_pf {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsVecU24.deserialize_bytes inst bytes ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  pf_of_total (tls_vec.TlsVecU24.deserialize_bytes_char inst hlaw bytes)

/-! #### `SecretTlsVecU24` -/

@[spec] theorem tls_vec.SecretTlsVecU24.push_spec {T : Type} (z : zeroize.Zeroize T) (self : tls_vec.SecretTlsVecU24 T) (x : T)
    (h : self.vec.val.length < Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU24.push z self x ⦃ ⇓ r => ⌜ r.vec.val = self.vec.val ++ [x] ⌝ ⦄ :=
  TlsVecGen.push_spec _ tls_vec.SecretTlsVecU24.mk (fun _ => rfl) self x h

/-- The size of a `SecretTlsVecU24` is the size fold of its elements, starting at the prefix width. -/
theorem tls_vec.SecretTlsVecU24.size_rel {T : Type} (S : Size T) (z : zeroize.Zeroize T) (hl : Size.Lawful T S)
    (self : tls_vec.SecretTlsVecU24 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU24.tls_serialized_length S z self
    ⦃ ⇓ r => ⌜ SizeFoldRel S 3#usize self.vec.val r ⌝ ⦄ :=
  TlsVecGen.serLen_rel S hl (tls_vec.SecretTlsVecU24.as_slice z)
    (fun x => alloc.vec.Vec.Insts.CoreOpsDerefDerefSlice.deref_spec x.vec) _ (fun _ _ _ => rfl) () 3#usize self

/-- `SecretTlsVecU24::tls_serialized_length` does not fail when the element size does not. -/
theorem tls_vec.SecretTlsVecU24.tls_serialized_length_pf {T : Type} (SizeInst : Size T)
    (zeroizeZeroizeInst : zeroize.Zeroize T)
    (SizeInstLawful : Size.Lawful T SizeInst) (self_ : tls_vec.SecretTlsVecU24 T) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU24.tls_serialized_length SizeInst zeroizeZeroizeInst self_ ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  pf_of_total (tls_vec.SecretTlsVecU24.size_rel SizeInst zeroizeZeroizeInst SizeInstLawful self_)

/-- `SecretTlsVecU24::deserialize_bytes` is the generic one (rfl modulo the message literal). -/
theorem tls_vec.SecretTlsVecU24.deserialize_bytes_eq {T : Type} :
    ∃ (M : Std.Usize) (pieces : Aeneas.Std.Array Std.U8 M), ∀ (inst : DeserializeBytes T) (z : zeroize.Zeroize T),
      tls_vec.SecretTlsVecU24.deserialize_bytes inst z =
      TlsVecGen.deser tls_vec.SecretTlsVecU24.mk U24.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
        (core.convert.TryFromTUInfallible.Blanket.try_from
          (core.convert.Into.Blanket Usize.Insts.CoreConvertFromU24))
        core.convert.Infallible.Insts.CoreFmtDebug (tls_vec.SecretTlsVecU24.deserialize_bytes_loop inst z) pieces := by
  apply Exists.intro; apply Exists.intro; intro inst z; funext bytes
  unfold tls_vec.SecretTlsVecU24.deserialize_bytes TlsVecGen.deser
  congr 1; funext v; congr 1; funext r; congr 1; funext cf; cases cf <;> rfl

/-- `SecretTlsVecU24::deserialize_bytes` from the trait contract of `T`: never fails to terminate, and an `Ok`
result accounts for the whole input (`rem.len + size v = bytes.len`). -/
theorem tls_vec.SecretTlsVecU24.deserialize_bytes_char {T : Type} (inst : DeserializeBytes T)
    (z : zeroize.Zeroize T) (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU24.deserialize_bytes inst z bytes
    ⦃ ⇓ r => ⌜ ∀ v rem, r = .Ok (v, rem) → ∃ n,
        tls_vec.SecretTlsVecU24.Insts.Tls_codecSize.tls_serialized_len z inst.SizeInst v = ok n ∧
        rem.val.length + n.val = bytes.val.length ∧ rem.val <:+ bytes.val ⌝ ⦄ := by
  obtain ⟨_, _, h⟩ := tls_vec.SecretTlsVecU24.deserialize_bytes_eq (T := T)
  rw [h]
  exact TlsVecGen.deser_char inst.SizeInst _ _ (fun _ => rfl) _ 3#usize
    (tls_vec.SecretTlsVecU24.size_rel inst.SizeInst z hlaw.SizeInstLawful) _
    (TlsVecGen.prefix_len 3#usize 3 (by simp) U24_deserialize_char) _
    (core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U24_ok) _ _
    (fun N _ hN _ _ len _ hinv => TlsVecGen.loop_char _ _ (tls_vec.SecretTlsVecU24.push_spec z) inst len _ rfl
      hlaw 3#usize N hN _ _ _ hinv) _ bytes

/-- Functional correctness of `SecretTlsVecU24::deserialize_bytes` (function-level post). -/
theorem tls_vec.SecretTlsVecU24.deserialize_bytes_fc {T : Type} (inst : DeserializeBytes T)
    (z : zeroize.Zeroize T) (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU24.deserialize_bytes inst z bytes
    ⦃ ⇓? res => ⌜ (tls_vec.SecretTlsVecU24.deserialize_bytes.post inst z bytes res).holds ⌝ ⦄ :=
  TlsVecGen.fc_of_char _ bytes (tls_vec.SecretTlsVecU24.deserialize_bytes_char inst z hlaw bytes)

/-- `SecretTlsVecU24::deserialize_bytes` does not fail. -/
theorem tls_vec.SecretTlsVecU24.deserialize_bytes_pf {T : Type} (inst : DeserializeBytes T)
    (z : zeroize.Zeroize T) (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.SecretTlsVecU24.deserialize_bytes inst z bytes ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  pf_of_total (tls_vec.SecretTlsVecU24.deserialize_bytes_char inst z hlaw bytes)

/-! #### From a characterization of the result to the trait-level post -/

/-- A result `r` meeting `∀ v rem, r = Ok (v, rem) → ∃ n, size v = n ∧ rem.len + n = bytes.len` meets the
trait-level post of `tls_deserialize_bytes`. -/
theorem DeserializeBytes.post_of_char {Self : Type} (S : Size Self) (inst : DeserializeBytes Self)
    (bytes : Slice Std.U8) (r : core.result.Result (Self × Slice Std.U8) Error)
    (h : ∀ v rem, r = .Ok (v, rem) → ∃ n, S.tls_serialized_len v = ok n ∧
      rem.val.length + n.val = bytes.val.length ∧ rem.val <:+ bytes.val) :
    (DeserializeBytes.tls_deserialize_bytes.post S inst bytes r).holds := by
  cases r with
  | Err e => exact DeserializeBytes.post_err S inst bytes e
  | Ok p =>
    obtain ⟨v, rem⟩ := p
    obtain ⟨n, hn, hr, hs⟩ := h v rem rfl
    exact DeserializeBytes.post_ok S inst bytes v rem n hn hr hs

/-- Total characterization of a `tls_deserialize_bytes`-shaped program gives the trait-level post
(as a partial triple). -/
theorem DeserializeBytes.fc_of_char {Self : Type} (S : Size Self) (inst : DeserializeBytes Self)
    (bytes : Slice Std.U8) (m : RustM (core.result.Result (Self × Slice Std.U8) Error))
    (h : ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓ r => ⌜ ∀ v rem, r = .Ok (v, rem) → ∃ n, S.tls_serialized_len v = ok n ∧
      rem.val.length + n.val = bytes.val.length ∧ rem.val <:+ bytes.val ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓? res => ⌜ (DeserializeBytes.tls_deserialize_bytes.post S inst bytes res).holds ⌝ ⦄ := by
  obtain ⟨v, hv, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp h
  rw [hv]
  apply RustM.ok_spec
  exact DeserializeBytes.post_of_char S inst bytes v hP

/-! #### `TlsVecU8`: function and trait-level specs -/

/-- Functional correctness of the trait method of `TlsVecU8` (trait-level post). -/
theorem tls_vec.TlsVecU8.trait_fc {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄
      (tls_vec.TlsVecU8.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes inst) bytes
    ⦃ ⇓? res => ⌜ (DeserializeBytes.tls_deserialize_bytes.post
        (tls_vec.TlsVecU8.Insts.Tls_codecDeserializeBytes inst).SizeInst
        (tls_vec.TlsVecU8.Insts.Tls_codecDeserializeBytes inst) bytes res).holds ⌝ ⦄ :=
  DeserializeBytes.fc_of_char (tls_vec.TlsVecU8.Insts.Tls_codecSize inst.SizeInst)
    (tls_vec.TlsVecU8.Insts.Tls_codecDeserializeBytes inst) bytes _
    (tls_vec.TlsVecU8.deserialize_bytes_char inst hlaw bytes)

/-- The trait method of `TlsVecU8` does not fail. -/
theorem tls_vec.TlsVecU8.trait_pf {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄
      (tls_vec.TlsVecU8.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes inst) bytes
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  tls_vec.TlsVecU8.deserialize_bytes_pf inst hlaw bytes

/-! #### `TlsVecU16`: function and trait-level specs -/

/-- Functional correctness of the trait method of `TlsVecU16` (trait-level post). -/
theorem tls_vec.TlsVecU16.trait_fc {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄
      (tls_vec.TlsVecU16.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes inst) bytes
    ⦃ ⇓? res => ⌜ (DeserializeBytes.tls_deserialize_bytes.post
        (tls_vec.TlsVecU16.Insts.Tls_codecDeserializeBytes inst).SizeInst
        (tls_vec.TlsVecU16.Insts.Tls_codecDeserializeBytes inst) bytes res).holds ⌝ ⦄ :=
  DeserializeBytes.fc_of_char (tls_vec.TlsVecU16.Insts.Tls_codecSize inst.SizeInst)
    (tls_vec.TlsVecU16.Insts.Tls_codecDeserializeBytes inst) bytes _
    (tls_vec.TlsVecU16.deserialize_bytes_char inst hlaw bytes)

/-- The trait method of `TlsVecU16` does not fail. -/
theorem tls_vec.TlsVecU16.trait_pf {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄
      (tls_vec.TlsVecU16.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes inst) bytes
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  tls_vec.TlsVecU16.deserialize_bytes_pf inst hlaw bytes

/-! #### `TlsVecU24`: function and trait-level specs -/

/-- Functional correctness of the trait method of `TlsVecU24` (trait-level post). -/
theorem tls_vec.TlsVecU24.trait_fc {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄
      (tls_vec.TlsVecU24.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes inst) bytes
    ⦃ ⇓? res => ⌜ (DeserializeBytes.tls_deserialize_bytes.post
        (tls_vec.TlsVecU24.Insts.Tls_codecDeserializeBytes inst).SizeInst
        (tls_vec.TlsVecU24.Insts.Tls_codecDeserializeBytes inst) bytes res).holds ⌝ ⦄ :=
  DeserializeBytes.fc_of_char (tls_vec.TlsVecU24.Insts.Tls_codecSize inst.SizeInst)
    (tls_vec.TlsVecU24.Insts.Tls_codecDeserializeBytes inst) bytes _
    (tls_vec.TlsVecU24.deserialize_bytes_char inst hlaw bytes)

/-- The trait method of `TlsVecU24` does not fail. -/
theorem tls_vec.TlsVecU24.trait_pf {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄
      (tls_vec.TlsVecU24.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes inst) bytes
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  tls_vec.TlsVecU24.deserialize_bytes_pf inst hlaw bytes

/-! #### `TlsVecU32`: function and trait-level specs -/

/-- Functional correctness of the trait method of `TlsVecU32` (trait-level post). -/
theorem tls_vec.TlsVecU32.trait_fc {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄
      (tls_vec.TlsVecU32.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes inst) bytes
    ⦃ ⇓? res => ⌜ (DeserializeBytes.tls_deserialize_bytes.post
        (tls_vec.TlsVecU32.Insts.Tls_codecDeserializeBytes inst).SizeInst
        (tls_vec.TlsVecU32.Insts.Tls_codecDeserializeBytes inst) bytes res).holds ⌝ ⦄ :=
  DeserializeBytes.fc_of_char (tls_vec.TlsVecU32.Insts.Tls_codecSize inst.SizeInst)
    (tls_vec.TlsVecU32.Insts.Tls_codecDeserializeBytes inst) bytes _
    (tls_vec.TlsVecU32.deserialize_bytes_char inst hlaw bytes)

/-- The trait method of `TlsVecU32` does not fail. -/
theorem tls_vec.TlsVecU32.trait_pf {T : Type} (inst : DeserializeBytes T)
    (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄
      (tls_vec.TlsVecU32.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes inst) bytes
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  tls_vec.TlsVecU32.deserialize_bytes_pf inst hlaw bytes

/-! #### `SecretTlsVecU8`: function and trait-level specs -/

/-- Functional correctness of the trait method of `SecretTlsVecU8` (trait-level post). -/
theorem tls_vec.SecretTlsVecU8.trait_fc {T : Type} (inst : DeserializeBytes T)
    (z : zeroize.Zeroize T) (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄
      (tls_vec.SecretTlsVecU8.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes z inst) bytes
    ⦃ ⇓? res => ⌜ (DeserializeBytes.tls_deserialize_bytes.post
        (tls_vec.SecretTlsVecU8.Insts.Tls_codecDeserializeBytes z inst).SizeInst
        (tls_vec.SecretTlsVecU8.Insts.Tls_codecDeserializeBytes z inst) bytes res).holds ⌝ ⦄ :=
  DeserializeBytes.fc_of_char (tls_vec.SecretTlsVecU8.Insts.Tls_codecSize z inst.SizeInst)
    (tls_vec.SecretTlsVecU8.Insts.Tls_codecDeserializeBytes z inst) bytes _
    (tls_vec.SecretTlsVecU8.deserialize_bytes_char inst z hlaw bytes)

/-- The trait method of `SecretTlsVecU8` does not fail. -/
theorem tls_vec.SecretTlsVecU8.trait_pf {T : Type} (inst : DeserializeBytes T)
    (z : zeroize.Zeroize T) (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄
      (tls_vec.SecretTlsVecU8.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes z inst) bytes
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  tls_vec.SecretTlsVecU8.deserialize_bytes_pf inst z hlaw bytes

/-! #### `SecretTlsVecU16`: function and trait-level specs -/

/-- Functional correctness of the trait method of `SecretTlsVecU16` (trait-level post). -/
theorem tls_vec.SecretTlsVecU16.trait_fc {T : Type} (inst : DeserializeBytes T)
    (z : zeroize.Zeroize T) (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄
      (tls_vec.SecretTlsVecU16.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes z inst) bytes
    ⦃ ⇓? res => ⌜ (DeserializeBytes.tls_deserialize_bytes.post
        (tls_vec.SecretTlsVecU16.Insts.Tls_codecDeserializeBytes z inst).SizeInst
        (tls_vec.SecretTlsVecU16.Insts.Tls_codecDeserializeBytes z inst) bytes res).holds ⌝ ⦄ :=
  DeserializeBytes.fc_of_char (tls_vec.SecretTlsVecU16.Insts.Tls_codecSize z inst.SizeInst)
    (tls_vec.SecretTlsVecU16.Insts.Tls_codecDeserializeBytes z inst) bytes _
    (tls_vec.SecretTlsVecU16.deserialize_bytes_char inst z hlaw bytes)

/-- The trait method of `SecretTlsVecU16` does not fail. -/
theorem tls_vec.SecretTlsVecU16.trait_pf {T : Type} (inst : DeserializeBytes T)
    (z : zeroize.Zeroize T) (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄
      (tls_vec.SecretTlsVecU16.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes z inst) bytes
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  tls_vec.SecretTlsVecU16.deserialize_bytes_pf inst z hlaw bytes

/-! #### `SecretTlsVecU24`: function and trait-level specs -/

/-- Functional correctness of the trait method of `SecretTlsVecU24` (trait-level post). -/
theorem tls_vec.SecretTlsVecU24.trait_fc {T : Type} (inst : DeserializeBytes T)
    (z : zeroize.Zeroize T) (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄
      (tls_vec.SecretTlsVecU24.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes z inst) bytes
    ⦃ ⇓? res => ⌜ (DeserializeBytes.tls_deserialize_bytes.post
        (tls_vec.SecretTlsVecU24.Insts.Tls_codecDeserializeBytes z inst).SizeInst
        (tls_vec.SecretTlsVecU24.Insts.Tls_codecDeserializeBytes z inst) bytes res).holds ⌝ ⦄ :=
  DeserializeBytes.fc_of_char (tls_vec.SecretTlsVecU24.Insts.Tls_codecSize z inst.SizeInst)
    (tls_vec.SecretTlsVecU24.Insts.Tls_codecDeserializeBytes z inst) bytes _
    (tls_vec.SecretTlsVecU24.deserialize_bytes_char inst z hlaw bytes)

/-- The trait method of `SecretTlsVecU24` does not fail. -/
theorem tls_vec.SecretTlsVecU24.trait_pf {T : Type} (inst : DeserializeBytes T)
    (z : zeroize.Zeroize T) (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄
      (tls_vec.SecretTlsVecU24.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes z inst) bytes
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  tls_vec.SecretTlsVecU24.deserialize_bytes_pf inst z hlaw bytes

/-! #### `SecretTlsVecU32`: function and trait-level specs -/

/-- Functional correctness of the trait method of `SecretTlsVecU32` (trait-level post). -/
theorem tls_vec.SecretTlsVecU32.trait_fc {T : Type} (inst : DeserializeBytes T)
    (z : zeroize.Zeroize T) (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄
      (tls_vec.SecretTlsVecU32.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes z inst) bytes
    ⦃ ⇓? res => ⌜ (DeserializeBytes.tls_deserialize_bytes.post
        (tls_vec.SecretTlsVecU32.Insts.Tls_codecDeserializeBytes z inst).SizeInst
        (tls_vec.SecretTlsVecU32.Insts.Tls_codecDeserializeBytes z inst) bytes res).holds ⌝ ⦄ :=
  DeserializeBytes.fc_of_char (tls_vec.SecretTlsVecU32.Insts.Tls_codecSize z inst.SizeInst)
    (tls_vec.SecretTlsVecU32.Insts.Tls_codecDeserializeBytes z inst) bytes _
    (tls_vec.SecretTlsVecU32.deserialize_bytes_char inst z hlaw bytes)

/-- The trait method of `SecretTlsVecU32` does not fail. -/
theorem tls_vec.SecretTlsVecU32.trait_pf {T : Type} (inst : DeserializeBytes T)
    (z : zeroize.Zeroize T) (hlaw : DeserializeBytes.Lawful T inst) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄
      (tls_vec.SecretTlsVecU32.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes z inst) bytes
    ⦃ ⇓ _ => ⌜ True ⌝ ⦄ :=
  tls_vec.SecretTlsVecU32.deserialize_bytes_pf inst z hlaw bytes

end tls_codec
