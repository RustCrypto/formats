/- Per-width instances of the generic `TlsVecU*` / `SecretTlsVecU*` / `TlsByteVecU*` lemmas (each a
link by `rfl` and a one-line instantiation).

Obligations: none directly; the `std`-path halves (`Serialize` / `Deserialize` `Lawful` fields,
lemma traits) of `PanicFreedom.lean` / `FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): ASSUMED `size_of`, `size_of_Usize`, `numBits_eq_64`;
4 signature-only stubs (`core.convert.Infallible.Insts.CoreFmtDebug.fmt`,
`core.io.error.Error.Insts.CoreFmtDebug.fmt`,
`core.num.error.TryFromIntError.Insts.CoreFmtDebug.fmt`, `Error.Insts.CoreFmtDebug.fmt`);
`native_decide` (1). -/
import TlsCodec.Verification.Std.TlsByteVec
import TlsCodec.Verification.Std.Misc
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! ### Deserializers -/

theorem tls_vec.TlsVecU8.body_eq {T : Type} : ∃ msg, ∀ (DI : Deserialize T) (R : Type)
    (RI : alloc.io.read.Read R) back result t i i1,
    tls_vec.TlsVecU8.deserialize_loop.body DI RI back result t i i1 =
      TlsVecStd.body tls_vec.TlsVecU8.push msg DI RI back result t i i1 := by
  tlsvec_body_eq tls_vec.TlsVecU8.deserialize_loop.body

theorem tls_vec.TlsVecU8.deSpec {T : Type} {DI : Deserialize T} (hL : Deserialize.Lawful T DI) :
    DeSpec (tls_vec.TlsVecU8.Insts.Tls_codecDeserialize DI) := by
  obtain ⟨msg, hb⟩ := tls_vec.TlsVecU8.body_eq (T := T)
  refine TlsVecStd.deSpec (TlsVecStd.de_runs hL
    (fun w x => TlsVecStd.pre_triple (tls_vec.TlsVecU8.push_spec w x)) tls_vec.TlsVecU8.mk
    (fun _ => rfl) U8.Insts.Tls_codecDeserialize U8.de_runs 1#usize (fun _ => rfl) _
    (TlsVecGen.conv_ok core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U8_spec) core.convert.Infallible.Insts.CoreFmtDebug msg _
    (fun R RI r => ?_) (fun x => tls_vec.TlsVecU8.size_rel _ hL.SizeInstLawful x))
  tlsvec_de_eq tls_vec.TlsVecU8.Insts.Tls_codecDeserialize tls_vec.TlsVecU8.Insts.Tls_codecDeserialize.tls_deserialize
    tls_vec.TlsVecU8.deserialize tls_vec.TlsVecU8.deserialize_loop (hb DI R RI)

theorem tls_vec.SecretTlsVecU8.body_eq {T : Type} : ∃ msg, ∀ (DI : Deserialize T) (z : zeroize.Zeroize T) (R : Type)
    (RI : alloc.io.read.Read R) back result t i i1,
    tls_vec.SecretTlsVecU8.deserialize_loop.body DI z RI back result t i i1 =
      TlsVecStd.body (tls_vec.SecretTlsVecU8.push z) msg DI RI back result t i i1 := by
  tlsvec_body_eq tls_vec.SecretTlsVecU8.deserialize_loop.body

theorem tls_vec.SecretTlsVecU8.deSpec {T : Type} {DI : Deserialize T} (z : zeroize.Zeroize T) (hL : Deserialize.Lawful T DI) :
    DeSpec (tls_vec.SecretTlsVecU8.Insts.Tls_codecDeserialize z DI) := by
  obtain ⟨msg, hb⟩ := tls_vec.SecretTlsVecU8.body_eq (T := T)
  refine TlsVecStd.deSpec (TlsVecStd.de_runs hL
    (fun w x => TlsVecStd.pre_triple (tls_vec.SecretTlsVecU8.push_spec z w x)) tls_vec.SecretTlsVecU8.mk
    (fun _ => rfl) U8.Insts.Tls_codecDeserialize U8.de_runs 1#usize (fun _ => rfl) _
    (TlsVecGen.conv_ok core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U8_spec) core.convert.Infallible.Insts.CoreFmtDebug msg _
    (fun R RI r => ?_) (fun x => tls_vec.SecretTlsVecU8.size_rel _ z hL.SizeInstLawful x))
  tlsvec_de_eq tls_vec.SecretTlsVecU8.Insts.Tls_codecDeserialize tls_vec.SecretTlsVecU8.Insts.Tls_codecDeserialize.tls_deserialize
    tls_vec.SecretTlsVecU8.deserialize tls_vec.SecretTlsVecU8.deserialize_loop (hb DI z R RI)

theorem tls_vec.TlsVecU16.body_eq {T : Type} : ∃ msg, ∀ (DI : Deserialize T) (R : Type)
    (RI : alloc.io.read.Read R) back result t i i1,
    tls_vec.TlsVecU16.deserialize_loop.body DI RI back result t i i1 =
      TlsVecStd.body tls_vec.TlsVecU16.push msg DI RI back result t i i1 := by
  tlsvec_body_eq tls_vec.TlsVecU16.deserialize_loop.body

theorem tls_vec.TlsVecU16.deSpec {T : Type} {DI : Deserialize T} (hL : Deserialize.Lawful T DI) :
    DeSpec (tls_vec.TlsVecU16.Insts.Tls_codecDeserialize DI) := by
  obtain ⟨msg, hb⟩ := tls_vec.TlsVecU16.body_eq (T := T)
  refine TlsVecStd.deSpec (TlsVecStd.de_runs hL
    (fun w x => TlsVecStd.pre_triple (tls_vec.TlsVecU16.push_spec w x)) tls_vec.TlsVecU16.mk
    (fun _ => rfl) U16.Insts.Tls_codecDeserialize U16.de_runs 2#usize (fun _ => rfl) _
    (TlsVecGen.conv_ok core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U16_spec) core.convert.Infallible.Insts.CoreFmtDebug msg _
    (fun R RI r => ?_) (fun x => tls_vec.TlsVecU16.size_rel _ hL.SizeInstLawful x))
  tlsvec_de_eq tls_vec.TlsVecU16.Insts.Tls_codecDeserialize tls_vec.TlsVecU16.Insts.Tls_codecDeserialize.tls_deserialize
    tls_vec.TlsVecU16.deserialize tls_vec.TlsVecU16.deserialize_loop (hb DI R RI)

theorem tls_vec.SecretTlsVecU16.body_eq {T : Type} : ∃ msg, ∀ (DI : Deserialize T) (z : zeroize.Zeroize T) (R : Type)
    (RI : alloc.io.read.Read R) back result t i i1,
    tls_vec.SecretTlsVecU16.deserialize_loop.body DI z RI back result t i i1 =
      TlsVecStd.body (tls_vec.SecretTlsVecU16.push z) msg DI RI back result t i i1 := by
  tlsvec_body_eq tls_vec.SecretTlsVecU16.deserialize_loop.body

theorem tls_vec.SecretTlsVecU16.deSpec {T : Type} {DI : Deserialize T} (z : zeroize.Zeroize T) (hL : Deserialize.Lawful T DI) :
    DeSpec (tls_vec.SecretTlsVecU16.Insts.Tls_codecDeserialize z DI) := by
  obtain ⟨msg, hb⟩ := tls_vec.SecretTlsVecU16.body_eq (T := T)
  refine TlsVecStd.deSpec (TlsVecStd.de_runs hL
    (fun w x => TlsVecStd.pre_triple (tls_vec.SecretTlsVecU16.push_spec z w x)) tls_vec.SecretTlsVecU16.mk
    (fun _ => rfl) U16.Insts.Tls_codecDeserialize U16.de_runs 2#usize (fun _ => rfl) _
    (TlsVecGen.conv_ok core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U16_spec) core.convert.Infallible.Insts.CoreFmtDebug msg _
    (fun R RI r => ?_) (fun x => tls_vec.SecretTlsVecU16.size_rel _ z hL.SizeInstLawful x))
  tlsvec_de_eq tls_vec.SecretTlsVecU16.Insts.Tls_codecDeserialize tls_vec.SecretTlsVecU16.Insts.Tls_codecDeserialize.tls_deserialize
    tls_vec.SecretTlsVecU16.deserialize tls_vec.SecretTlsVecU16.deserialize_loop (hb DI z R RI)

theorem tls_vec.TlsVecU24.body_eq {T : Type} : ∃ msg, ∀ (DI : Deserialize T) (R : Type)
    (RI : alloc.io.read.Read R) back result t i i1,
    tls_vec.TlsVecU24.deserialize_loop.body DI RI back result t i i1 =
      TlsVecStd.body tls_vec.TlsVecU24.push msg DI RI back result t i i1 := by
  tlsvec_body_eq tls_vec.TlsVecU24.deserialize_loop.body

theorem tls_vec.TlsVecU24.deSpec {T : Type} {DI : Deserialize T} (hL : Deserialize.Lawful T DI) :
    DeSpec (tls_vec.TlsVecU24.Insts.Tls_codecDeserialize DI) := by
  obtain ⟨msg, hb⟩ := tls_vec.TlsVecU24.body_eq (T := T)
  refine TlsVecStd.deSpec (TlsVecStd.de_runs hL
    (fun w x => TlsVecStd.pre_triple (tls_vec.TlsVecU24.push_spec w x)) tls_vec.TlsVecU24.mk
    (fun _ => rfl) U24.Insts.Tls_codecDeserialize (DeRuns_of_fixed _ _ _ (fun _ => rfl) U24.fixed_runs) 3#usize (fun _ => rfl) _
    core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U24_ok core.convert.Infallible.Insts.CoreFmtDebug msg _
    (fun R RI r => ?_) (fun x => tls_vec.TlsVecU24.size_rel _ hL.SizeInstLawful x))
  tlsvec_de_eq tls_vec.TlsVecU24.Insts.Tls_codecDeserialize tls_vec.TlsVecU24.Insts.Tls_codecDeserialize.tls_deserialize
    tls_vec.TlsVecU24.deserialize tls_vec.TlsVecU24.deserialize_loop (hb DI R RI)

theorem tls_vec.SecretTlsVecU24.body_eq {T : Type} : ∃ msg, ∀ (DI : Deserialize T) (z : zeroize.Zeroize T) (R : Type)
    (RI : alloc.io.read.Read R) back result t i i1,
    tls_vec.SecretTlsVecU24.deserialize_loop.body DI z RI back result t i i1 =
      TlsVecStd.body (tls_vec.SecretTlsVecU24.push z) msg DI RI back result t i i1 := by
  tlsvec_body_eq tls_vec.SecretTlsVecU24.deserialize_loop.body

theorem tls_vec.SecretTlsVecU24.deSpec {T : Type} {DI : Deserialize T} (z : zeroize.Zeroize T) (hL : Deserialize.Lawful T DI) :
    DeSpec (tls_vec.SecretTlsVecU24.Insts.Tls_codecDeserialize z DI) := by
  obtain ⟨msg, hb⟩ := tls_vec.SecretTlsVecU24.body_eq (T := T)
  refine TlsVecStd.deSpec (TlsVecStd.de_runs hL
    (fun w x => TlsVecStd.pre_triple (tls_vec.SecretTlsVecU24.push_spec z w x)) tls_vec.SecretTlsVecU24.mk
    (fun _ => rfl) U24.Insts.Tls_codecDeserialize (DeRuns_of_fixed _ _ _ (fun _ => rfl) U24.fixed_runs) 3#usize (fun _ => rfl) _
    core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U24_ok core.convert.Infallible.Insts.CoreFmtDebug msg _
    (fun R RI r => ?_) (fun x => tls_vec.SecretTlsVecU24.size_rel _ z hL.SizeInstLawful x))
  tlsvec_de_eq tls_vec.SecretTlsVecU24.Insts.Tls_codecDeserialize tls_vec.SecretTlsVecU24.Insts.Tls_codecDeserialize.tls_deserialize
    tls_vec.SecretTlsVecU24.deserialize tls_vec.SecretTlsVecU24.deserialize_loop (hb DI z R RI)

theorem tls_vec.TlsVecU32.body_eq {T : Type} : ∃ msg, ∀ (DI : Deserialize T) (R : Type)
    (RI : alloc.io.read.Read R) back result t i i1,
    tls_vec.TlsVecU32.deserialize_loop.body DI RI back result t i i1 =
      TlsVecStd.body tls_vec.TlsVecU32.push msg DI RI back result t i i1 := by
  tlsvec_body_eq tls_vec.TlsVecU32.deserialize_loop.body

theorem tls_vec.TlsVecU32.deSpec {T : Type} {DI : Deserialize T} (hL : Deserialize.Lawful T DI) :
    DeSpec (tls_vec.TlsVecU32.Insts.Tls_codecDeserialize DI) := by
  obtain ⟨msg, hb⟩ := tls_vec.TlsVecU32.body_eq (T := T)
  refine TlsVecStd.deSpec (TlsVecStd.de_runs hL
    (fun w x => TlsVecStd.pre_triple (tls_vec.TlsVecU32.push_spec w x)) tls_vec.TlsVecU32.mk
    (fun _ => rfl) U32.Insts.Tls_codecDeserialize (DeRuns_of_fixed _ _ _ (fun _ => rfl) U32.fixed_runs) 4#usize (fun _ => rfl) _
    (TlsVecGen.conv_ok core.Usize.Insts.CoreConvertTryFromU32TryFromIntError.try_from_spec) core.num.error.TryFromIntError.Insts.CoreFmtDebug msg _
    (fun R RI r => ?_) (fun x => tls_vec.TlsVecU32.size_rel _ hL.SizeInstLawful x))
  tlsvec_de_eq tls_vec.TlsVecU32.Insts.Tls_codecDeserialize tls_vec.TlsVecU32.Insts.Tls_codecDeserialize.tls_deserialize
    tls_vec.TlsVecU32.deserialize tls_vec.TlsVecU32.deserialize_loop (hb DI R RI)

theorem tls_vec.SecretTlsVecU32.body_eq {T : Type} : ∃ msg, ∀ (DI : Deserialize T) (z : zeroize.Zeroize T) (R : Type)
    (RI : alloc.io.read.Read R) back result t i i1,
    tls_vec.SecretTlsVecU32.deserialize_loop.body DI z RI back result t i i1 =
      TlsVecStd.body (tls_vec.SecretTlsVecU32.push z) msg DI RI back result t i i1 := by
  tlsvec_body_eq tls_vec.SecretTlsVecU32.deserialize_loop.body

theorem tls_vec.SecretTlsVecU32.deSpec {T : Type} {DI : Deserialize T} (z : zeroize.Zeroize T) (hL : Deserialize.Lawful T DI) :
    DeSpec (tls_vec.SecretTlsVecU32.Insts.Tls_codecDeserialize z DI) := by
  obtain ⟨msg, hb⟩ := tls_vec.SecretTlsVecU32.body_eq (T := T)
  refine TlsVecStd.deSpec (TlsVecStd.de_runs hL
    (fun w x => TlsVecStd.pre_triple (tls_vec.SecretTlsVecU32.push_spec z w x)) tls_vec.SecretTlsVecU32.mk
    (fun _ => rfl) U32.Insts.Tls_codecDeserialize (DeRuns_of_fixed _ _ _ (fun _ => rfl) U32.fixed_runs) 4#usize (fun _ => rfl) _
    (TlsVecGen.conv_ok core.Usize.Insts.CoreConvertTryFromU32TryFromIntError.try_from_spec) core.num.error.TryFromIntError.Insts.CoreFmtDebug msg _
    (fun R RI r => ?_) (fun x => tls_vec.SecretTlsVecU32.size_rel _ z hL.SizeInstLawful x))
  tlsvec_de_eq tls_vec.SecretTlsVecU32.Insts.Tls_codecDeserialize tls_vec.SecretTlsVecU32.Insts.Tls_codecDeserialize.tls_deserialize
    tls_vec.SecretTlsVecU32.deserialize tls_vec.SecretTlsVecU32.deserialize_loop (hb DI z R RI)

/-! ### Serializers: the width pieces -/

theorem max_len_U8_spec : ⦃ ⌜ True ⌝ ⦄ tls_codec.HandTranslated.max_len_U8 ⦃ ⇓ r => ⌜ r.val = 255 ⌝ ⦄ := by
  unfold tls_codec.HandTranslated.max_len_U8
  mvcgen [core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U8_spec,
    core.result.Result.unwrap_ok_spec]
  all_goals (intro h; subst_vars; first | exact ⟨_, rfl⟩ | (cases h; simp [core.num.U8.MAX, U8.rMax]))

theorem max_len_U16_spec :
    ⦃ ⌜ True ⌝ ⦄ tls_codec.HandTranslated.max_len_U16 ⦃ ⇓ r => ⌜ r.val = 65535 ⌝ ⦄ := by
  unfold tls_codec.HandTranslated.max_len_U16
  mvcgen [core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U16_spec,
    core.result.Result.unwrap_ok_spec]
  all_goals (intro h; subst_vars; first | exact ⟨_, rfl⟩ | (cases h; simp [core.num.U16.MAX, U16.rMax]))

theorem max_len_U32_spec :
    ⦃ ⌜ True ⌝ ⦄ tls_codec.HandTranslated.max_len_U32 ⦃ ⇓ r => ⌜ r.val = 4294967295 ⌝ ⦄ := by
  unfold tls_codec.HandTranslated.max_len_U32
  mvcgen [core.Usize.Insts.CoreConvertTryFromU32TryFromIntError.try_from_spec,
    core.result.Result.unwrap_ok_spec]
  all_goals (intro h; subst_vars; first | exact ⟨_, rfl⟩ | (cases h; simp [core.num.U32.MAX, U32.rMax]))

theorem max_len_U24_spec :
    ⦃ ⌜ True ⌝ ⦄ tls_codec.HandTranslated.max_len_U24 ⦃ ⇓ r => ⌜ r.val = 16777215 ⌝ ⦄ := by
  unfold tls_codec.HandTranslated.max_len_U24
  simp only [Copied.Usize.Insts.CoreConvertFromU24_eq, Copied.U24.MAX_eq]
  mvcgen [core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U24_content,
    core.result.Result.unwrap_ok_spec]
  · rename_i hy _
    intro h
    obtain ⟨y, rfl, hv⟩ := hy
    cases h
    simpa using hv 255#u8 255#u8 255#u8 U24.MAX_val
  · rintro ⟨y, h, -⟩; exact ⟨y, h⟩

theorem prefix_U8 (n : Std.Usize) (h : n.val ≤ 255) : ∃ p pre,
    core.U8.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from n = ok (.Ok p) ∧
    SerRuns U8.Insts.Tls_codecSerialize p 1#usize (some pre) ∧ pre.length = (1#usize).val := by
  obtain ⟨r, hr, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (core.U8.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from_char n)
  obtain ⟨y, rfl, -⟩ := hP.1 h
  exact ⟨y, _, hr, U8.ser_runs y, rfl⟩

theorem prefix_U16 (n : Std.Usize) (h : n.val ≤ 65535) : ∃ p pre,
    core.U16.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from n = ok (.Ok p) ∧
    SerRuns U16.Insts.Tls_codecSerialize p 2#usize (some pre) ∧ pre.length = (2#usize).val := by
  obtain ⟨r, hr, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (core.U16.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from_char n)
  obtain ⟨y, rfl, -⟩ := hP.1 h
  exact ⟨y, _, hr, U16.ser_runs y, by simp⟩

theorem prefix_U32 (n : Std.Usize) (h : n.val ≤ 4294967295) : ∃ p pre,
    core.U32.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from n = ok (.Ok p) ∧
    SerRuns U32.Insts.Tls_codecSerialize p 4#usize (some pre) ∧ pre.length = (4#usize).val := by
  obtain ⟨r, hr, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (core.U32.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from_char n)
  obtain ⟨y, rfl, -⟩ := hP.1 h
  exact ⟨y, _, hr, U32.ser_runs y, by simp⟩

theorem prefix_U24 (n : Std.Usize) (h : n.val ≤ 16777215) : ∃ p pre,
    U24.Insts.CoreConvertTryFromUsizeU24OverflowError.try_from n = ok (.Ok p) ∧
    SerRuns U24.Insts.Tls_codecSerialize p 3#usize (some pre) ∧ pre.length = (3#usize).val := by
  obtain ⟨r, hr, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (U24.Insts.CoreConvertTryFromUsizeU24OverflowError.try_from_char n)
  obtain ⟨y, _, _, _, rfl, -⟩ := hP.1 h
  exact ⟨y, _, hr, U24.ser_runs y, by simp⟩

/-! ### Serializers (`T`, and `&T` which serializes as `T`) -/

theorem tls_vec.TlsVecU8.serSpec {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsVecU8 T) : SerSpec (tls_vec.TlsVecU8.Insts.Tls_codecSerialize SI) x :=
  TlsVecStd.serSpec hL _ x x.vec 1#usize 255 (by scalar_tac) _ max_len_U8_spec _ rfl _ _ _ prefix_U8
    _ rfl _ (fun a => by simp [tls_vec.TlsVecU8.assert_written_bytes]) (fun _ _ _ => rfl)
    (tls_vec.TlsVecU8.size_rel _ hL.SizeInstLawful x)

theorem tls_vec.TlsVecU8.serDetached {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsVecU8 T) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default (tls_vec.TlsVecU8.Insts.Tls_codecSerialize SI) x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post (tls_vec.TlsVecU8.Insts.Tls_codecSerialize SI).SizeInst
      (tls_vec.TlsVecU8.Insts.Tls_codecSerialize SI) x r).holds ⌝ ⦄ :=
  TlsVecStd.detached_of (tls_vec.TlsVecU8.serSpec hL x)
    (tls_vec.TlsVecU8.size_rel _ hL.SizeInstLawful x)

theorem Shared0TlsVecU8.serSpec {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsVecU8 T) : SerSpec (Shared0TlsVecU8.Insts.Tls_codecSerialize SI) x :=
  TlsVecStd.serSpec hL _ x x.vec 1#usize 255 (by scalar_tac) _ max_len_U8_spec _ rfl _ _ _ prefix_U8
    _ rfl _ (fun a => by simp [tls_vec.TlsVecU8.assert_written_bytes]) (fun _ _ _ => rfl)
    (tls_vec.TlsVecU8.size_rel _ hL.SizeInstLawful x)

theorem Shared0TlsVecU8.serDetached {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsVecU8 T) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default (Shared0TlsVecU8.Insts.Tls_codecSerialize SI) x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post (Shared0TlsVecU8.Insts.Tls_codecSerialize SI).SizeInst
      (Shared0TlsVecU8.Insts.Tls_codecSerialize SI) x r).holds ⌝ ⦄ :=
  TlsVecStd.detached_of (Shared0TlsVecU8.serSpec hL x)
    (tls_vec.TlsVecU8.size_rel _ hL.SizeInstLawful x)

theorem tls_vec.SecretTlsVecU8.serSpec {T : Type} {SI : Serialize T} (z : zeroize.Zeroize T) (hL : Serialize.Lawful T SI)
    (x : tls_vec.SecretTlsVecU8 T) : SerSpec (tls_vec.SecretTlsVecU8.Insts.Tls_codecSerialize z SI) x :=
  TlsVecStd.serSpec hL _ x x.vec 1#usize 255 (by scalar_tac) _ max_len_U8_spec _ rfl _ _ _ prefix_U8
    _ rfl _ (fun a => by simp [tls_vec.SecretTlsVecU8.assert_written_bytes]) (fun _ _ _ => rfl)
    (tls_vec.SecretTlsVecU8.size_rel _ z hL.SizeInstLawful x)

theorem tls_vec.SecretTlsVecU8.serDetached {T : Type} {SI : Serialize T} (z : zeroize.Zeroize T) (hL : Serialize.Lawful T SI)
    (x : tls_vec.SecretTlsVecU8 T) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default (tls_vec.SecretTlsVecU8.Insts.Tls_codecSerialize z SI) x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post (tls_vec.SecretTlsVecU8.Insts.Tls_codecSerialize z SI).SizeInst
      (tls_vec.SecretTlsVecU8.Insts.Tls_codecSerialize z SI) x r).holds ⌝ ⦄ :=
  TlsVecStd.detached_of (tls_vec.SecretTlsVecU8.serSpec z hL x)
    (tls_vec.SecretTlsVecU8.size_rel _ z hL.SizeInstLawful x)

theorem Shared0SecretTlsVecU8.serSpec {T : Type} {SI : Serialize T} (z : zeroize.Zeroize T) (hL : Serialize.Lawful T SI)
    (x : tls_vec.SecretTlsVecU8 T) : SerSpec (Shared0SecretTlsVecU8.Insts.Tls_codecSerialize z SI) x :=
  TlsVecStd.serSpec hL _ x x.vec 1#usize 255 (by scalar_tac) _ max_len_U8_spec _ rfl _ _ _ prefix_U8
    _ rfl _ (fun a => by simp [tls_vec.SecretTlsVecU8.assert_written_bytes]) (fun _ _ _ => rfl)
    (tls_vec.SecretTlsVecU8.size_rel _ z hL.SizeInstLawful x)

theorem Shared0SecretTlsVecU8.serDetached {T : Type} {SI : Serialize T} (z : zeroize.Zeroize T) (hL : Serialize.Lawful T SI)
    (x : tls_vec.SecretTlsVecU8 T) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default (Shared0SecretTlsVecU8.Insts.Tls_codecSerialize z SI) x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post (Shared0SecretTlsVecU8.Insts.Tls_codecSerialize z SI).SizeInst
      (Shared0SecretTlsVecU8.Insts.Tls_codecSerialize z SI) x r).holds ⌝ ⦄ :=
  TlsVecStd.detached_of (Shared0SecretTlsVecU8.serSpec z hL x)
    (tls_vec.SecretTlsVecU8.size_rel _ z hL.SizeInstLawful x)

theorem tls_vec.TlsSliceU8.serSpec {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsSliceU8 T) : SerSpec (tls_vec.TlsSliceU8.Insts.Tls_codecSerialize SI) x :=
  TlsVecStd.serSpec hL _ x x 1#usize 255 (by scalar_tac) _ max_len_U8_spec _ rfl _ _ _ prefix_U8
    _ rfl _ (fun a => by simp [tls_vec.TlsSliceU8.assert_written_bytes]) (fun _ _ _ => rfl)
    (TlsVecGen.serLen_rel _ hL.SizeInstLawful tls_vec.TlsSliceU8.as_slice TlsVecGen.ok_view _
      (fun _ _ _ => rfl) () 1#usize x)

theorem tls_vec.TlsSliceU8.serDetached {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsSliceU8 T) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default (tls_vec.TlsSliceU8.Insts.Tls_codecSerialize SI) x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post (tls_vec.TlsSliceU8.Insts.Tls_codecSerialize SI).SizeInst
      (tls_vec.TlsSliceU8.Insts.Tls_codecSerialize SI) x r).holds ⌝ ⦄ :=
  TlsVecStd.detached_of (tls_vec.TlsSliceU8.serSpec hL x)
    (TlsVecGen.serLen_rel _ hL.SizeInstLawful tls_vec.TlsSliceU8.as_slice TlsVecGen.ok_view _
      (fun _ _ _ => rfl) () 1#usize x)

theorem Shared0TlsSliceU8.serSpec {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsSliceU8 T) : SerSpec (Shared0TlsSliceU8.Insts.Tls_codecSerialize SI) x :=
  TlsVecStd.serSpec hL _ x x 1#usize 255 (by scalar_tac) _ max_len_U8_spec _ rfl _ _ _ prefix_U8
    _ rfl _ (fun a => by simp [tls_vec.TlsSliceU8.assert_written_bytes]) (fun _ _ _ => rfl)
    (TlsVecGen.serLen_rel _ hL.SizeInstLawful tls_vec.TlsSliceU8.as_slice TlsVecGen.ok_view _
      (fun _ _ _ => rfl) () 1#usize x)

theorem Shared0TlsSliceU8.serDetached {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsSliceU8 T) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default (Shared0TlsSliceU8.Insts.Tls_codecSerialize SI) x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post (Shared0TlsSliceU8.Insts.Tls_codecSerialize SI).SizeInst
      (Shared0TlsSliceU8.Insts.Tls_codecSerialize SI) x r).holds ⌝ ⦄ :=
  TlsVecStd.detached_of (Shared0TlsSliceU8.serSpec hL x)
    (TlsVecGen.serLen_rel _ hL.SizeInstLawful tls_vec.TlsSliceU8.as_slice TlsVecGen.ok_view _
      (fun _ _ _ => rfl) () 1#usize x)

theorem tls_vec.TlsVecU16.serSpec {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsVecU16 T) : SerSpec (tls_vec.TlsVecU16.Insts.Tls_codecSerialize SI) x :=
  TlsVecStd.serSpec hL _ x x.vec 2#usize 65535 (by scalar_tac) _ max_len_U16_spec _ rfl _ _ _ prefix_U16
    _ rfl _ (fun a => by simp [tls_vec.TlsVecU16.assert_written_bytes]) (fun _ _ _ => rfl)
    (tls_vec.TlsVecU16.size_rel _ hL.SizeInstLawful x)

theorem tls_vec.TlsVecU16.serDetached {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsVecU16 T) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default (tls_vec.TlsVecU16.Insts.Tls_codecSerialize SI) x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post (tls_vec.TlsVecU16.Insts.Tls_codecSerialize SI).SizeInst
      (tls_vec.TlsVecU16.Insts.Tls_codecSerialize SI) x r).holds ⌝ ⦄ :=
  TlsVecStd.detached_of (tls_vec.TlsVecU16.serSpec hL x)
    (tls_vec.TlsVecU16.size_rel _ hL.SizeInstLawful x)

theorem Shared0TlsVecU16.serSpec {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsVecU16 T) : SerSpec (Shared0TlsVecU16.Insts.Tls_codecSerialize SI) x :=
  TlsVecStd.serSpec hL _ x x.vec 2#usize 65535 (by scalar_tac) _ max_len_U16_spec _ rfl _ _ _ prefix_U16
    _ rfl _ (fun a => by simp [tls_vec.TlsVecU16.assert_written_bytes]) (fun _ _ _ => rfl)
    (tls_vec.TlsVecU16.size_rel _ hL.SizeInstLawful x)

theorem Shared0TlsVecU16.serDetached {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsVecU16 T) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default (Shared0TlsVecU16.Insts.Tls_codecSerialize SI) x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post (Shared0TlsVecU16.Insts.Tls_codecSerialize SI).SizeInst
      (Shared0TlsVecU16.Insts.Tls_codecSerialize SI) x r).holds ⌝ ⦄ :=
  TlsVecStd.detached_of (Shared0TlsVecU16.serSpec hL x)
    (tls_vec.TlsVecU16.size_rel _ hL.SizeInstLawful x)

theorem tls_vec.SecretTlsVecU16.serSpec {T : Type} {SI : Serialize T} (z : zeroize.Zeroize T) (hL : Serialize.Lawful T SI)
    (x : tls_vec.SecretTlsVecU16 T) : SerSpec (tls_vec.SecretTlsVecU16.Insts.Tls_codecSerialize z SI) x :=
  TlsVecStd.serSpec hL _ x x.vec 2#usize 65535 (by scalar_tac) _ max_len_U16_spec _ rfl _ _ _ prefix_U16
    _ rfl _ (fun a => by simp [tls_vec.SecretTlsVecU16.assert_written_bytes]) (fun _ _ _ => rfl)
    (tls_vec.SecretTlsVecU16.size_rel _ z hL.SizeInstLawful x)

theorem tls_vec.SecretTlsVecU16.serDetached {T : Type} {SI : Serialize T} (z : zeroize.Zeroize T) (hL : Serialize.Lawful T SI)
    (x : tls_vec.SecretTlsVecU16 T) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default (tls_vec.SecretTlsVecU16.Insts.Tls_codecSerialize z SI) x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post (tls_vec.SecretTlsVecU16.Insts.Tls_codecSerialize z SI).SizeInst
      (tls_vec.SecretTlsVecU16.Insts.Tls_codecSerialize z SI) x r).holds ⌝ ⦄ :=
  TlsVecStd.detached_of (tls_vec.SecretTlsVecU16.serSpec z hL x)
    (tls_vec.SecretTlsVecU16.size_rel _ z hL.SizeInstLawful x)

theorem Shared0SecretTlsVecU16.serSpec {T : Type} {SI : Serialize T} (z : zeroize.Zeroize T) (hL : Serialize.Lawful T SI)
    (x : tls_vec.SecretTlsVecU16 T) : SerSpec (Shared0SecretTlsVecU16.Insts.Tls_codecSerialize z SI) x :=
  TlsVecStd.serSpec hL _ x x.vec 2#usize 65535 (by scalar_tac) _ max_len_U16_spec _ rfl _ _ _ prefix_U16
    _ rfl _ (fun a => by simp [tls_vec.SecretTlsVecU16.assert_written_bytes]) (fun _ _ _ => rfl)
    (tls_vec.SecretTlsVecU16.size_rel _ z hL.SizeInstLawful x)

theorem Shared0SecretTlsVecU16.serDetached {T : Type} {SI : Serialize T} (z : zeroize.Zeroize T) (hL : Serialize.Lawful T SI)
    (x : tls_vec.SecretTlsVecU16 T) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default (Shared0SecretTlsVecU16.Insts.Tls_codecSerialize z SI) x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post (Shared0SecretTlsVecU16.Insts.Tls_codecSerialize z SI).SizeInst
      (Shared0SecretTlsVecU16.Insts.Tls_codecSerialize z SI) x r).holds ⌝ ⦄ :=
  TlsVecStd.detached_of (Shared0SecretTlsVecU16.serSpec z hL x)
    (tls_vec.SecretTlsVecU16.size_rel _ z hL.SizeInstLawful x)

theorem tls_vec.TlsSliceU16.serSpec {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsSliceU16 T) : SerSpec (tls_vec.TlsSliceU16.Insts.Tls_codecSerialize SI) x :=
  TlsVecStd.serSpec hL _ x x 2#usize 65535 (by scalar_tac) _ max_len_U16_spec _ rfl _ _ _ prefix_U16
    _ rfl _ (fun a => by simp [tls_vec.TlsSliceU16.assert_written_bytes]) (fun _ _ _ => rfl)
    (TlsVecGen.serLen_rel _ hL.SizeInstLawful tls_vec.TlsSliceU16.as_slice TlsVecGen.ok_view _
      (fun _ _ _ => rfl) () 2#usize x)

theorem tls_vec.TlsSliceU16.serDetached {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsSliceU16 T) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default (tls_vec.TlsSliceU16.Insts.Tls_codecSerialize SI) x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post (tls_vec.TlsSliceU16.Insts.Tls_codecSerialize SI).SizeInst
      (tls_vec.TlsSliceU16.Insts.Tls_codecSerialize SI) x r).holds ⌝ ⦄ :=
  TlsVecStd.detached_of (tls_vec.TlsSliceU16.serSpec hL x)
    (TlsVecGen.serLen_rel _ hL.SizeInstLawful tls_vec.TlsSliceU16.as_slice TlsVecGen.ok_view _
      (fun _ _ _ => rfl) () 2#usize x)

theorem Shared0TlsSliceU16.serSpec {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsSliceU16 T) : SerSpec (Shared0TlsSliceU16.Insts.Tls_codecSerialize SI) x :=
  TlsVecStd.serSpec hL _ x x 2#usize 65535 (by scalar_tac) _ max_len_U16_spec _ rfl _ _ _ prefix_U16
    _ rfl _ (fun a => by simp [tls_vec.TlsSliceU16.assert_written_bytes]) (fun _ _ _ => rfl)
    (TlsVecGen.serLen_rel _ hL.SizeInstLawful tls_vec.TlsSliceU16.as_slice TlsVecGen.ok_view _
      (fun _ _ _ => rfl) () 2#usize x)

theorem Shared0TlsSliceU16.serDetached {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsSliceU16 T) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default (Shared0TlsSliceU16.Insts.Tls_codecSerialize SI) x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post (Shared0TlsSliceU16.Insts.Tls_codecSerialize SI).SizeInst
      (Shared0TlsSliceU16.Insts.Tls_codecSerialize SI) x r).holds ⌝ ⦄ :=
  TlsVecStd.detached_of (Shared0TlsSliceU16.serSpec hL x)
    (TlsVecGen.serLen_rel _ hL.SizeInstLawful tls_vec.TlsSliceU16.as_slice TlsVecGen.ok_view _
      (fun _ _ _ => rfl) () 2#usize x)

theorem tls_vec.TlsVecU24.serSpec {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsVecU24 T) : SerSpec (tls_vec.TlsVecU24.Insts.Tls_codecSerialize SI) x :=
  TlsVecStd.serSpec hL _ x x.vec 3#usize 16777215 (by scalar_tac) _ max_len_U24_spec _ rfl _ _ _ prefix_U24
    _ rfl _ (fun a => by simp [tls_vec.TlsVecU24.assert_written_bytes]) (fun _ _ _ => rfl)
    (tls_vec.TlsVecU24.size_rel _ hL.SizeInstLawful x)

theorem tls_vec.TlsVecU24.serDetached {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsVecU24 T) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default (tls_vec.TlsVecU24.Insts.Tls_codecSerialize SI) x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post (tls_vec.TlsVecU24.Insts.Tls_codecSerialize SI).SizeInst
      (tls_vec.TlsVecU24.Insts.Tls_codecSerialize SI) x r).holds ⌝ ⦄ :=
  TlsVecStd.detached_of (tls_vec.TlsVecU24.serSpec hL x)
    (tls_vec.TlsVecU24.size_rel _ hL.SizeInstLawful x)

theorem Shared0TlsVecU24.serSpec {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsVecU24 T) : SerSpec (Shared0TlsVecU24.Insts.Tls_codecSerialize SI) x :=
  TlsVecStd.serSpec hL _ x x.vec 3#usize 16777215 (by scalar_tac) _ max_len_U24_spec _ rfl _ _ _ prefix_U24
    _ rfl _ (fun a => by simp [tls_vec.TlsVecU24.assert_written_bytes]) (fun _ _ _ => rfl)
    (tls_vec.TlsVecU24.size_rel _ hL.SizeInstLawful x)

theorem Shared0TlsVecU24.serDetached {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsVecU24 T) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default (Shared0TlsVecU24.Insts.Tls_codecSerialize SI) x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post (Shared0TlsVecU24.Insts.Tls_codecSerialize SI).SizeInst
      (Shared0TlsVecU24.Insts.Tls_codecSerialize SI) x r).holds ⌝ ⦄ :=
  TlsVecStd.detached_of (Shared0TlsVecU24.serSpec hL x)
    (tls_vec.TlsVecU24.size_rel _ hL.SizeInstLawful x)

theorem tls_vec.SecretTlsVecU24.serSpec {T : Type} {SI : Serialize T} (z : zeroize.Zeroize T) (hL : Serialize.Lawful T SI)
    (x : tls_vec.SecretTlsVecU24 T) : SerSpec (tls_vec.SecretTlsVecU24.Insts.Tls_codecSerialize z SI) x :=
  TlsVecStd.serSpec hL _ x x.vec 3#usize 16777215 (by scalar_tac) _ max_len_U24_spec _ rfl _ _ _ prefix_U24
    _ rfl _ (fun a => by simp [tls_vec.SecretTlsVecU24.assert_written_bytes]) (fun _ _ _ => rfl)
    (tls_vec.SecretTlsVecU24.size_rel _ z hL.SizeInstLawful x)

theorem tls_vec.SecretTlsVecU24.serDetached {T : Type} {SI : Serialize T} (z : zeroize.Zeroize T) (hL : Serialize.Lawful T SI)
    (x : tls_vec.SecretTlsVecU24 T) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default (tls_vec.SecretTlsVecU24.Insts.Tls_codecSerialize z SI) x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post (tls_vec.SecretTlsVecU24.Insts.Tls_codecSerialize z SI).SizeInst
      (tls_vec.SecretTlsVecU24.Insts.Tls_codecSerialize z SI) x r).holds ⌝ ⦄ :=
  TlsVecStd.detached_of (tls_vec.SecretTlsVecU24.serSpec z hL x)
    (tls_vec.SecretTlsVecU24.size_rel _ z hL.SizeInstLawful x)

theorem Shared0SecretTlsVecU24.serSpec {T : Type} {SI : Serialize T} (z : zeroize.Zeroize T) (hL : Serialize.Lawful T SI)
    (x : tls_vec.SecretTlsVecU24 T) : SerSpec (Shared0SecretTlsVecU24.Insts.Tls_codecSerialize z SI) x :=
  TlsVecStd.serSpec hL _ x x.vec 3#usize 16777215 (by scalar_tac) _ max_len_U24_spec _ rfl _ _ _ prefix_U24
    _ rfl _ (fun a => by simp [tls_vec.SecretTlsVecU24.assert_written_bytes]) (fun _ _ _ => rfl)
    (tls_vec.SecretTlsVecU24.size_rel _ z hL.SizeInstLawful x)

theorem Shared0SecretTlsVecU24.serDetached {T : Type} {SI : Serialize T} (z : zeroize.Zeroize T) (hL : Serialize.Lawful T SI)
    (x : tls_vec.SecretTlsVecU24 T) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default (Shared0SecretTlsVecU24.Insts.Tls_codecSerialize z SI) x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post (Shared0SecretTlsVecU24.Insts.Tls_codecSerialize z SI).SizeInst
      (Shared0SecretTlsVecU24.Insts.Tls_codecSerialize z SI) x r).holds ⌝ ⦄ :=
  TlsVecStd.detached_of (Shared0SecretTlsVecU24.serSpec z hL x)
    (tls_vec.SecretTlsVecU24.size_rel _ z hL.SizeInstLawful x)

theorem tls_vec.TlsSliceU24.serSpec {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsSliceU24 T) : SerSpec (tls_vec.TlsSliceU24.Insts.Tls_codecSerialize SI) x :=
  TlsVecStd.serSpec hL _ x x 3#usize 16777215 (by scalar_tac) _ max_len_U24_spec _ rfl _ _ _ prefix_U24
    _ rfl _ (fun a => by simp [tls_vec.TlsSliceU24.assert_written_bytes]) (fun _ _ _ => rfl)
    (TlsVecGen.serLen_rel _ hL.SizeInstLawful tls_vec.TlsSliceU24.as_slice TlsVecGen.ok_view _
      (fun _ _ _ => rfl) () 3#usize x)

theorem tls_vec.TlsSliceU24.serDetached {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsSliceU24 T) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default (tls_vec.TlsSliceU24.Insts.Tls_codecSerialize SI) x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post (tls_vec.TlsSliceU24.Insts.Tls_codecSerialize SI).SizeInst
      (tls_vec.TlsSliceU24.Insts.Tls_codecSerialize SI) x r).holds ⌝ ⦄ :=
  TlsVecStd.detached_of (tls_vec.TlsSliceU24.serSpec hL x)
    (TlsVecGen.serLen_rel _ hL.SizeInstLawful tls_vec.TlsSliceU24.as_slice TlsVecGen.ok_view _
      (fun _ _ _ => rfl) () 3#usize x)

theorem Shared0TlsSliceU24.serSpec {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsSliceU24 T) : SerSpec (Shared0TlsSliceU24.Insts.Tls_codecSerialize SI) x :=
  TlsVecStd.serSpec hL _ x x 3#usize 16777215 (by scalar_tac) _ max_len_U24_spec _ rfl _ _ _ prefix_U24
    _ rfl _ (fun a => by simp [tls_vec.TlsSliceU24.assert_written_bytes]) (fun _ _ _ => rfl)
    (TlsVecGen.serLen_rel _ hL.SizeInstLawful tls_vec.TlsSliceU24.as_slice TlsVecGen.ok_view _
      (fun _ _ _ => rfl) () 3#usize x)

theorem Shared0TlsSliceU24.serDetached {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsSliceU24 T) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default (Shared0TlsSliceU24.Insts.Tls_codecSerialize SI) x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post (Shared0TlsSliceU24.Insts.Tls_codecSerialize SI).SizeInst
      (Shared0TlsSliceU24.Insts.Tls_codecSerialize SI) x r).holds ⌝ ⦄ :=
  TlsVecStd.detached_of (Shared0TlsSliceU24.serSpec hL x)
    (TlsVecGen.serLen_rel _ hL.SizeInstLawful tls_vec.TlsSliceU24.as_slice TlsVecGen.ok_view _
      (fun _ _ _ => rfl) () 3#usize x)

theorem tls_vec.TlsVecU32.serSpec {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsVecU32 T) : SerSpec (tls_vec.TlsVecU32.Insts.Tls_codecSerialize SI) x :=
  TlsVecStd.serSpec hL _ x x.vec 4#usize 4294967295 (by have := numBits_eq_64; scalar_tac) _ max_len_U32_spec _ rfl _ _ _ prefix_U32
    _ rfl _ (fun a => by simp [tls_vec.TlsVecU32.assert_written_bytes]) (fun _ _ _ => rfl)
    (tls_vec.TlsVecU32.size_rel _ hL.SizeInstLawful x)

theorem tls_vec.TlsVecU32.serDetached {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsVecU32 T) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default (tls_vec.TlsVecU32.Insts.Tls_codecSerialize SI) x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post (tls_vec.TlsVecU32.Insts.Tls_codecSerialize SI).SizeInst
      (tls_vec.TlsVecU32.Insts.Tls_codecSerialize SI) x r).holds ⌝ ⦄ :=
  TlsVecStd.detached_of (tls_vec.TlsVecU32.serSpec hL x)
    (tls_vec.TlsVecU32.size_rel _ hL.SizeInstLawful x)

theorem Shared0TlsVecU32.serSpec {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsVecU32 T) : SerSpec (Shared0TlsVecU32.Insts.Tls_codecSerialize SI) x :=
  TlsVecStd.serSpec hL _ x x.vec 4#usize 4294967295 (by have := numBits_eq_64; scalar_tac) _ max_len_U32_spec _ rfl _ _ _ prefix_U32
    _ rfl _ (fun a => by simp [tls_vec.TlsVecU32.assert_written_bytes]) (fun _ _ _ => rfl)
    (tls_vec.TlsVecU32.size_rel _ hL.SizeInstLawful x)

theorem Shared0TlsVecU32.serDetached {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsVecU32 T) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default (Shared0TlsVecU32.Insts.Tls_codecSerialize SI) x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post (Shared0TlsVecU32.Insts.Tls_codecSerialize SI).SizeInst
      (Shared0TlsVecU32.Insts.Tls_codecSerialize SI) x r).holds ⌝ ⦄ :=
  TlsVecStd.detached_of (Shared0TlsVecU32.serSpec hL x)
    (tls_vec.TlsVecU32.size_rel _ hL.SizeInstLawful x)

theorem tls_vec.SecretTlsVecU32.serSpec {T : Type} {SI : Serialize T} (z : zeroize.Zeroize T) (hL : Serialize.Lawful T SI)
    (x : tls_vec.SecretTlsVecU32 T) : SerSpec (tls_vec.SecretTlsVecU32.Insts.Tls_codecSerialize z SI) x :=
  TlsVecStd.serSpec hL _ x x.vec 4#usize 4294967295 (by have := numBits_eq_64; scalar_tac) _ max_len_U32_spec _ rfl _ _ _ prefix_U32
    _ rfl _ (fun a => by simp [tls_vec.SecretTlsVecU32.assert_written_bytes]) (fun _ _ _ => rfl)
    (tls_vec.SecretTlsVecU32.size_rel _ z hL.SizeInstLawful x)

theorem tls_vec.SecretTlsVecU32.serDetached {T : Type} {SI : Serialize T} (z : zeroize.Zeroize T) (hL : Serialize.Lawful T SI)
    (x : tls_vec.SecretTlsVecU32 T) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default (tls_vec.SecretTlsVecU32.Insts.Tls_codecSerialize z SI) x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post (tls_vec.SecretTlsVecU32.Insts.Tls_codecSerialize z SI).SizeInst
      (tls_vec.SecretTlsVecU32.Insts.Tls_codecSerialize z SI) x r).holds ⌝ ⦄ :=
  TlsVecStd.detached_of (tls_vec.SecretTlsVecU32.serSpec z hL x)
    (tls_vec.SecretTlsVecU32.size_rel _ z hL.SizeInstLawful x)

theorem Shared0SecretTlsVecU32.serSpec {T : Type} {SI : Serialize T} (z : zeroize.Zeroize T) (hL : Serialize.Lawful T SI)
    (x : tls_vec.SecretTlsVecU32 T) : SerSpec (Shared0SecretTlsVecU32.Insts.Tls_codecSerialize z SI) x :=
  TlsVecStd.serSpec hL _ x x.vec 4#usize 4294967295 (by have := numBits_eq_64; scalar_tac) _ max_len_U32_spec _ rfl _ _ _ prefix_U32
    _ rfl _ (fun a => by simp [tls_vec.SecretTlsVecU32.assert_written_bytes]) (fun _ _ _ => rfl)
    (tls_vec.SecretTlsVecU32.size_rel _ z hL.SizeInstLawful x)

theorem Shared0SecretTlsVecU32.serDetached {T : Type} {SI : Serialize T} (z : zeroize.Zeroize T) (hL : Serialize.Lawful T SI)
    (x : tls_vec.SecretTlsVecU32 T) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default (Shared0SecretTlsVecU32.Insts.Tls_codecSerialize z SI) x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post (Shared0SecretTlsVecU32.Insts.Tls_codecSerialize z SI).SizeInst
      (Shared0SecretTlsVecU32.Insts.Tls_codecSerialize z SI) x r).holds ⌝ ⦄ :=
  TlsVecStd.detached_of (Shared0SecretTlsVecU32.serSpec z hL x)
    (tls_vec.SecretTlsVecU32.size_rel _ z hL.SizeInstLawful x)

theorem tls_vec.TlsSliceU32.serSpec {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsSliceU32 T) : SerSpec (tls_vec.TlsSliceU32.Insts.Tls_codecSerialize SI) x :=
  TlsVecStd.serSpec hL _ x x 4#usize 4294967295 (by have := numBits_eq_64; scalar_tac) _ max_len_U32_spec _ rfl _ _ _ prefix_U32
    _ rfl _ (fun a => by simp [tls_vec.TlsSliceU32.assert_written_bytes]) (fun _ _ _ => rfl)
    (TlsVecGen.serLen_rel _ hL.SizeInstLawful tls_vec.TlsSliceU32.as_slice TlsVecGen.ok_view _
      (fun _ _ _ => rfl) () 4#usize x)

theorem tls_vec.TlsSliceU32.serDetached {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsSliceU32 T) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default (tls_vec.TlsSliceU32.Insts.Tls_codecSerialize SI) x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post (tls_vec.TlsSliceU32.Insts.Tls_codecSerialize SI).SizeInst
      (tls_vec.TlsSliceU32.Insts.Tls_codecSerialize SI) x r).holds ⌝ ⦄ :=
  TlsVecStd.detached_of (tls_vec.TlsSliceU32.serSpec hL x)
    (TlsVecGen.serLen_rel _ hL.SizeInstLawful tls_vec.TlsSliceU32.as_slice TlsVecGen.ok_view _
      (fun _ _ _ => rfl) () 4#usize x)

theorem Shared0TlsSliceU32.serSpec {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsSliceU32 T) : SerSpec (Shared0TlsSliceU32.Insts.Tls_codecSerialize SI) x :=
  TlsVecStd.serSpec hL _ x x 4#usize 4294967295 (by have := numBits_eq_64; scalar_tac) _ max_len_U32_spec _ rfl _ _ _ prefix_U32
    _ rfl _ (fun a => by simp [tls_vec.TlsSliceU32.assert_written_bytes]) (fun _ _ _ => rfl)
    (TlsVecGen.serLen_rel _ hL.SizeInstLawful tls_vec.TlsSliceU32.as_slice TlsVecGen.ok_view _
      (fun _ _ _ => rfl) () 4#usize x)

theorem Shared0TlsSliceU32.serDetached {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : tls_vec.TlsSliceU32 T) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default (Shared0TlsSliceU32.Insts.Tls_codecSerialize SI) x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post (Shared0TlsSliceU32.Insts.Tls_codecSerialize SI).SizeInst
      (Shared0TlsSliceU32.Insts.Tls_codecSerialize SI) x r).holds ⌝ ⦄ :=
  TlsVecStd.detached_of (Shared0TlsSliceU32.serSpec hL x)
    (TlsVecGen.serLen_rel _ hL.SizeInstLawful tls_vec.TlsSliceU32.as_slice TlsVecGen.ok_view _
      (fun _ _ _ => rfl) () 4#usize x)

/-! ### `TlsByteVecU*`, `TlsByteSliceU*` -/

/-- A width's `deserialize_bytes` is `deB`. -/
macro "bytevec_de_eq" i:ident f:ident d:ident : tactic => `(tactic| (
  intro R RI r
  unfold $i:ident $f:ident $d:ident TlsVecStd.deB
  dsimp only
  congr 1; funext q; rcases q with ⟨r1, b1⟩; congr 1; funext cf
  cases cf <;> first
    | rfl
    | (congr 1; funext r2; congr 1; funext l; congr 1; funext q2; rcases q2 with ⟨r3, b3⟩
       congr 1; funext cf1; cases cf1 <;> rfl)))

/-- `TlsByteVecU*::get_content_lengths` (the hand-translated loop) is the generic body. -/
macro "bytevec_gcl_eq" g:ident m:ident : tactic => `(tactic| (
  unfold $g:ident tls_codec.HandTranslated.get_content_lengths_std
    tls_codec.HandTranslated.checked_len_fold $m:ident
  simp only [deref_vec_ok, bind_assoc]
  erw [bind_tc_ok]
  congr 1; funext i; congr 1; congr 1; funext p; congr 1; funext q
  rcases q with ⟨o, it⟩
  cases o <;> rfl))

theorem conv_U8 (p : Std.U8) : ⦃ ⌜ True ⌝ ⦄ core.convert.TryFromTUInfallible.Blanket.try_from
    (core.convert.Into.Blanket core.Usize.Insts.CoreConvertFromU8) p
    ⦃ ⇓ r => ⌜ ∃ y : Std.Usize, r = .Ok y ∧ y.val ≤ 255 ⌝ ⦄ :=
  triple_post_mono (core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U8_spec p)
    (fun _ h => ⟨_, h, by scalar_tac⟩)

theorem conv_U16 (p : Std.U16) : ⦃ ⌜ True ⌝ ⦄ core.convert.TryFromTUInfallible.Blanket.try_from
    (core.convert.Into.Blanket core.Usize.Insts.CoreConvertFromU16) p
    ⦃ ⇓ r => ⌜ ∃ y : Std.Usize, r = .Ok y ∧ y.val ≤ 65535 ⌝ ⦄ :=
  triple_post_mono (core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U16_spec p)
    (fun _ h => ⟨_, h, by scalar_tac⟩)

theorem conv_U32 (p : Std.U32) : ⦃ ⌜ True ⌝ ⦄
    core.Usize.Insts.CoreConvertTryFromU32TryFromIntError.try_from p
    ⦃ ⇓ r => ⌜ ∃ y : Std.Usize, r = .Ok y ∧ y.val ≤ 4294967295 ⌝ ⦄ :=
  triple_post_mono (core.Usize.Insts.CoreConvertTryFromU32TryFromIntError.try_from_spec p)
    (fun _ h => ⟨_, h, by have := numBits_eq_64; scalar_tac⟩)

theorem conv_U24 (p : U24) : ⦃ ⌜ True ⌝ ⦄ core.convert.TryFromTUInfallible.Blanket.try_from
    (core.convert.Into.Blanket Usize.Insts.CoreConvertFromU24) p
    ⦃ ⇓ r => ⌜ ∃ y : Std.Usize, r = .Ok y ∧ y.val ≤ 16777215 ⌝ ⦄ := by
  refine triple_post_mono (core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U24_content p)
    (fun _ ⟨y, hy, hv⟩ => ⟨y, hy, ?_⟩)
  obtain ⟨b0, b1, b2, hb⟩ : ∃ b0 b1 b2 : Std.U8, p.val = [b0, b1, b2] := by
    have hl : p.val.length = 3 := by simp
    match p.val, hl with
    | [b0, b1, b2], _ => exact ⟨b0, b1, b2, rfl⟩
  rw [hv b0 b1 b2 hb]; scalar_tac

/-! #### Width `U8` -/

theorem tls_vec.TlsByteVecU8.gcl_eq (x : tls_vec.TlsByteVecU8) :
    tls_vec.TlsByteVecU8.get_content_lengths x = tls_codec.HandTranslated.get_content_lengths_std
      U8.Insts.Tls_codecSize.tls_serialized_len 1#usize tls_codec.HandTranslated.max_len_U8 x.vec := by
  bytevec_gcl_eq tls_vec.TlsByteVecU8.get_content_lengths tls_codec.HandTranslated.max_len_U8

theorem tls_vec.TlsByteVecU8.deSpec : DeSpec tls_vec.TlsByteVecU8.Insts.Tls_codecDeserialize :=
  TlsVecStd.deSpec (TlsVecStd.deB_runs (fun x => x.vec) tls_vec.TlsByteVecU8.mk (fun _ => rfl)
    U8.Insts.Tls_codecDeserialize U8.de_runs 1#usize (fun _ => rfl) 255 (by scalar_tac) _ conv_U8
    core.convert.Infallible.Insts.CoreFmtDebug _ (by bytevec_de_eq tls_vec.TlsByteVecU8.Insts.Tls_codecDeserialize
      tls_vec.TlsByteVecU8.Insts.Tls_codecDeserialize.tls_deserialize tls_vec.TlsByteVecU8.deserialize_bytes) (fun _ => rfl))

theorem tls_vec.TlsByteVecU8.serSpec (x : tls_vec.TlsByteVecU8) : SerSpec tls_vec.TlsByteVecU8.Insts.Tls_codecSerialize x :=
  TlsVecStd.serSpecB _ x x.vec 1#usize 255 (by scalar_tac) _ max_len_U8_spec _ (tls_vec.TlsByteVecU8.gcl_eq x) _ _ _ prefix_U8 _ rfl _
    (fun a => by simp [tls_vec.TlsByteVecU8.assert_written_bytes]) (fun _ _ _ => rfl) rfl

theorem tls_vec.TlsByteVecU8.serDetached (x : tls_vec.TlsByteVecU8) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default tls_vec.TlsByteVecU8.Insts.Tls_codecSerialize x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post tls_vec.TlsByteVecU8.Insts.Tls_codecSerialize.SizeInst
      tls_vec.TlsByteVecU8.Insts.Tls_codecSerialize x r).holds ⌝ ⦄ :=
  TlsVecStd.detachedB (tls_vec.TlsByteVecU8.serSpec x) (a := Slice.len x.vec) (k := 1#usize) rfl

theorem Shared0TlsByteVecU8.serSpec (x : tls_vec.TlsByteVecU8) : SerSpec Shared0TlsByteVecU8.Insts.Tls_codecSerialize x :=
  TlsVecStd.serSpecB _ x x.vec 1#usize 255 (by scalar_tac) _ max_len_U8_spec _ (tls_vec.TlsByteVecU8.gcl_eq x) _ _ _ prefix_U8 _ rfl _
    (fun a => by simp [tls_vec.TlsByteVecU8.assert_written_bytes]) (fun _ _ _ => rfl) rfl

theorem Shared0TlsByteVecU8.serDetached (x : tls_vec.TlsByteVecU8) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default Shared0TlsByteVecU8.Insts.Tls_codecSerialize x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post Shared0TlsByteVecU8.Insts.Tls_codecSerialize.SizeInst
      Shared0TlsByteVecU8.Insts.Tls_codecSerialize x r).holds ⌝ ⦄ :=
  TlsVecStd.detachedB (Shared0TlsByteVecU8.serSpec x) (a := Slice.len x.vec) (k := 1#usize) rfl

theorem tls_vec.TlsByteSliceU8.serSpec (x : tls_vec.TlsByteSliceU8) : SerSpec tls_vec.TlsByteSliceU8.Insts.Tls_codecSerialize x :=
  TlsVecStd.serSpecB _ x x 1#usize 255 (by scalar_tac) _ max_len_U8_spec _ rfl _ _ _ prefix_U8 _ rfl _
    (fun a => by simp [tls_vec.TlsByteSliceU8.assert_written_bytes]) (fun _ _ _ => rfl) rfl

theorem tls_vec.TlsByteSliceU8.serDetached (x : tls_vec.TlsByteSliceU8) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default tls_vec.TlsByteSliceU8.Insts.Tls_codecSerialize x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post tls_vec.TlsByteSliceU8.Insts.Tls_codecSerialize.SizeInst
      tls_vec.TlsByteSliceU8.Insts.Tls_codecSerialize x r).holds ⌝ ⦄ :=
  TlsVecStd.detachedB (tls_vec.TlsByteSliceU8.serSpec x) (a := Slice.len x) (k := 1#usize) rfl

theorem Shared0TlsByteSliceU8.serSpec (x : tls_vec.TlsByteSliceU8) : SerSpec Shared0TlsByteSliceU8.Insts.Tls_codecSerialize x :=
  TlsVecStd.serSpecB _ x x 1#usize 255 (by scalar_tac) _ max_len_U8_spec _ rfl _ _ _ prefix_U8 _ rfl _
    (fun a => by simp [tls_vec.TlsByteSliceU8.assert_written_bytes]) (fun _ _ _ => rfl) rfl

theorem Shared0TlsByteSliceU8.serDetached (x : tls_vec.TlsByteSliceU8) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default Shared0TlsByteSliceU8.Insts.Tls_codecSerialize x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post Shared0TlsByteSliceU8.Insts.Tls_codecSerialize.SizeInst
      Shared0TlsByteSliceU8.Insts.Tls_codecSerialize x r).holds ⌝ ⦄ :=
  TlsVecStd.detachedB (Shared0TlsByteSliceU8.serSpec x) (a := Slice.len x) (k := 1#usize) rfl

/-! #### Width `U16` -/

theorem tls_vec.TlsByteVecU16.gcl_eq (x : tls_vec.TlsByteVecU16) :
    tls_vec.TlsByteVecU16.get_content_lengths x = tls_codec.HandTranslated.get_content_lengths_std
      U8.Insts.Tls_codecSize.tls_serialized_len 2#usize tls_codec.HandTranslated.max_len_U16 x.vec := by
  bytevec_gcl_eq tls_vec.TlsByteVecU16.get_content_lengths tls_codec.HandTranslated.max_len_U16

theorem tls_vec.TlsByteVecU16.deSpec : DeSpec tls_vec.TlsByteVecU16.Insts.Tls_codecDeserialize :=
  TlsVecStd.deSpec (TlsVecStd.deB_runs (fun x => x.vec) tls_vec.TlsByteVecU16.mk (fun _ => rfl)
    U16.Insts.Tls_codecDeserialize U16.de_runs 2#usize (fun _ => rfl) 65535 (by scalar_tac) _ conv_U16
    core.convert.Infallible.Insts.CoreFmtDebug _ (by bytevec_de_eq tls_vec.TlsByteVecU16.Insts.Tls_codecDeserialize
      tls_vec.TlsByteVecU16.Insts.Tls_codecDeserialize.tls_deserialize tls_vec.TlsByteVecU16.deserialize_bytes) (fun _ => rfl))

theorem tls_vec.TlsByteVecU16.serSpec (x : tls_vec.TlsByteVecU16) : SerSpec tls_vec.TlsByteVecU16.Insts.Tls_codecSerialize x :=
  TlsVecStd.serSpecB _ x x.vec 2#usize 65535 (by scalar_tac) _ max_len_U16_spec _ (tls_vec.TlsByteVecU16.gcl_eq x) _ _ _ prefix_U16 _ rfl _
    (fun a => by simp [tls_vec.TlsByteVecU16.assert_written_bytes]) (fun _ _ _ => rfl) rfl

theorem tls_vec.TlsByteVecU16.serDetached (x : tls_vec.TlsByteVecU16) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default tls_vec.TlsByteVecU16.Insts.Tls_codecSerialize x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post tls_vec.TlsByteVecU16.Insts.Tls_codecSerialize.SizeInst
      tls_vec.TlsByteVecU16.Insts.Tls_codecSerialize x r).holds ⌝ ⦄ :=
  TlsVecStd.detachedB (tls_vec.TlsByteVecU16.serSpec x) (a := Slice.len x.vec) (k := 2#usize) rfl

theorem Shared0TlsByteVecU16.serSpec (x : tls_vec.TlsByteVecU16) : SerSpec Shared0TlsByteVecU16.Insts.Tls_codecSerialize x :=
  TlsVecStd.serSpecB _ x x.vec 2#usize 65535 (by scalar_tac) _ max_len_U16_spec _ (tls_vec.TlsByteVecU16.gcl_eq x) _ _ _ prefix_U16 _ rfl _
    (fun a => by simp [tls_vec.TlsByteVecU16.assert_written_bytes]) (fun _ _ _ => rfl) rfl

theorem Shared0TlsByteVecU16.serDetached (x : tls_vec.TlsByteVecU16) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default Shared0TlsByteVecU16.Insts.Tls_codecSerialize x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post Shared0TlsByteVecU16.Insts.Tls_codecSerialize.SizeInst
      Shared0TlsByteVecU16.Insts.Tls_codecSerialize x r).holds ⌝ ⦄ :=
  TlsVecStd.detachedB (Shared0TlsByteVecU16.serSpec x) (a := Slice.len x.vec) (k := 2#usize) rfl

theorem tls_vec.TlsByteSliceU16.serSpec (x : tls_vec.TlsByteSliceU16) : SerSpec tls_vec.TlsByteSliceU16.Insts.Tls_codecSerialize x :=
  TlsVecStd.serSpecB _ x x 2#usize 65535 (by scalar_tac) _ max_len_U16_spec _ rfl _ _ _ prefix_U16 _ rfl _
    (fun a => by simp [tls_vec.TlsByteSliceU16.assert_written_bytes]) (fun _ _ _ => rfl) rfl

theorem tls_vec.TlsByteSliceU16.serDetached (x : tls_vec.TlsByteSliceU16) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default tls_vec.TlsByteSliceU16.Insts.Tls_codecSerialize x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post tls_vec.TlsByteSliceU16.Insts.Tls_codecSerialize.SizeInst
      tls_vec.TlsByteSliceU16.Insts.Tls_codecSerialize x r).holds ⌝ ⦄ :=
  TlsVecStd.detachedB (tls_vec.TlsByteSliceU16.serSpec x) (a := Slice.len x) (k := 2#usize) rfl

theorem Shared0TlsByteSliceU16.serSpec (x : tls_vec.TlsByteSliceU16) : SerSpec Shared0TlsByteSliceU16.Insts.Tls_codecSerialize x :=
  TlsVecStd.serSpecB _ x x 2#usize 65535 (by scalar_tac) _ max_len_U16_spec _ rfl _ _ _ prefix_U16 _ rfl _
    (fun a => by simp [tls_vec.TlsByteSliceU16.assert_written_bytes]) (fun _ _ _ => rfl) rfl

theorem Shared0TlsByteSliceU16.serDetached (x : tls_vec.TlsByteSliceU16) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default Shared0TlsByteSliceU16.Insts.Tls_codecSerialize x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post Shared0TlsByteSliceU16.Insts.Tls_codecSerialize.SizeInst
      Shared0TlsByteSliceU16.Insts.Tls_codecSerialize x r).holds ⌝ ⦄ :=
  TlsVecStd.detachedB (Shared0TlsByteSliceU16.serSpec x) (a := Slice.len x) (k := 2#usize) rfl

/-! #### Width `U24` -/

theorem tls_vec.TlsByteVecU24.gcl_eq (x : tls_vec.TlsByteVecU24) :
    tls_vec.TlsByteVecU24.get_content_lengths x = tls_codec.HandTranslated.get_content_lengths_std
      U8.Insts.Tls_codecSize.tls_serialized_len 3#usize tls_codec.HandTranslated.max_len_U24 x.vec := by
  bytevec_gcl_eq tls_vec.TlsByteVecU24.get_content_lengths tls_codec.HandTranslated.max_len_U24

theorem tls_vec.TlsByteVecU24.deSpec : DeSpec tls_vec.TlsByteVecU24.Insts.Tls_codecDeserialize :=
  TlsVecStd.deSpec (TlsVecStd.deB_runs (fun x => x.vec) tls_vec.TlsByteVecU24.mk (fun _ => rfl)
    U24.Insts.Tls_codecDeserialize (DeRuns_of_fixed _ _ _ (fun _ => rfl) U24.fixed_runs) 3#usize (fun _ => rfl) 16777215 (by scalar_tac) _ conv_U24
    core.convert.Infallible.Insts.CoreFmtDebug _ (by bytevec_de_eq tls_vec.TlsByteVecU24.Insts.Tls_codecDeserialize
      tls_vec.TlsByteVecU24.Insts.Tls_codecDeserialize.tls_deserialize tls_vec.TlsByteVecU24.deserialize_bytes) (fun _ => rfl))

theorem tls_vec.TlsByteVecU24.serSpec (x : tls_vec.TlsByteVecU24) : SerSpec tls_vec.TlsByteVecU24.Insts.Tls_codecSerialize x :=
  TlsVecStd.serSpecB _ x x.vec 3#usize 16777215 (by scalar_tac) _ max_len_U24_spec _ (tls_vec.TlsByteVecU24.gcl_eq x) _ _ _ prefix_U24 _ rfl _
    (fun a => by simp [tls_vec.TlsByteVecU24.assert_written_bytes]) (fun _ _ _ => rfl) rfl

theorem tls_vec.TlsByteVecU24.serDetached (x : tls_vec.TlsByteVecU24) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default tls_vec.TlsByteVecU24.Insts.Tls_codecSerialize x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post tls_vec.TlsByteVecU24.Insts.Tls_codecSerialize.SizeInst
      tls_vec.TlsByteVecU24.Insts.Tls_codecSerialize x r).holds ⌝ ⦄ :=
  TlsVecStd.detachedB (tls_vec.TlsByteVecU24.serSpec x) (a := Slice.len x.vec) (k := 3#usize) rfl

theorem Shared0TlsByteVecU24.serSpec (x : tls_vec.TlsByteVecU24) : SerSpec Shared0TlsByteVecU24.Insts.Tls_codecSerialize x :=
  TlsVecStd.serSpecB _ x x.vec 3#usize 16777215 (by scalar_tac) _ max_len_U24_spec _ (tls_vec.TlsByteVecU24.gcl_eq x) _ _ _ prefix_U24 _ rfl _
    (fun a => by simp [tls_vec.TlsByteVecU24.assert_written_bytes]) (fun _ _ _ => rfl) rfl

theorem Shared0TlsByteVecU24.serDetached (x : tls_vec.TlsByteVecU24) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default Shared0TlsByteVecU24.Insts.Tls_codecSerialize x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post Shared0TlsByteVecU24.Insts.Tls_codecSerialize.SizeInst
      Shared0TlsByteVecU24.Insts.Tls_codecSerialize x r).holds ⌝ ⦄ :=
  TlsVecStd.detachedB (Shared0TlsByteVecU24.serSpec x) (a := Slice.len x.vec) (k := 3#usize) rfl

theorem tls_vec.TlsByteSliceU24.serSpec (x : tls_vec.TlsByteSliceU24) : SerSpec tls_vec.TlsByteSliceU24.Insts.Tls_codecSerialize x :=
  TlsVecStd.serSpecB _ x x 3#usize 16777215 (by scalar_tac) _ max_len_U24_spec _ rfl _ _ _ prefix_U24 _ rfl _
    (fun a => by simp [tls_vec.TlsByteSliceU24.assert_written_bytes]) (fun _ _ _ => rfl) rfl

theorem tls_vec.TlsByteSliceU24.serDetached (x : tls_vec.TlsByteSliceU24) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default tls_vec.TlsByteSliceU24.Insts.Tls_codecSerialize x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post tls_vec.TlsByteSliceU24.Insts.Tls_codecSerialize.SizeInst
      tls_vec.TlsByteSliceU24.Insts.Tls_codecSerialize x r).holds ⌝ ⦄ :=
  TlsVecStd.detachedB (tls_vec.TlsByteSliceU24.serSpec x) (a := Slice.len x) (k := 3#usize) rfl

theorem Shared0TlsByteSliceU24.serSpec (x : tls_vec.TlsByteSliceU24) : SerSpec Shared0TlsByteSliceU24.Insts.Tls_codecSerialize x :=
  TlsVecStd.serSpecB _ x x 3#usize 16777215 (by scalar_tac) _ max_len_U24_spec _ rfl _ _ _ prefix_U24 _ rfl _
    (fun a => by simp [tls_vec.TlsByteSliceU24.assert_written_bytes]) (fun _ _ _ => rfl) rfl

theorem Shared0TlsByteSliceU24.serDetached (x : tls_vec.TlsByteSliceU24) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default Shared0TlsByteSliceU24.Insts.Tls_codecSerialize x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post Shared0TlsByteSliceU24.Insts.Tls_codecSerialize.SizeInst
      Shared0TlsByteSliceU24.Insts.Tls_codecSerialize x r).holds ⌝ ⦄ :=
  TlsVecStd.detachedB (Shared0TlsByteSliceU24.serSpec x) (a := Slice.len x) (k := 3#usize) rfl

/-! #### Width `U32` -/

theorem tls_vec.TlsByteVecU32.gcl_eq (x : tls_vec.TlsByteVecU32) :
    tls_vec.TlsByteVecU32.get_content_lengths x = tls_codec.HandTranslated.get_content_lengths_std
      U8.Insts.Tls_codecSize.tls_serialized_len 4#usize tls_codec.HandTranslated.max_len_U32 x.vec := by
  bytevec_gcl_eq tls_vec.TlsByteVecU32.get_content_lengths tls_codec.HandTranslated.max_len_U32

theorem tls_vec.TlsByteVecU32.deSpec : DeSpec tls_vec.TlsByteVecU32.Insts.Tls_codecDeserialize :=
  TlsVecStd.deSpec (TlsVecStd.deB_runs (fun x => x.vec) tls_vec.TlsByteVecU32.mk (fun _ => rfl)
    U32.Insts.Tls_codecDeserialize (DeRuns_of_fixed _ _ _ (fun _ => rfl) U32.fixed_runs) 4#usize (fun _ => rfl) 4294967295 (by have := numBits_eq_64; scalar_tac) _ conv_U32
    core.num.error.TryFromIntError.Insts.CoreFmtDebug _ (by bytevec_de_eq tls_vec.TlsByteVecU32.Insts.Tls_codecDeserialize
      tls_vec.TlsByteVecU32.Insts.Tls_codecDeserialize.tls_deserialize tls_vec.TlsByteVecU32.deserialize_bytes) (fun _ => rfl))

theorem tls_vec.TlsByteVecU32.serSpec (x : tls_vec.TlsByteVecU32) : SerSpec tls_vec.TlsByteVecU32.Insts.Tls_codecSerialize x :=
  TlsVecStd.serSpecB _ x x.vec 4#usize 4294967295 (by have := numBits_eq_64; scalar_tac) _ max_len_U32_spec _ (tls_vec.TlsByteVecU32.gcl_eq x) _ _ _ prefix_U32 _ rfl _
    (fun a => by simp [tls_vec.TlsByteVecU32.assert_written_bytes]) (fun _ _ _ => rfl) rfl

theorem tls_vec.TlsByteVecU32.serDetached (x : tls_vec.TlsByteVecU32) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default tls_vec.TlsByteVecU32.Insts.Tls_codecSerialize x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post tls_vec.TlsByteVecU32.Insts.Tls_codecSerialize.SizeInst
      tls_vec.TlsByteVecU32.Insts.Tls_codecSerialize x r).holds ⌝ ⦄ :=
  TlsVecStd.detachedB (tls_vec.TlsByteVecU32.serSpec x) (a := Slice.len x.vec) (k := 4#usize) rfl

theorem Shared0TlsByteVecU32.serSpec (x : tls_vec.TlsByteVecU32) : SerSpec Shared0TlsByteVecU32.Insts.Tls_codecSerialize x :=
  TlsVecStd.serSpecB _ x x.vec 4#usize 4294967295 (by have := numBits_eq_64; scalar_tac) _ max_len_U32_spec _ (tls_vec.TlsByteVecU32.gcl_eq x) _ _ _ prefix_U32 _ rfl _
    (fun a => by simp [tls_vec.TlsByteVecU32.assert_written_bytes]) (fun _ _ _ => rfl) rfl

theorem Shared0TlsByteVecU32.serDetached (x : tls_vec.TlsByteVecU32) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default Shared0TlsByteVecU32.Insts.Tls_codecSerialize x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post Shared0TlsByteVecU32.Insts.Tls_codecSerialize.SizeInst
      Shared0TlsByteVecU32.Insts.Tls_codecSerialize x r).holds ⌝ ⦄ :=
  TlsVecStd.detachedB (Shared0TlsByteVecU32.serSpec x) (a := Slice.len x.vec) (k := 4#usize) rfl

theorem tls_vec.TlsByteSliceU32.serSpec (x : tls_vec.TlsByteSliceU32) : SerSpec tls_vec.TlsByteSliceU32.Insts.Tls_codecSerialize x :=
  TlsVecStd.serSpecB _ x x 4#usize 4294967295 (by have := numBits_eq_64; scalar_tac) _ max_len_U32_spec _ rfl _ _ _ prefix_U32 _ rfl _
    (fun a => by simp [tls_vec.TlsByteSliceU32.assert_written_bytes]) (fun _ _ _ => rfl) rfl

theorem tls_vec.TlsByteSliceU32.serDetached (x : tls_vec.TlsByteSliceU32) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default tls_vec.TlsByteSliceU32.Insts.Tls_codecSerialize x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post tls_vec.TlsByteSliceU32.Insts.Tls_codecSerialize.SizeInst
      tls_vec.TlsByteSliceU32.Insts.Tls_codecSerialize x r).holds ⌝ ⦄ :=
  TlsVecStd.detachedB (tls_vec.TlsByteSliceU32.serSpec x) (a := Slice.len x) (k := 4#usize) rfl

theorem Shared0TlsByteSliceU32.serSpec (x : tls_vec.TlsByteSliceU32) : SerSpec Shared0TlsByteSliceU32.Insts.Tls_codecSerialize x :=
  TlsVecStd.serSpecB _ x x 4#usize 4294967295 (by have := numBits_eq_64; scalar_tac) _ max_len_U32_spec _ rfl _ _ _ prefix_U32 _ rfl _
    (fun a => by simp [tls_vec.TlsByteSliceU32.assert_written_bytes]) (fun _ _ _ => rfl) rfl

theorem Shared0TlsByteSliceU32.serDetached (x : tls_vec.TlsByteSliceU32) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default Shared0TlsByteSliceU32.Insts.Tls_codecSerialize x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post Shared0TlsByteSliceU32.Insts.Tls_codecSerialize.SizeInst
      Shared0TlsByteSliceU32.Insts.Tls_codecSerialize x r).holds ⌝ ⦄ :=
  TlsVecStd.detachedB (Shared0TlsByteSliceU32.serSpec x) (a := Slice.len x) (k := 4#usize) rfl

end tls_codec
