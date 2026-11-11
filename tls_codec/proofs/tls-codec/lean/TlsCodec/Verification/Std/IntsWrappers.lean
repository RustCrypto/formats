/- `u32` / `u64` (the `fixed_runs` pattern), and the delegating impls (`&T`, `Box<T>`,
`SecretVLBytes`) through two generic transport lemmas.

Obligations: none directly; the `std`-path halves (`Serialize` / `Deserialize` `Lawful` fields,
lemma traits) of `PanicFreedom.lean` / `FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): nothing ASSUMED; 1 signature-only stub
(`core.io.error.Error.Insts.CoreFmtDebug.fmt`). -/
import TlsCodec.Verification.Std.VecRoundTrip
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! ### `u32`, `u64` -/

theorem U32.ser_runs (x : Std.U32) : SerRuns U32.Insts.Tls_codecSerialize x 4#usize
    (some (Aeneas.Std.core.num.U32.to_be_bytes x).val) := by
  apply ser_runs_of_write_all U32.Insts.Tls_codecSerialize x
    (Array.to_slice (Aeneas.Std.core.num.U32.to_be_bytes x)) 4#usize
    (by simpa [Array.to_slice] using (Aeneas.Std.core.num.U32.to_be_bytes x).property.symm)
  intro W WI w w' hw
  obtain ⟨_, he, rfl⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (core.num.U32.to_be_bytes_spec x)
  simp only [U32.Insts.Tls_codecSerialize.tls_serialize, he, lift, bind_tc_ok, hw]
  rfl

theorem U64.ser_runs (x : Std.U64) : SerRuns U64.Insts.Tls_codecSerialize x 8#usize
    (some (Aeneas.Std.core.num.U64.to_be_bytes x).val) := by
  apply ser_runs_of_write_all U64.Insts.Tls_codecSerialize x
    (Array.to_slice (Aeneas.Std.core.num.U64.to_be_bytes x)) 8#usize
    (by simpa [Array.to_slice] using (Aeneas.Std.core.num.U64.to_be_bytes x).property.symm)
  intro W WI w w' hw
  obtain ⟨_, he, rfl⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (core.num.U64.to_be_bytes_spec x)
  simp only [U64.Insts.Tls_codecSerialize.tls_serialize, he, lift, bind_tc_ok, hw]
  rfl

theorem U32.fixed_runs : FixedRuns U32.Insts.Tls_codecDeserialize 4#usize
    Aeneas.Std.core.num.U32.from_be_bytes := by
  fixed_runs U32.Insts.Tls_codecDeserialize.tls_deserialize
    core.U32.Insts.CoreDefaultDefault.default core.num.U32.to_be_bytes_spec
    core.num.U32.from_be_bytes_spec 4#usize

theorem U64.fixed_runs : FixedRuns U64.Insts.Tls_codecDeserialize 8#usize
    Aeneas.Std.core.num.U64.from_be_bytes := by
  fixed_runs U64.Insts.Tls_codecDeserialize.tls_deserialize
    core.U64.Insts.CoreDefaultDefault.default core.num.U64.to_be_bytes_spec
    core.num.U64.from_be_bytes_spec 8#usize

theorem U32.ser_spec {W : Type} (WI : core.io.write.Write W)
    (hWI : core.io.write.Write.Lawful W WI) (x : Std.U32) (w : W)
    (hpre : (Serialize.tls_serialize.pre WI U32.Insts.Tls_codecSerialize.SizeInst
      U32.Insts.Tls_codecSerialize x w).holds) :
    ⦃ ⌜ True ⌝ ⦄ U32.Insts.Tls_codecSerialize.tls_serialize WI x w
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize.post WI U32.Insts.Tls_codecSerialize.SizeInst
      U32.Insts.Tls_codecSerialize x w r).holds ⌝ ⦄ :=
  Serialize.tls_serialize_spec_of_runs U32.Insts.Tls_codecSerialize x 4#usize rfl _
    (fun b hb => by cases hb; simpa using (Aeneas.Std.core.num.U32.to_be_bytes x).property)
    (U32.ser_runs x) WI hWI w hpre

theorem U64.ser_spec {W : Type} (WI : core.io.write.Write W)
    (hWI : core.io.write.Write.Lawful W WI) (x : Std.U64) (w : W)
    (hpre : (Serialize.tls_serialize.pre WI U64.Insts.Tls_codecSerialize.SizeInst
      U64.Insts.Tls_codecSerialize x w).holds) :
    ⦃ ⌜ True ⌝ ⦄ U64.Insts.Tls_codecSerialize.tls_serialize WI x w
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize.post WI U64.Insts.Tls_codecSerialize.SizeInst
      U64.Insts.Tls_codecSerialize x w r).holds ⌝ ⦄ :=
  Serialize.tls_serialize_spec_of_runs U64.Insts.Tls_codecSerialize x 8#usize rfl _
    (fun b hb => by cases hb; simpa using (Aeneas.Std.core.num.U64.to_be_bytes x).property)
    (U64.ser_runs x) WI hWI w hpre

theorem U32.de_spec {R : Type} (RI : alloc.io.read.Read R) (hRI : alloc.io.read.Read.Lawful R RI)
    (r : R) :
    ⦃ ⌜ True ⌝ ⦄ U32.Insts.Tls_codecDeserialize.tls_deserialize RI r
    ⦃ ⇓ p => ⌜ (Deserialize.tls_deserialize.post RI U32.Insts.Tls_codecDeserialize.SizeInst
      U32.Insts.Tls_codecDeserialize r p).holds ⌝ ⦄ :=
  Deserialize.tls_deserialize_spec_of_runs U32.Insts.Tls_codecDeserialize
    (DeRuns_of_fixed _ _ _ (fun _ => rfl) U32.fixed_runs) RI hRI r

theorem U64.de_spec {R : Type} (RI : alloc.io.read.Read R) (hRI : alloc.io.read.Read.Lawful R RI)
    (r : R) :
    ⦃ ⌜ True ⌝ ⦄ U64.Insts.Tls_codecDeserialize.tls_deserialize RI r
    ⦃ ⇓ p => ⌜ (Deserialize.tls_deserialize.post RI U64.Insts.Tls_codecDeserialize.SizeInst
      U64.Insts.Tls_codecDeserialize r p).holds ⌝ ⦄ :=
  Deserialize.tls_deserialize_spec_of_runs U64.Insts.Tls_codecDeserialize
    (DeRuns_of_fixed _ _ _ (fun _ => rfl) U64.fixed_runs) RI hRI r

/-! ### Delegating impls: transport of the contracts

`&T` and `SecretVLBytes` serialize exactly as the type they wrap, `Box<T>` (de)serializes as `T`
(aeneas represents `&T` / `Box<T>` as `T`, and the newtype `SecretVLBytes` as `VLBytes`). The
contract only depends on the serializer's runs and the size, so it transports. -/

/-- The trait-level contract of `tls_serialize`, for one value. -/
def SerSpec {T : Type} (SI : Serialize T) (x : T) : Prop :=
  ∀ (W : Type) (WI : core.io.write.Write W), core.io.write.Write.Lawful W WI → ∀ w,
    (Serialize.tls_serialize.pre WI SI.SizeInst SI x w).holds →
    ⦃ ⌜ True ⌝ ⦄ SI.tls_serialize WI x w
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize.post WI SI.SizeInst SI x w r).holds ⌝ ⦄

theorem SerSpec.runs {T : Type} {SI : Serialize T} {x : T} (h : SerSpec SI x)
    (sz : Std.Usize) (hsz : SI.SizeInst.tls_serialized_len x = ok sz) :
    SerRuns SI x sz (encOut SI x) := by
  intro W WI hWI w hroom
  obtain ⟨⟨r, w'⟩, hr, hp⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (h W WI hWI w (Serialize.tls_serialize.pre_of_bound SI WI x w sz hsz hroom))
  obtain ⟨e, he, hok, herr⟩ := Serialize.tls_serialize.post_elim SI WI x w _ hp
  refine ⟨r, w', hr, ?_, ?_⟩
  · intro b hb
    cases e with
    | Ok bv =>
      rw [encOut_ok he] at hb
      cases hb
      obtain ⟨-, h1, h2⟩ := hok bv rfl
      exact ⟨⟨_, h1, by simp [Slice.len_val, Slice.length]⟩, h2⟩
    | Err err => rw [encOut_err he] at hb; cases hb
  · intro hn
    cases e with
    | Ok bv => rw [encOut_ok he] at hn; cases hn
    | Err err => exact herr err rfl

theorem SerSpec.enc_len {T : Type} {SI : Serialize T} {x : T} (h : SerSpec SI x)
    (sz : Std.Usize) (hsz : SI.SizeInst.tls_serialized_len x = ok sz) (hroom : sz.val ≤ imax) :
    ∀ b, encOut SI x = some b → b.length = sz.val := by
  intro b hb
  obtain ⟨e, he, hes, -⟩ := encode_of_runs SI x sz _ (h.runs sz hsz) hroom
  obtain ⟨bv, rfl, hbv⟩ := hes b hb
  obtain ⟨⟨r2, w2⟩, hr2, hp2⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (h _ _ StdIo.vec_lawful ⟨[], by simp⟩
      (Serialize.tls_serialize.pre_of_bound SI _ x _ sz hsz (by rw [StdIo.vec_sink]; simpa using hroom)))
  obtain ⟨e2, he2, hok2, -⟩ := Serialize.tls_serialize.post_elim SI _ x _ _ hp2
  rw [he] at he2; cases he2
  obtain ⟨h1, -, -⟩ := hok2 bv rfl
  rw [hsz] at h1; cases h1
  rw [← hbv]; simp [Slice.len_val, Slice.length]

/-- Transport: a serializer running as `SI`'s on `x`, with the same size, meets the contract. -/
theorem SerSpec.transport {T : Type} {SI : Serialize T} {x : T} (h : SerSpec SI x)
    (SI' : Serialize T)
    (hser : ∀ (W : Type) (WI : core.io.write.Write W) w, SI'.tls_serialize WI x w = SI.tls_serialize WI x w)
    (hsz : SI'.SizeInst.tls_serialized_len x = SI.SizeInst.tls_serialized_len x)
    (hS : ∃ sz, SI.SizeInst.tls_serialized_len x = ok sz) : SerSpec SI' x := by
  intro W WI hWI w hpre
  obtain ⟨sz, hsz0⟩ := hS
  have hr : SerRuns SI' x sz (encOut SI x) := by
    intro W' WI' hWI' w' hroom
    rw [hser]
    exact h.runs sz hsz0 W' WI' hWI' w' hroom
  exact Serialize.tls_serialize_spec_of_runs' SI' x sz (hsz.trans hsz0) _
    (fun hle b hb => h.enc_len sz hsz0 hle b hb) hr WI hWI w hpre

/-- The trait-level contract of `tls_deserialize`. -/
def DeSpec {T : Type} (DI : Deserialize T) : Prop :=
  ∀ (R : Type) (RI : alloc.io.read.Read R), alloc.io.read.Read.Lawful R RI → ∀ r,
    ⦃ ⌜ True ⌝ ⦄ DI.tls_deserialize RI r
    ⦃ ⇓ p => ⌜ (Deserialize.tls_deserialize.post RI DI.SizeInst DI r p).holds ⌝ ⦄

theorem DeSpec.runs {T : Type} {DI : Deserialize T} (h : DeSpec DI) :
    DeRuns DI (fun _ _ _ => True) := by
  intro R RI v a law r
  have hRI : alloc.io.read.Read.Lawful R RI := ⟨⟨v, a, law⟩⟩
  refine triple_post_mono (h R RI hRI r) ?_
  intro p hp val hval
  obtain ⟨⟨n, hn, hp2⟩, sz, hsz, hlen⟩ := Deserialize.tls_deserialize.post_elim DI RI r p val hval hp
  rw [StdIo.view_eq law] at hn hlen
  rw [StdIo.adv_eq law r n hn] at hp2
  rw [hp2, StdIo.view_eq law, law.adv_view r n hn, List.length_drop] at hlen
  exact ⟨n, sz, hn, hp2, hsz, by omega, trivial⟩

/-- Transport: a deserializer running as `DI`'s, with the same sizes, meets the contract. -/
theorem DeSpec.transport {T : Type} {DI : Deserialize T} (h : DeSpec DI) (DI' : Deserialize T)
    (hde : ∀ (R : Type) (RI : alloc.io.read.Read R) r, DI'.tls_deserialize RI r = DI.tls_deserialize RI r)
    (hsz : ∀ x, DI'.SizeInst.tls_serialized_len x = DI.SizeInst.tls_serialized_len x) :
    DeSpec DI' := by
  have hr : DeRuns DI' (fun _ _ _ => True) := by
    intro R RI v a law r
    rw [hde]
    refine triple_post_mono (h.runs R RI v a law r) ?_
    intro p hp val hval
    obtain ⟨n, sz, h1, h2, h3, h4, h5⟩ := hp val hval
    exact ⟨n, sz, h1, h2, (hsz val).trans h3, h4, h5⟩
  intro R RI hRI r
  exact Deserialize.tls_deserialize_spec_of_runs DI' hr RI hRI r

/-- The `?`-rewrap of a deserializer result (`Ok(T::tls_deserialize(r)?)`) is the identity. -/
theorem rewrap_de_eq {T R : Type} (m : RustM (core.result.Result T Error × R)) :
    (do
      let (r, bytes1) ← m
      let cf ← core.result.Result.Insts.CoreOpsTry_traitTry.branch r
      match cf with
      | core.ops.control_flow.ControlFlow.Continue val => ok (core.result.Result.Ok val, bytes1)
      | core.ops.control_flow.ControlFlow.Break residual =>
        let r1 ← core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
          T (core.convert.From.Blanket Error) residual
        ok (r1, bytes1) : RustM (core.result.Result T Error × R)) = m := by
  rcases m with ⟨res, b⟩ | e | _
  · cases res <;> rfl
  · rfl
  · rfl

theorem Box.de_eq {T R : Type} (DI : Deserialize T) (RI : alloc.io.read.Read R) (r : R) :
    Box.Insts.Tls_codecDeserialize.tls_deserialize DI RI r = DI.tls_deserialize RI r :=
  rewrap_de_eq _

theorem SecretVLBytes.de_eq {R : Type} (RI : alloc.io.read.Read R) (r : R) :
    quic_vec.secret_bytes.SecretVLBytes.Insts.Tls_codecDeserialize.tls_deserialize RI r =
      quic_vec.VLBytes.Insts.Tls_codecDeserialize.tls_deserialize RI r := by
  unfold quic_vec.secret_bytes.SecretVLBytes.Insts.Tls_codecDeserialize.tls_deserialize
  generalize quic_vec.VLBytes.Insts.Tls_codecDeserialize.tls_deserialize RI r = m
  rcases m with ⟨res, b⟩ | e | _
  · cases res <;> rfl
  · rfl
  · rfl

/-- The default `tls_serialize_detached`, from the contract of `tls_serialize` on one value. -/
theorem SerSpec.detached {T : Type} {SI : Serialize T} {x : T} (h : SerSpec SI x)
    (hS : ∃ sz, SI.SizeInst.tls_serialized_len x = ok sz) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default SI x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post SI.SizeInst SI x r).holds ⌝ ⦄ := by
  obtain ⟨sz, hsz⟩ := hS
  exact Serialize.tls_serialize_detached.default_spec SI x sz hsz
    (fun w hpre => h _ _ StdIo.vec_lawful w hpre)

/-- The default `tls_deserialize_exact`, from the contract of `tls_deserialize`. -/
theorem DeSpec.exact {T T1 : Type} {DI : Deserialize T} (h : DeSpec DI)
    (AI : core.convert.AsRef T1 (Slice Std.U8)) (hAI : core.convert.AsRef.Lawful T1 (Slice Std.U8) AI)
    (bytes : T1) :
    ⦃ ⌜ True ⌝ ⦄ Deserialize.tls_deserialize_exact.default DI AI bytes
    ⦃ ⇓ r => ⌜ (Deserialize.tls_deserialize_exact.post DI.SizeInst DI AI bytes r).holds ⌝ ⦄ :=
  Deserialize.tls_deserialize_exact.default_spec DI AI hAI bytes (fun s => h _ _ StdIo.slice_lawful s)

theorem Serialize.Lawful.serSpec {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI) (x : T) :
    SerSpec SI x := fun _ WI hWI w h => hL.tls_serialize_spec WI hWI x w h

theorem Deserialize.Lawful.deSpec {T : Type} {DI : Deserialize T} (hL : Deserialize.Lawful T DI) :
    DeSpec DI := fun _ RI hRI r => hL.tls_deserialize_spec RI hRI r (pre_holds_of_ok_true rfl)

/-! #### Per-type contracts -/

theorem U8.serSpec (x : Std.U8) : SerSpec U8.Insts.Tls_codecSerialize x :=
  fun _ WI hWI w h => U8.ser_spec WI hWI x w h
theorem U16.serSpec (x : Std.U16) : SerSpec U16.Insts.Tls_codecSerialize x :=
  fun _ WI hWI w h => U16.ser_spec WI hWI x w h
theorem U32.serSpec (x : Std.U32) : SerSpec U32.Insts.Tls_codecSerialize x :=
  fun _ WI hWI w h => U32.ser_spec WI hWI x w h
theorem U64.serSpec (x : Std.U64) : SerSpec U64.Insts.Tls_codecSerialize x :=
  fun _ WI hWI w h => U64.ser_spec WI hWI x w h
theorem VLBytes.serSpec (x : quic_vec.VLBytes) : SerSpec quic_vec.VLBytes.Insts.Tls_codecSerialize x :=
  fun _ WI hWI w h => VLBytes.ser_spec WI hWI x w h

theorem U32.deSpec : DeSpec U32.Insts.Tls_codecDeserialize := fun _ RI hRI r => U32.de_spec RI hRI r
theorem U64.deSpec : DeSpec U64.Insts.Tls_codecDeserialize := fun _ RI hRI r => U64.de_spec RI hRI r
theorem VLBytes.deSpec : DeSpec quic_vec.VLBytes.Insts.Tls_codecDeserialize :=
  fun _ RI hRI r => VLBytes.de_spec RI hRI r

theorem VLBytes.size_ex (x : quic_vec.VLBytes) :
    ∃ sz, quic_vec.VLBytes.Insts.Tls_codecSize.tls_serialized_len x = ok sz := by
  obtain ⟨sz, h, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (quic_vec.VLBytes.size_pos x)
  exact ⟨sz, h⟩

/-- `&u8` .. `&u64`: as the integer. -/
theorem Shared0U8.serSpec (x : Std.U8) : SerSpec Shared0U8.Insts.Tls_codecSerialize x :=
  (U8.serSpec x).transport _ (fun _ _ _ => rfl) rfl ⟨_, rfl⟩
theorem Shared0U16.serSpec (x : Std.U16) : SerSpec Shared0U16.Insts.Tls_codecSerialize x :=
  (U16.serSpec x).transport _ (fun _ _ _ => rfl) rfl ⟨_, rfl⟩
theorem Shared0U32.serSpec (x : Std.U32) : SerSpec Shared0U32.Insts.Tls_codecSerialize x :=
  (U32.serSpec x).transport _ (fun _ _ _ => rfl) rfl ⟨_, rfl⟩
theorem Shared0U64.serSpec (x : Std.U64) : SerSpec Shared0U64.Insts.Tls_codecSerialize x :=
  (U64.serSpec x).transport _ (fun _ _ _ => rfl) rfl ⟨_, rfl⟩
theorem Shared0VLBytes.serSpec (x : quic_vec.VLBytes) :
    SerSpec Shared0VLBytes.Insts.Tls_codecSerialize x :=
  (VLBytes.serSpec x).transport _ (fun _ _ _ => rfl) rfl (VLBytes.size_ex x)

/-- `&Option<T>`: as `Option<T>`. -/
theorem Shared0Option.serSpec {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : core.option.Option T) : SerSpec (Shared0Option.Insts.Tls_codecSerialize SI) x :=
  (show SerSpec (core.option.Option.Insts.Tls_codecSerialize SI) x from
    fun _ WI hWI w h => Option.ser_spec hL WI hWI x w h).transport _ (fun _ _ _ => rfl) rfl
    (Option.size_ok hL.SizeInstLawful x)

/-- `Box<T>`: as `T`. -/
theorem Box.serSpec {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI) (x : T) :
    SerSpec (Box.Insts.Tls_codecSerialize SI) x :=
  (hL.serSpec x).transport _ (fun _ _ _ => rfl) rfl (Size.lawful_ok _ hL.SizeInstLawful x)

theorem Box.deSpec {T : Type} {DI : Deserialize T} (hL : Deserialize.Lawful T DI) :
    DeSpec (Box.Insts.Tls_codecDeserialize DI) :=
  hL.deSpec.transport _ (fun _ RI r => Box.de_eq DI RI r) (fun _ => rfl)

/-- `SecretVLBytes`: as `VLBytes`. -/
theorem SecretVLBytes.serSpec (x : quic_vec.secret_bytes.SecretVLBytes) :
    SerSpec quic_vec.secret_bytes.SecretVLBytes.Insts.Tls_codecSerialize x :=
  SerSpec.transport (T := quic_vec.secret_bytes.SecretVLBytes)
    (SI := quic_vec.VLBytes.Insts.Tls_codecSerialize) (VLBytes.serSpec x) _
    (fun _ _ _ => rfl) rfl (VLBytes.size_ex x)

theorem SecretVLBytes.deSpec : DeSpec quic_vec.secret_bytes.SecretVLBytes.Insts.Tls_codecDeserialize :=
  DeSpec.transport (T := quic_vec.secret_bytes.SecretVLBytes)
    (DI := quic_vec.VLBytes.Insts.Tls_codecDeserialize) VLBytes.deSpec _
    (fun _ RI r => SecretVLBytes.de_eq RI r) (fun _ => rfl)

end tls_codec
