/- Round trip of the `std` path (`RoundTripStd`, `NonEmptyStd`) of composed codecs: the
downstream crates' derived and hand-written impls.

`RtStd SI DI L B`: on every lawful writer with room for `B` bytes the serializer appends the
encoding of the value (between `L` and `B` bytes, of the value's size) or returns `Err`, and the
deserializer gives the value back from its encoding. Leaves get it from their contracts plus the
fact that a value larger than `B` never serializes (`RtStd.of_lawful`, `RtStd.of_const`; `u16`,
`VLBytes`, `Vec<T>`); derived structs, newtypes and `u16` enums from their fields
(`derive_rt_std`, `derive_rt_std_flat`). A `RoundTripStd` / `NonEmptyStd` `Lawful` then follows
(`RoundTripStd.lawful_of_rtStd`, `NonEmptyStd.lawful_of_rtStd`).

Obligations: none in TlsCodec; the downstream round-trip obligations use it.
Axioms reached (`scripts/axiom_whitelist.txt`): ASSUMED `size_of`, `size_of_U16`, `numBits_eq_64`
(`imax_64` only: the room for compositions above `2^31 - 1` bytes); 1 signature-only stub
(`core.io.error.Error.Insts.CoreFmtDebug.fmt`); `native_decide` (1, through `Vec<T>`). -/
import TlsCodec.Verification.ProofObligations
import TlsCodec.Verification.Derive.Std
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec.Derive
open tls_codec

/-! ## The predicate -/

/-- Round-trip facts of a `std` codec pair whose encodings have between `L` and `B` bytes. -/
structure RtStd {T : Type} (SI : Serialize T) (DI : Deserialize T) (L B : Nat) : Prop where
  room : B ≤ imax
  ser : ∀ (x : T) (W : Type) (WI : core.io.write.Write W), core.io.write.Write.Lawful W WI →
    ∀ w : W, (core.io.write.Write.view WI w).length + B ≤ imax →
    ⦃ ⌜ True ⌝ ⦄ SI.tls_serialize WI x w
    ⦃ ⇓ p => ⌜ SerPost WI (encOut SI x) (szv SI.SizeInst x).val w p ⌝ ⦄
  bound : ∀ x b, encOut SI x = some b → b.length ≤ B
  lo : ∀ x b, encOut SI x = some b → L ≤ b.length
  dec : ∀ x b, encOut SI x = some b → DecodesTo DI b x

theorem encOut_some {T : Type} {SI : Serialize T} {x : T} {b : List Std.U8}
    (h : encOut SI x = some b) :
    ∃ bv : alloc.vec.Vec Std.U8, spec.io.encode SI x = ok (.Ok bv) ∧ (bv : Slice Std.U8).val = b := by
  unfold encOut at h
  split at h
  · rename_i hex
    exact ⟨_, Classical.choose_spec hex, Option.some.inj h⟩
  · cases h

/-- `encode` from the behaviour of the serializer on writers with room for `B` bytes. -/
theorem encode_of_post {T : Type} (SI : Serialize T) (x : T) (o : Option (List Std.U8))
    (sz B : Nat) (hB : B ≤ imax)
    (h : ∀ (W : Type) (WI : core.io.write.Write W), core.io.write.Write.Lawful W WI →
      ∀ w : W, (core.io.write.Write.view WI w).length + B ≤ imax →
      ⦃ ⌜ True ⌝ ⦄ SI.tls_serialize WI x w ⦃ ⇓ p => ⌜ SerPost WI o sz w p ⌝ ⦄) :
    (∀ b, o = some b → ∃ bv : alloc.vec.Vec Std.U8,
      spec.io.encode SI x = ok (.Ok bv) ∧ (bv : Slice Std.U8).val = b) ∧
    (o = none → ∃ e, spec.io.encode SI x = ok (.Err e)) := by
  obtain ⟨⟨r, w'⟩, hr, hp⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (h _ alloc.vec.VecU8.Insts.CoreIoWriteWrite StdIo.vec_lawful ⟨[], by simp⟩
      (by rw [StdIo.vec_sink]; simpa using hB))
  have hnew : CoreModels.alloc.vec.Vec.new Std.U8 = ok ⟨[], by simp⟩ := rfl
  cases r with
  | Ok n =>
    obtain ⟨-, b, hb, -, hv⟩ := hp.1 n rfl
    have he : spec.io.encode SI x = ok (.Ok w') := by
      unfold spec.io.encode; rw [hnew]; simp only [bind_tc_ok]; rw [hr]; rfl
    rw [StdIo.vec_sink, StdIo.vec_sink] at hv
    subst hb
    refine ⟨fun b' hb' => ⟨w', he, ?_⟩, fun h => (by cases h)⟩
    cases hb'
    simpa using hv
  | Err e =>
    have ho := hp.2 e rfl
    subst ho
    refine ⟨fun b hb => (by cases hb), fun _ => ⟨e, ?_⟩⟩
    unfold spec.io.encode; rw [hnew]; simp only [bind_tc_ok]; rw [hr]; rfl

theorem encOut_of_post {T : Type} (SI : Serialize T) (x : T) (o : Option (List Std.U8))
    (sz B : Nat) (hB : B ≤ imax)
    (h : ∀ (W : Type) (WI : core.io.write.Write W), core.io.write.Write.Lawful W WI →
      ∀ w : W, (core.io.write.Write.view WI w).length + B ≤ imax →
      ⦃ ⌜ True ⌝ ⦄ SI.tls_serialize WI x w ⦃ ⇓ p => ⌜ SerPost WI o sz w p ⌝ ⦄) :
    encOut SI x = o := by
  obtain ⟨hs, hn⟩ := encode_of_post SI x o sz B hB h
  cases o with
  | some b => obtain ⟨bv, he, hb⟩ := hs b rfl; rw [encOut_ok he, hb]
  | none => obtain ⟨e, he⟩ := hn rfl; exact encOut_err he

/-- The encoding of a successful `encode` is the one `RtStd` speaks of. -/
theorem RtStd.encode_cases {T : Type} {SI : Serialize T} {DI : Deserialize T} {L B : Nat}
    (h : RtStd SI DI L B) (x : T) :
    (∃ bv : alloc.vec.Vec Std.U8, spec.io.encode SI x = ok (.Ok bv) ∧
      encOut SI x = some (bv : Slice Std.U8).val) ∨
    (∃ e, spec.io.encode SI x = ok (.Err e)) := by
  have := encode_of_post SI x (encOut SI x) _ B h.room (h.ser x)
  cases ho : encOut SI x with
  | some b =>
    obtain ⟨bv, he, hb⟩ := this.1 b ho
    exact Or.inl ⟨bv, he, by rw [hb]⟩
  | none => exact Or.inr (this.2 ho)

/-- `isize::MAX` on the 64-bit targets (ASSUMED `numBits_eq_64`): room for any composition of
MLS-bounded encodings. -/
theorem imax_64 : 2 ^ 62 ≤ imax := by
  have h := imax_eq
  have h64 := numBits_eq_64
  simp [Usize.max, Usize.numBits, h64] at h
  omega

/-! ## From the predicate to the lemma traits -/

theorem RoundTripStd.lawful_of_rtStd {T : Type} (RT : spec.io.RoundTripStd T)
    (hS : Serialize.Lawful T RT.SerializeInst) (hD : Deserialize.Lawful T RT.DeserializeInst)
    (hEq : core.cmp.PartialEq.Lawful T T RT.corecmpPartialEqInst) {L B : Nat}
    (h : RtStd RT.SerializeInst RT.DeserializeInst L B)
    (hex : ∀ s : Slice Std.U8, RT.DeserializeInst.tls_deserialize_exact
        (core.Shared0T.Insts.CoreConvertAsRef (core.Slice.Insts.CoreConvertAsRefSlice Std.U8)) s =
      Deserialize.tls_deserialize_exact.default RT.DeserializeInst
        (core.Shared0T.Insts.CoreConvertAsRef (core.Slice.Insts.CoreConvertAsRefSlice Std.U8)) s)
    (hrt : ∀ {R : Type} (RI : alloc.io.read.Read R),
      RT.round_trip_std RI = spec.io.RoundTripStd.round_trip_std.default RI)
    (hre : RT.round_trip_exact = spec.io.RoundTripStd.round_trip_exact.default) :
    spec.io.RoundTripStd.Lawful T RT where
  SerializeInstLawful := hS
  DeserializeInstLawful := hD
  corecmpPartialEqInstLawful := hEq
  round_trip_std_spec RI hRI x reader rest hpre := by
    rw [hrt]
    rcases h.encode_cases x with ⟨bv, he, ho⟩ | ⟨e, he⟩
    · exact spec.io.RoundTripStd.round_trip_std_of RT hEq x bv he (h.dec x _ ho) RI hRI reader rest
        hpre
    · exact (spec.io.RoundTripStd.round_trip_std.pre_err RT RI x reader rest e he hpre).elim
  round_trip_exact_spec x _ := by
    rw [hre]
    rcases h.encode_cases x with ⟨bv, he, ho⟩ | ⟨e, he⟩
    · exact spec.io.RoundTripStd.round_trip_exact_of RT hEq x bv he fun s hs => by
        rw [hex]
        exact Deserialize.tls_deserialize_exact.default_decodes _ _ x (h.dec x _ ho) s hs
    · exact spec.io.RoundTripStd.round_trip_exact_err RT x e he

theorem NonEmptyStd.lawful_of_rtStd {T : Type} (NE : spec.io.NonEmptyStd T)
    (hRT : spec.io.RoundTripStd.Lawful T NE.RoundTripStdInst) {L B : Nat}
    (h : RtStd NE.RoundTripStdInst.SerializeInst NE.RoundTripStdInst.DeserializeInst L B)
    (hL : 1 ≤ L)
    (hd : NE.nonempty_std = spec.io.NonEmptyStd.nonempty_std.default) :
    spec.io.NonEmptyStd.Lawful T NE where
  RoundTripStdInstLawful := hRT
  nonempty_std_spec x _ := by
    rw [hd]
    rcases h.encode_cases x with ⟨bv, he, ho⟩ | ⟨e, he⟩
    · refine spec.io.NonEmptyStd.nonempty_std_of NE x bv he fun hn => ?_
      have := h.lo x _ ho
      rw [hn] at this
      simp at this
      omega
    · exact spec.io.NonEmptyStd.nonempty_std_err NE x e he

/-- `DecodesTo` of a lawful `RoundTripStd`, through `encOut`. -/
theorem rt_decodes_out {T : Type} {RT : spec.io.RoundTripStd T}
    (h : spec.io.RoundTripStd.Lawful T RT) (x : T) (b : List Std.U8)
    (hb : encOut RT.SerializeInst x = some b) : DecodesTo RT.DeserializeInst b x := by
  obtain ⟨bv, he, rfl⟩ := encOut_some hb
  exact h.decodes x bv he

/-! ## Leaves -/

/-- `RtStd` of a codec meeting its contracts, whose values of size above `B` never serialize. -/
theorem RtStd.of_lawful {T : Type} {SI : Serialize T} {DI : Deserialize T} {L B : Nat}
    (hL : Serialize.Lawful T SI) (hB : B ≤ imax)
    (big : ∀ x, B < (szv SI.SizeInst x).val → ∀ (W : Type) (WI : core.io.write.Write W),
      core.io.write.Write.Lawful W WI → ∀ w : W,
      (core.io.write.Write.view WI w).length + B ≤ imax →
      ⦃ ⌜ True ⌝ ⦄ SI.tls_serialize WI x w ⦃ ⇓ p => ⌜ ∃ e, p.1 = .Err e ⌝ ⦄)
    (lo : ∀ x b, encOut SI x = some b → L ≤ b.length)
    (dec : ∀ x b, encOut SI x = some b → DecodesTo DI b x) : RtStd SI DI L B := by
  have hnone : ∀ x, B < (szv SI.SizeInst x).val → encOut SI x = none := fun x hx =>
    encOut_of_post SI x none 0 B hB fun W WI hWI w hr =>
      triple_post_mono (big x hx W WI hWI w hr) fun p ⟨e, he⟩ => by
        obtain ⟨r, w'⟩ := p; simp only at he; subst he; simp
  refine ⟨hB, fun x W WI hWI w hr => ?_, fun x b hb => ?_, lo, dec⟩
  · by_cases hx : (szv SI.SizeInst x).val ≤ B
    · exact fun _ => ser_std_spec hL WI hWI x w (show (core.io.write.Write.view WI w).length + (szv SI.SizeInst x).val ≤ imax by omega)
    · rw [hnone x (by omega)]
      exact triple_post_mono (big x (by omega) W WI hWI w hr) fun p ⟨e, he⟩ => by
        obtain ⟨r, w'⟩ := p; simp only at he; subst he; simp
  · by_cases hx : (szv SI.SizeInst x).val ≤ B
    · rw [hL.enc_len x _ (size_ok hL.SizeInstLawful x) (by omega) b hb]; exact hx
    · rw [hnone x (by omega)] at hb; cases hb

/-- `RtStd` of a codec of constant size `n ≤ B`. -/
theorem RtStd.of_const {T : Type} {SI : Serialize T} {DI : Deserialize T} {L B : Nat}
    (hL : Serialize.Lawful T SI) (hB : B ≤ imax) (hsz : ∀ x, (szv SI.SizeInst x).val ≤ B)
    (lo : ∀ x b, encOut SI x = some b → L ≤ b.length)
    (dec : ∀ x b, encOut SI x = some b → DecodesTo DI b x) : RtStd SI DI L B :=
  RtStd.of_lawful hL hB (fun x hx => absurd (hsz x) (by omega)) lo dec

theorem U16.encOut (x : Std.U16) :
    encOut U16.Insts.Tls_codecSerialize x = some (Aeneas.Std.core.num.U16.to_be_bytes x).val := by
  have := imax_ge
  obtain ⟨e, he, hs, -⟩ := encode_of_runs _ x _ _ (U16.ser_runs x) (by simp; omega)
  obtain ⟨bv, rfl, hbv⟩ := hs _ rfl
  rw [encOut_ok he, hbv]

theorem U16.decodes (x : Std.U16) :
    DecodesTo U16.Insts.Tls_codecDeserialize (Aeneas.Std.core.num.U16.to_be_bytes x).val x := by
  have h := DecodesTo_of_fixed _ _ _ U16.fixed_runs (Aeneas.Std.core.num.U16.to_be_bytes x)
  rwa [U16_from_be_bytes_to_be_bytes] at h

theorem U16.rtStd : RtStd U16.Insts.Tls_codecSerialize U16.Insts.Tls_codecDeserialize 2 2 := by
  have := imax_ge
  refine RtStd.of_const U16.Insts.Tls_codecSerialize.Lawful (by omega)
    (fun x => by rw [szv_eq (u16_size x)]; simp) (fun x b hb => ?_) fun x b hb => ?_
  · rw [U16.encOut] at hb; cases hb; simp
  · rw [U16.encOut] at hb
    cases hb
    exact U16.decodes x

/-- The size of a `VLBytes` value whose length fits the MLS bound. -/
theorem VLBytes.szv_small (x : quic_vec.VLBytes) (hx : x.vec.val.length ≤ 2 ^ 30 - 1) :
    (szv quic_vec.VLBytes.Insts.Tls_codecSize x).val ≤ 2 ^ 30 + 3 := by
  obtain ⟨sz, hsz, hv⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (quic_vec.VLBytes.serialized_len_char x hx)
  rw [szv_eq hsz, hv]
  unfold varint.lenOf
  split_ifs <;> omega

theorem VLBytes.rtStd :
    RtStd quic_vec.VLBytes.Insts.Tls_codecSerialize quic_vec.VLBytes.Insts.Tls_codecDeserialize
      1 (2 ^ 30 + 3) := by
  have := imax_ge
  refine RtStd.of_lawful quic_vec.VLBytes.Insts.Tls_codecSerialize.Lawful (by omega)
    (fun x hx W WI hWI w _ => ?_) (fun x b hb => ?_)
    (rt_decodes_out quic_vec.VLBytes.Insts.Tls_codecSpecIoRoundTripStd.Lawful)
  · change 2 ^ 30 + 3 < (szv quic_vec.VLBytes.Insts.Tls_codecSize x).val at hx
    have hbig : 2 ^ 30 - 1 < x.vec.val.length := by
      by_contra hc; have := VLBytes.szv_small x (by omega); omega
    exact triple_post_mono (VLBytes.ser_triple (core.io.write.Write.Lawful.law' hWI) w x
      (fun h => absurd h (by omega))) fun p hp => (hp.2 hbig).1
  · obtain ⟨bv, he, rfl⟩ := encOut_some hb
    by_cases hx : x.vec.val.length ≤ 2 ^ 30 - 1
    · obtain ⟨bv', he', hbv⟩ := VLBytes.encode_ok x hx
      rw [he] at he'
      cases he'
      rw [hbv, List.length_append, varint.enc_length]
      have := varint.lenOf_pos x.vec.val.length
      omega
    · obtain ⟨e, he'⟩ := VLBytes.encode_big x (by omega)
      rw [he] at he'; cases he'

/-! ## Derived codecs -/

/-- A field decoder call, in the form `mvcgen` uses: on a reader starting with `b`, it returns
`x` and consumes `b`. -/
theorem DecodesTo.spec {T : Type} {DI : Deserialize T} {b : List Std.U8} {x : T}
    (h : DecodesTo DI b x) {R : Type} {RI : alloc.io.read.Read R} {v : R → List Std.U8}
    {a : R → Nat → R} (law : StdIo.RLaw RI v a) (r : R) :
    ⦃ ⌜ ∃ rest, v r = b ++ rest ⌝ ⦄ DI.tls_deserialize RI r
    ⦃ ⇓ p => ⌜ p.1 = .Ok x ∧ v r = b ++ v p.2 ⌝ ⦄ := by
  intro hpre
  obtain ⟨rest, hv⟩ := hpre
  exact triple_post_mono (h _ RI v a law r rest hv) (fun p hp => ⟨hp.1, by rw [hv, hp.2]⟩) trivial

/-- A field serializer call, in the form `mvcgen` uses. -/
theorem RtStd.ser_spec {T : Type} {SI : Serialize T} {DI : Deserialize T} {L B : Nat}
    (h : RtStd SI DI L B) {W : Type} (WI : core.io.write.Write W)
    (hWI : core.io.write.Write.Lawful W WI) (x : T) (w : W) :
    ⦃ ⌜ (core.io.write.Write.view WI w).length + B ≤ imax ⌝ ⦄ SI.tls_serialize WI x w
    ⦃ ⇓ p => ⌜ SerPost WI (encOut SI x) (szv SI.SizeInst x).val w p ⌝ ⦄ :=
  fun hr => h.ser x W WI hWI w hr trivial

/-- `RtStd` from, for each value, an encoding `o` that the serializer appends on writers with
room for `B` bytes, of at most `B` bytes and decoding back to the value. -/
theorem RtStd.of_post {T : Type} {SI : Serialize T} {DI : Deserialize T} {L B : Nat}
    (hB : B ≤ imax)
    (h : ∀ x : T, ∃ o : Option (List Std.U8),
      (∀ (W : Type) (WI : core.io.write.Write W), core.io.write.Write.Lawful W WI →
        ∀ w : W, (core.io.write.Write.view WI w).length + B ≤ imax →
        ⦃ ⌜ True ⌝ ⦄ SI.tls_serialize WI x w
        ⦃ ⇓ p => ⌜ SerPost WI o (szv SI.SizeInst x).val w p ⌝ ⦄) ∧
      (∀ b, o = some b → b.length ≤ B ∧ L ≤ b.length ∧ DecodesTo DI b x)) :
    RtStd SI DI L B := by
  refine ⟨hB, fun x W WI hWI w hr => ?_, fun x b hb => ?_, fun x b hb => ?_, fun x b hb => ?_⟩
  · obtain ⟨o, hs, -⟩ := h x
    rw [encOut_of_post SI x o _ B hB hs]; exact hs W WI hWI w hr
  · obtain ⟨o, hs, hd⟩ := h x
    rw [encOut_of_post SI x o _ B hB hs] at hb; exact (hd b hb).1
  · obtain ⟨o, hs, hd⟩ := h x
    rw [encOut_of_post SI x o _ B hB hs] at hb; exact (hd b hb).2.1
  · obtain ⟨o, hs, hd⟩ := h x
    rw [encOut_of_post SI x o _ B hB hs] at hb; exact (hd b hb).2.2

open Lean Elab Tactic Meta in
/-- For every hypothesis `h : encOut S x = some b` and bound `f : ∀ x b, encOut S x = some b →
b.length ≤ B` of `fs` that applies, adds `f x b h`. -/
elab "rt_bounds " "[" fs:term,* "]" : tactic => withMainContext do
  let mut hs : Array Expr := #[]
  for d in (← getLCtx) do
    if d.isImplementationDetail then continue
    let ty ← instantiateMVars d.type
    let some (_, lhs, _) := ty.eq? | continue
    unless lhs.isAppOf ``encOut do continue
    hs := hs.push d.toExpr
  for h in hs do
    for f in fs.getElems do
      let g ← getMainGoal
      let r ← observing? (g.withContext do
        let fe ← Term.elabTerm f none
        Term.synthesizeSyntheticMVarsNoPostponing
        let e ← mkAppOptM' fe #[none, none, some h]
        let e ← instantiateMVars e
        let ty ← inferType e
        let g' ← g.assert `h_rtb ty e
        let (_, g') ← g'.intro1P
        return g')
      if let some g' := r then replaceMainGoal [g']

/-- A field decoder call, in the form `mvcgen` uses: on a reader starting with an encoding, the
decoder returns the encoded value and consumes the encoding (for every such encoding). -/
theorem RtStd.de_spec {T : Type} {SI : Serialize T} {DI : Deserialize T} {L B : Nat}
    (h : RtStd SI DI L B) {R : Type} {RI : alloc.io.read.Read R} {v : R → List Std.U8}
    {a : R → Nat → R} (law : StdIo.RLaw RI v a) (r : R) :
    ⦃ ⌜ ∃ y b rest, encOut SI y = some b ∧ v r = b ++ rest ⌝ ⦄ DI.tls_deserialize RI r
    ⦃ ⇓ p => ⌜ ∀ y b rest, encOut SI y = some b → v r = b ++ rest →
      p.1 = .Ok y ∧ v p.2 = rest ⌝ ⦄ := by
  intro hpre
  obtain ⟨y, b, rest, hb, hv⟩ := hpre
  obtain ⟨p, hp, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (h.dec y b hb _ RI v a law r rest hv)
  rw [hp]
  refine ok_triple_of (fun y' b' rest' hb' hv' => ?_) trivial
  obtain ⟨p', hp', hpost⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (h.dec y' b' hb' _ RI v a law r rest' hv')
  rw [hp] at hp'
  cases hp'
  exact hpost

open Lean Elab Tactic Meta in
/-- Instantiates the field-decoder posts of `RtStd.de_spec` (`∀ y b rest, encOut S y = some b →
v r = b ++ rest → …`) with the encodings `encOut S x = some b` and reader equations `v r = b ++ s`
of the context, until none applies. -/
elab "rt_dec_inst" : tactic => do
  let mut used : Array (FVarId × FVarId) := #[]
  let mut fuel := 64
  while fuel > 0 do
    fuel := fuel - 1
    let g ← getMainGoal
    let found ← g.withContext do
      let mut encs : Array LocalDecl := #[]
      let mut eqs : Array LocalDecl := #[]
      let mut alls : Array LocalDecl := #[]
      for d in (← getLCtx) do
        if d.isImplementationDetail then continue
        let ty ← instantiateMVars d.type
        if let some (_, lhs, _) := ty.eq? then
          if lhs.isAppOf ``encOut then encs := encs.push d else eqs := eqs.push d
        else if ty.isForall then alls := alls.push d
      for H in alls do
        for h in encs do
          if used.contains (H.fvarId, h.fvarId) then continue
          for E in eqs do
            let r ← observing? do
              let e ← mkAppOptM' H.toExpr #[none, none, none, some h.toExpr, some E.toExpr]
              let e ← instantiateMVars e
              if e.hasExprMVar then throwError "rt_dec_inst: unassigned"
              return e
            if let some e := r then return some (H.fvarId, h.fvarId, e)
      return none
    let some (H, h, e) := found | break
    used := used.push (H, h)
    let g ← getMainGoal
    let g ← g.withContext do
      let e1 ← mkAppM ``And.left #[e]
      let e2 ← mkAppM ``And.right #[e]
      let (_, g) ← (← g.assert (← mkFreshUserName `h_rtd) (← inferType e1) e1).intro1P
      let (_, g) ← (← g.assert (← mkFreshUserName `h_rtd) (← inferType e2) e2).intro1P
      return g
    replaceMainGoal [g]
  evalTactic (← `(tactic| try simp only [List.append_assoc, List.append_nil] at *))

open Lean Elab Tactic Meta in
/-- Closes a field-decoder precondition `∃ y b rest, encOut S y = some b ∧ v r = b ++ rest` from
an encoding and a reader equation of the context. -/
elab "rt_dec_pre" : tactic => withMainContext do
  let mut encs : Array LocalDecl := #[]
  let mut eqs : Array LocalDecl := #[]
  for d in (← getLCtx) do
    if d.isImplementationDetail then continue
    let ty ← instantiateMVars d.type
    if let some (_, lhs, _) := ty.eq? then
      if lhs.isAppOf ``encOut then encs := encs.push d else eqs := eqs.push d
  for h in encs do
    for E in eqs do
      let hs ← Term.exprToSyntax h.toExpr
      let es ← Term.exprToSyntax E.toExpr
      let ok ← observing? (evalTactic (← `(tactic| exact ⟨_, _, _, $hs, $es⟩)))
      if ok.isSome then return
  throwError "rt_dec_pre: no encoding / reader equation applies"

theorem cast_u16_self (x : Std.U16) : UScalar.cast UScalarTy.U16 x = x := by
  apply UScalar.eq_of_val_eq
  rw [UScalar.cast_val_eq]
  have := x.hBounds
  simp [UScalarTy.numBits] at *

open Lean Elab Tactic Meta in
/-- Closes a goal with a contradictory scalar hypothesis of a decoder's `match` on constants:
`h : c = d` between distinct literals, or `h : ¬ ↑c = n` with `c` the literal `n`. -/
elab "rt_absurd_core" : tactic => withMainContext do
  let g ← getMainGoal
  let hs := (← getLCtx).foldl (init := #[]) fun acc d =>
    if d.isImplementationDetail then acc else acc.push d.toExpr
  for h in hs.reverse do
    let hsx ← Term.exprToSyntax h
    let ok ← observing? (evalTactic (← `(tactic| (
      exfalso
      first
        | exact absurd rfl $hsx
        | (have h' := congrArg UScalar.bv $hsx; simp at h'; done)))))
    if ok.isSome then
      if (← getUnsolvedGoals).isEmpty || !(← getUnsolvedGoals).contains g then return
  throwError "rt_absurd: no contradictory scalar hypothesis"

/-- `rt_absurd_core` after substituting the decoded values. -/
macro "rt_absurd" : tactic => `(tactic| (
  exfalso
  try simp only [continue_eq_tryCF] at *
  try subst_vars
  try simp_all only [core.result.Result.Ok.injEq, cast_u16_self]
  first | done | rt_absurd_core))


/-- `RtStd SI DI B` of a derived struct / newtype (`B` the sum of the fields' bounds). `hB`:
`B ≤ imax`; `sz`: its `Size.Lawful`; `ss`: the serializer and the derived defs it calls (as
`derive_ser_std`); `zs`: the size defs to unfold; `ds`: the deserializer; `zl`: the fields'
`Size.Lawful`; `rs`: the fields' `RtStd` (in field order). -/
syntax "derive_rt_std " term:max term:max " [" Lean.Parser.Tactic.simpArg,* "]"
  " [" Lean.Parser.Tactic.simpArg,* "]" " [" Lean.Parser.Tactic.simpArg,* "]"
  " [" term,* "]" " [" term,* "]" : tactic
macro_rules
  | `(tactic| derive_rt_std $hB $sz [$ss,*] [$zs,*] [$ds,*] [$zl,*] [$rs,*]) => do
    let rs := rs.getElems
    let sn := freshNames "h_rser" rs.size
    let dn := freshNames "h_rde" rs.size
    let hsers ← haves sn rs fun r => `(RtStd.ser_spec $r WI hWI)
    let hdes ← haves dn rs fun r => `(fun r => RtStd.de_spec $r law r)
    let bs ← rs.mapM fun r => `(RtStd.bound $r)
    let ls ← rs.mapM fun r => `(RtStd.lo $r)
    let sargs ← mvArgs ss.getElems sn
    let dargs ← mvArgs ds.getElems dn
    `(tactic| (
      apply RtStd.of_post $hB
      intro x
      have hr := size_ok $sz x
      have hS := size_spec $sz
      cases x
      all_goals (
        try conv at hr => lhs; simp only [$zs,*]
        try derive_size_eqs hr [$zl,*]
        have hdec := congrArg UScalar.val hr
        try simp only [lenAddVal_min] at hdec
        refine ⟨?_, fun W WI hWI w hroom => ?_, ?_⟩
        rotate_left
        · $hsers:tactic
          mvcgen [$sargs,*, hS]
          derive_ser_std_vcs
          all_goals (rt_bounds [$bs,*]; have := imax_le; omega)
        · intro b hb
          simp only [seqL, Option.bind_eq_some_iff, Option.map_eq_some_iff, Option.some.injEq] at hb
          casesm* ∃ _, _, _ ∧ _
          subst_vars
          rt_bounds [$bs,*]
          rt_bounds [$ls,*]
          refine ⟨by simp only [List.length_append, List.length_nil]; omega,
            by simp only [List.length_append, List.length_nil]; omega, ?_⟩
          intro R RI v a law r rest hv
          $hdes:tactic
          try simp only [List.append_assoc, List.append_nil, List.nil_append] at hv
          mvcgen [$dargs,*]
          all_goals rt_dec_inst
          all_goals (first | rt_dec_pre | rt_absurd | (simp_all [tryCF, cast_u16_self]; done)))))

/-- `derive_rt_std` for a derived newtype that the extraction merges with its field type (no
`cases` on the value). -/
syntax "derive_rt_std_flat " term:max term:max " [" Lean.Parser.Tactic.simpArg,* "]"
  " [" Lean.Parser.Tactic.simpArg,* "]" " [" Lean.Parser.Tactic.simpArg,* "]"
  " [" term,* "]" " [" term,* "]" : tactic
macro_rules
  | `(tactic| derive_rt_std_flat $hB $sz [$ss,*] [$zs,*] [$ds,*] [$zl,*] [$rs,*]) => do
    let rs := rs.getElems
    let sn := freshNames "h_rser" rs.size
    let dn := freshNames "h_rde" rs.size
    let hsers ← haves sn rs fun r => `(RtStd.ser_spec $r WI hWI)
    let hdes ← haves dn rs fun r => `(fun r => RtStd.de_spec $r law r)
    let bs ← rs.mapM fun r => `(RtStd.bound $r)
    let ls ← rs.mapM fun r => `(RtStd.lo $r)
    let sargs ← mvArgs ss.getElems sn
    let dargs ← mvArgs ds.getElems dn
    `(tactic| (
      apply RtStd.of_post $hB
      intro x
      have hr := size_ok $sz x
      have hS := size_spec $sz
      all_goals (
        try conv at hr => lhs; simp only [$zs,*]
        try derive_size_eqs hr [$zl,*]
        have hdec := congrArg UScalar.val hr
        try simp only [lenAddVal_min] at hdec
        refine ⟨?_, fun W WI hWI w hroom => ?_, ?_⟩
        rotate_left
        · $hsers:tactic
          mvcgen [$sargs,*, hS]
          derive_ser_std_vcs
          all_goals (rt_bounds [$bs,*]; have := imax_le; omega)
        · intro b hb
          simp only [seqL, Option.bind_eq_some_iff, Option.map_eq_some_iff, Option.some.injEq] at hb
          casesm* ∃ _, _, _ ∧ _
          subst_vars
          rt_bounds [$bs,*]
          rt_bounds [$ls,*]
          refine ⟨by simp only [List.length_append, List.length_nil]; omega,
            by simp only [List.length_append, List.length_nil]; omega, ?_⟩
          intro R RI v a law r rest hv
          $hdes:tactic
          try simp only [List.append_assoc, List.append_nil, List.nil_append] at hv
          mvcgen [$dargs,*]
          all_goals rt_dec_inst
          all_goals (first | rt_dec_pre | rt_absurd | (simp_all [tryCF, cast_u16_self]; done)))))

/-! ## Vectors -/

/-- A vector whose content exceeds the MLS bound is rejected on every writer with some room. -/
theorem Vec.ser_big {T : Type} {SI : Serialize T} (DbgI : core.fmt.Debug T)
    (hL : Serialize.Lawful T SI) (v : alloc.vec.Vec T) {N : Nat}
    (hN : SizeNat SI.SizeInst v.val N) (hbig : 2 ^ 30 - 1 < N) {W : Type}
    (WI : core.io.write.Write W) (hWI : core.io.write.Write.Lawful W WI) (w : W)
    (hroom : (core.io.write.Write.view WI w).length ≤ imax) :
    ⦃ ⌜ True ⌝ ⦄ (alloc.vec.Vec.Insts.Tls_codecSerialize SI DbgI).tls_serialize WI v w
    ⦃ ⇓ p => ⌜ ∃ e, p.1 = .Err e ⌝ ⦄ := by
  have himax := imax_eq
  have hge := imax_ge
  have hcc : ∀ s : Slice T, ⦃ ⌜ s = (v : Slice T) ⌝ ⦄ quic_vec.rw.checked_content_length SI.SizeInst s
      ⦃ ⇓ r => ⌜ (N ≤ Usize.max → ∃ c, r = .Ok c ∧ c.val = N) ∧
        (Usize.max < N → ∃ e, r = .Err e) ⌝ ⦄ := by
    intro s hs
    subst hs
    exact checked_len_fold_spec hL.SizeInstLawful _ hN trivial
  have hwl : ∀ (w' : W) (n : Std.Usize),
      ⦃ ⌜ (core.io.write.Write.view WI w').length + 8 ≤ Usize.max ⌝ ⦄
        quic_vec.rw.write_length WI w' n
      ⦃ ⇓ p => ⌜ (n.val ≤ 2 ^ 30 - 1 → (∃ l : Std.Usize, p.1 = .Ok l ∧ l.val = varint.lenOf n.val) ∧
          core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w' ++ varint.enc n.val) ∧
        (2 ^ 30 - 1 < n.val → ∃ e, p.1 = .Err e) ⌝ ⦄ :=
    by intro w' n hr; exact write_length_runs.2 W WI hWI w' n hr trivial
  have hel : ∀ (s : Slice T) (w' : W),
      ⦃ ⌜ s = (v : Slice T) ∧ (core.io.write.Write.view WI w').length + N ≤ imax ⌝ ⦄
        tls_vec.serialize_elements SI WI s w'
      ⦃ ⇓ p => ⌜ (∀ bs, encAll SI v.val = some bs → (∃ n : Std.Usize, p.1 = .Ok n ∧ n.val = N) ∧
          core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w' ++ bs ∧ bs.length = N) ∧
        (encAll SI v.val = none → ∃ e, p.1 = .Err e) ⌝ ⦄ :=
    by intro s w' ⟨hs, hr⟩; subst hs; exact serialize_elements_spec hL WI hWI w' _ N hN hr trivial
  mvcgen [alloc.vec.Vec.Insts.Tls_codecSerialize.tls_serialize,
    Shared0Slice.Insts.Tls_codecSerialize.tls_serialize, hcc, hwl, hel, checked_len_add_triple,
    tls_codec.Copied.checked_len_add_triple]
  · omega
  · rename_i s hs r1 hr1 cf val hx hcf wr hwr cf1 val1 hx1 hcf1
    obtain ⟨hval, hv30, hl⟩ := vec_prefix r1 val hr1 hcf wr hwr val1 hcf1
    omega
  · rename_i s hs r1 hr1 cf val hx hcf wr hwr cf1 val1 hx1 hcf1 er her cf2 val2 hx2 hne hcf2
    obtain ⟨hval, hv30, hl⟩ := vec_prefix r1 val hr1 hcf wr hwr val1 hcf1
    omega
  · rename_i s hs r1 hr1 cf val hx hcf wr hwr cf1 val1 hx1 hcf1 er her cf2 val2 hx2 hnne hcf2 r3 hr3
    obtain ⟨hval, hv30, hl⟩ := vec_prefix r1 val hr1 hcf wr hwr val1 hcf1
    omega
  all_goals
    rename_i hbr
    refine try_break_vc (fun e he => ?_) hbr
    mvcgen
    intro _
    mvcgen
    exact ⟨_, rfl⟩

/-- `RtStd` of `Vec<T>` from the elements' `NonEmptyStd` (its round trip). -/
theorem Vec.rtStd {T : Type} (NE : spec.io.NonEmptyStd T) (DbgI : core.fmt.Debug T)
    (hNE : spec.io.NonEmptyStd.Lawful T NE) (hDbg : core.fmt.Debug.Lawful T DbgI) :
    RtStd (alloc.vec.Vec.Insts.Tls_codecSerialize NE.RoundTripStdInst.SerializeInst DbgI)
      (alloc.vec.Vec.Insts.Tls_codecDeserialize NE.RoundTripStdInst.DeserializeInst)
      1 (2 ^ 30 + 3) := by
  have := imax_ge
  have himax := imax_eq
  have hRT := alloc.vec.Vec.Insts.Tls_codecSpecIoRoundTripStd.Lawful NE DbgI hNE hDbg
  have hNEv := alloc.vec.Vec.Insts.Tls_codecSpecIoNonEmptyStd.Lawful NE DbgI hNE hDbg
  have hL := hRT.SerializeInstLawful
  refine RtStd.of_lawful hL (by omega) (fun v hv W WI hWI w hr => ?_) (fun v b hb => ?_)
    (rt_decodes_out hRT)
  · have hLe := hNE.RoundTripStdInstLawful.SerializeInstLawful
    obtain ⟨N, hN⟩ := SizeNat.exists hLe.SizeInstLawful v.val
    by_cases hN30 : N ≤ 2 ^ 30 - 1
    · exfalso
      obtain ⟨sz, hsz, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
        (alloc.vec.Vec.size_rel _ hLe.SizeInstLawful v)
      obtain ⟨c, -, hc, hszv⟩ := Vec.size_exact hLe v sz hsz hN
      have hl4 : varint.lenOf N ≤ 4 := by unfold varint.lenOf; split_ifs <;> omega
      have hcN : c.val = N := by rw [hc]; omega
      rw [hcN, if_pos hN30] at hszv
      have : (szv (alloc.vec.Vec.Insts.Tls_codecSize NE.RoundTripStdInst.SerializeInst.SizeInst) v).val
          = sz.val := by rw [szv_eq hsz]
      change 2 ^ 30 + 3 < (szv (alloc.vec.Vec.Insts.Tls_codecSize
        NE.RoundTripStdInst.SerializeInst.SizeInst) v).val at hv
      omega
    · exact Vec.ser_big (N := N) DbgI hLe v hN (by omega) WI hWI w (by omega)
  · obtain ⟨bv, he, rfl⟩ := encOut_some hb
    have := spec.io.NonEmptyStd.Lawful.nonempty hNEv v bv he
    exact List.length_pos_iff.mpr this

end tls_codec.Derive
