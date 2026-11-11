/- Agreement of the `std` and byte-slice decoders (`DecodersAgree`) and the mixed round trip
(`RoundTripMixed`: the `std` encoding decoded by the byte-slice decoder).

`Agree DI DB`: on every lawful reader, the `std` decoder fails exactly when the byte-slice
decoder fails on the reader's bytes, and otherwise both give the same value, the reader being
left with the byte-slice remainder. `BIndep DB`: the byte-slice decoder reads no further than
what it consumes. Together they are the `DecodersAgree` lemma trait (`DecodersAgree.lawful_of`,
and back: `spec.io.DecodersAgree.Lawful.agree`, `.bindep`). Leaves: fixed-size codecs (integers,
`[u8; N]`, `Agree.of_fixed`), codecs with a canonical encoding relation (`Agree.of_enc`:
`ContentLength`, `VLBytes`, `SecretVLBytes`), and `Vec<T>` from its elements' facts.

Obligations: none directly; the `DecodersAgree` / `RoundTripMixed` halves of `PanicFreedom.lean` /
`FunctionalCorrectness.lean` use them, and the downstream tactics (`Derive/DecodersAgree.lean`).
Axioms reached: none beyond those of the imported `std`-path and bytes-path proofs. -/
import Aeneas
import CoreModels
import Hax
import TlsCodec.Extraction
import TlsCodec.Verification.Helpers
import TlsCodec.Verification.Std.Io
import TlsCodec.Verification.Std.Bridge
import TlsCodec.Verification.Std.Containers
import TlsCodec.Verification.Std.VecRoundTrip
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

/-! ## The predicates -/

/-- A byte-slice decoder result and a `std` decoder result (value, reader after) agree: both
`Ok` with the same value, the reader left with the byte-slice remainder, or both `Err`. -/
def AgreeRes {T R : Type} (v : R → List Std.U8) :
    core.result.Result (T × Slice Std.U8) Error → core.result.Result T Error × R → Prop
  | .Ok (x, t), p => p.1 = .Ok x ∧ v p.2 = t.val
  | .Err _, p => ∃ e, p.1 = .Err e

/-- The `std` decoder agrees with the byte-slice decoder on every lawful reader. -/
def Agree {T : Type} (DI : Deserialize T) (DB : DeserializeBytes T) : Prop :=
  ∀ (R : Type) (RI : alloc.io.read.Read R) (v : R → List Std.U8) (a : R → Nat → R),
    StdIo.RLaw RI v a → ∀ r, ⦃ ⌜ True ⌝ ⦄ DI.tls_deserialize RI r
    ⦃ ⇓ p => ⌜ ∀ s : Slice Std.U8, s.val = v r →
      ∃ res, DB.tls_deserialize_bytes s = ok res ∧ AgreeRes v res p ⌝ ⦄

/-- The byte-slice decoder reads no further than what it consumes. -/
def BIndep {T : Type} (DB : DeserializeBytes T) : Prop :=
  ∀ s x t, DB.tls_deserialize_bytes s = ok (.Ok (x, t)) →
    ∃ pre, s.val = pre ++ t.val ∧ ∀ (s' : Slice Std.U8) (rest : List Std.U8),
      s'.val = pre ++ rest → ∃ t', DB.tls_deserialize_bytes s' = ok (.Ok (x, t')) ∧ t'.val = rest

/-- The slice holding the bytes of a lawful reader. -/
def viewSlice {R : Type} {RI : alloc.io.read.Read R} {v : R → List Std.U8} {a : R → Nat → R}
    (law : StdIo.RLaw RI v a) (r : R) : Slice Std.U8 :=
  ⟨v r, law.view_le r⟩


open Classical in
theorem PartialEq.eq_ok {T : Type} {PE : core.cmp.PartialEq T T}
    (h : core.cmp.PartialEq.Lawful T T PE) (x y : T) : PE.eq x y = ok (decide (x = y)) := by
  obtain ⟨b, hb, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (h.eq_spec x y)
  rw [hb]
  congr 1
  cases b <;> simp_all

theorem slice_eq_U8_ok (a b : Slice Std.U8) :
    core.Slice.Insts.CoreCmpPartialEqSlice.eq core.U8.Insts.CoreCmpPartialEqU8 a b =
      ok (decide (a.val = b.val)) := by
  obtain ⟨r, hr, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (slice_eq_U8_spec a b)
  rw [hr, hP]

/-! ## From the predicates to the lemma traits -/

theorem decoders_agree_post_of {T R : Type} {DI : Deserialize T} {DB : DeserializeBytes T}
    {PE : core.cmp.PartialEq T T} (DA : spec.io.DecodersAgree T)
    (hEq : core.cmp.PartialEq.Lawful T T PE) (hA : Agree DI DB)
    (RI : alloc.io.read.Read R) (hRI : alloc.io.read.Read.Lawful R RI) (reader : R) :
    (spec.io.DecodersAgree.decoders_agree.post RI DI DB PE DA reader ()).holds := by
  have law := hRI.law'
  obtain ⟨p, hp, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (hA _ RI _ _ law reader)
  obtain ⟨res, hres, hrel⟩ := hP (viewSlice law reader) rfl
  unfold spec.io.DecodersAgree.decoders_agree.post
  simp only [spec.io.stream, spec.io.decode_std, hp, bind_tc_ok]
  obtain ⟨res0, after⟩ := p
  simp only [viewSlice] at hres
  simp only [alloc.vec.Vec.Insts.CoreOpsDerefDerefSlice.deref, alloc.vec.Vec.as_slice,
    rust_primitives.sequence.seq_to_slice, bind_tc_ok]
  rw [hres]
  simp only [bind_tc_ok]
  cases res with
  | Ok q =>
    obtain ⟨x, t⟩ := q
    obtain ⟨h1, h2⟩ := hrel
    simp only at h1 h2
    subst h1
    simp [core.result.Result.is_ok_and, PartialEq.eq_ok hEq,
      spec.io.__5.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleSelf_Bool.call_once,
      h2]
    simp [slice_eq_U8_ok, Functor.map]
    exact holds_ok_iff.mpr trivial
  | Err e =>
    obtain ⟨e', h1⟩ := hrel
    simp only at h1
    subst h1
    simp [core.result.Result.is_err, Functor.map]
    exact holds_ok_iff.mpr trivial

theorem DeserializeBytes.Lawful.total {T : Type} {DB : DeserializeBytes T}
    (h : DeserializeBytes.Lawful T DB) (s : Slice Std.U8) :
    ∃ res, DB.tls_deserialize_bytes s = ok res := by
  obtain ⟨res, hres, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (h.tls_deserialize_bytes_spec s (pre_holds_of_ok_true rfl))
  exact ⟨res, hres⟩

/-- An agreeing byte-slice decoder does not fail (on the slice reader of any slice). -/
theorem Agree.total {T : Type} {DI : Deserialize T} {DB : DeserializeBytes T} (hA : Agree DI DB)
    (s : Slice Std.U8) : ∃ res, DB.tls_deserialize_bytes s = ok res := by
  obtain ⟨p, -, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (hA _ _ _ _ StdIo.slice_law s)
  obtain ⟨res, h, -⟩ := hP s rfl
  exact ⟨res, h⟩

theorem bytes_prefix_only_pre_elim {T : Type} {DI : Deserialize T} {DB : DeserializeBytes T}
    {PE : core.cmp.PartialEq T T} (DA : spec.io.DecodersAgree T)
    (pfx rest bytes other_rest other : Slice Std.U8)
    (h : (spec.io.DecodersAgree.bytes_prefix_only.pre DI DB PE DA pfx rest bytes other_rest
      other).holds) :
    bytes.val = pfx.val ++ rest.val ∧ other.val = pfx.val ++ other_rest.val := by
  unfold spec.io.DecodersAgree.bytes_prefix_only.pre at h
  simp only [spec.io.is_concat, bind_tc_ok] at h
  by_cases h1 : bytes.val = pfx.val ++ rest.val
  · simp only [h1, decide_true, if_true] at h
    exact ⟨h1, by simpa using holds_ok_iff.mp h⟩
  · simp only [h1, decide_false] at h
    exact absurd (holds_ok_iff.mp h) (by simp)

theorem bytes_prefix_only_post_of {T : Type} {DI : Deserialize T} {DB : DeserializeBytes T}
    {PE : core.cmp.PartialEq T T} (DA : spec.io.DecodersAgree T)
    (hA : Agree DI DB) (hEq : core.cmp.PartialEq.Lawful T T PE)
    (hI : BIndep DB) (pfx rest bytes other_rest other : Slice Std.U8)
    (hpre : (spec.io.DecodersAgree.bytes_prefix_only.pre DI DB PE DA pfx rest bytes other_rest
      other).holds) :
    (spec.io.DecodersAgree.bytes_prefix_only.post DI DB PE DA pfx rest bytes other_rest other
      ()).holds := by
  obtain ⟨hb, ho⟩ := bytes_prefix_only_pre_elim DA pfx rest bytes other_rest other hpre
  obtain ⟨res, hres⟩ := hA.total bytes
  unfold spec.io.DecodersAgree.bytes_prefix_only.post
  rw [hres]
  simp only [bind_tc_ok]
  cases res with
  | Err e => exact holds_ok_iff.mpr rfl
  | Ok q =>
    obtain ⟨x, t⟩ := q
    simp only [core.Shared1A.Insts.CoreCmpPartialEqShared0B.ne,
      core.Slice.Insts.CoreCmpPartialEqSlice.ne,
      slice_eq_U8_ok, bind_tc_ok]
    by_cases ht : t.val = rest.val
    · obtain ⟨pre, hpre', hall⟩ := hI _ _ _ hres
      have hp : pre = pfx.val := by
        rw [hb, ht] at hpre'
        exact (List.append_cancel_right hpre').symm
      subst hp
      obtain ⟨t', ht', htv⟩ := hall other other_rest.val ho
      simp [ht, ht', core.result.Result.is_ok_and,
        spec.io.__7.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairSelf_SharedSliceU8Bool.call_once,
        PartialEq.eq_ok hEq, slice_eq_U8_ok, htv, Functor.map]
      exact holds_ok_iff.mpr trivial
    · simp [ht, Functor.map]
      exact holds_ok_iff.mpr trivial

/-- `DecodersAgree` from `Agree` and `BIndep` (the lemma methods have their default bodies). -/
theorem DecodersAgree.lawful_of {T : Type} (DA : spec.io.DecodersAgree T)
    (hD : Deserialize.Lawful T DA.DeserializeInst)
    (hDB : DeserializeBytes.Lawful T DA.DeserializeBytesInst)
    (hEq : core.cmp.PartialEq.Lawful T T DA.corecmpPartialEqInst)
    (hA : Agree DA.DeserializeInst DA.DeserializeBytesInst) (hI : BIndep DA.DeserializeBytesInst)
    (hda : ∀ {R : Type} (RI : alloc.io.read.Read R),
      DA.decoders_agree RI = spec.io.DecodersAgree.decoders_agree.default T RI)
    (hbp : DA.bytes_prefix_only = spec.io.DecodersAgree.bytes_prefix_only.default T) :
    spec.io.DecodersAgree.Lawful T DA where
  DeserializeInstLawful := hD
  DeserializeBytesInstLawful := hDB
  corecmpPartialEqInstLawful := hEq
  decoders_agree_spec RI hRI reader _ := by
    rw [hda]
    exact ok_triple_of (decoders_agree_post_of DA hEq hA RI hRI reader)
  bytes_prefix_only_spec pfx rest bytes other_rest other hpre := by
    rw [hbp]
    exact ok_triple_of (bytes_prefix_only_post_of DA hA hEq hI pfx rest bytes other_rest other hpre)

/-! ## From the lemma trait back to the predicates -/

theorem spec.io.DecodersAgree.Lawful.agree {T : Type} {DA : spec.io.DecodersAgree T}
    (h : spec.io.DecodersAgree.Lawful T DA) :
    Agree DA.DeserializeInst DA.DeserializeBytesInst := by
  intro R RI v a law r
  have hRI : alloc.io.read.Read.Lawful R RI := ⟨⟨v, a, law⟩⟩
  have hv : alloc.io.read.Read.view RI = v := funext (StdIo.view_eq law)
  obtain ⟨u, -, hpost⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (h.decoders_agree_spec RI hRI r (pre_holds_of_ok_true rfl))
  obtain ⟨p, hp, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (h.DeserializeInstLawful.tls_deserialize_spec RI hRI r (pre_holds_of_ok_true rfl))
  rw [hp]
  refine ok_triple_of fun s hs => ?_
  obtain ⟨res, hres⟩ := h.DeserializeBytesInstLawful.total s
  refine ⟨res, hres, ?_⟩
  have hs' : s = ⟨alloc.io.read.Read.view RI r, alloc.io.read.Read.view_le RI r⟩ :=
    Subtype.ext (by show s.val = alloc.io.read.Read.view RI r; rw [hv]; exact hs)
  subst hs'
  unfold spec.io.DecodersAgree.decoders_agree.post at hpost
  simp only [spec.io.stream, spec.io.decode_std, hp, bind_tc_ok,
    alloc.vec.Vec.Insts.CoreOpsDerefDerefSlice.deref, alloc.vec.Vec.as_slice,
    rust_primitives.sequence.seq_to_slice] at hpost
  obtain ⟨res0, after⟩ := p
  rw [hres] at hpost
  have hEq := h.corecmpPartialEqInstLawful
  cases res with
  | Ok q =>
    obtain ⟨x, t⟩ := q
    cases res0 with
    | Ok y =>
      simp [core.result.Result.is_ok_and, PartialEq.eq_ok hEq,
        spec.io.__5.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleSelf_Bool.call_once,
        slice_eq_U8_ok, Functor.map] at hpost
      by_cases hyx : y = x
      · subst hyx
        by_cases ht : alloc.io.read.Read.view RI after = t.val
        · exact ⟨rfl, by rw [← hv]; exact ht⟩
        · simp [ht] at hpost
          exact absurd (holds_ok_iff.mp hpost) id
      · simp [hyx] at hpost
        exact absurd (holds_ok_iff.mp hpost) id
    | Err e =>
      simp [core.result.Result.is_ok_and, Functor.map] at hpost
      exact absurd (holds_ok_iff.mp hpost) id
  | Err e =>
    cases res0 with
    | Ok y =>
      simp [core.result.Result.is_err, Functor.map] at hpost
      exact absurd (holds_ok_iff.mp hpost) id
    | Err e' => exact ⟨e', rfl⟩

theorem DeserializeBytes.Lawful.suffix {T : Type} {DB : DeserializeBytes T}
    (h : DeserializeBytes.Lawful T DB) {s : Slice Std.U8} {x : T} {t : Slice Std.U8}
    (hst : DB.tls_deserialize_bytes s = ok (.Ok (x, t))) : ∃ pre, s.val = pre ++ t.val := by
  obtain ⟨res, hres, hpost⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (h.tls_deserialize_bytes_spec s (pre_holds_of_ok_true rfl))
  rw [hst] at hres
  cases hres
  obtain ⟨pre, hpre⟩ := DeserializeBytes.post_ok_suffix _ _ _ _ _ hpost
  exact ⟨pre, hpre.symm⟩

theorem spec.io.DecodersAgree.Lawful.bindep {T : Type} {DA : spec.io.DecodersAgree T}
    (h : spec.io.DecodersAgree.Lawful T DA) : BIndep DA.DeserializeBytesInst := by
  intro s x t hst
  obtain ⟨pre, hpre⟩ := h.DeserializeBytesInstLawful.suffix hst
  refine ⟨pre, hpre, fun s' rest hs' => ?_⟩
  have hl := s'.property
  have hl0 := s.property
  let pfx : Slice Std.U8 := ⟨pre, by rw [hpre] at hl0; simp at hl0; omega⟩
  let orest : Slice Std.U8 := ⟨rest, by rw [hs'] at hl; simp at hl; omega⟩
  have hpr : (spec.io.DecodersAgree.bytes_prefix_only.pre DA.DeserializeInst
      DA.DeserializeBytesInst DA.corecmpPartialEqInst DA pfx t s orest s').holds := by
    unfold spec.io.DecodersAgree.bytes_prefix_only.pre
    simp only [spec.io.is_concat, bind_tc_ok, pfx, orest, hpre, hs', decide_true, if_true]
    exact holds_ok_iff.mpr trivial
  obtain ⟨u, -, hpost⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (h.bytes_prefix_only_spec pfx t s orest s' hpr)
  obtain ⟨res, hres⟩ := h.DeserializeBytesInstLawful.total s'
  have hEq := h.corecmpPartialEqInstLawful
  unfold spec.io.DecodersAgree.bytes_prefix_only.post at hpost
  simp only [hst, hres, bind_tc_ok, core.Shared1A.Insts.CoreCmpPartialEqShared0B.ne,
    core.Slice.Insts.CoreCmpPartialEqSlice.ne, slice_eq_U8_ok] at hpost
  cases res with
  | Ok q =>
    obtain ⟨y, t'⟩ := q
    simp [core.result.Result.is_ok_and, PartialEq.eq_ok hEq, slice_eq_U8_ok, Functor.map,
      spec.io.__7.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairSelf_SharedSliceU8Bool.call_once]
      at hpost
    by_cases hyx : y = x
    · subst hyx
      by_cases ht : t'.val = rest
      · exact ⟨t', hres, ht⟩
      · simp [ht, orest] at hpost
        exact absurd (holds_ok_iff.mp hpost) id
    · simp [hyx] at hpost
      exact absurd (holds_ok_iff.mp hpost) id
  | Err e =>
    simp [core.result.Result.is_ok_and, Functor.map] at hpost
    exact absurd (holds_ok_iff.mp hpost) id

/-! ## The mixed round trip -/

theorem round_trip_mixed_pre_elim {T : Type} (RT : spec.io.RoundTripStd T)
    (DA : spec.io.DecodersAgree T) (RM : spec.io.RoundTripMixed T) (x : T)
    (rest whole : Slice Std.U8)
    (h : (spec.io.RoundTripMixed.round_trip_mixed.pre RT DA RM x rest whole).holds) :
    ∃ bv : alloc.vec.Vec Std.U8, spec.io.encode RT.SerializeInst x = ok (.Ok bv) ∧
      whole.val = (bv : Slice Std.U8).val ++ rest.val := by
  unfold spec.io.RoundTripMixed.round_trip_mixed.pre at h
  rcases he : spec.io.encode RT.SerializeInst x with r | e | _
  · rw [he] at h
    simp only [bind_tc_ok] at h
    cases r with
    | Ok bv =>
      refine ⟨bv, rfl, ?_⟩
      simp [core.result.Result.is_ok_and, spec.io.is_concat, Functor.map,
        spec.io.__8.requires.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.call_once,
        alloc.vec.Vec.Insts.CoreOpsDerefDerefSlice.deref, alloc.vec.Vec.as_slice,
        rust_primitives.sequence.seq_to_slice] at h
      by_cases hw : whole.val = bv.val ++ rest.val
      · exact hw
      · simp [hw] at h
        exact absurd (holds_ok_iff.mp h) id
    | Err e =>
      simp [core.result.Result.is_ok_and, Functor.map] at h
      exact absurd (holds_ok_iff.mp h) id
  all_goals
    rw [he] at h
    obtain ⟨q, hq, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp h
    simp [Functor.map] at hq

/-- The mixed round trip: from the `std` round trip and the agreement of the decoders (stated for
the same `std` decoder: the two lemma-trait impls of a type share their parent impls). -/
theorem round_trip_mixed_post_of {T : Type} (RT : spec.io.RoundTripStd T)
    (DA : spec.io.DecodersAgree T) (RM : spec.io.RoundTripMixed T)
    (hEq : core.cmp.PartialEq.Lawful T T RT.corecmpPartialEqInst)
    (hdec : ∀ x (bv : alloc.vec.Vec Std.U8), spec.io.encode RT.SerializeInst x = ok (.Ok bv) →
      DecodesTo DA.DeserializeInst (bv : Slice Std.U8).val x)
    (hA : Agree DA.DeserializeInst DA.DeserializeBytesInst) (x : T) (rest whole : Slice Std.U8)
    (hpre : (spec.io.RoundTripMixed.round_trip_mixed.pre RT DA RM x rest whole).holds) :
    (spec.io.RoundTripMixed.round_trip_mixed.post RT DA RM x rest whole ()).holds := by
  obtain ⟨bv, he, hw⟩ := round_trip_mixed_pre_elim RT DA RM x rest whole hpre
  have hdw := hdec x bv he _ _ _ _ StdIo.slice_law whole rest.val hw
  obtain ⟨p, hp, hp1, hp2⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp hdw
  obtain ⟨q, hq, hQ⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (hA _ _ _ _ StdIo.slice_law whole)
  rw [hp] at hq
  cases hq
  obtain ⟨res, hres, hrel⟩ := hQ whole rfl
  unfold spec.io.RoundTripMixed.round_trip_mixed.post
  rw [hres]
  simp only [bind_tc_ok]
  cases res with
  | Ok r =>
    obtain ⟨y, t⟩ := r
    obtain ⟨h1, h2⟩ := hrel
    rw [hp1] at h1
    cases h1
    simp [core.result.Result.is_ok_and, PartialEq.eq_ok hEq, slice_eq_U8_ok, Functor.map,
      spec.io.__9.ensures.closure.Insts.CoreOpsFunctionFnOnceTuplePairSelf_SharedSliceU8Bool.call_once]
    exact holds_ok_iff.mpr (by rw [← hp2]; exact h2.symm)
  | Err e =>
    obtain ⟨e', h1⟩ := hrel
    rw [hp1] at h1
    cases h1

/-- `u8`: its `std` encodings decode back (the `hdec` premise of `round_trip_mixed_post_of`). -/
theorem U8.encode_decodes (x : Std.U8) (bv : alloc.vec.Vec Std.U8)
    (he : spec.io.encode U8.Insts.Tls_codecSerialize x = ok (.Ok bv)) :
    DecodesTo U8.Insts.Tls_codecDeserialize (bv : Slice Std.U8).val x := by
  obtain ⟨e, he', hs, -⟩ := encode_of_runs _ x 1#usize [x] (U8.ser_runs x)
    (by have := imax_ge; simp; omega)
  rw [he] at he'
  cases he'
  obtain ⟨bv', hbv', hval⟩ := hs _ rfl
  cases hbv'
  rw [hval]
  exact U8.decodes x

/-- `VLBytes`: its `std` encodings decode back. -/
theorem VLBytes.encode_decodes (x : quic_vec.VLBytes) (bv : alloc.vec.Vec Std.U8)
    (he : spec.io.encode quic_vec.VLBytes.Insts.Tls_codecSerialize x = ok (.Ok bv)) :
    DecodesTo quic_vec.VLBytes.Insts.Tls_codecDeserialize (bv : Slice Std.U8).val x := by
  by_cases hx : x.vec.val.length ≤ 2 ^ 30 - 1
  · obtain ⟨bv', he', hv⟩ := VLBytes.encode_ok x hx
    rw [he] at he'
    cases he'
    rw [hv]
    exact VLBytes.decodes x hx
  · obtain ⟨e, he'⟩ := VLBytes.encode_big x (by omega)
    rw [he] at he'
    cases he'

/-- `RoundTripMixed` from the lawful parents (sharing their `std` decoder). -/
theorem RoundTripMixed.lawful_of {T : Type} (RM : spec.io.RoundTripMixed T)
    (hRT : spec.io.RoundTripStd.Lawful T RM.RoundTripStdInst)
    (hDA : spec.io.DecodersAgree.Lawful T RM.DecodersAgreeInst)
    (hDe : RM.DecodersAgreeInst.DeserializeInst = RM.RoundTripStdInst.DeserializeInst)
    (hd : RM.round_trip_mixed = spec.io.RoundTripMixed.round_trip_mixed.default) :
    spec.io.RoundTripMixed.Lawful T RM where
  RoundTripStdInstLawful := hRT
  DecodersAgreeInstLawful := hDA
  round_trip_mixed_spec x rest whole hpre := by
    rw [hd]
    exact ok_triple_of (round_trip_mixed_post_of _ _ RM hRT.corecmpPartialEqInstLawful
      (fun x bv he => hDe ▸ hRT.decodes x bv he) hDA.agree x rest whole hpre)

/-! ## Leaves -/

/-- `Agree` and `BIndep` from an encoding relation `E` (value, bytes): the byte-slice decoder
succeeds exactly on an encoding followed by anything (`ha`, `hb`), the `std` decoder decodes every
encoding (`hc`) and reads one when it succeeds (`hd`). -/
theorem Agree.of_enc {T : Type} {DI : Deserialize T} {DB : DeserializeBytes T}
    (E : T → List Std.U8 → Prop)
    (htot : ∀ s, ∃ res, DB.tls_deserialize_bytes s = ok res)
    (ha : ∀ s x t, DB.tls_deserialize_bytes s = ok (.Ok (x, t)) → ∃ p, E x p ∧ s.val = p ++ t.val)
    (hb : ∀ x p, E x p → ∀ (s : Slice Std.U8) (rest : List Std.U8), s.val = p ++ rest →
      ∃ t, DB.tls_deserialize_bytes s = ok (.Ok (x, t)) ∧ t.val = rest)
    (hc : ∀ x p, E x p → DecodesTo DI p x)
    (hd : ∀ (R : Type) (RI : alloc.io.read.Read R) (v : R → List Std.U8) (a : R → Nat → R),
      StdIo.RLaw RI v a → ∀ r, ⦃ ⌜ True ⌝ ⦄ DI.tls_deserialize RI r
      ⦃ ⇓ q => ⌜ ∀ x, q.1 = .Ok x → ∃ p, E x p ∧ v r = p ++ v q.2 ⌝ ⦄) :
    Agree DI DB ∧ BIndep DB := by
  refine ⟨fun R RI v a law r => ?_, fun s x t h => ?_⟩
  · obtain ⟨q, hq, hQ⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (hd R RI v a law r)
    rw [hq]
    refine ok_triple_of fun s hs => ?_
    obtain ⟨res, hres⟩ := htot s
    refine ⟨res, hres, ?_⟩
    cases res with
    | Ok xt =>
      obtain ⟨x, t⟩ := xt
      obtain ⟨p, hE, hsp⟩ := ha s x t hres
      obtain ⟨q', hq', hQ'⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
        (hc x p hE R RI v a law r t.val (by rw [← hs, hsp]))
      rw [hq] at hq'
      cases hq'
      exact hQ'
    | Err e =>
      rcases hq1 : q.1 with x | e'
      · obtain ⟨p, hE, hvr⟩ := hQ x hq1
        obtain ⟨t, ht, -⟩ := hb x p hE s (v q.2) (by rw [hs, hvr])
        rw [hres] at ht
        cases ht
      · exact ⟨e', hq1⟩
  · obtain ⟨p, hE, hsp⟩ := ha s x t h
    exact ⟨p, hsp, fun s' rest h' => hb x p hE s' rest h'⟩

/-- `Agree` and `BIndep` of a fixed-size codec: `N` bytes, read by `read_exact` on the `std`
path (`FixedRuns`) and by `get(..N)` on the byte-slice path. -/
theorem Agree.of_fixed {T : Type} {DI : Deserialize T} {DB : DeserializeBytes T} (N : Std.Usize)
    (fromb : Aeneas.Std.Array Std.U8 N → T) (hF : FixedRuns DI N fromb)
    (hB : ∀ s : Slice Std.U8, ⦃ ⌜ True ⌝ ⦄ DB.tls_deserialize_bytes s
      ⦃ ⇓ r => ⌜ (N.val ≤ s.val.length → ∃ (arr : Aeneas.Std.Array Std.U8 N) (t : Slice Std.U8),
          arr.val = s.val.take N.val ∧ t.val = s.val.drop N.val ∧ r = .Ok (fromb arr, t)) ∧
        (s.val.length < N.val → r = .Err Error.EndOfStream) ⌝ ⦄) :
    Agree DI DB ∧ BIndep DB := by
  have hlen : ∀ arr : Aeneas.Std.Array Std.U8 N, arr.val.length = N.val := fun arr => by
    simp
  refine Agree.of_enc (fun x p => ∃ arr : Aeneas.Std.Array Std.U8 N, arr.val = p ∧ fromb arr = x)
    (fun s => ?_) (fun s x t h => ?_) (fun x p hE s rest hs => ?_) (fun x p hE => ?_)
    (fun R RI v a law r => ?_)
  · obtain ⟨res, hres, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (hB s)
    exact ⟨res, hres⟩
  · obtain ⟨res, hres, h1, h2⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (hB s)
    rw [h] at hres
    cases hres
    by_cases hN : N.val ≤ s.val.length
    · obtain ⟨arr, t', harr, ht', he⟩ := h1 hN
      obtain ⟨⟩ := he
      exact ⟨arr.val, ⟨arr, rfl, rfl⟩, by rw [harr, ht', List.take_append_drop]⟩
    · have := h2 (by omega)
      cases this
  · obtain ⟨arr, rfl, rfl⟩ := hE
    obtain ⟨res, hres, h1, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (hB s)
    have hN : N.val ≤ s.val.length := by rw [hs, List.length_append, hlen]; omega
    obtain ⟨arr', t, harr', ht, he⟩ := h1 hN
    have : arr' = arr := Subtype.ext (by rw [harr', hs, List.take_left' (hlen arr)])
    subst this he
    refine ⟨t, hres, ?_⟩
    rw [ht, hs, List.drop_left' (hlen arr')]
  · obtain ⟨arr, rfl, rfl⟩ := hE
    exact DecodesTo_of_fixed DI N fromb hF arr
  · refine triple_post_mono (hF R RI v a law r) fun q hq x hx => ?_
    by_cases hN : N.val ≤ (v r).length
    · obtain ⟨arr, harr, rfl⟩ := hq.1 hN
      cases hx
      refine ⟨arr.val, ⟨arr, rfl, rfl⟩, ?_⟩
      rw [law.adv_view r _ hN, harr, List.take_append_drop]
    · obtain ⟨e, he⟩ := hq.2 (by omega)
      rw [he] at hx
      cases hx

theorem U8.agree : Agree U8.Insts.Tls_codecDeserialize U8.Insts.Tls_codecDeserializeBytes ∧
    BIndep U8.Insts.Tls_codecDeserializeBytes :=
  Agree.of_fixed 1#usize _ U8.fixed_runs U8_deserialize_char

theorem U16.agree : Agree U16.Insts.Tls_codecDeserialize U16.Insts.Tls_codecDeserializeBytes ∧
    BIndep U16.Insts.Tls_codecDeserializeBytes :=
  Agree.of_fixed 2#usize _ U16.fixed_runs U16_deserialize_char

theorem U32.agree : Agree U32.Insts.Tls_codecDeserialize U32.Insts.Tls_codecDeserializeBytes ∧
    BIndep U32.Insts.Tls_codecDeserializeBytes :=
  Agree.of_fixed 4#usize _ U32.fixed_runs U32_deserialize_char

theorem U64.agree : Agree U64.Insts.Tls_codecDeserialize U64.Insts.Tls_codecDeserializeBytes ∧
    BIndep U64.Insts.Tls_codecDeserializeBytes :=
  Agree.of_fixed 8#usize _ U64.fixed_runs U64_deserialize_char

theorem ArrayU8.agree (LEN : Std.Usize) :
    Agree (ArrayU8LEN.Insts.Tls_codecDeserialize LEN) (ArrayU8LEN.Insts.Tls_codecDeserializeBytes LEN) ∧
    BIndep (ArrayU8LEN.Insts.Tls_codecDeserializeBytes LEN) :=
  Agree.of_fixed LEN (fun a => a) (ArrayU8.fixed_runs LEN) (ArrayU8LEN_deserialize_char LEN)

theorem map_val_inj {l1 l2 : List Std.U8} (h : l1.map (·.val) = l2.map (·.val)) : l1 = l2 :=
  List.map_injective_iff.mpr (fun _ _ h => UScalar.eq_of_val_eq h) h

/-- `ContentLength`: the canonical varint encoding of a length at most `2^30 - 1`. -/
theorem ContentLength.agree :
    Agree quic_vec.ContentLength.Insts.Tls_codecDeserialize
      quic_vec.ContentLength.Insts.Tls_codecDeserializeBytes ∧
    BIndep quic_vec.ContentLength.Insts.Tls_codecDeserializeBytes := by
  refine Agree.of_enc (fun x p => x.val ≤ 2 ^ 30 - 1 ∧ p = varint.enc x.val)
    (fun s => ?_) (fun s x t h => ?_) (fun x p hE s rest hs => ?_) (fun x p hE => ?_)
    (fun R RI v a law r => ?_)
  · obtain ⟨res, hres, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (quic_vec.ContentLength.deserialize_content s)
    exact ⟨res, hres⟩
  · obtain ⟨res, hres, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (quic_vec.ContentLength.deserialize_content s)
    have he := hres.symm.trans h
    cases he
    obtain ⟨hx, hm⟩ := hP x t rfl
    refine ⟨varint.enc x.val, ⟨hx, rfl⟩, map_val_inj ?_⟩
    rw [hm, List.map_append, varint.enc_map _ (by omega)]
  · obtain ⟨hx, rfl⟩ := hE
    have hrl : rest.length ≤ Usize.max := by
      have := s.property; rw [hs, List.length_append] at this; omega
    have hm : s.val.map (·.val) = varint.encList x.val ++ (⟨rest, hrl⟩ : Slice Std.U8).val.map (·.val) := by
      rw [hs, List.map_append, varint.enc_map _ (by omega)]
    obtain ⟨res, hres, hok, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (triple_and (quic_vec.ContentLength.deserialize_ok s x.val _ hx hm)
        (quic_vec.ContentLength.deserialize_content s))
    obtain ⟨⟨y, t⟩, rfl⟩ := hok
    obtain ⟨hy, hmy⟩ := hP y t rfl
    obtain ⟨hn, hr⟩ := varint.encList_append_inj x.val y.val _ _ (by omega) (by omega) (hm.symm.trans hmy)
    have : y = x := UScalar.eq_of_val_eq hn.symm
    subst this
    exact ⟨t, hres, (map_val_inj hr).symm⟩
  · obtain ⟨hx, rfl⟩ := hE
    exact ContentLength.decodes x hx
  · refine triple_post_mono (ContentLength.std_de_content law r) fun q hq x hx => ?_
    obtain ⟨n, hn, hadv, hd, hle⟩ := hq x hx
    have hLv : n = varint.lenOf x.val := by obtain ⟨_, _, _, _, h, -⟩ := hd; exact h
    obtain ⟨htk, -⟩ := VarintDe.take_enc hd
    refine ⟨varint.enc x.val, ⟨hle, rfl⟩, ?_⟩
    rw [hadv, law.adv_view r n hn, ← htk, List.take_append_drop]

/-- `VLBytes`: the canonical length prefix (at most `2^30 - 1`) and the payload. -/
theorem VLBytes.agree :
    Agree quic_vec.VLBytes.Insts.Tls_codecDeserialize quic_vec.VLBytes.Insts.Tls_codecDeserializeBytes ∧
    BIndep quic_vec.VLBytes.Insts.Tls_codecDeserializeBytes := by
  refine Agree.of_enc (fun x p => x.vec.val.length ≤ 2 ^ 30 - 1 ∧
      p = varint.enc x.vec.val.length ++ x.vec.val)
    (fun s => ?_) (fun s x t h => ?_) (fun x p hE s rest hs => ?_) (fun x p hE => ?_)
    (fun R RI v a law r => ?_)
  · obtain ⟨res, hres, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (quic_vec.VLBytes.deserialize_content s)
    exact ⟨res, hres⟩
  · obtain ⟨res, hres, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (quic_vec.VLBytes.deserialize_content s)
    have he := hres.symm.trans h
    cases he
    obtain ⟨hx, hm⟩ := hP x t rfl
    refine ⟨_, ⟨hx, rfl⟩, map_val_inj ?_⟩
    rw [hm, List.map_append, List.map_append, varint.enc_map _ (by omega)]
  · obtain ⟨hx, rfl⟩ := hE
    have hrl : rest.length ≤ Usize.max := by
      have := s.property; rw [hs, List.length_append] at this; omega
    have hm : s.val.map (·.val) = varint.encList x.vec.val.length ++ x.vec.val.map (·.val) ++
        (⟨rest, hrl⟩ : Slice Std.U8).val.map (·.val) := by
      rw [hs, List.map_append, List.map_append, varint.enc_map _ (by omega)]
    obtain ⟨res, hres, ⟨q, hq, hq1, hq2⟩⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (quic_vec.VLBytes.deserialize_enc_rest x ⟨rest, hrl⟩ s hx hm)
    subst hq
    obtain ⟨y, t⟩ := q
    simp only at hq1 hq2
    subst hq1
    exact ⟨t, hres, hq2⟩
  · obtain ⟨hx, rfl⟩ := hE
    exact VLBytes.decodes x hx
  · refine triple_post_mono (VLBytes.std_de_content law r) fun q hq x hx => ?_
    obtain ⟨n, hn, hadv, hd⟩ := hq x hx
    obtain ⟨-, hle, htk, -⟩ := hd
    refine ⟨_, ⟨hle, rfl⟩, ?_⟩
    rw [hadv, law.adv_view r n hn, ← htk, List.take_append_drop]

theorem SecretVLBytes.debytes_eq (s : Slice Std.U8) :
    quic_vec.secret_bytes.SecretVLBytes.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes s =
      quic_vec.VLBytes.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes s := by
  unfold quic_vec.secret_bytes.SecretVLBytes.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
  generalize quic_vec.VLBytes.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes s = m
  rcases m with res | e | _
  · cases res <;> rfl
  · rfl
  · rfl

/-- `Agree` / `BIndep` carried over to decoders computing the same functions. -/
theorem Agree.transport {T : Type} {DI DI' : Deserialize T} {DB DB' : DeserializeBytes T}
    (h : Agree DI DB ∧ BIndep DB)
    (hD : ∀ (R : Type) (RI : alloc.io.read.Read R) (r : R),
      DI'.tls_deserialize RI r = DI.tls_deserialize RI r)
    (hB : ∀ s, DB'.tls_deserialize_bytes s = DB.tls_deserialize_bytes s) :
    Agree DI' DB' ∧ BIndep DB' := by
  refine ⟨fun R RI v a law r => ?_, fun s x t hs => ?_⟩
  · rw [hD]
    refine triple_post_mono (h.1 R RI v a law r) fun p hp s hs => ?_
    rw [hB]
    exact hp s hs
  · rw [hB] at hs
    obtain ⟨pre, h1, h2⟩ := h.2 s x t hs
    exact ⟨pre, h1, fun s' rest h' => by rw [hB]; exact h2 s' rest h'⟩

theorem SecretVLBytes.agree :
    Agree quic_vec.secret_bytes.SecretVLBytes.Insts.Tls_codecDeserialize
      quic_vec.secret_bytes.SecretVLBytes.Insts.Tls_codecDeserializeBytes ∧
    BIndep quic_vec.secret_bytes.SecretVLBytes.Insts.Tls_codecDeserializeBytes :=
  Agree.transport (T := quic_vec.VLBytes) VLBytes.agree (fun _ RI r => SecretVLBytes.de_eq RI r)
    SecretVLBytes.debytes_eq

/-! ## `Vec<T>` -/

theorem loop_cont {α β : Type} {body : α → RustM (ControlFlow α β)} {x x' : α}
    (h : body x = ok (.cont x')) : Aeneas.Std.loop body x = Aeneas.Std.loop body x' := by
  rw [Aeneas.Std.loop, h]

theorem loop_done {α β : Type} {body : α → RustM (ControlFlow α β)} {x : α} {y : β}
    (h : body x = ok (.done y)) : Aeneas.Std.loop body x = ok y := by
  rw [Aeneas.Std.loop, h]

section VecBytes
variable {T : Type} (DB : DeserializeBytes T)

theorem Vec.bbody_stop (L : Std.Usize) (rem : Slice Std.U8) (res : alloc.vec.Vec T)
    (read : Std.Usize) (h : ¬ read.val < L.val) :
    alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop.body DB L rem res read
      = ok (.done (rem, res, read, core.option.Option.None)) := by
  unfold alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop.body
  rw [if_neg (by scalar_tac)]

theorem Vec.bbody_err (L : Std.Usize) (rem : Slice Std.U8) (res : alloc.vec.Vec T)
    (read : Std.Usize) (h : read.val < L.val) (e : Error)
    (he : DB.tls_deserialize_bytes rem = ok (.Err e)) :
    alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop.body DB L rem res read
      = ok (.done (rem, res, read, core.option.Option.Some e)) := by
  unfold alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop.body
  rw [if_pos (by scalar_tac), he]
  rfl

theorem Vec.bbody_ok (L : Std.Usize) (rem : Slice Std.U8) (res : alloc.vec.Vec T)
    (read : Std.Usize) (h : read.val < L.val) (x : T) (t : Slice Std.U8)
    (hx : DB.tls_deserialize_bytes rem = ok (.Ok (x, t)))
    (hsuf : t.val.length ≤ rem.val.length)
    (hrd : read.val + (rem.val.length - t.val.length) ≤ Usize.max)
    (hres : res.val.length < Usize.max) :
    ⦃ ⌜ True ⌝ ⦄
    alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop.body DB L rem res read
    ⦃ ⇓ r => ⌜ (rem.val.length = t.val.length → ∃ res' e, r = .done (t, res', read, .Some e)) ∧
      (t.val.length < rem.val.length → ∃ (res' : alloc.vec.Vec T) (rd : Std.Usize),
        r = .cont (t, res', rd) ∧ rd.val = read.val + (rem.val.length - t.val.length) ∧
        res'.val = res.val ++ [x]) ⌝ ⦄ := by
  unfold alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop.body
  rw [if_pos (by scalar_tac), hx]
  have l1 := Slice.len_val rem
  have l2 := Slice.len_val t
  simp only [Slice.length] at l1 l2
  mvcgen [core.convert.Into.Blanket.into]
  · exact toStr_utf8 _ _
  · rename_i i hi i1 hi1 c hc hle r' hz hr' _ _
    subst hi hi1
    have hc0 : c.val = 0 := by rw [hz]; rfl
    refine ⟨fun _ => ⟨_, _, rfl⟩, fun hlt => ?_⟩
    exfalso; omega
  · rename_i i hi i1 hi1 c hc hle r' hz hr' rd hrd'
    subst hi hi1
    have hc0 : c.val ≠ 0 := fun h0 => hz (UScalar.eq_of_val_eq (by simpa using h0))
    refine ⟨fun heq => ?_, fun _ => ⟨r', rd, rfl, by omega, hr'⟩⟩
    exfalso; omega
  · rename_i i hi i1 hi1 c hc hle r' hz hr' hov
    subst hi hi1
    exfalso
    scalar_tac
  · rename_i i hi i1 hi1 hlt
    subst hi hi1
    exfalso; omega

theorem Vec.bloop_cont {L : Std.Usize} {rem rem' : Slice Std.U8} {res res' : alloc.vec.Vec T}
    {read read' : Std.Usize}
    (h : alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop.body DB L rem res
      read = ok (.cont (rem', res', read'))) :
    alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop DB rem L res read =
      alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop DB rem' L res' read' := by
  unfold alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop
  exact loop_cont h

theorem Vec.bloop_done {L : Std.Usize} {rem : Slice Std.U8} {res : alloc.vec.Vec T}
    {read : Std.Usize} {y : Slice Std.U8 × alloc.vec.Vec T × Std.Usize × core.option.Option Error}
    (h : alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop.body DB L rem res
      read = ok (.done y)) :
    alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop DB rem L res read =
      ok y := by
  unfold alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop
  exact loop_done h

theorem Vec.bloop_total (hDB : DeserializeBytes.Lawful T DB) (rem : Slice Std.U8)
    (L : Std.Usize) (r0 : alloc.vec.Vec T) (hr0 : (r0 : Slice T).val = []) :
    ∃ out, alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop DB rem L r0
      0#usize = ok out := by
  have hinv : DesLoopInv DB.SizeInst 0#usize rem.val.length rem.val (r0 : Slice T).val rem 0#usize := by
    refine ⟨by simp [hr0], ⟨0#usize, ?_, by simp⟩, by simp, List.suffix_refl _⟩
    rw [hr0]; exact .nil _
  obtain ⟨out, hout, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (alloc.vec.Vec.deserialize_bytes_loop_char DB hDB L rem.val.length
      (by have := rem.property; scalar_tac) r0 rem 0#usize hinv)
  exact ⟨out, hout⟩

/-- The final result of `Vec<T>::tls_deserialize_bytes` from the final state `out` of its loop. -/
def Vec.bfin (Lu : Std.Usize)
    (out : Slice Std.U8 × alloc.vec.Vec T × Std.Usize × core.option.Option Error)
    (res : core.result.Result (alloc.vec.Vec T × Slice Std.U8) Error) : Prop :=
  (out.2.2.2 = .None ∧ out.2.2.1.val = Lu.val → res = .Ok (out.2.1, out.1)) ∧
  (¬ (out.2.2.2 = .None ∧ out.2.2.1.val = Lu.val) → ∃ e, res = .Err e)

/-- `Vec<T>::tls_deserialize_bytes` from the length prefix and the loop. -/
theorem Vec.bytes_shape (hDB : DeserializeBytes.Lawful T DB) (s : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ (alloc.vec.Vec.Insts.Tls_codecDeserializeBytes DB).tls_deserialize_bytes s
    ⦃ ⇓ res => ⌜ (∀ e, quic_vec.ContentLength.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes s =
      ok (.Err e) → ∃ e', res = .Err e') ∧
    (∀ cl rem, quic_vec.ContentLength.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes s =
      ok (.Ok (cl, rem)) →
      (cl.val = 0 → res = .Ok (Slice.new T, rem)) ∧
      (cl.val ≠ 0 → ∃ Lu : Std.Usize, Lu.val = cl.val ∧ ∃ out,
        alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop DB rem Lu
          (Slice.new T) 0#usize = ok out ∧ Vec.bfin Lu out res)) ⌝ ⦄ := by
  have hCL : ⦃ ⌜ True ⌝ ⦄ quic_vec.ContentLength.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes s
      ⦃ ⇓ r => ⌜ quic_vec.ContentLength.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes s = ok r ∧
        ∀ (v : quic_vec.ContentLength) (t : Slice Std.U8), r = .Ok (v, t) → v.val ≤ 2 ^ 30 - 1 ⌝ ⦄ := by
    obtain ⟨cres, hcres, hcP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (quic_vec.ContentLength.deserialize_content s)
    rw [hcres]; exact ok_triple_of ⟨rfl, fun v t h => (hcP v t h).1⟩
  have hloop : ∀ rem L, ⦃ ⌜ True ⌝ ⦄
      alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop DB rem L
        (Slice.new T) 0#usize
      ⦃ ⇓ out => ⌜ alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop DB rem L
        (Slice.new T) 0#usize = ok out ⌝ ⦄ := by
    intro rem L
    obtain ⟨out, hout⟩ := Vec.bloop_total DB hDB rem L (Slice.new T) (by simp [Slice.new])
    rw [hout]; exact ok_triple_of rfl
  mvcgen [alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes, hCL, hloop,
    varint.TlsVarInt.value, CoreModels.alloc.vec.Vec.new, rust_primitives.sequence.seq_empty,
    core.hint.must_use_spec]
  · rename_i r hr cf p hcf h1 rc hrc cf2 val hcf2 hz h2
    have hr1 := continue_eq_tryCF.mp h1
    refine ⟨fun e he => ?_, fun cl rem hc => ?_⟩
    · have h := hr.1.symm.trans he; rw [hr1] at h; cases h
    · have h := hr.1.symm.trans hc; rw [hr1] at h; cases h
      have hv := hrc.1 val (continue_eq_tryCF.mp h2)
      refine ⟨fun _ => rfl, fun hne => ?_⟩
      exfalso; apply hne; rw [← hv, hz]; rfl
  · rename_i r hr cf p hcf h1 rc hrc cf2 val hcf2 hnz h2 out hnone hneq hloop' _ _ _ _ _ _
    have hr1 := continue_eq_tryCF.mp h1
    refine ⟨fun e he => ⟨_, rfl⟩, fun cl rem hc => ?_⟩
    have h := hr.1.symm.trans hc; rw [hr1] at h; cases h
    have hv := hrc.1 val (continue_eq_tryCF.mp h2)
    refine ⟨fun h0 => ?_, fun _ => ⟨val, hv, out, hloop', ?_, fun _ => ⟨_, rfl⟩⟩⟩
    · exfalso; apply hnz; apply UScalar.eq_of_val_eq; simp only at hv h0 ⊢; rw [hv, h0]; rfl
    · rintro ⟨-, hrv⟩
      exfalso
      have : out.2.2.1 = val := UScalar.eq_of_val_eq hrv
      simp [this] at hneq
  · rename_i r hr cf p hcf h1 rc hrc cf2 val hcf2 hnz h2 out hnone hneq hloop'
    have hr1 := continue_eq_tryCF.mp h1
    refine ⟨fun e he => ?_, fun cl rem hc => ?_⟩
    · have h := hr.1.symm.trans he; rw [hr1] at h; cases h
    · have h := hr.1.symm.trans hc; rw [hr1] at h; cases h
      have hv := hrc.1 val (continue_eq_tryCF.mp h2)
      have hrd : out.2.2.1.val = val.val := by simpa using hneq
      refine ⟨fun h0 => ?_, fun _ => ⟨val, hv, out, hloop', fun _ => rfl, fun hn => ?_⟩⟩
      · exfalso; apply hnz; apply UScalar.eq_of_val_eq; simp only at hv h0 ⊢; rw [hv, h0]; rfl
      · exact absurd ⟨hnone, hrd⟩ hn
  · rename_i r hr cf p hcf h1 rc hrc cf2 val hcf2 hnz h2 out e hsome hloop'
    have hr1 := continue_eq_tryCF.mp h1
    refine ⟨fun e' he => ⟨_, rfl⟩, fun cl rem hc => ?_⟩
    have h := hr.1.symm.trans hc; rw [hr1] at h; cases h
    have hv := hrc.1 val (continue_eq_tryCF.mp h2)
    refine ⟨fun h0 => ?_, fun _ => ⟨val, hv, out, hloop', fun ⟨hn, _⟩ => ?_, fun _ => ⟨_, rfl⟩⟩⟩
    · exfalso; apply hnz; apply UScalar.eq_of_val_eq; simp only at hv h0 ⊢; rw [hv, h0]; rfl
    · rw [hsome] at hn; cases hn
  · rename_i r hr cf p hcf h1 rc hrc cf2 res _
    intro hbr
    have hr1 := continue_eq_tryCF.mp h1
    have hle := hr.2 p.1 p.2 hr1
    obtain ⟨y, hy⟩ := hrc.2 (by omega)
    refine try_break_vc (x := rc) (fun e he => ?_) hbr
    rw [hy] at he
    cases he
  · rename_i r hr cf res _
    intro hbr
    refine try_break_vc (x := r) (fun e he => ?_) hbr
    refine triple_post_mono (core.convert.From.Blanket.from_spec _) ?_
    intro f hf
    subst hf
    simp only [PostCond.ok]
    mvcgen
    refine ⟨fun _ _ => ⟨_, rfl⟩, fun cl rem hc => ?_⟩
    have h := hr.1.symm.trans hc; rw [he] at h; cases h

/-- A successful run of the bytes loop (no failure, `L` bytes read) consumes a prefix `P` of its
remainder (`L - read` bytes) and reads nothing after it: on `P ++ X'` it gives the same elements
and leaves `X'`. -/
theorem Vec.bloop_indep (hDB : DeserializeBytes.Lawful T DB) (hI : BIndep DB) (Lu : Std.Usize) :
    ∀ (n : Nat) (rem : Slice Std.U8) (res : alloc.vec.Vec T) (read : Std.Usize),
    Lu.val - read.val = n → read.val ≤ Lu.val → read.val + rem.val.length ≤ Usize.max →
    (res : Slice T).val.length ≤ read.val → Lu.val ≤ 2 ^ 30 - 1 →
    ∀ (t : Slice Std.U8) (resf : alloc.vec.Vec T),
    alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop DB rem Lu res read =
      ok (t, resf, Lu, .None) →
    ∃ P : List Std.U8, P.length = n ∧ rem.val = P ++ t.val ∧
      ∀ (rem' : Slice Std.U8) (X' : List Std.U8), rem'.val = P ++ X' →
        read.val + rem'.val.length ≤ Usize.max →
        ∃ t' : Slice Std.U8, alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop
          DB rem' Lu res read = ok (t', resf, Lu, .None) ∧ t'.val = X' := by
  intro n
  induction n using Nat.strong_induction_on with
  | _ n ih =>
  intro rem res read hn hrl hrm hres hL30 t resf hout
  by_cases hlt : read.val < Lu.val
  · obtain ⟨r0, hr0⟩ := hDB.total rem
    cases r0 with
    | Err e =>
      rw [Vec.bloop_done DB (Vec.bbody_err DB Lu rem res read hlt e hr0)] at hout
      cases hout
    | Ok xt =>
      obtain ⟨x, tf⟩ := xt
      obtain ⟨pre, hpre, hall⟩ := hI _ _ _ hr0
      have hlen : rem.val.length = pre.length + tf.val.length := by rw [hpre]; simp
      have hc : rem.val.length - tf.val.length = pre.length := by rw [hlen, Nat.add_sub_cancel]
      obtain ⟨r, hr, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
        (Vec.bbody_ok DB Lu rem res read hlt x tf hr0 (by rw [hlen]; exact Nat.le_add_left _ _)
          (by rw [hc]; omega)
          (by have := imax_ge; have := imax_le; omega))
      by_cases hc0 : pre.length = 0
      · obtain ⟨res', e, rfl⟩ := hP.1 (by omega)
        rw [Vec.bloop_done DB hr] at hout
        cases hout
      · obtain ⟨res', rd, rfl, hrd, hres'⟩ := hP.2 (by omega)
        rw [hc] at hrd
        rw [Vec.bloop_cont DB hr] at hout
        -- the element stays within the `L - read` bytes left
        have hcle : pre.length ≤ n := by
          by_contra hcn
          have hrd' : ¬ rd.val < Lu.val := by omega
          rw [Vec.bloop_done DB (Vec.bbody_stop DB Lu tf res' rd hrd')] at hout
          cases hout
          omega
        obtain ⟨P2, hP2, hrem2, hall2⟩ := ih (n - pre.length) (by omega) tf res' rd
          (by rw [hrd, Nat.sub_add_eq, hn]) (by omega) (by omega) (by rw [hres']; simp; omega) hL30 t resf hout
        refine ⟨pre ++ P2, by simp; omega, by rw [hpre, hrem2, List.append_assoc], ?_⟩
        intro rem' X' hrem' hrm'
        obtain ⟨tf', htf', htfv'⟩ := hall rem' (P2 ++ X') (by rw [hrem', List.append_assoc])
        have hlen' : rem'.val.length = pre.length + tf'.val.length := by
          rw [hrem', htfv']; simp
        have hc' : rem'.val.length - tf'.val.length = pre.length := by
          rw [hlen', Nat.add_sub_cancel]
        obtain ⟨r', hr', hP'⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
          (Vec.bbody_ok DB Lu rem' res read hlt x tf' htf' (by rw [hlen']; exact Nat.le_add_left _ _)
            (by rw [hc']; omega)
            (by have := imax_ge; have := imax_le; omega))
        obtain ⟨res'', rd', rfl, hrd'', hres''⟩ := hP'.2
          (by rw [hlen']; exact Nat.lt_add_of_pos_left (Nat.pos_of_ne_zero hc0))
        rw [hc'] at hrd''
        have e1 : res'' = res' := Subtype.ext (by rw [hres'', hres'])
        have e2 : rd' = rd := UScalar.eq_of_val_eq (by rw [hrd'', hrd])
        subst e1 e2
        rw [Vec.bloop_cont DB hr']
        exact hall2 tf' X' htfv' (by rw [hrd'']; omega)
  · have hz : n = 0 := by omega
    subst hz
    rw [Vec.bloop_done DB (Vec.bbody_stop DB Lu rem res read hlt)] at hout
    cases hout
    refine ⟨[], rfl, rfl, fun rem' X' hrem' _ => ⟨rem', ?_, by simpa using hrem'⟩⟩
    rw [Vec.bloop_done DB (Vec.bbody_stop DB Lu rem' res Lu hlt)]

end VecBytes

section VecStd
variable {T : Type} {DI : Deserialize T} {DB : DeserializeBytes T} {R : Type}
  {RI : alloc.io.read.Read R} {v : R → List Std.U8} {a : R → Nat → R}

/-- The final states of the two loops agree: the `std` loop succeeds exactly when the bytes loop
read exactly `L` bytes without failure, with the same elements and remainder. -/
def VecFin (v : R → List Std.U8) (L : Nat)
    (out : Slice Std.U8 × alloc.vec.Vec T × Std.Usize × core.option.Option Error)
    (y : core.io.util.Take R × alloc.vec.Vec T × core.option.Option Error ×
      (core.io.util.Take R → R)) : Prop :=
  (y.2.2.1 = .None → out.2.2.2 = .None ∧ out.2.2.1.val = L ∧ out.2.1 = y.2.1 ∧
    v y.1.inner = out.1.val ∧ ∀ t, y.2.2.2 t = t.inner) ∧
  (y.2.2.1 ≠ .None → out.2.2.2 ≠ .None ∨ out.2.2.1.val ≠ L)

/-- Simulation invariant: the bytes loop, run from the state matching the `std` loop state, gives
the final result `B0` of the bytes loop. -/
def VecSim (DB : DeserializeBytes T) (v : R → List Std.U8) (Lu : Std.Usize)
    (B0 : RustM (Slice Std.U8 × alloc.vec.Vec T × Std.Usize × core.option.Option Error))
    (p : (R → R) × R × Std.U64 × Std.U64 × alloc.vec.Vec T) : Prop :=
  (∀ x, p.1 x = x) ∧ p.2.2.1.val = Lu.val ∧ p.2.2.2.1.val ≤ Lu.val ∧ Lu.val ≤ 2 ^ 30 - 1 ∧
  ∃ (rem : Slice Std.U8) (read : Std.Usize), rem.val = v p.2.1 ∧
    read.val + p.2.2.2.1.val = Lu.val ∧ read.val + rem.val.length ≤ Usize.max ∧
    (p.2.2.2.2 : Slice T).val.length ≤ read.val ∧
    alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop DB rem Lu
      p.2.2.2.2 read = B0

theorem drop_take_append {α : Type} (l : List α) (n m : Nat) (h : n ≤ m) (hl : n ≤ l.length) :
    (l.take m).drop n ++ l.drop m = l.drop n := by
  conv_rhs => rw [← List.take_append_drop m l]
  rw [List.drop_append_of_le_length (by simp; omega)]

/-- One element decoded by the `std` loop on the `Take` reader (limit `lim`) and by the bytes
loop on the whole remainder `rem`: same value, same consumption `n`. -/
theorem Vec.elem_ok (hI : BIndep DB) (law : StdIo.RLaw RI v a) (t : R) (len lim : Std.U64)
    (rem : Slice Std.U8) (hrem : rem.val = v t)
    (q : core.result.Result T Error × core.io.util.Take R)
    (hAg : ∀ s : Slice Std.U8, s.val = StdIo.takeView v ⟨t, len, lim⟩ →
      ∃ res, DB.tls_deserialize_bytes s = ok res ∧ AgreeRes (StdIo.takeView v) res q)
    (hRuns : ∀ val, q.1 = .Ok val → ∃ n sz, n ≤ (StdIo.takeView v ⟨t, len, lim⟩).length ∧
      q.2 = StdIo.takeAdv a ⟨t, len, lim⟩ n ∧ DI.SizeInst.tls_serialized_len val = ok sz ∧
      sz.val = n)
    (el : T) (hel : q.1 = .Ok el) :
    ∃ n, n ≤ lim.val ∧ n ≤ rem.val.length ∧ q.2 = StdIo.takeAdv a ⟨t, len, lim⟩ n ∧
      ∃ tf : Slice Std.U8, DB.tls_deserialize_bytes rem = ok (.Ok (el, tf)) ∧
        tf.val = rem.val.drop n := by
  obtain ⟨n, sz, hn, hq2, -, -⟩ := hRuns el hel
  have hn' : n ≤ lim.val ∧ n ≤ rem.val.length := by
    simp only [StdIo.takeView, List.length_take] at hn; rw [hrem]; omega
  have hl := rem.property
  let s' : Slice Std.U8 := ⟨rem.val.take lim.val, by simp; omega⟩
  obtain ⟨res, hres, hrel⟩ := hAg s' (by simp [s', StdIo.takeView, hrem])
  cases res with
  | Err e =>
    obtain ⟨e', he'⟩ := hrel
    rw [hel] at he'; cases he'
  | Ok xt =>
    obtain ⟨x, ttr⟩ := xt
    obtain ⟨h1, h2⟩ := hrel
    rw [hel] at h1; cases h1
    have hv2 : ttr.val = (rem.val.take lim.val).drop n := by
      rw [← h2, hq2, StdIo.take_adv_view law _ n hn]
      simp [StdIo.takeView, hrem]
    obtain ⟨pre, hpre, hall⟩ := hI _ _ _ hres
    have hpre' : pre = (rem.val.take lim.val).take n := by
      have e := hpre
      simp only [s'] at e
      rw [hv2] at e
      conv_lhs at e => rw [← List.take_append_drop n (rem.val.take lim.val)]
      exact (List.append_cancel_right e).symm
    obtain ⟨tf, htf, htfv⟩ := hall rem ((rem.val.take lim.val).drop n ++ rem.val.drop lim.val)
      (by rw [hpre', ← List.append_assoc, List.take_append_drop, List.take_append_drop])
    refine ⟨n, hn'.1, hn'.2, hq2, tf, htf, ?_⟩
    rw [htfv, drop_take_append _ _ _ hn'.1 hn'.2]

/-- The `std` element decoder fails on the `Take` reader: the bytes decoder fails on the whole
remainder, or consumes more than the limit. -/
theorem Vec.elem_err (hDB : DeserializeBytes.Lawful T DB) (hI : BIndep DB) (t : R)
    (len lim : Std.U64) (rem : Slice Std.U8) (hrem : rem.val = v t)
    (q : core.result.Result T Error × core.io.util.Take R)
    (hAg : ∀ s : Slice Std.U8, s.val = StdIo.takeView v ⟨t, len, lim⟩ →
      ∃ res, DB.tls_deserialize_bytes s = ok res ∧ AgreeRes (StdIo.takeView v) res q)
    (e : Error) (he : q.1 = .Err e) :
    (∃ e', DB.tls_deserialize_bytes rem = ok (.Err e')) ∨
    ∃ (y : T) (tf : Slice Std.U8), DB.tls_deserialize_bytes rem = ok (.Ok (y, tf)) ∧
      tf.val.length ≤ rem.val.length ∧ lim.val < rem.val.length - tf.val.length := by
  have hl := rem.property
  let s' : Slice Std.U8 := ⟨rem.val.take lim.val, by simp; omega⟩
  obtain ⟨res', hres', hrel'⟩ := hAg s' (by simp [s', StdIo.takeView, hrem])
  have hs'err : ∃ e', res' = .Err e' := by
    cases res' with
    | Err e' => exact ⟨e', rfl⟩
    | Ok xt => obtain ⟨h1, -⟩ := hrel'; rw [he] at h1; cases h1
  obtain ⟨res, hres⟩ := hDB.total rem
  cases res with
  | Err e' => exact Or.inl ⟨e', hres⟩
  | Ok yt =>
    obtain ⟨y, tf⟩ := yt
    right
    obtain ⟨pre, hpre⟩ := hDB.suffix hres
    have hlen : tf.val.length ≤ rem.val.length := by rw [hpre]; simp
    refine ⟨y, tf, hres, hlen, ?_⟩
    by_contra hc
    have hc' : pre.length ≤ lim.val := by
      have : rem.val.length = pre.length + tf.val.length := by rw [hpre]; simp
      omega
    obtain ⟨pre', hpre', hall⟩ := hI _ _ _ hres
    have : pre' = pre := List.append_cancel_right (hpre'.symm.trans hpre)
    subst this
    obtain ⟨t'', ht'', -⟩ := hall s' (tf.val.take (lim.val - pre'.length))
      (by simp only [s']; rw [hpre, List.take_append, List.take_of_length_le hc'])
    obtain ⟨e', rfl⟩ := hs'err
    rw [hres'] at ht''
    cases ht''

theorem Vec.sim_body (hD : Deserialize.Lawful T DI) (hDB : DeserializeBytes.Lawful T DB)
    (hA : Agree DI DB) (hI : BIndep DB) (law : StdIo.RLaw RI v a) (Lu : Std.Usize)
    (B0 : RustM (Slice Std.U8 × alloc.vec.Vec T × Std.Usize × core.option.Option Error))
    (p : (R → R) × R × Std.U64 × Std.U64 × alloc.vec.Vec T) (hp : VecSim DB v Lu B0 p) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.Tls_codecDeserialize.tls_deserialize_loop.body DI RI
      p.1 p.2.1 p.2.2.1 p.2.2.2.1 p.2.2.2.2
    ⦃ ⇓ r => ⌜ match r with
      | .done y => ∀ out, B0 = ok out → VecFin v Lu.val out y
      | .cont p' => VecSim DB v Lu B0 p' ∧ p'.2.2.2.1.val < p.2.2.2.1.val ⌝ ⦄ := by
  obtain ⟨back, t, len, lim, res⟩ := p
  obtain ⟨hback, hlen, hlim, hL30, rem, read, hrem, hrl, hrm, hres, hB⟩ := hp
  dsimp only at hback hlen hlim hrem hrl hrm hres hB ⊢
  have hT := fun t' => triple_and (hA _ _ _ _ (StdIo.take_law law) t')
    (Deserialize.Lawful.runs hD _ _ _ _ (StdIo.take_law law) t')
  mvcgen [alloc.vec.Vec.Insts.Tls_codecDeserialize.tls_deserialize_loop.body,
    core.io.util.Take.impl.limit, hT, core.convert.Into.Blanket.into]
  · exact toStr_utf8 _ _
  · -- element `Ok`, limit unchanged: nothing consumed, both loops stop with an error
    rename_i hlim0 _ q el hel hlimq _ _ hq
    obtain ⟨n, hnl, hnr, hq2, tf, htf, htfv⟩ := Vec.elem_ok hI law t len lim rem hrem q hq.1 hq.2 el hel
    have hn0 : n = 0 := by
      have h1 := congrArg UScalar.val hlimq
      rw [hq2, StdIo.takeAdv_limit] at h1
      have h2 : 0 < lim.val := by scalar_tac
      simp only at h1
      omega
    subst hn0
    have hte : tf.val.length = rem.val.length := by simp [htfv]
    obtain ⟨r, hr, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (Vec.bbody_ok DB Lu rem res read (by scalar_tac) el tf htf (by omega) (by omega)
        (by have := imax_ge; have := imax_le; omega))
    obtain ⟨res', e', rfl⟩ := hP.1 hte.symm
    intro out hout
    rw [← hB, Vec.bloop_done DB hr] at hout
    cases hout
    unfold VecFin
    exact ⟨fun h => by simp at h, fun _ => by left; simp⟩
  · have := imax_ge; have := imax_le; omega
  · -- element `Ok`, `n > 0` bytes consumed: both loops continue
    rename_i hlim0 _ q el hel hlimq r' hr' hq
    obtain ⟨n, hnl, hnr, hq2, tf, htf, htfv⟩ := Vec.elem_ok hI law t len lim rem hrem q hq.1 hq.2 el hel
    have hn0 : 0 < n := by
      rcases Nat.eq_zero_or_pos n with h0 | h0
      · exfalso; apply hlimq; rw [hq2, h0]; exact UScalar.eq_of_val_eq (by simp)
      · exact h0
    have hte : tf.val.length < rem.val.length := by simp [htfv]; omega
    obtain ⟨r, hr, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (Vec.bbody_ok DB Lu rem res read (by scalar_tac) el tf htf (by omega) (by simp [htfv]; omega)
        (by have := imax_ge; have := imax_le; omega))
    obtain ⟨res', rd, rfl, hrd, hres'⟩ := hP.2 hte
    have hrr : r' = res' := Subtype.ext (by rw [hr', hres'])
    subst hrr
    have hlq : q.2.limit.val = lim.val - n := by rw [hq2, StdIo.takeAdv_limit]
    have htl : tf.val.length = rem.val.length - n := by rw [htfv, List.length_drop]
    have hrl' : r'.val.length = res.val.length + 1 := by rw [hr']; simp
    refine ⟨⟨fun x => by simp +zetaDelta [hback], ?_, ?_, hL30, tf, rd, ?_, ?_, ?_, ?_, ?_⟩, ?_⟩
    · rw [hq2]; exact hlen
    · show q.2.limit.val ≤ Lu.val
      omega
    · rw [hq2, StdIo.takeAdv_inner, htfv, hrem, law.adv_view t n (by rw [← hrem]; omega)]
    · show rd.val + q.2.limit.val = Lu.val
      have e1 : rem.val.length - tf.val.length = n := by rw [htl]; omega
      rw [hrd, hlq, e1]
      omega
    · omega
    · show r'.val.length ≤ rd.val
      omega
    · rw [← hB, Vec.bloop_cont DB hr]
    · show q.2.limit.val < lim.val
      omega
  · -- element `Err`: the bytes loop fails too, or overshoots the length
    rename_i hlim0 _ q e he hq
    rcases Vec.elem_err hDB hI t len lim rem hrem q hq.1 e he with ⟨e', he'⟩ | ⟨y, tf, htf, hle, hgt⟩
    · intro out hout
      rw [← hB, Vec.bloop_done DB (Vec.bbody_err DB Lu rem res read (by scalar_tac) e' he')] at hout
      cases hout
      unfold VecFin
      exact ⟨fun h => by simp at h, fun _ => by left; simp⟩
    · obtain ⟨r, hr, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
        (Vec.bbody_ok DB Lu rem res read (by scalar_tac) y tf htf hle (by omega)
          (by have := imax_ge; have := imax_le; omega))
      obtain ⟨res', rd, rfl, hrd, -⟩ := hP.2 (by omega)
      intro out hout
      rw [← hB, Vec.bloop_cont DB hr, Vec.bloop_done DB (Vec.bbody_stop DB Lu tf res' rd (by omega))]
        at hout
      cases hout
      unfold VecFin
      exact ⟨fun h => by simp at h, fun _ => by right; simp only; omega⟩
  · -- limit `0`: both loops stop, having read the whole length
    rename_i hlim0
    have h0 : lim.val = 0 := by
      have : ¬ (0#u64).val < lim.val := hlim0
      simp at this; omega
    intro out hout
    rw [← hB, Vec.bloop_done DB (Vec.bbody_stop DB Lu rem res read (by omega))] at hout
    cases hout
    unfold VecFin
    exact ⟨fun _ => ⟨rfl, by simp only; omega, rfl, by simp [hrem], fun t1 => hback _⟩,
      fun h => absurd rfl h⟩

theorem Vec.sim_loop (hD : Deserialize.Lawful T DI) (hDB : DeserializeBytes.Lawful T DB)
    (hA : Agree DI DB) (hI : BIndep DB) (law : StdIo.RLaw RI v a) (Lu : Std.Usize)
    (B0 : RustM (Slice Std.U8 × alloc.vec.Vec T × Std.Usize × core.option.Option Error))
    (p : (R → R) × R × Std.U64 × Std.U64 × alloc.vec.Vec T) (hp : VecSim DB v Lu B0 p) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.Tls_codecDeserialize.tls_deserialize_loop DI RI
      p.1 p.2.1 p.2.2.1 p.2.2.2.1 p.2.2.2.2
    ⦃ ⇓ y => ⌜ ∀ out, B0 = ok out → VecFin v Lu.val out y ⌝ ⦄ := by
  unfold alloc.vec.Vec.Insts.Tls_codecDeserialize.tls_deserialize_loop
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.loop.spec_decr_nat
    (fun q : (R → R) × R × Std.U64 × Std.U64 × alloc.vec.Vec T => q.2.2.2.1.val)
    (VecSim DB v Lu B0)
  · rintro ⟨b, t, ln, lm, rs⟩ hq
    have := Vec.sim_body hD hDB hA hI law Lu B0 _ hq
    obtain ⟨y, hy, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp this
    show Aeneas.Std.WP.spec (alloc.vec.Vec.Insts.Tls_codecDeserialize.tls_deserialize_loop.body DI RI
      b t ln lm rs) _
    rw [hy, Aeneas.Std.WP.spec_ok]
    cases y with
    | done y => exact hP
    | cont q => exact hP
  · exact hp

/-- `read_length` against the bytes decoder of `ContentLength`. -/
theorem read_length_agree (law : StdIo.RLaw RI v a) (r : R) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.rw.read_length RI r
    ⦃ ⇓ p => ⌜ ∀ s : Slice Std.U8, s.val = v r → ∃ res,
      quic_vec.ContentLength.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes s = ok res ∧
      (∀ c t, res = .Ok (c, t) → ∃ L ll, p.1 = .Ok (L, ll) ∧ L.val = c.val ∧ v p.2 = t.val) ∧
      (∀ e, res = .Err e → ∃ e', p.1 = .Err e') ⌝ ⦄ := by
  have hc := triple_and (ContentLength.agree.1 _ RI v a law r) (ContentLength.std_de_content law r)
  mvcgen [quic_vec.rw.read_length, hc, varint.TlsVarInt.value]
  · rename_i q H _ val1 _ h1 ll _ rc hrc _ L _ h2
    have hq1 := continue_eq_tryCF.mp h1
    have hL := hrc.1 L (continue_eq_tryCF.mp h2)
    intro s hs
    obtain ⟨res, hres, hrel⟩ := H.1 s hs
    refine ⟨res, hres, fun c t hct => ?_, fun e he => ?_⟩
    · subst hct
      obtain ⟨h1', h2'⟩ := hrel
      rw [hq1] at h1'
      cases h1'
      exact ⟨L, ll, rfl, hL, h2'⟩
    · subst he
      obtain ⟨e', he'⟩ := hrel
      rw [hq1] at he'
      cases he'
  · rename_i q H _ val1 _ h1 ll _ rc hrc _ res _ hbr
    have hq1 := continue_eq_tryCF.mp h1
    obtain ⟨n, -, -, -, hle⟩ := H.2 val1 hq1
    obtain ⟨y, hy⟩ := hrc.2 (by omega)
    refine try_break_vc (x := rc) (fun e he => ?_) hbr
    rw [hy] at he
    cases he
  · rename_i q H _ res _ hbr
    refine try_break_vc (x := q.1) (fun e he => ?_) hbr
    refine triple_post_mono (core.convert.From.Blanket.from_spec _) ?_
    intro f hf
    subst hf
    simp only [PostCond.ok]
    mvcgen
    intro s hs
    obtain ⟨res', hres', hrel⟩ := H.1 s hs
    refine ⟨res', hres', fun c t hct => ?_, fun e' _ => ⟨_, rfl⟩⟩
    subst hct
    obtain ⟨h1', -⟩ := hrel
    rw [he] at h1'
    cases h1'

/-- The `std` loop from its initial state, against the bytes loop from any matching state. -/
theorem Vec.sim_loop_init (hD : Deserialize.Lawful T DI) (hDB : DeserializeBytes.Lawful T DB)
    (hA : Agree DI DB) (hI : BIndep DB) (law : StdIo.RLaw RI v a) (b : R → R) (t : R)
    (len lim : Std.U64) (res : alloc.vec.Vec T) :
    ⦃ ⌜ (∀ x, b x = x) ∧ lim.val = len.val ∧ len.val ≤ 2 ^ 30 - 1 ∧ (res : Slice T).val = [] ⌝ ⦄
    alloc.vec.Vec.Insts.Tls_codecDeserialize.tls_deserialize_loop DI RI b t len lim res
    ⦃ ⇓ y => ⌜ ∀ (Lu : Std.Usize) (rem : Slice Std.U8), Lu.val = len.val → rem.val = v t →
      ∀ out, alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop DB rem Lu
        res 0#usize = ok out → VecFin v Lu.val out y ⌝ ⦄ := by
  rintro ⟨hb, hll, hl30, hr⟩
  have hsim : ∀ (Lu : Std.Usize) (rem : Slice Std.U8), Lu.val = len.val → rem.val = v t →
      VecSim DB v Lu (alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop DB
        rem Lu res 0#usize) (b, t, len, lim, res) := fun Lu rem hLu hrem =>
    ⟨hb, hLu.symm, by simp only; omega, by omega, rem, 0#usize, hrem, by simp only; simp; omega,
      by simp; exact rem.property, by simp [hr], rfl⟩
  have hl := law.view_le t
  obtain ⟨y, hy, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (Vec.sim_loop hD hDB hA hI law ⟨len.val, by scalar_tac⟩ _ _
      (hsim ⟨len.val, by scalar_tac⟩ ⟨v t, hl⟩ rfl rfl))
  rw [hy]
  have key : ∀ (Lu : Std.Usize) (rem : Slice Std.U8), Lu.val = len.val → rem.val = v t →
      ∀ out, alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop DB rem Lu
        res 0#usize = ok out → VecFin v Lu.val out y := by
    intro Lu rem hLu hrem out hout
    obtain ⟨y', hy', hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (Vec.sim_loop hD hDB hA hI law Lu _ _ (hsim Lu rem hLu hrem))
    rw [hy] at hy'
    cases hy'
    exact hP out hout
  exact (ok_triple_of key) trivial

theorem Vec.agree_std (hD : Deserialize.Lawful T DI) (hDB : DeserializeBytes.Lawful T DB)
    (hA : Agree DI DB) (hI : BIndep DB) :
    Agree (alloc.vec.Vec.Insts.Tls_codecDeserialize DI)
      (alloc.vec.Vec.Insts.Tls_codecDeserializeBytes DB) := by
  intro R RI v a law r
  have hRL := triple_and (read_length_agree law r) (read_length_content law r)
  have hloop := fun b t len lim res => Vec.sim_loop_init hD hDB hA hI law b t len lim res
  have hshape := fun s => Vec.bytes_shape DB hDB s
  mvcgen [alloc.vec.Vec.Insts.Tls_codecDeserialize.tls_deserialize, hRL, hloop,
    alloc.io.read.Read.take.default, CoreModels.alloc.vec.Vec.new, rust_primitives.sequence.seq_empty]
  · rename_i q H _ val _ hz hcf
    have hq1 := continue_eq_tryCF.mp hcf
    intro s hs
    obtain ⟨cres, hcres, hok, herr⟩ := H.1 s hs
    obtain ⟨res, hres, hsh⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (hshape s)
    refine ⟨res, hres, ?_⟩
    cases cres with
    | Ok ct =>
      obtain ⟨c, t⟩ := ct
      obtain ⟨L, ll, hq, hL, hv⟩ := hok c t rfl
      rw [hq1] at hq
      cases hq
      have hc0 : c.val = 0 := by
        have : L = 0#usize := hz
        rw [← hL, this]; rfl
      rw [(hsh.2 c t hcres).1 hc0]
      exact ⟨rfl, hv⟩
    | Err e =>
      obtain ⟨e', he'⟩ := herr e rfl
      rw [hq1] at he'; cases he'
  · rename_i q H _ val _ hz hcf
    have hq1 := continue_eq_tryCF.mp hcf
    obtain ⟨n, -, -, -, hle, -⟩ := H.2 val hq1
    refine ⟨fun _ => trivial, trivial, ?_, by simp [Slice.new]⟩
    rw [Usize.cast_U64_val_eq]; exact hle
  · rename_i q H _ val _ hz hcf y hnone t' b2 hy
    have hq1 := continue_eq_tryCF.mp hcf
    intro s hs
    obtain ⟨cres, hcres, hok, herr⟩ := H.1 s hs
    obtain ⟨res, hres, hsh⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (hshape s)
    refine ⟨res, hres, ?_⟩
    cases cres with
    | Ok ct =>
      obtain ⟨c, t⟩ := ct
      obtain ⟨L, ll, hq, hL, hv⟩ := hok c t rfl
      rw [hq1] at hq
      cases hq
      have hc0 : c.val ≠ 0 := fun h0 => hz (UScalar.eq_of_val_eq (by rw [hL, h0]; rfl))
      obtain ⟨Lu, hLu, out, hout, hfin⟩ := (hsh.2 c t hcres).2 hc0
      have hF := hy Lu t (by rw [Usize.cast_U64_val_eq, hLu, hL]) hv.symm out hout
      obtain ⟨hn, hrd, hres', hvo, hback⟩ := hF.1 hnone
      rw [hfin.1 ⟨hn, hrd⟩]
      refine ⟨by rw [hres'], ?_⟩
      simp only [b2, t', hback, hvo]
    | Err e =>
      obtain ⟨e', he'⟩ := herr e rfl
      rw [hq1] at he'; cases he'
  · rename_i q H _ val _ hz hcf y e hsome t' b2 hy
    have hq1 := continue_eq_tryCF.mp hcf
    intro s hs
    obtain ⟨cres, hcres, hok, herr⟩ := H.1 s hs
    obtain ⟨res, hres, hsh⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (hshape s)
    refine ⟨res, hres, ?_⟩
    cases cres with
    | Ok ct =>
      obtain ⟨c, t⟩ := ct
      obtain ⟨L, ll, hq, hL, hv⟩ := hok c t rfl
      rw [hq1] at hq
      cases hq
      have hc0 : c.val ≠ 0 := fun h0 => hz (UScalar.eq_of_val_eq (by rw [hL, h0]; rfl))
      obtain ⟨Lu, hLu, out, hout, hfin⟩ := (hsh.2 c t hcres).2 hc0
      have hF := hy Lu t (by rw [Usize.cast_U64_val_eq, hLu, hL]) hv.symm out hout
      have h2 := hF.2 (by rw [hsome]; simp)
      obtain ⟨e', he'⟩ := hfin.2 (by
        rintro ⟨h1, h3⟩
        rcases h2 with h2 | h2
        · exact h2 h1
        · exact h2 h3)
      rw [he']
      exact ⟨e, rfl⟩
    | Err e' =>
      obtain ⟨e'', he'⟩ := herr e' rfl
      rw [hq1] at he'; cases he'
  · rename_i q H _ res _ hbr
    refine try_break_vc (x := q.1) (fun e he => ?_) hbr
    refine triple_post_mono (core.convert.From.Blanket.from_spec _) ?_
    intro f hf
    subst hf
    simp only [PostCond.ok]
    mvcgen
    intro s hs
    obtain ⟨cres, hcres, hok, herr⟩ := H.1 s hs
    obtain ⟨res', hres', hsh⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (hshape s)
    refine ⟨res', hres', ?_⟩
    cases cres with
    | Ok ct =>
      obtain ⟨c, t⟩ := ct
      obtain ⟨L, ll, hq, -, -⟩ := hok c t rfl
      rw [he] at hq; cases hq
    | Err e' =>
      obtain ⟨e'', he''⟩ := hsh.1 e' hcres
      rw [he'']
      exact ⟨_, rfl⟩

theorem Vec.bindep (hDB : DeserializeBytes.Lawful T DB) (hI : BIndep DB) :
    BIndep (alloc.vec.Vec.Insts.Tls_codecDeserializeBytes DB) := by
  intro s xs t h
  obtain ⟨res, hres, hsh⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (Vec.bytes_shape DB hDB s)
  have he := hres.symm.trans h
  cases he
  obtain ⟨cres, hcres, hcP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (quic_vec.ContentLength.deserialize_content s)
  cases cres with
  | Err e =>
    obtain ⟨e', he'⟩ := hsh.1 e hcres
    cases he'
  | Ok cr =>
    obtain ⟨cl, rem⟩ := cr
    have hcl := (hcP cl rem rfl).1
    obtain ⟨preCL, hpreCL, hallCL⟩ := ContentLength.agree.2 s cl rem hcres
    by_cases hz : cl.val = 0
    · have h0 := (hsh.2 cl rem hcres).1 hz
      cases h0
      refine ⟨preCL, hpreCL, fun s' rest hs' => ?_⟩
      obtain ⟨rem', hrem', hremv⟩ := hallCL s' rest hs'
      obtain ⟨res', hres', hsh'⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (Vec.bytes_shape DB hDB s')
      rw [(hsh'.2 cl rem' hrem').1 hz] at hres'
      exact ⟨rem', hres', hremv⟩
    · obtain ⟨Lu, hLu, out, hout, hfin⟩ := (hsh.2 cl rem hcres).2 hz
      obtain ⟨o1, o2, o3, o4⟩ := out
      have hok : o4 = .None ∧ o3.val = Lu.val := by
        by_contra hc
        obtain ⟨e, he⟩ := hfin.2 hc
        cases he
      obtain ⟨ho4, ho3⟩ := hok
      have e3 : o3 = Lu := UScalar.eq_of_val_eq ho3
      subst ho4 e3
      have hfo := hfin.1 ⟨rfl, rfl⟩
      simp only [core.result.Result.Ok.injEq, Prod.mk.injEq] at hfo
      obtain ⟨rfl, rfl⟩ := hfo
      obtain ⟨P, hPl, hremP, hallP⟩ := Vec.bloop_indep DB hDB hI o3 (o3.val - 0) rem (Slice.new T)
        0#usize (by simp) (by simp) (by simpa using rem.property) (by simp [Slice.new])
        (by rw [hLu]; exact hcl) t xs hout
      refine ⟨preCL ++ P, by rw [hpreCL, hremP, List.append_assoc], fun s' rest hs' => ?_⟩
      obtain ⟨rem', hrem', hremv⟩ := hallCL s' (P ++ rest) (by rw [hs', List.append_assoc])
      obtain ⟨res', hres', hsh'⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (Vec.bytes_shape DB hDB s')
      obtain ⟨Lu', hLu', out', hout', hfin'⟩ := (hsh'.2 cl rem' hrem').2 hz
      have e4 : Lu' = o3 := UScalar.eq_of_val_eq (by rw [hLu', hLu])
      subst e4
      obtain ⟨t', ht', ht'v⟩ := hallP rem' rest hremv (by simpa using rem'.property)
      rw [ht'] at hout'
      cases hout'
      rw [hfin'.1 ⟨rfl, rfl⟩] at hres'
      exact ⟨t', hres', ht'v⟩

theorem Vec.agree (hD : Deserialize.Lawful T DI) (hDB : DeserializeBytes.Lawful T DB)
    (hA : Agree DI DB) (hI : BIndep DB) :
    Agree (alloc.vec.Vec.Insts.Tls_codecDeserialize DI)
      (alloc.vec.Vec.Insts.Tls_codecDeserializeBytes DB) ∧
    BIndep (alloc.vec.Vec.Insts.Tls_codecDeserializeBytes DB) :=
  ⟨Vec.agree_std hD hDB hA hI, Vec.bindep hDB hI⟩

end VecStd

end tls_codec
