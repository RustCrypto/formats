/- Generic bridges between the trait-level contracts of `Serialize` / `Deserialize` and the
behaviour of a codec on lawful writers / readers (`SerRuns` / `DeRuns`, `SerSpec` / `DeSpec`),
and the behaviour lemmas of the primitive codecs (`u8`, `u16`, ...) they consume.

Obligations: none directly; the `std`-path halves (`Serialize` / `Deserialize` `Lawful` fields,
lemma traits) of `PanicFreedom.lean` / `FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): nothing ASSUMED; 1 signature-only stub
(`core.io.error.Error.Insts.CoreFmtDebug.fmt`). -/
import Aeneas
import CoreModels
import Hax
import TlsCodec.Extraction
import TlsCodec.Verification.Helpers
import TlsCodec.Verification.Std.Io
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-- `isize::MAX as usize`: the room bound of the `tls_serialize` contract. -/
def imax : Nat := (IScalar.hcast UScalarTy.Usize core.num.Isize.MAX).val

theorem imax_eq : imax * 2 + 1 = Usize.max := by
  have h := Usize.hcast_Isize_MAX_val
  unfold imax
  rcases System.Platform.numBits_eq with h' | h' <;>
    simp [UScalar.max, Usize.max, Usize.numBits, UScalarTy.numBits, h'] at h ⊢ <;> omega

theorem imax_le : imax ≤ Usize.max := by have := imax_eq; omega

theorem imax_ge : 2 ^ 31 - 1 ≤ imax := by
  have := imax_eq
  rcases System.Platform.numBits_eq with h' | h' <;> simp [Usize.max, Usize.numBits, h'] at * <;> omega

/-! ### Serializers

A serializer whose run on any lawful writer is described by one `out : Option (List U8)` (`some
b`: `Ok b.len`, the bytes `b` appended; `none`: an `Err`) meets the trait-level contract of
`tls_serialize` (both halves), and `encode` is `out`. -/

/-- The behaviour of `x`'s serializer on every lawful writer with room for `sz` bytes. -/
def SerRuns {T : Type} (SI : Serialize T) (x : T) (sz : Std.Usize) (out : Option (List Std.U8)) :
    Prop :=
  ∀ (W : Type) (WI : core.io.write.Write W), core.io.write.Write.Lawful W WI →
    ∀ w, (core.io.write.Write.view WI w).length + sz.val ≤ imax →
    ∃ r w', SI.tls_serialize WI x w = ok (r, w') ∧
      (∀ b, out = some b → (∃ n : Std.Usize, r = .Ok n ∧ n.val = b.length) ∧
        core.io.write.Write.view WI w' = core.io.write.Write.view WI w ++ b) ∧
      (out = none → ∃ e, r = .Err e)

theorem encode_of_runs {T : Type} (SI : Serialize T) (x : T) (sz : Std.Usize)
    (out : Option (List Std.U8)) (h : SerRuns SI x sz out) (hroom : sz.val ≤ imax) :
    ∃ e, spec.io.encode SI x = ok e ∧ (∀ b, out = some b → ∃ bv : alloc.vec.Vec Std.U8,
      e = .Ok bv ∧ (bv : Slice Std.U8).val = b) ∧ (out = none → ∃ err, e = .Err err) := by
  obtain ⟨r, w', hr, hs, hn⟩ := h _ alloc.vec.VecU8.Insts.CoreIoWriteWrite StdIo.vec_lawful
    ⟨[], by simp⟩ (by rw [StdIo.vec_sink]; simpa using hroom)
  have hnew : CoreModels.alloc.vec.Vec.new Std.U8 = ok ⟨[], by simp⟩ := rfl
  unfold spec.io.encode
  rw [hnew]
  simp only [bind_tc_ok]
  rw [hr]
  simp only [bind_tc_ok]
  cases out with
  | none =>
    obtain ⟨err, rfl⟩ := hn rfl
    exact ⟨_, rfl, fun b hb => (by cases hb), fun _ => ⟨err, rfl⟩⟩
  | some b =>
    obtain ⟨⟨n, rfl, _⟩, hv⟩ := hs b rfl
    refine ⟨_, rfl, fun b' hb' => ⟨w', rfl, ?_⟩, fun h => (by cases h)⟩
    cases hb'
    rw [StdIo.vec_sink, StdIo.vec_sink] at hv
    simpa using hv

theorem ok_triple_of {α : Type} {x : α} {P : α → Prop} (h : P x) :
    ⦃ ⌜ True ⌝ ⦄ (ok x : RustM α) ⦃ ⇓ r => ⌜ P r ⌝ ⦄ := RustM.ok_spec h

/-- Using a `holds` fact through a triple whose post implies the goal. -/
theorem holds_imp {m : RustM Prop} {B : Prop} (h : m.holds)
    (h2 : ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓ p => ⌜ p → B ⌝ ⦄) : B := by
  obtain ⟨p1, e1, hp1⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp h
  obtain ⟨p2, e2, hp2⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp h2
  rw [e1] at e2
  cases e2
  exact hp2 hp1

/-- Using a `holds` fact through a partial triple whose post implies the goal. -/
theorem holds_imp' {m : RustM Prop} {B : Prop} (h : m.holds)
    (h2 : ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓? p => ⌜ p → B ⌝ ⦄) : B := by
  obtain ⟨p1, e1, hp1⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp h
  exact ok_of_partial_triple h2 e1 hp1

/-- The `requires` of `tls_serialize`: room for `sz` bytes in the writer's view. -/
theorem Serialize.tls_serialize.pre_bound {T W : Type} (SI : Serialize T)
    (WI : core.io.write.Write W) (x : T) (w : W) (sz : Std.Usize)
    (hsz : SI.SizeInst.tls_serialized_len x = ok sz)
    (h : (Serialize.tls_serialize.pre WI SI.SizeInst SI x w).holds) :
    (core.io.write.Write.view WI w).length + sz.val ≤ imax := by
  apply holds_imp' h
  unfold Serialize.tls_serialize.pre
  mvcgen [hsz, spec.io.sink]
  rename_i m hm l hl d hd _
  intro hdec
  have hlv : l.val = (core.io.write.Write.view WI w).length := by rw [hl, Slice.len_val]
  simp only [decide_eq_true_eq] at hdec
  have : sz.val ≤ d.val := hdec
  unfold imax; rw [← hm]; omega

/-- The trait-level contract of `tls_serialize`, from the behaviour on lawful writers. -/
theorem Serialize.tls_serialize_spec_of_runs' {T : Type} (SI : Serialize T) (x : T)
    (sz : Std.Usize) (hsz : SI.SizeInst.tls_serialized_len x = ok sz)
    (out : Option (List Std.U8)) (hlen : sz.val ≤ imax → ∀ b, out = some b → b.length = sz.val)
    (h : SerRuns SI x sz out) {W : Type} (WI : core.io.write.Write W)
    (hWI : core.io.write.Write.Lawful W WI) (w : W)
    (hpre : (Serialize.tls_serialize.pre WI SI.SizeInst SI x w).holds) :
    ⦃ ⌜ True ⌝ ⦄ SI.tls_serialize WI x w
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize.post WI SI.SizeInst SI x w r).holds ⌝ ⦄ := by
  have hb := Serialize.tls_serialize.pre_bound SI WI x w sz hsz hpre
  obtain ⟨r, w', hr, hs, hn⟩ := h _ WI hWI w hb
  obtain ⟨e, he, hes, hen⟩ := encode_of_runs SI x sz out h (by omega)
  rw [hr]
  refine ok_triple_of ?_
  have hsk : ∀ w0, spec.io.sink WI w0 = ok ⟨core.io.write.Write.view WI w0,
      core.io.write.Write.view_le WI w0⟩ := fun _ => rfl
  unfold Serialize.tls_serialize.post RustM.holds
  cases out with
  | none =>
    obtain ⟨err, rfl⟩ := hen rfl
    obtain ⟨e', rfl⟩ := hn rfl
    mvcgen [he, core.result.Result.is_err]
  | some b =>
    obtain ⟨bv, rfl, hbv⟩ := hes b rfl
    obtain ⟨⟨n, rfl, hn'⟩, hv⟩ := hs b rfl
    mvcgen [he, hsz, hsk, core.result.Result.is_ok_and,
      __4.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleUsizeBool.call_once,
      alloc.vec.Vec.Insts.CoreOpsDerefDerefSlice.deref, alloc.vec.Vec.as_slice,
      spec.io.is_concat]
    · simpa [hbv] using hv
    · rename_i _ _ _ l hl hne
      exact absurd (decide_eq_true (UScalar.eq_of_val_eq (by
        rw [hl, Slice.len_val]; simp [Slice.length, hbv, hn']))) hne
    · rename_i l hl hne
      exact absurd (UScalar.eq_of_val_eq (by
        rw [hl, Slice.len_val]; simp [Slice.length, hbv, hlen (by omega) b rfl])) hne

theorem Serialize.tls_serialize_spec_of_runs {T : Type} (SI : Serialize T) (x : T)
    (sz : Std.Usize) (hsz : SI.SizeInst.tls_serialized_len x = ok sz)
    (out : Option (List Std.U8)) (hlen : ∀ b, out = some b → b.length = sz.val)
    (h : SerRuns SI x sz out) {W : Type} (WI : core.io.write.Write W)
    (hWI : core.io.write.Write.Lawful W WI) (w : W)
    (hpre : (Serialize.tls_serialize.pre WI SI.SizeInst SI x w).holds) :
    ⦃ ⌜ True ⌝ ⦄ SI.tls_serialize WI x w
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize.post WI SI.SizeInst SI x w r).holds ⌝ ⦄ :=
  Serialize.tls_serialize_spec_of_runs' SI x sz hsz out (fun _ => hlen) h WI hWI w hpre

/-- What the trait-level post of `tls_serialize` gives (used by generic callers). -/
theorem Serialize.tls_serialize.post_elim {T W : Type} (SI : Serialize T)
    (WI : core.io.write.Write W) (x : T) (w : W)
    (r : core.result.Result Std.Usize Error × W)
    (h : (Serialize.tls_serialize.post WI SI.SizeInst SI x w r).holds) :
    ∃ e, spec.io.encode SI x = ok e ∧
      (∀ b, e = .Ok b → SI.SizeInst.tls_serialized_len x = ok (Slice.len b) ∧
        r.1 = .Ok (Slice.len b) ∧
        core.io.write.Write.view WI r.2 = core.io.write.Write.view WI w ++ b.val) ∧
      (∀ err, e = .Err err → ∃ err', r.1 = .Err err') := by
  obtain ⟨res, w'⟩ := r
  obtain ⟨p, hp, hpt⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp h
  cases he : spec.io.encode SI x with
  | fail err => simp [Serialize.tls_serialize.post, he, Functor.map] at hp
  | div => simp [Serialize.tls_serialize.post, he, Functor.map] at hp
  | ok e =>
    refine ⟨e, rfl, ?_⟩
    apply holds_imp' h
    have he' : ⦃ ⌜ True ⌝ ⦄ spec.io.encode SI x ⦃ ⇓? r => ⌜ r = e ⌝ ⦄ :=
      partial_triple_of_ok fun r hr => by rw [he] at hr; cases hr; rfl
    have hS : ⦃ ⌜ True ⌝ ⦄ SI.SizeInst.tls_serialized_len x
        ⦃ ⇓? n => ⌜ SI.SizeInst.tls_serialized_len x = ok n ⌝ ⦄ :=
      partial_triple_of_ok fun r hr => hr
    unfold Serialize.tls_serialize.post
    mvcgen [he', hS, core.result.Result.is_err, core.result.Result.is_ok_and, spec.io.sink,
      __4.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleUsizeBool.call_once,
      alloc.vec.Vec.Insts.CoreOpsDerefDerefSlice.deref, alloc.vec.Vec.as_slice, spec.io.is_concat]
    · rename_i _ b _ he1 l hl l' hll' hsz t ht l2 hl2 hdec
      intro hcat
      subst he1 ht
      simp only [decide_eq_true_eq] at hdec hcat
      refine ⟨fun b' hb' => ?_, fun _ h => by cases h⟩
      cases hb'
      exact ⟨by rw [hsz, ← hll', hl], by rw [hdec, hl2], hcat⟩
    all_goals try (intro hf; cases hf)
    rename_i _ err _ e2 _ he1
    subst he1
    exact ⟨fun b hb => (by cases hb), fun _ _ => ⟨_, rfl⟩⟩

/-- The `requires` of `tls_serialize` from room in the writer's view. -/
theorem Serialize.tls_serialize.pre_of_bound {T W : Type} (SI : Serialize T)
    (WI : core.io.write.Write W) (x : T) (w : W) (sz : Std.Usize)
    (hsz : SI.SizeInst.tls_serialized_len x = ok sz)
    (hb : (core.io.write.Write.view WI w).length + sz.val ≤ imax) :
    (Serialize.tls_serialize.pre WI SI.SizeInst SI x w).holds := by
  unfold imax at hb
  unfold Serialize.tls_serialize.pre RustM.holds
  mvcgen [hsz, spec.io.sink]
  · rename_i m hm l hl d hd _
    have hlv : l.val = (core.io.write.Write.view WI w).length := by rw [hl, Slice.len_val]
    simp only [decide_eq_true_eq]
    show sz.val ≤ d.val
    rw [← hm] at hb; omega
  · rename_i m hm l hl hlt
    have hlv : l.val = (core.io.write.Write.view WI w).length := by rw [hl, Slice.len_val]
    rw [← hm] at hb; omega

theorem slice_eq_U8_spec (a b : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ core.Slice.Insts.CoreCmpPartialEqSlice.eq core.U8.Insts.CoreCmpPartialEqU8 a b
    ⦃ ⇓ r => ⌜ r = decide (a.val = b.val) ⌝ ⦄ :=
  core.Slice.Insts.CoreCmpPartialEqSlice.eq_spec _ a b core.U8.Insts.CoreCmpPartialEqU8.eq_decide_spec

theorem Serialize.tls_serialize_detached.post_ok {T : Type} (SI : Serialize T) (x : T)
    (b w : alloc.vec.Vec Std.U8) (he : spec.io.encode SI x = ok (.Ok b))
    (hw : (w : Slice Std.U8).val = (b : Slice Std.U8).val) :
    (Serialize.tls_serialize_detached.post SI.SizeInst SI x (.Ok w)).holds := by
  simp only [Serialize.tls_serialize_detached.post, core.result.Result.is_err, RustM.holds]
  mvcgen [core.result.Result.is_ok_and, he, alloc.vec.Vec.as_slice,
    __5.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.call_once,
    __5.ensures.closure.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.call_once,
    slice_eq_U8_spec]
  rename_i _ r hr
  rw [hr, hw]; simp

theorem Serialize.tls_serialize_detached.post_err {T : Type} (SI : Serialize T) (x : T) (e : Error) :
    (Serialize.tls_serialize_detached.post SI.SizeInst SI x (.Err e)).holds := by
  simp [Serialize.tls_serialize_detached.post, core.result.Result.is_err, RustM.holds]
  mvcgen

/-- The default body of `tls_serialize_detached`, from the contract of the type's own
`tls_serialize` at `Vec<u8>` (one generic proof for every impl that keeps the default). -/
theorem Serialize.tls_serialize_detached.default_spec {T : Type} (SI : Serialize T) (x : T)
    (sz : Std.Usize) (hsz : SI.SizeInst.tls_serialized_len x = ok sz)
    (hser : ∀ w, (Serialize.tls_serialize.pre alloc.vec.VecU8.Insts.CoreIoWriteWrite
        SI.SizeInst SI x w).holds →
      ⦃ ⌜ True ⌝ ⦄ SI.tls_serialize alloc.vec.VecU8.Insts.CoreIoWriteWrite x w
      ⦃ ⇓ r => ⌜ (Serialize.tls_serialize.post alloc.vec.VecU8.Insts.CoreIoWriteWrite
        SI.SizeInst SI x w r).holds ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default SI x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post SI.SizeInst SI x r).holds ⌝ ⦄ := by
  by_cases hle : sz.val ≤ imax
  · have hrun := hser (Slice.new Std.U8) (Serialize.tls_serialize.pre_of_bound SI _ x _ sz hsz
      (by rw [StdIo.vec_sink]; simpa [Slice.new] using hle))
    obtain ⟨⟨res, w'⟩, hr, hpost⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp hrun
    obtain ⟨e, he, hok, herr⟩ := Serialize.tls_serialize.post_elim SI _ x _ _ hpost
    have key : ∀ v, res = .Ok v → ∃ b, e = .Ok b ∧ v = Slice.len b ∧
        (w' : Slice Std.U8).val = (b : Slice Std.U8).val := by
      intro v hv
      cases e with
      | Err err => obtain ⟨_, h'⟩ := herr err rfl; rw [hv] at h'; cases h'
      | Ok b =>
        obtain ⟨_, h2, h3⟩ := hok b rfl
        rw [hv] at h2
        refine ⟨b, rfl, by cases h2; rfl, ?_⟩
        rw [StdIo.vec_sink, StdIo.vec_sink] at h3
        simpa [Slice.new] using h3
    unfold Serialize.tls_serialize_detached.default
    mvcgen [hsz, checked_capacity, CoreModels.alloc.vec.Vec.with_capacity,
      CoreModels.alloc.vec.Vec.new, rust_primitives.sequence.seq_empty, hr]
    all_goals try_vcs
    · intro _; exact Serialize.tls_serialize_detached.post_err SI x _
    · rename_i _ _ _ _ _ _ _ _ _ heq hne _ _ _ _ _ _ _
      simp [heq] at hne
    · rename_i _ _ _ _ _ v _ hv _ _ _ _
      obtain ⟨b, rfl, -, hw⟩ := key v (continue_eq_tryCF.mp hv)
      exact Serialize.tls_serialize_detached.post_ok SI x b w' he hw
    · rename_i _ _ _ _ _ v _ hv l hne hl _ _ _
      obtain ⟨b, -, hvb, hw⟩ := key v (continue_eq_tryCF.mp hv)
      exact hne (by rw [hvb, hl]; apply UScalar.eq_of_val_eq; simp [Slice.len_val, Slice.length, hw])
    · intro _; exact Serialize.tls_serialize_detached.post_err SI x _
  · unfold Serialize.tls_serialize_detached.default
    mvcgen [hsz, checked_capacity]
    all_goals try_vcs
    · intro _; exact Serialize.tls_serialize_detached.post_err SI x _
    · rename_i hng _ _ _ _
      exfalso; apply hle; unfold imax
      have : ¬ (IScalar.hcast UScalarTy.Usize core.num.Isize.MAX).val < sz.val := hng
      omega

/-! ### `u8`, `u16` -/

/-- A serializer that writes one fixed buffer `bs` with `write_all` (the integer serializers). -/
theorem ser_runs_of_write_all {T : Type} (SI : Serialize T) (x : T) (bs : Slice Std.U8)
    (sz : Std.Usize) (hsz : sz.val = bs.val.length)
    (hser : ∀ {W : Type} (WI : core.io.write.Write W) (w w' : W),
      WI.write_all w bs = ok (.Ok (), w') → SI.tls_serialize WI x w = ok (.Ok sz, w')) :
    SerRuns SI x sz (some bs.val) := by
  intro W WI hWI w hroom
  have := imax_le
  obtain ⟨w', hw, hv⟩ := hWI.law'.write_all_ok w bs (by omega)
  exact ⟨_, w', hser WI w w' hw, fun b hb => by cases hb; exact ⟨⟨sz, rfl, hsz⟩, hv⟩,
    fun h => (by cases h)⟩

theorem U8.ser_runs (x : Std.U8) : SerRuns U8.Insts.Tls_codecSerialize x 1#usize (some [x]) := by
  have hs : (Array.to_slice (Aeneas.Std.core.num.U8.to_be_bytes x)).val = [x] := by
    simp [Array.to_slice, U8_to_be_bytes_val]
  rw [← hs]
  apply ser_runs_of_write_all U8.Insts.Tls_codecSerialize x _ 1#usize (by rw [hs]; rfl)
  intro W WI w w' hw
  obtain ⟨_, he, rfl⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (core.num.U8.to_be_bytes_spec x)
  simp only [U8.Insts.Tls_codecSerialize.tls_serialize, he, lift, bind_tc_ok, write_all_of_ok hw]
  rfl

theorem U16.ser_runs (x : Std.U16) : SerRuns U16.Insts.Tls_codecSerialize x 2#usize
    (some (Aeneas.Std.core.num.U16.to_be_bytes x).val) := by
  apply ser_runs_of_write_all U16.Insts.Tls_codecSerialize x
    (Array.to_slice (Aeneas.Std.core.num.U16.to_be_bytes x)) 2#usize
    (by simpa [Array.to_slice] using (Aeneas.Std.core.num.U16.to_be_bytes x).property.symm)
  intro W WI w w' hw
  obtain ⟨_, he, rfl⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (core.num.U16.to_be_bytes_spec x)
  simp only [U16.Insts.Tls_codecSerialize.tls_serialize, he, lift, bind_tc_ok, write_all_of_ok hw]
  rfl

/-! ### Deserializers

A deserializer whose `Ok` results on lawful readers consume exactly the size of the value meets
the trait-level contract of `tls_deserialize`. `P` (the bytes before, the value, the bytes
consumed) carries what a round trip needs. -/

def DeRuns {T : Type} (DI : Deserialize T) (P : List Std.U8 → T → Nat → Prop) : Prop :=
  ∀ (R : Type) (RI : alloc.io.read.Read R) (v : R → List Std.U8) (a : R → Nat → R),
    StdIo.RLaw RI v a → ∀ r, ⦃ ⌜ True ⌝ ⦄ DI.tls_deserialize RI r
      ⦃ ⇓ p => ⌜ ∀ val, p.1 = .Ok val → ∃ n sz, n ≤ (v r).length ∧ p.2 = a r n ∧
        DI.SizeInst.tls_serialized_len val = ok sz ∧ sz.val = n ∧ P (v r) val n ⌝ ⦄

/-- Decoding gives back `x` from any lawful reader yielding `b ++ rest`, leaving `rest`. -/
def DecodesTo {T : Type} (DI : Deserialize T) (b : List Std.U8) (x : T) : Prop :=
  ∀ (R : Type) (RI : alloc.io.read.Read R) (v : R → List Std.U8) (a : R → Nat → R),
    StdIo.RLaw RI v a → ∀ r rest, v r = b ++ rest →
    ⦃ ⌜ True ⌝ ⦄ DI.tls_deserialize RI r ⦃ ⇓ p => ⌜ p.1 = .Ok x ∧ v p.2 = rest ⌝ ⦄

theorem Deserialize.tls_deserialize_spec_of_runs {T : Type} (DI : Deserialize T)
    {P : List Std.U8 → T → Nat → Prop} (h : DeRuns DI P) {R : Type}
    (RI : alloc.io.read.Read R) (hRI : alloc.io.read.Read.Lawful R RI) (r : R) :
    ⦃ ⌜ True ⌝ ⦄ DI.tls_deserialize RI r
    ⦃ ⇓ p => ⌜ (Deserialize.tls_deserialize.post RI DI.SizeInst DI r p).holds ⌝ ⦄ := by
  have law := hRI.law'
  obtain ⟨⟨res, r'⟩, hr, hok⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (h _ RI _ _ law r)
  rw [hr]
  refine ok_triple_of ?_
  unfold Deserialize.tls_deserialize.post RustM.holds
  cases res with
  | Err e => mvcgen [core.result.Result.is_err]
  | Ok val =>
    obtain ⟨n, sz, hn, rfl, hsz, hszn, _⟩ := hok val rfl
    have hv := law.adv_view r n hn
    have hl := alloc.io.read.Read.view_le RI r
    mvcgen [core.result.Result.is_err, core.result.Result.is_ok_and, spec.io.advanced,
      spec.io.stream, __7.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleSelf_Bool.call_once, hsz]
    · rename_i _ _ l hl1 l' hl2 s hs
      simp only [decide_eq_true_eq]
      apply UScalar.eq_of_val_eq
      rw [hs, hl2, hl1, Slice.len_val, Slice.len_val]
      simp only [Slice.length, hv, List.length_drop]
      omega
    · rename_i _ _ l hl1 l' hl2 hov
      rw [hl2, Slice.len_val] at hov
      simp only [Slice.length, hv, List.length_drop] at hov
      scalar_tac
    · rename_i _ hne
      exfalso; apply hne; simp only [decide_eq_true_eq]; exact ⟨n, hn, rfl⟩

/-- What the trait-level post of `tls_deserialize` gives on `Ok`. -/
theorem Deserialize.tls_deserialize.post_elim {T R : Type} (DI : Deserialize T)
    (RI : alloc.io.read.Read R) (r : R) (p : core.result.Result T Error × R) (val : T)
    (hv : p.1 = .Ok val)
    (h : (Deserialize.tls_deserialize.post RI DI.SizeInst DI r p).holds) :
    (∃ n ≤ (alloc.io.read.Read.view RI r).length, p.2 = alloc.io.read.Read.adv RI r n) ∧
    ∃ sz, DI.SizeInst.tls_serialized_len val = ok sz ∧
      (alloc.io.read.Read.view RI r).length = (alloc.io.read.Read.view RI p.2).length + sz.val := by
  obtain ⟨res, r'⟩ := p
  simp only at hv
  subst hv
  cases hsz : DI.SizeInst.tls_serialized_len val with
  | fail _ =>
    obtain ⟨q, hq, hqt⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp h
    simp [Deserialize.tls_deserialize.post, core.result.Result.is_err, core.result.Result.is_ok_and,
      __7.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleSelf_Bool.call_once, spec.io.advanced,
      spec.io.stream, hsz, Functor.map] at hq
    split at hq
    · simp [CoreModels.alloc.vec.Vec.len, rust_primitives.sequence.seq_len] at hq
    · cases hq; cases hqt
  | div =>
    obtain ⟨q, hq, hqt⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp h
    simp [Deserialize.tls_deserialize.post, core.result.Result.is_err, core.result.Result.is_ok_and,
      __7.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleSelf_Bool.call_once, spec.io.advanced,
      spec.io.stream, hsz, Functor.map] at hq
    split at hq
    · simp [CoreModels.alloc.vec.Vec.len, rust_primitives.sequence.seq_len] at hq
    · cases hq; cases hqt
  | ok sz =>
    apply holds_imp' h
    have hS : ⦃ ⌜ True ⌝ ⦄ DI.SizeInst.tls_serialized_len val ⦃ ⇓? n => ⌜ n = sz ⌝ ⦄ :=
      partial_triple_of_ok fun n hn => by rw [hsz] at hn; cases hn; rfl
    simp only [Deserialize.tls_deserialize.post, core.result.Result.is_err]
    mvcgen [core.result.Result.is_ok_and, spec.io.advanced, spec.io.stream, hS,
      __7.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleSelf_Bool.call_once]
    · rename_i _ hadv l hl l2 hl2 _ hsz' s hs
      intro hdec
      simp only [decide_eq_true_eq] at hdec hadv
      refine ⟨hadv, sz, rfl, ?_⟩
      have := congrArg UScalar.val hdec
      rw [hl, Slice.len_val, hs, hl2, Slice.len_val, hsz'] at this
      simpa [Slice.length] using this
    · intro hf; cases hf

theorem Deserialize.tls_deserialize_exact.post_err {T T1 : Type} (DI : Deserialize T)
    (AI : core.convert.AsRef T1 (Slice Std.U8)) (bytes : T1) (e : Error) :
    (Deserialize.tls_deserialize_exact.post DI.SizeInst DI AI bytes (.Err e)).holds := by
  simp [Deserialize.tls_deserialize_exact.post, core.result.Result.is_err, RustM.holds]
  mvcgen

theorem Deserialize.tls_deserialize_exact.post_ok {T T1 : Type} (DI : Deserialize T)
    (AI : core.convert.AsRef T1 (Slice Std.U8)) (bytes : T1) (val : T) (s : Slice Std.U8)
    (sz : Std.Usize) (hsz : DI.SizeInst.tls_serialized_len val = ok sz)
    (hs : AI.as_ref bytes = ok s) (hl : s.val.length = sz.val) :
    (Deserialize.tls_deserialize_exact.post DI.SizeInst DI AI bytes (.Ok val)).holds := by
  simp only [Deserialize.tls_deserialize_exact.post, core.result.Result.is_err, RustM.holds]
  mvcgen [core.result.Result.is_ok_and, hsz, hs,
    __8.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleSelf_Bool.call_once]
  rename_i _ l hl'
  simp only [decide_eq_true_eq]
  apply UScalar.eq_of_val_eq
  rw [hl', Slice.len_val]; simp [Slice.length, hl]

/-- The default body of `tls_deserialize_exact`, from the contract of the type's own
`tls_deserialize` at `&[u8]` (one generic proof for every impl that keeps the default). -/
theorem Deserialize.tls_deserialize_exact.default_spec {T T1 : Type} (DI : Deserialize T)
    (AI : core.convert.AsRef T1 (Slice Std.U8)) (hAI : core.convert.AsRef.Lawful T1 (Slice Std.U8) AI)
    (bytes : T1)
    (hde : ∀ s, ⦃ ⌜ True ⌝ ⦄ DI.tls_deserialize alloc.Shared0SliceU8.Insts.AllocIoReadRead s
      ⦃ ⇓ p => ⌜ (Deserialize.tls_deserialize.post alloc.Shared0SliceU8.Insts.AllocIoReadRead
        DI.SizeInst DI s p).holds ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ Deserialize.tls_deserialize_exact.default DI AI bytes
    ⦃ ⇓ r => ⌜ (Deserialize.tls_deserialize_exact.post DI.SizeInst DI AI bytes r).holds ⌝ ⦄ := by
  obtain ⟨s, hs, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (hAI.as_ref_spec bytes)
  obtain ⟨⟨res, s'⟩, hr, hpost⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (hde s)
  have hv := StdIo.view_eq StdIo.slice_law
  unfold Deserialize.tls_deserialize_exact.default
  mvcgen [hs, hr, core.slice.Slice.is_empty_spec]
  all_goals try_vcs
  · rename_i _ val _ hcf b hb hbe
    have hres := continue_eq_tryCF.mp hcf
    obtain ⟨-, sz, hsz, hlen⟩ := Deserialize.tls_deserialize.post_elim DI _ s _ val hres hpost
    rw [hv, hv] at hlen
    subst hbe
    simp only [decide_eq_true_eq] at hb
    have h0 : s'.val.length = 0 := by
      have := congrArg UScalar.val hb; simpa [Slice.len_val, Slice.length] using this
    exact Deserialize.tls_deserialize_exact.post_ok DI AI bytes val s sz hsz hs (by simp at hlen; omega)
  · exact Deserialize.tls_deserialize_exact.post_err DI AI bytes _
  · intro _; exact Deserialize.tls_deserialize_exact.post_err DI AI bytes _

theorem from_io_eof :
    Error.Insts.CoreConvertFromError.from core.io.error.Error.READ_EXACT_EOF = ok Error.EndOfStream :=
  rfl

/-- `read_exact` on a lawful reader, as a triple. -/
theorem read_exact_spec {R : Type} {RI : alloc.io.read.Read R} {v : R → List Std.U8}
    {a : R → Nat → R} (law : StdIo.RLaw RI v a) (r : R) (buf : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ RI.read_exact r buf
    ⦃ ⇓ p => ⌜ (buf.val.length ≤ (v r).length →
        p = (.Ok (), a r buf.val.length, alloc.io.read.cut (v r) buf)) ∧
      ((v r).length < buf.val.length → p.1 = .Err core.io.error.Error.READ_EXACT_EOF) ⌝ ⦄ := by
  by_cases h : buf.val.length ≤ (v r).length
  · rw [law.read_exact_ok r buf h]
    exact ok_triple_of ⟨fun _ => rfl, fun h' => by omega⟩
  · obtain ⟨r', b', e⟩ := law.read_exact_eof r buf (by omega)
    rw [e]
    exact ok_triple_of ⟨fun h' => by omega, fun _ => rfl⟩

/-- The buffer of a fixed-width `read_exact` (`let (s, back) ← to_slice_mut arr`) after reading
from a reader with view `vr`. -/
theorem read_fixed {N : Std.Usize} (arr : Aeneas.Std.Array Std.U8 N) (vr : List Std.U8)
    (h : N.val ≤ vr.length) :
    ((arr.to_slice_mut).2 (alloc.io.read.cut vr (arr.to_slice_mut).1)).val = vr.take N.val := by
  have ha : arr.val.length = N.val := by simpa using arr.property
  simp only [Array.to_slice_mut, Array.to_slice]
  rw [Array.from_slice_val _ _ (by simp [StdIo.cut_val, ha]; omega)]
  simp [StdIo.cut_val, ha]

theorem to_slice_mut_len {N : Std.Usize} (arr : Aeneas.Std.Array Std.U8 N) :
    (arr.to_slice_mut).1.val.length = N.val := by
  simpa [Array.to_slice_mut, Array.to_slice] using arr.property

/-- What a fixed-width integer deserializer (`N` bytes, decoded by `fromb`) gives. -/
def FixedDe {T : Type} (N : Std.Usize) (fromb : Aeneas.Std.Array Std.U8 N → T)
    (l : List Std.U8) (val : T) (n : Nat) : Prop :=
  n = N.val ∧ ∃ arr : Aeneas.Std.Array Std.U8 N, arr.val = l.take N.val ∧ val = fromb arr

/-- The behaviour of a fixed-width integer deserializer on a lawful reader. -/
def FixedRuns {T : Type} (DI : Deserialize T) (N : Std.Usize)
    (fromb : Aeneas.Std.Array Std.U8 N → T) : Prop :=
  ∀ (R : Type) (RI : alloc.io.read.Read R) (v : R → List Std.U8) (a : R → Nat → R),
    StdIo.RLaw RI v a → ∀ r, ⦃ ⌜ True ⌝ ⦄ DI.tls_deserialize RI r
    ⦃ ⇓ p => ⌜ (N.val ≤ (v r).length → ∃ arr : Aeneas.Std.Array Std.U8 N,
        arr.val = (v r).take N.val ∧ p = (.Ok (fromb arr), a r N.val)) ∧
      ((v r).length < N.val → ∃ e, p.1 = .Err e) ⌝ ⦄

theorem DeRuns_of_fixed {T : Type} (DI : Deserialize T) (N : Std.Usize)
    (fromb : Aeneas.Std.Array Std.U8 N → T) (hsz : ∀ val, DI.SizeInst.tls_serialized_len val = ok N)
    (h : FixedRuns DI N fromb) : DeRuns DI (FixedDe N fromb) := by
  intro R RI v a law r
  refine triple_post_mono (h _ RI v a law r) fun p hp val hval => ?_
  by_cases hN : N.val ≤ (v r).length
  · obtain ⟨arr, harr, rfl⟩ := hp.1 hN
    cases hval
    exact ⟨_, N, hN, rfl, hsz _, rfl, rfl, arr, harr, rfl⟩
  · obtain ⟨e, he⟩ := hp.2 (by omega)
    rw [he] at hval; cases hval

theorem DecodesTo_of_fixed {T : Type} (DI : Deserialize T) (N : Std.Usize)
    (fromb : Aeneas.Std.Array Std.U8 N → T) (h : FixedRuns DI N fromb)
    (arr : Aeneas.Std.Array Std.U8 N) : DecodesTo DI arr.val (fromb arr) := by
  intro R RI v a law r rest hv
  have hl : arr.val.length = N.val := by simpa using arr.property
  refine triple_post_mono (h _ RI v a law r) fun p hp => ?_
  obtain ⟨arr', harr, rfl⟩ := hp.1 (by rw [hv]; simp)
  have : arr' = arr := Subtype.ext (by rw [harr, hv, List.take_left' hl])
  subst this
  refine ⟨rfl, ?_⟩
  rw [law.adv_view r _ (by rw [hv]; simp), hv, List.drop_left' hl]

/-- `FixedRuns` of an integer deserializer: `read_exact` of `N` bytes into the `to_be_bytes`
buffer of `default`, then `from_be_bytes` (the impl's function, its `default`, its
`to_be_bytes` / `from_be_bytes` specs and `N`). -/
macro "fixed_runs" f:ident dflt:ident tob:ident fromb:ident N:term : tactic => `(tactic| (
  intro R RI v a law r
  have hre := read_exact_spec law r
  mvcgen [$f:ident, hre, $dflt:ident, $tob:ident, $fromb:ident]
  · rename_i arr _ p hp _ _ _ x1 hcf x hx
    have hl : (arr.to_slice_mut).1.val.length = ($N : Std.Usize).val := to_slice_mut_len arr
    by_cases h1 : ($N : Std.Usize).val ≤ (v r).length
    · have hpe := hp.1 (by rw [hl]; exact h1)
      subst hpe
      exact ⟨fun _ => ⟨x1, read_fixed arr (v r) h1, by rw [hx, hl]⟩, fun h => by omega⟩
    · rw [hp.2 (by rw [hl]; omega)] at hcf
      simp [tryCF] at hcf
  · rename_i arr _ p hp _ res _ hcf
    have hl : (arr.to_slice_mut).1.val.length = ($N : Std.Usize).val := to_slice_mut_len arr
    by_cases h1 : ($N : Std.Usize).val ≤ (v r).length
    · rw [hp.1 (by rw [hl]; exact h1)] at hcf
      simp [tryCF] at hcf
    · rw [hp.2 (by rw [hl]; omega)] at hcf
      simp only [tryCF] at hcf
      cases hcf
      refine ⟨_, rfl, ?_⟩
      rw [from_io_eof]
      refine ok_triple_of ?_
      mvcgen
      exact ⟨fun h => by omega, fun _ => ⟨_, rfl⟩⟩))

theorem U8.fixed_runs : FixedRuns U8.Insts.Tls_codecDeserialize 1#usize
    Aeneas.Std.core.num.U8.from_be_bytes := by
  fixed_runs U8.Insts.Tls_codecDeserialize.tls_deserialize core.U8.Insts.CoreDefaultDefault.default
    core.num.U8.to_be_bytes_spec core.num.U8.from_be_bytes_spec 1#usize

theorem U16.fixed_runs : FixedRuns U16.Insts.Tls_codecDeserialize 2#usize
    Aeneas.Std.core.num.U16.from_be_bytes := by
  fixed_runs U16.Insts.Tls_codecDeserialize.tls_deserialize
    core.U16.Insts.CoreDefaultDefault.default core.num.U16.to_be_bytes_spec
    core.num.U16.from_be_bytes_spec 2#usize

theorem U8.de_runs : DeRuns U8.Insts.Tls_codecDeserialize
    (FixedDe 1#usize Aeneas.Std.core.num.U8.from_be_bytes) :=
  DeRuns_of_fixed _ _ _ (fun _ => rfl) U8.fixed_runs

theorem U16.de_runs : DeRuns U16.Insts.Tls_codecDeserialize
    (FixedDe 2#usize Aeneas.Std.core.num.U16.from_be_bytes) :=
  DeRuns_of_fixed _ _ _ (fun _ => rfl) U16.fixed_runs

theorem U8.ser_spec {W : Type} (WI : core.io.write.Write W)
    (hWI : core.io.write.Write.Lawful W WI) (x : Std.U8) (w : W)
    (hpre : (Serialize.tls_serialize.pre WI U8.Insts.Tls_codecSerialize.SizeInst
      U8.Insts.Tls_codecSerialize x w).holds) :
    ⦃ ⌜ True ⌝ ⦄ U8.Insts.Tls_codecSerialize.tls_serialize WI x w
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize.post WI U8.Insts.Tls_codecSerialize.SizeInst
      U8.Insts.Tls_codecSerialize x w r).holds ⌝ ⦄ :=
  Serialize.tls_serialize_spec_of_runs U8.Insts.Tls_codecSerialize x 1#usize rfl (some [x])
    (fun b hb => by cases hb; rfl) (U8.ser_runs x) WI hWI w hpre

theorem U8.de_spec {R : Type} (RI : alloc.io.read.Read R) (hRI : alloc.io.read.Read.Lawful R RI)
    (r : R) :
    ⦃ ⌜ True ⌝ ⦄ U8.Insts.Tls_codecDeserialize.tls_deserialize RI r
    ⦃ ⇓ p => ⌜ (Deserialize.tls_deserialize.post RI U8.Insts.Tls_codecDeserialize.SizeInst
      U8.Insts.Tls_codecDeserialize r p).holds ⌝ ⦄ :=
  Deserialize.tls_deserialize_spec_of_runs U8.Insts.Tls_codecDeserialize U8.de_runs RI hRI r

theorem U16.ser_spec {W : Type} (WI : core.io.write.Write W)
    (hWI : core.io.write.Write.Lawful W WI) (x : Std.U16) (w : W)
    (hpre : (Serialize.tls_serialize.pre WI U16.Insts.Tls_codecSerialize.SizeInst
      U16.Insts.Tls_codecSerialize x w).holds) :
    ⦃ ⌜ True ⌝ ⦄ U16.Insts.Tls_codecSerialize.tls_serialize WI x w
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize.post WI U16.Insts.Tls_codecSerialize.SizeInst
      U16.Insts.Tls_codecSerialize x w r).holds ⌝ ⦄ :=
  Serialize.tls_serialize_spec_of_runs U16.Insts.Tls_codecSerialize x 2#usize rfl _
    (fun b hb => by cases hb; simpa using (Aeneas.Std.core.num.U16.to_be_bytes x).property)
    (U16.ser_runs x) WI hWI w hpre

theorem U16.de_spec {R : Type} (RI : alloc.io.read.Read R) (hRI : alloc.io.read.Read.Lawful R RI)
    (r : R) :
    ⦃ ⌜ True ⌝ ⦄ U16.Insts.Tls_codecDeserialize.tls_deserialize RI r
    ⦃ ⇓ p => ⌜ (Deserialize.tls_deserialize.post RI U16.Insts.Tls_codecDeserialize.SizeInst
      U16.Insts.Tls_codecDeserialize r p).holds ⌝ ⦄ :=
  Deserialize.tls_deserialize_spec_of_runs U16.Insts.Tls_codecDeserialize U16.de_runs RI hRI r

/-! ### Lemma traits (`RoundTripStd`, `NonEmptyStd`, `SameBytes`)

From two per-type facts: the encoding (`encode x = Ok b`) and decoding of `b ++ rest` on every
lawful reader (`DecodesTo`). -/

theorem PartialEq.eq_self {T : Type} {PI : core.cmp.PartialEq T T}
    (h : core.cmp.PartialEq.Lawful T T PI) (x : T) :
    ⦃ ⌜ True ⌝ ⦄ PI.eq x x ⦃ ⇓ r => ⌜ r = true ⌝ ⦄ :=
  triple_post_mono (h.eq_spec x x) fun r hr => hr.mpr HEq.rfl

theorem spec.io.RoundTripStd.round_trip_std.pre_elim {T R : Type} (RT : spec.io.RoundTripStd T)
    (RI : alloc.io.read.Read R) (x : T) (bv : alloc.vec.Vec Std.U8) (reader : R)
    (rest : Slice Std.U8) (henc : spec.io.encode RT.SerializeInst x = ok (.Ok bv))
    (h : (spec.io.RoundTripStd.round_trip_std.pre RI RT.SerializeInst RT.DeserializeInst
      RT.corecmpPartialEqInst RT x reader rest).holds) :
    alloc.io.read.Read.view RI reader = (bv : Slice Std.U8).val ++ rest.val := by
  apply holds_imp' h
  have he' : ⦃ ⌜ True ⌝ ⦄ spec.io.encode RT.SerializeInst x ⦃ ⇓? r => ⌜ r = .Ok bv ⌝ ⦄ :=
    partial_triple_of_ok fun r hr => by rw [henc] at hr; cases hr; rfl
  unfold spec.io.RoundTripStd.round_trip_std.pre
  mvcgen [he', core.result.Result.is_ok_and, spec.io.stream, spec.io.is_concat,
    spec.io._.requires.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.call_once,
    alloc.vec.Vec.Insts.CoreOpsDerefDerefSlice.deref, alloc.vec.Vec.as_slice]
  rename_i _ t _ ht
  cases ht
  simp

theorem spec.io.RoundTripStd.round_trip_std_of {T : Type} (RT : spec.io.RoundTripStd T)
    (hEq : core.cmp.PartialEq.Lawful T T RT.corecmpPartialEqInst) (x : T)
    (bv : alloc.vec.Vec Std.U8) (henc : spec.io.encode RT.SerializeInst x = ok (.Ok bv))
    (hdec : DecodesTo RT.DeserializeInst (bv : Slice Std.U8).val x) {R : Type}
    (RI : alloc.io.read.Read R) (hRI : alloc.io.read.Read.Lawful R RI) (reader : R)
    (rest : Slice Std.U8)
    (hpre : (spec.io.RoundTripStd.round_trip_std.pre RI RT.SerializeInst RT.DeserializeInst
      RT.corecmpPartialEqInst RT x reader rest).holds) :
    ⦃ ⌜ True ⌝ ⦄ spec.io.RoundTripStd.round_trip_std.default RI x reader rest
    ⦃ ⇓ r => ⌜ (spec.io.RoundTripStd.round_trip_std.post RI RT.SerializeInst RT.DeserializeInst
      RT.corecmpPartialEqInst RT x reader rest r).holds ⌝ ⦄ := by
  have hv := spec.io.RoundTripStd.round_trip_std.pre_elim RT RI x bv reader rest henc hpre
  have hd := hdec _ RI _ _ hRI.law' reader rest.val hv
  have heq := PartialEq.eq_self hEq x
  unfold spec.io.RoundTripStd.round_trip_std.default
  refine ok_triple_of ?_
  unfold spec.io.RoundTripStd.round_trip_std.post RustM.holds
  mvcgen [spec.io.decode_std, hd, core.result.Result.is_ok_and, spec.io.stream, heq,
    spec.io.__1.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleSelf_Bool.call_once,
    alloc.vec.Vec.as_slice, slice_eq_U8_spec]
  · rename_i p hp t ht
    rw [hp.1] at ht; cases ht
    mvcgen [heq, slice_eq_U8_spec]
    rename_i _ _ q hq
    rw [hq]; exact decide_eq_true hp.2
  · rename_i p hp e he _
    rw [hp.1] at he; cases he

/-- The default `tls_deserialize_exact` on a slice holding exactly an encoding of `x`. -/
theorem Deserialize.tls_deserialize_exact.default_decodes {T : Type} (DI : Deserialize T)
    (b : List Std.U8) (x : T) (hdec : DecodesTo DI b x) (s : Slice Std.U8) (hs : s.val = b) :
    ⦃ ⌜ True ⌝ ⦄ Deserialize.tls_deserialize_exact.default DI
      (core.Shared0T.Insts.CoreConvertAsRef (core.Slice.Insts.CoreConvertAsRefSlice Std.U8)) s
    ⦃ ⇓ r => ⌜ r = .Ok x ⌝ ⦄ := by
  have hd := hdec _ _ _ _ StdIo.slice_law s [] (by simp [hs])
  unfold Deserialize.tls_deserialize_exact.default
  mvcgen [hd, core.Slice.Insts.CoreConvertAsRefSlice.as_ref, core.slice.Slice.is_empty_spec]
  rename_i r hr
  subst hr
  mvcgen [hd, core.slice.Slice.is_empty_spec]
  · rename_i p hp _ v _ hcf _ _ _
    rw [hp.1] at hcf; simp [tryCF] at hcf; rw [hcf]
  · rename_i p hp _ v _ hcf q hq hqe
    exfalso; apply hq; rw [hqe]; simp only [decide_eq_true_eq]
    apply UScalar.eq_of_val_eq; simp [Slice.len_val, Slice.length, hp.2]
  · rename_i p hp _ _ _
    intro hcf; rw [hp.1] at hcf; simp [tryCF] at hcf

/-- `round_trip_exact` of a type whose `tls_deserialize_exact` is the default. -/
theorem spec.io.RoundTripStd.round_trip_exact_of {T : Type} (RT : spec.io.RoundTripStd T)
    (hEq : core.cmp.PartialEq.Lawful T T RT.corecmpPartialEqInst) (x : T)
    (bv : alloc.vec.Vec Std.U8) (henc : spec.io.encode RT.SerializeInst x = ok (.Ok bv))
    (hex : ∀ s : Slice Std.U8, s.val = (bv : Slice Std.U8).val →
      ⦃ ⌜ True ⌝ ⦄ RT.DeserializeInst.tls_deserialize_exact
        (core.Shared0T.Insts.CoreConvertAsRef (core.Slice.Insts.CoreConvertAsRefSlice Std.U8)) s
      ⦃ ⇓ r => ⌜ r = .Ok x ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ spec.io.RoundTripStd.round_trip_exact.default x
    ⦃ ⇓ r => ⌜ (spec.io.RoundTripStd.round_trip_exact.post RT.SerializeInst RT.DeserializeInst
      RT.corecmpPartialEqInst RT x r).holds ⌝ ⦄ := by
  have heq := PartialEq.eq_self hEq x
  have hx := hex bv rfl
  unfold spec.io.RoundTripStd.round_trip_exact.default
  refine ok_triple_of ?_
  simp only [spec.io.RoundTripStd.round_trip_exact.post, henc, core.result.Result.is_err,
    RustM.holds]
  mvcgen [core.result.Result.is_ok_and, alloc.vec.Vec.as_slice, hx, heq,
    spec.io.__2.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.call_once,
    spec.io.__2.ensures.closure.closure.Insts.CoreOpsFunctionFnOnceTupleSelf_Bool.call_once]
  intro ht
  cases ht
  mvcgen [heq]

/-- `nonempty_std` from a non-empty encoding. -/
theorem spec.io.NonEmptyStd.nonempty_std_of {T : Type} (NE : spec.io.NonEmptyStd T) (x : T)
    (bv : alloc.vec.Vec Std.U8)
    (henc : spec.io.encode NE.RoundTripStdInst.SerializeInst x = ok (.Ok bv))
    (hne : (bv : Slice Std.U8).val ≠ []) :
    ⦃ ⌜ True ⌝ ⦄ spec.io.NonEmptyStd.nonempty_std.default x
    ⦃ ⇓ r => ⌜ (spec.io.NonEmptyStd.nonempty_std.post NE.RoundTripStdInst NE x r).holds ⌝ ⦄ := by
  unfold spec.io.NonEmptyStd.nonempty_std.default
  refine ok_triple_of ?_
  simp only [spec.io.NonEmptyStd.nonempty_std.post, henc, core.result.Result.is_err, RustM.holds]
  mvcgen [core.result.Result.is_ok_and,
    spec.io.__3.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.call_once]
  rename_i _ l hl
  simp only [decide_eq_true_eq, gt_iff_lt]
  rw [UScalar.lt_equiv, hl, Slice.len_val]
  simpa [Slice.length, List.length_pos_iff] using hne

/-- `same_bytes` from equal `Ok` outputs of both serializers. -/
theorem spec.io.SameBytes.same_bytes_of {T : Type} (SB : spec.io.SameBytes T) (x : T)
    (bv bv' : alloc.vec.Vec Std.U8)
    (henc : spec.io.encode SB.SerializeInst x = ok (.Ok bv))
    (hbytes : SB.SerializeBytesInst.tls_serialize_bytes x = ok (.Ok bv'))
    (heq : (bv : Slice Std.U8).val = (bv' : Slice Std.U8).val) :
    ⦃ ⌜ True ⌝ ⦄ spec.io.SameBytes.same_bytes.default x
    ⦃ ⇓ r => ⌜ (spec.io.SameBytes.same_bytes.post SB.SerializeInst SB.SerializeBytesInst SB x r).holds ⌝ ⦄ := by
  unfold spec.io.SameBytes.same_bytes.default
  refine ok_triple_of ?_
  simp only [spec.io.SameBytes.same_bytes.post, henc, hbytes, core.result.Result.is_err, RustM.holds]
  mvcgen [core.result.Result.is_ok_and, alloc.vec.Vec.as_slice, slice_eq_U8_spec,
    spec.io.__4.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.call_once,
    spec.io.__4.ensures.closure.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.call_once]
  rename_i _ q hq
  rw [hq]; exact decide_eq_true heq

/-! ### `u8`: lemma traits -/

theorem U8.encode (x : Std.U8) : ∃ bv : alloc.vec.Vec Std.U8,
    spec.io.encode U8.Insts.Tls_codecSerialize x = ok (.Ok bv) ∧ (bv : Slice Std.U8).val = [x] := by
  obtain ⟨e, he, hs, -⟩ := encode_of_runs _ x _ _ (U8.ser_runs x) (by have := imax_ge; simp; omega)
  obtain ⟨bv, rfl, hbv⟩ := hs [x] rfl
  exact ⟨bv, he, hbv⟩

theorem U8.decodes (x : Std.U8) : DecodesTo U8.Insts.Tls_codecDeserialize [x] x := by
  have h := DecodesTo_of_fixed _ _ _ U8.fixed_runs (Aeneas.Std.core.num.U8.to_be_bytes x)
  rwa [U8_from_be_bytes_to_be_bytes, U8_to_be_bytes_val] at h

theorem U8.round_trip_std {R : Type} (RI : alloc.io.read.Read R)
    (hRI : alloc.io.read.Read.Lawful R RI) (x : Std.U8) (reader : R) (rest : Slice Std.U8)
    (hpre : (spec.io.RoundTripStd.round_trip_std.pre RI U8.Insts.Tls_codecSpecIoRoundTripStd.SerializeInst
      U8.Insts.Tls_codecSpecIoRoundTripStd.DeserializeInst
      U8.Insts.Tls_codecSpecIoRoundTripStd.corecmpPartialEqInst U8.Insts.Tls_codecSpecIoRoundTripStd
      x reader rest).holds) :
    ⦃ ⌜ True ⌝ ⦄ spec.io.RoundTripStd.round_trip_std.default RI x reader rest
    ⦃ ⇓ r => ⌜ (spec.io.RoundTripStd.round_trip_std.post RI
      U8.Insts.Tls_codecSpecIoRoundTripStd.SerializeInst U8.Insts.Tls_codecSpecIoRoundTripStd.DeserializeInst
      U8.Insts.Tls_codecSpecIoRoundTripStd.corecmpPartialEqInst U8.Insts.Tls_codecSpecIoRoundTripStd
      x reader rest r).holds ⌝ ⦄ := by
  obtain ⟨bv, he, hbv⟩ := U8.encode x
  exact spec.io.RoundTripStd.round_trip_std_of _ core.U8.Insts.CoreCmpPartialEqU8.Lawful x bv he
    (hbv ▸ U8.decodes x) RI hRI reader rest hpre

theorem U8.round_trip_exact (x : Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ spec.io.RoundTripStd.round_trip_exact.default x
    ⦃ ⇓ r => ⌜ (spec.io.RoundTripStd.round_trip_exact.post
      U8.Insts.Tls_codecSpecIoRoundTripStd.SerializeInst U8.Insts.Tls_codecSpecIoRoundTripStd.DeserializeInst
      U8.Insts.Tls_codecSpecIoRoundTripStd.corecmpPartialEqInst U8.Insts.Tls_codecSpecIoRoundTripStd
      x r).holds ⌝ ⦄ := by
  obtain ⟨bv, he, hbv⟩ := U8.encode x
  exact spec.io.RoundTripStd.round_trip_exact_of _ core.U8.Insts.CoreCmpPartialEqU8.Lawful x bv he
    fun s hs => Deserialize.tls_deserialize_exact.default_decodes U8.Insts.Tls_codecDeserialize _ x
      (U8.decodes x) s (hs.trans hbv)

theorem U8.nonempty_std (x : Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ spec.io.NonEmptyStd.nonempty_std.default x
    ⦃ ⇓ r => ⌜ (spec.io.NonEmptyStd.nonempty_std.post U8.Insts.Tls_codecSpecIoNonEmptyStd.RoundTripStdInst
      U8.Insts.Tls_codecSpecIoNonEmptyStd x r).holds ⌝ ⦄ := by
  obtain ⟨bv, he, hbv⟩ := U8.encode x
  exact spec.io.NonEmptyStd.nonempty_std_of _ x bv he (by simp [hbv])

theorem U8.same_bytes (x : Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ spec.io.SameBytes.same_bytes.default x
    ⦃ ⇓ r => ⌜ (spec.io.SameBytes.same_bytes.post U8.Insts.Tls_codecSpecIoSameBytes.SerializeInst
      U8.Insts.Tls_codecSpecIoSameBytes.SerializeBytesInst U8.Insts.Tls_codecSpecIoSameBytes x r).holds ⌝ ⦄ := by
  obtain ⟨bv, he, hbv⟩ := U8.encode x
  obtain ⟨_, hb, bv', rfl, hbv'⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (U8_serialize_char x)
  exact spec.io.SameBytes.same_bytes_of _ x bv bv' he hb (by rw [hbv, hbv', U8_to_be_bytes_val])

end tls_codec
