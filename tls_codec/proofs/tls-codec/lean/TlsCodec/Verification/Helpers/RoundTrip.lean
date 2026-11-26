/- `RoundTrip` of the generic containers (`Vec<T>`) on the bytes path: deserialization on the
concatenated encodings of known elements.

Obligations: none directly; the `RoundTrip` FC
halves of `FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): ASSUMED `size_of`, `size_of_U8`; `native_decide`
(1). -/
import Aeneas
import CoreModels
import Hax
import TlsCodec.Extraction
import TlsCodec.Verification.Helpers
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-- `NonEmpty::nonempty`, FC: the post reads the serializer's output, so it follows from every `Ok`
output of the (total) serializer being non-empty. -/
theorem spec.NonEmpty.nonempty.default_fc {Self : Type} (RT : spec.RoundTrip Self)
    (NE : spec.NonEmpty Self) (x : Self)
    (hpf : ⦃ ⌜ True ⌝ ⦄ RT.SerializeBytesInst.tls_serialize_bytes x ⦃ ⇓ _ => ⌜ True ⌝ ⦄)
    (h : ⦃ ⌜ True ⌝ ⦄ RT.SerializeBytesInst.tls_serialize_bytes x
      ⦃ ⇓? r => ⌜ ∀ v, r = .Ok v → 0 < v.val.length ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ spec.NonEmpty.nonempty.default x
    ⦃ ⇓? r => ⌜ (spec.NonEmpty.nonempty.post RT NE x r).holds ⌝ ⦄ := by
  have h' := total_of_pf_partial hpf h
  unfold spec.NonEmpty.nonempty.default
  mvcgen
  unfold spec.NonEmpty.nonempty.post RustM.holds
  mvcgen [h', core.result.Result.is_ok_and,
    spec.__2.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.call_once]
  simp only [decide_eq_true_eq, UScalar.lt_equiv]
  simp_all

/-- `NonEmpty::nonempty`, FC, when the size is positive: an `Ok` output has the (positive) size
as length (`hpf`, `hfc`: the serializer's PF and trait-level post). -/
theorem spec.NonEmpty.nonempty.default_fc_size {Self : Type} (RT : spec.RoundTrip Self)
    (NE : spec.NonEmpty Self) (x : Self)
    (hpf : ⦃ ⌜ True ⌝ ⦄ RT.SerializeBytesInst.tls_serialize_bytes x ⦃ ⇓ _ => ⌜ True ⌝ ⦄)
    (hfc : ⦃ ⌜ True ⌝ ⦄ RT.SerializeBytesInst.tls_serialize_bytes x
      ⦃ ⇓? res => ⌜ (SerializeBytes.tls_serialize_bytes.post RT.SerializeBytesInst.SizeInst
        RT.SerializeBytesInst x res).holds ⌝ ⦄)
    (hsize : ⦃ ⌜ True ⌝ ⦄ RT.SerializeBytesInst.SizeInst.tls_serialized_len x
      ⦃ ⇓ n => ⌜ 0 < n.val ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ spec.NonEmpty.nonempty.default x
    ⦃ ⇓? r => ⌜ (spec.NonEmpty.nonempty.post RT NE x r).holds ⌝ ⦄ := by
  refine spec.NonEmpty.nonempty.default_fc RT NE x hpf
    (partial_triple_post_mono hfc fun r hp v hv => ?_)
  subst hv
  obtain ⟨n, hn, hl⟩ := SerializeBytes.post_ok_elim _ _ _ _ hp
  obtain ⟨m, hm, hpos⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp hsize
  obtain rfl := ok.inj (hn.symm.trans hm)
  exact hl ▸ hpos

/-- The serializer's `Ok` output of an element of a `NonEmpty.Lawful` type is non-empty. -/
theorem spec.NonEmpty.Lawful.ser_pos {T : Type} {NE : spec.NonEmpty T}
    (hl : spec.NonEmpty.Lawful T NE) (x : T) (b : alloc.vec.Vec Std.U8)
    (hb : NE.RoundTripInst.SerializeBytesInst.tls_serialize_bytes x = ok (.Ok b)) :
    0 < b.val.length := by
  obtain ⟨u, hu, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (hl.nonempty_spec x (pre_holds_of_ok_true rfl))
  have hlen : alloc.vec.Vec.len b = ok (Slice.len (b : Slice Std.U8)) := by
    obtain ⟨l, hl, hl'⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (alloc.vec.Vec.len_spec b)
    rw [hl, hl']
  unfold spec.NonEmpty.nonempty.post at hP
  rw [hb] at hP
  simp only [core.result.Result.is_err, core.result.Result.is_ok_and,
    spec.__2.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleVecU8Bool.call_once] at hP
  simp [hlen, Functor.map] at hP
  have h := holds_ok_iff.mp hP
  simpa [UScalar.lt_equiv, Slice.len_val] using h

/-- The serializer of a `NonEmpty.Lawful` type, as a content function `enc` with a property `P`
("serializes to `Ok`"): `enc x` is the `Ok` output (`hs`, the form `Vec.serialize_content_all`
takes), and `P x` gives a non-empty `Ok` output `enc x`. -/
theorem spec.NonEmpty.Lawful.ser_enc {T : Type} {NE : spec.NonEmpty T}
    (hl : spec.NonEmpty.Lawful T NE) :
    ∃ (enc : T → List Std.U8) (P : T → Prop),
      (∀ x, ⦃ ⌜ True ⌝ ⦄ NE.RoundTripInst.SerializeBytesInst.tls_serialize_bytes x
        ⦃ ⇓? r => ⌜ ∀ b, r = .Ok b → (b : Slice Std.U8).val = enc x ∧ P x ⌝ ⦄) ∧
      (∀ x, P x → enc x ≠ [] ∧ ∃ b, NE.RoundTripInst.SerializeBytesInst.tls_serialize_bytes x =
        ok (.Ok b) ∧ b.val = enc x) := by
  classical
  have hpf := fun x => pf_of_total
    (hl.RoundTripInstLawful.SerializeBytesInstLawful.tls_serialize_bytes_spec
      x (pre_holds_of_ok_true rfl))
  obtain ⟨enc, henc⟩ : ∃ enc : T → List Std.U8, ∀ x b,
      NE.RoundTripInst.SerializeBytesInst.tls_serialize_bytes x = ok (.Ok b) →
      enc x = b.val := by
    refine ⟨fun x => if h : ∃ b, NE.RoundTripInst.SerializeBytesInst.tls_serialize_bytes x =
      ok (.Ok b) then h.choose.val else [], fun x b hb => ?_⟩
    have h : ∃ b, NE.RoundTripInst.SerializeBytesInst.tls_serialize_bytes x = ok (.Ok b) := ⟨b, hb⟩
    simp only [dif_pos h]
    rw [core.result.Result.Ok.inj (ok.inj (h.choose_spec.symm.trans hb))]
  refine ⟨enc, fun x => ∃ b, NE.RoundTripInst.SerializeBytesInst.tls_serialize_bytes x =
    ok (.Ok b), fun x => ?_, fun x ⟨b, hb⟩ => ?_⟩
  · apply partial_triple_of_ok
    intro r hr b hb
    subst hb
    exact ⟨(henc x b hr).symm, b, hr⟩
  · refine ⟨fun h => ?_, b, hb, (henc x b hb).symm⟩
    have := hl.ser_pos x b hb
    rw [henc x b hb] at h
    simp [h] at this

/-- One step of the `Vec<T>` deserialize loop on the encodings of `xs` followed by `w`: stop when
`xs` is empty, else read the head (`hd`: `T`'s deserializer on its encoding followed by anything). -/
theorem alloc.vec.Vec.deserialize_loop_body_rt {T : Type} (inst : DeserializeBytes T)
    (enc : T → List Std.U8) (xs : List T)
    (hd : ∀ x ∈ xs, ∀ (t : Slice Std.U8) (w : List Std.U8), t.val = enc x ++ w →
      ⦃ ⌜ True ⌝ ⦄ inst.tls_deserialize_bytes t
      ⦃ ⇓ r => ⌜ ∃ p, r = .Ok p ∧ p.1 = x ∧ p.2.val = w ⌝ ⦄)
    (hne : ∀ x ∈ xs, enc x ≠ []) (w : List Std.U8) (length : Std.Usize)
    (remainder : Slice Std.U8) (result : alloc.vec.Vec T) (read : Std.Usize)
    (hr : remainder.val = xs.flatMap enc ++ w) (hres : result.val.length ≤ read.val)
    (hlen : read.val + (xs.flatMap enc).length = length.val) :
    ⦃ ⌜ True ⌝ ⦄
    alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop.body inst length
      remainder result read
    ⦃ ⇓ r => ⌜ match r with
      | .done (rem, res, rd, fl) => xs = [] ∧ fl = core.option.Option.None ∧ rem = remainder ∧
          res = result ∧ rd = read
      | .cont (rem, res, rd) => ∃ x ys, xs = x :: ys ∧ rem.val = ys.flatMap enc ++ w ∧
          res.val = result.val ++ [x] ∧ rd.val + (ys.flatMap enc).length = length.val ∧
          res.val.length ≤ rd.val ∧ rem.val.length < remainder.val.length ⌝ ⦄ := by
  cases xs with
  | nil =>
    unfold alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop.body
    mvcgen
    · rename_i h
      simp at hlen
      scalar_tac
  | cons x ys =>
    have hx := hne x (by simp)
    have hdx := hd x (by simp) remainder (ys.flatMap enc ++ w) (by simpa using hr)
    mvcgen [alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop.body, hdx,
      core.convert.Into.Blanket.into]
    case vc1.h => rename_i hlt _ _ _ _ _ _ _ _ _ _; scalar_tac
    case vc2.h => exact toStr_utf8 _ _
    case vc3 =>
      rename_i hlt r p hx' hex i hi i1 hi1 c hc hle res hz hpush str hstr
      obtain ⟨q, hq, hqx, hqw⟩ := hex
      obtain rfl := core.result.Result.Ok.inj hq
      have l1 := Slice.len_val remainder
      have l2 := Slice.len_val p.2
      simp only [Slice.length] at l1 l2
      have := List.length_pos_of_ne_nil hx
      have hz0 : c.val = 0 := by rw [hz]; rfl
      subst hi hi1
      exfalso
      simp only [hr, hqw, List.flatMap_cons, List.length_append] at l1 l2
      omega
    case vc4.hQ =>
      rename_i hlt r p hx' hex i hi i1 hi1 c hc hle res hnz hpush rd hrd
      obtain ⟨q, hq, hqx, hqw⟩ := hex
      obtain rfl := core.result.Result.Ok.inj hq
      have l1 := Slice.len_val remainder
      have l2 := Slice.len_val p.2
      simp only [Slice.length] at l1 l2
      have hnz' : c.val ≠ 0 := fun h => hnz (UScalar.eq_of_val_eq (by simpa using h))
      have hxl := List.length_pos_of_ne_nil hx
      subst hi hi1
      simp only [hr, hqw, List.flatMap_cons, List.length_append] at l1 l2 hlen hc hrd
      refine ⟨x, ys, rfl, hqw, by rw [hpush, hqx], ?_, ?_, ?_⟩
      · omega
      · rw [hpush]; simp; omega
      · simp only [hr, hqw, List.flatMap_cons, List.length_append]; omega
    case vc5.h_fail =>
      exfalso
      rename_i hlt r p hx' hex i hi i1 hi1 c hc hle res hnz hpush hbig
      obtain ⟨q, hq, hqx, hqw⟩ := hex
      obtain rfl := core.result.Result.Ok.inj hq
      have l1 := Slice.len_val remainder
      have l2 := Slice.len_val p.2
      simp only [Slice.length] at l1 l2
      subst hi hi1
      simp only [hr, hqw, List.flatMap_cons, List.length_append] at l1 l2 hlen hc
      scalar_tac
    case vc6.h_fail =>
      exfalso
      rename_i hlt r p hx' hex i hi i1 hi1 hlt2
      obtain ⟨q, hq, hqx, hqw⟩ := hex
      obtain rfl := core.result.Result.Ok.inj hq
      have l1 := Slice.len_val remainder
      have l2 := Slice.len_val p.2
      simp only [Slice.length] at l1 l2
      subst hi hi1
      simp only [hr, hqw, List.flatMap_cons, List.length_append] at l1 l2 hlt2
      omega
    case vc7 =>
      rename_i hlt r e hx' hex
      obtain ⟨q, hq, _⟩ := hex
      cases hq
    case vc8.hQ =>
      rename_i hnlt
      exfalso
      simp only [List.flatMap_cons, List.length_append] at hlen
      have := List.length_pos_of_ne_nil hx
      scalar_tac

/-- The `Vec<T>` deserialize loop on the encodings of `xs` followed by `w` (all non-empty): reads
exactly `xs`, leaves `w`, stops with no failure once `read` reaches `length`. -/
theorem alloc.vec.Vec.deserialize_loop_rt {T : Type} (inst : DeserializeBytes T)
    (enc : T → List Std.U8) (xs : List T)
    (hd : ∀ x ∈ xs, ∀ (t : Slice Std.U8) (w : List Std.U8), t.val = enc x ++ w →
      ⦃ ⌜ True ⌝ ⦄ inst.tls_deserialize_bytes t
      ⦃ ⇓ r => ⌜ ∃ p, r = .Ok p ∧ p.1 = x ∧ p.2.val = w ⌝ ⦄)
    (hne : ∀ x ∈ xs, enc x ≠ []) (w : List Std.U8) (length : Std.Usize)
    (remainder : Slice Std.U8) (result : alloc.vec.Vec T) (read : Std.Usize)
    (hr : remainder.val = xs.flatMap enc ++ w) (hres : result.val.length ≤ read.val)
    (hlen : read.val + (xs.flatMap enc).length = length.val) :
    ⦃ ⌜ True ⌝ ⦄
    alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop inst remainder length
      result read
    ⦃ ⇓ r => ⌜ r.2.2.2 = core.option.Option.None ∧ r.1.val = w ∧
        r.2.1.val = result.val ++ xs ∧ r.2.2.1.val = length.val ⌝ ⦄ := by
  unfold alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.loop.spec_decr_nat
    (fun p : Slice Std.U8 × alloc.vec.Vec T × Std.Usize => p.1.val.length)
    (fun p => ∃ zs ys, xs = zs ++ ys ∧ (∀ x ∈ ys, enc x ≠ []) ∧ p.1.val = ys.flatMap enc ++ w ∧
      p.2.1.val = result.val ++ zs ∧ p.2.2.val + (ys.flatMap enc).length = length.val ∧
      p.2.1.val.length ≤ p.2.2.val)
  · rintro ⟨rem, res, rd⟩ ⟨zs, ys, hxs, hys, h1, h2, h3, h4⟩
    obtain ⟨v, hv, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (alloc.vec.Vec.deserialize_loop_body_rt inst enc ys (fun x hx => hd x (hxs ▸ List.mem_append_right _ hx)) hys w length rem res rd h1 h4 h3)
    dsimp only
    rw [hv]
    refine (Aeneas.Std.WP.spec_ok v).mpr ?_
    cases v with
    | done y =>
      obtain ⟨rem', res', rd', fl⟩ := y
      obtain ⟨rfl, rfl, rfl, rfl, rfl⟩ := hP
      simp only [List.flatMap_nil, List.length_nil, Nat.add_zero] at h1 h3
      exact ⟨rfl, h1, by rw [hxs, List.append_nil]; exact h2, h3⟩
    | cont y =>
      obtain ⟨rem', res', rd'⟩ := y
      obtain ⟨x, ys', rfl, h1', h2', h3', h4', h5'⟩ := hP
      refine ⟨⟨zs ++ [x], ys', by simp [hxs], fun a ha => hys a (by simp [ha]), h1', ?_, h3', h4'⟩, h5'⟩
      rw [h2', h2, List.append_assoc]
  · exact ⟨[], xs, rfl, hne, hr, by simp, hlen, hres⟩

/-- `Vec<T>::tls_deserialize_bytes` on the length prefix, the (non-empty) encodings of `xs` and `w`:
returns `xs` and `w`. -/
theorem alloc.vec.Vec.deserialize_rt {T : Type} (inst : DeserializeBytes T)
    (enc : T → List Std.U8) (xs : List T)
    (hd : ∀ x ∈ xs, ∀ (t : Slice Std.U8) (w : List Std.U8), t.val = enc x ++ w →
      ⦃ ⌜ True ⌝ ⦄ inst.tls_deserialize_bytes t
      ⦃ ⇓ r => ⌜ ∃ p, r = .Ok p ∧ p.1 = x ∧ p.2.val = w ⌝ ⦄)
    (hne : ∀ x ∈ xs, enc x ≠ []) (w : List Std.U8) (bytes : Slice Std.U8)
    (hn : (xs.flatMap enc).length ≤ 2 ^ 30 - 1)
    (hb : bytes.val.map (·.val) = varint.encList (xs.flatMap enc).length ++
      (xs.flatMap enc).map (·.val) ++ w.map (·.val)) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes inst bytes
    ⦃ ⇓ r => ⌜ ∃ p, r = .Ok p ∧ p.1.val = xs ∧ p.2.val = w ⌝ ⦄ := by
  have hl := fun (t : Slice Std.U8) (result : alloc.vec.Vec T) (length read : Std.Usize)
      (ht : t.val = xs.flatMap enc ++ w) (hres : result.val.length ≤ read.val)
      (hlen : read.val + (xs.flatMap enc).length = length.val) =>
    alloc.vec.Vec.deserialize_loop_rt inst enc xs hd hne w length t result read ht hres hlen
  obtain ⟨r0, hr0, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (quic_vec.ContentLength.deserialize_content_ok bytes)
  obtain ⟨p, rfl⟩ := hP.2 ⟨_, _, hn, by rw [hb, List.append_assoc]⟩
  obtain ⟨hpn, hpb⟩ := hP.1 p.1 p.2 rfl
  obtain ⟨hpl, hpr⟩ := varint.encList_append_inj (xs.flatMap enc).length p.1.val
    ((xs.flatMap enc).map (·.val) ++ w.map (·.val)) (p.2.val.map (·.val)) (by omega) (by omega)
    (by rw [← List.append_assoc, ← hb, hpb])
  have hp2 : p.2.val = xs.flatMap enc ++ w :=
    (List.map_injective_iff.mpr (fun a b h => UScalar.eq_of_val_eq h)) (by simp [← hpr])
  unfold alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
  rw [hr0]
  mvcgen [varint.TlsVarInt.value, hl, alloc.vec.Vec.new_spec, core.hint.must_use_spec]
  try_vcs
  all_goals (try simp only [continue_eq_tryCF] at *)
  case vc1 =>
    rename_i _ q _ tf htf _ val _ hval0 v hv hqp htfv
    obtain rfl := core.result.Result.Ok.inj hqp
    have hv0 := htf.1 val htfv
    have hnil : xs.flatMap enc = [] := by
      rw [← List.length_eq_zero_iff]; rw [hval0] at hv0; simp [hpl] at hv0 ⊢; omega
    have hxs : xs = [] := by
      by_contra h
      obtain ⟨x, hx⟩ := List.exists_mem_of_ne_nil _ h
      exact hne x hx (List.flatMap_eq_nil_iff.mp hnil x hx)
    subst hxs
    exact ⟨_, rfl, by rw [hv]; rfl, by simpa using hp2⟩
  case vc2.ht =>
    rename_i _ q _ tf htf _ val _ hval0 v hv hqp htfv
    obtain rfl := core.result.Result.Ok.inj hqp
    exact hp2
  case vc3.hres =>
    rename_i _ q _ tf htf _ val _ hval0 v hv hqp htfv
    rw [hv]; simp [Slice.new]
  case vc4.hlen =>
    rename_i _ q _ tf htf _ val _ hval0 v hv hqp htfv
    obtain rfl := core.result.Result.Ok.inj hqp
    have hv0 := htf.1 val htfv
    simp [hpl, hv0]
  case vc5 =>
    exfalso
    rename_i hne' hpost _ _ _ _ _ _ hqp htfv
    have := UScalar.eq_of_val_eq hpost.2.2.2
    simp [this] at hne'
  case vc6 =>
    rename_i v hv lr hnone hne' hpost hqp htfv
    refine ⟨_, rfl, ?_, hpost.2.1⟩
    simpa [hv, Slice.new] using hpost.2.2.1
  case vc7 =>
    exfalso
    rename_i v hv lr e hsome hpost hqp htfv
    have := hpost.1
    rw [hsome] at this
    cases this
  case vc1.vc8 =>
    exfalso
    rename_i htf _ _ _ _ htfe hqp
    obtain rfl := core.result.Result.Ok.inj hqp
    obtain ⟨y, hy⟩ := htf.2 (by omega)
    rw [htfe] at hy
    cases hy
end tls_codec
