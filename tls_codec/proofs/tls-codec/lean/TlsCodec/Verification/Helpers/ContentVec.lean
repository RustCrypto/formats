/- Contents of the slice / `Vec<T>` / `u16` / `String` codecs (bytes path).

Obligations: none directly; the bytes-path halves of `PanicFreedom.lean` /
`FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): ASSUMED
`alloc.string.FromUtf8Error.Insts.CoreFmtDisplay.fmt.ok_spec`, `size_of`, `size_of_U16`,
`size_of_U8`; 1 signature-only stub (`alloc.string.FromUtf8Error.Insts.CoreFmtDisplay.fmt`);
`native_decide` (1). -/
import TlsCodec.Verification.Helpers.ContentVL
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-- Partial spec of the serialisation loop of the slice serializer, on contents: if it finishes
without error, the output grew by the concatenation of the element encodings `enc`. -/
theorem loop_ser_content_spec {T : Type} (enc : T → List Std.U8) (P : T → Prop) (it : core.slice.iter.Iter T)
    (out : alloc.vec.Vec Std.U8)
    (body : core.slice.iter.Iter T × alloc.vec.Vec Std.U8 →
      RustM (ControlFlow (core.slice.iter.Iter T × alloc.vec.Vec Std.U8)
        (alloc.vec.Vec Std.U8 × core.option.Option Error)))
    (hbody : ∀ (it' : core.slice.iter.Iter T) (o : alloc.vec.Vec Std.U8),
      ⦃ ⌜ True ⌝ ⦄ body (it', o)
      ⦃ ⇓? r => ⌜ match r with
        | .done y => y.2 = core.option.Option.None → (it' : Slice T).val = [] ∧ y.1 = o
        | .cont p => ∃ e, (it' : Slice T).val = e :: (p.1 : Slice T).val ∧
            (p.2 : Slice Std.U8).val = (o : Slice Std.U8).val ++ enc e ∧ P e ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ loop body (it, out)
    ⦃ ⇓? r => ⌜ r.2 = core.option.Option.None →
        (r.1 : Slice Std.U8).val = (out : Slice Std.U8).val ++ (it : Slice T).val.flatMap enc ∧
          ∀ x ∈ (it : Slice T).val, P x ⌝ ⦄ := by
  refine loop_partial_spec body (it, out)
    (fun p => ∃ lc, (it : Slice T).val = lc ++ (p.1 : Slice T).val ∧
      (p.2 : Slice Std.U8).val = (out : Slice Std.U8).val ++ lc.flatMap enc ∧ ∀ x ∈ lc, P x)
    _ ⟨[], by simp, by simp, by simp⟩ ?_
  rintro ⟨it', o⟩ ⟨lc, h1, h2, h3⟩
  apply partial_triple_post_mono (hbody it' o)
  intro r hr
  cases r with
  | done y =>
    intro hy
    obtain ⟨h0, rfl⟩ := hr hy
    simp only at h1 h0 h2 ⊢
    rw [h1, h0, List.append_nil]; exact ⟨h2, h3⟩
  | cont p =>
    obtain ⟨e, hl, hp, hP⟩ := hr
    refine ⟨lc ++ [e], ?_, ?_, ?_⟩
    · rw [h1, hl]; simp
    · rw [hp]; simp only at h2; rw [h2]; simp
    · intro x hx; rcases List.mem_append.mp hx with hx | hx
      · exact h3 x hx
      · simp at hx; exact hx ▸ hP

/-- `mvcgen` on the unfolded slice serializer for the content specs (cf. `ser_slice_mvcgen`). -/
syntax "ser_slice_mvcgen_content" " [" Lean.Parser.Tactic.simpLemma,* "]" : tactic
macro_rules
  | `(tactic| ser_slice_mvcgen_content [$ts,*]) => `(tactic| mvcgen [-Aeneas.Std.loop_spec, $ts,*,
    quic_vec.ContentLength.from_usize_spec, varint.TlsVarInt.bytes_len_spec,
    checked_alloc_len_ok, alloc.vec.Vec.with_capacity, alloc.vec.Vec.resize_U8_content,
    alloc.vec.Vec.Insts.CoreOpsDerefDerefMutSlice.deref_mut, alloc.vec.Vec.as_mut_slice,
    rust_primitives.sequence.seq_to_slice_mut, Copied.varint.TlsVarInt.write_bytes_content,
    core.slice.Slice.iter, core.iter.traits.collect.IntoIterator.Blanket.into_iter,
    core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.next,
    alloc.vec.Vec.append, rust_primitives.sequence.seq_concat])

/-- The `<&[T]>::tls_serialize_bytes` on contents, given the contents `enc` of the element
serializer: an `Ok` output is the length prefix of the total size and the concatenation of the
elements; and every element satisfies `P` (as given by the element serializer's post `hs`). -/
theorem Shared0Slice.serialize_content_all {T : Type} (inst : SerializeBytes T)
    (enc : T → List Std.U8) (P : T → Prop)
    (hs : ∀ x, ⦃ ⌜ True ⌝ ⦄ inst.tls_serialize_bytes x
      ⦃ ⇓? r => ⌜ ∀ b, r = .Ok b → (b : Slice Std.U8).val = enc x ∧ P x ⌝ ⦄) (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ Shared0Slice.Insts.Tls_codecSerializeBytes.tls_serialize_bytes inst s
    ⦃ ⇓? r => ⌜ ∀ out, r = .Ok out → (s.val.flatMap enc).length ≤ 2 ^ 30 - 1 ∧
        out.val.map (·.val) = varint.encList (s.val.flatMap enc).length ++
          (s.val.flatMap enc).map (·.val) ∧ ∀ x ∈ s.val, P x ⌝ ⦄ := by
  ser_slice_setup
  have hsum := loop_trivial_partial
    (α := core.slice.iter.Iter T × Std.Usize) (β := core.result.Result Std.Usize Error)
  have hser := loop_ser_content_spec enc P
  ser_slice_mvcgen_content [hsum, hser, hs]
  all_goals (try clear hsum hser)
  try_vcs
  all_goals (try (intros; simp [PostCond.ok]; done))
  case vc1.hv => rename_i h; rw [h]; rfl
  case vc2.h =>
    have hc := varint.lenOf_char _ _ ‹1 ≤ _ ∧ _›
    rename_i hrep back
    refine ⟨?_, by rw [hrep, List.length_replicate]; omega⟩
    try simp only [continue_eq_tryCF] at *
    try subst_vars
    dsimp only at *
    omega
  case vc3.hQ => rw [← List.length_eq_zero_iff]; scalar_tac
  case vc4.hQ =>
    rename_i it' o hne hlt r bytes hbr hb comb hc
    refine ⟨(it' : Slice T).val.get ⟨0, by simpa using hlt⟩, ?_, ?_, (hb bytes rfl).2⟩
    · simp only [show (0#usize).val = 0 from rfl, List.take_zero, List.nil_append, zero_add]
      exact list_cons_get_drop _ ‹_›
    · simp [comb, (hb bytes rfl).1]
  case vc6 => intro h; cases h
  case vc8 => intro out h; cases h
  case vc9.hQ => intro out h; cases h
  case vc10.hQ =>
    intro out h
    obtain rfl := core.result.Result.Ok.inj h
    simp only [continue_eq_tryCF] at *
    subst_vars
    rename_i acc2 val ll hll acc1 v1 hrep back w hw acc0 r1 hnone hr1 i hne hwr hv hcap hi1 hi2
    have hc := varint.lenOf_char _ _ hll
    have hpre := varint.write_prefix_content val.val w.2.val (fun k => by
      have := hw.2.2 k
      rwa [hrep, hc.1] at this)
    obtain ⟨hr1', hall⟩ := hr1 hnone
    have hwl : (w.2 : Slice Std.U8).val.length = ll.val := by
      rw [hw.2.1, hrep, List.length_replicate]
    have hlen : (r1.1 : Slice Std.U8).val.length = ll.val + (s.val.flatMap enc).length := by
      rw [hr1', List.length_append]
      show (w.2 : Slice Std.U8).val.length + _ = _
      rw [hwl]
    have hne' : i = acc2 := by simpa only [bne_iff_ne, ne_eq, not_not] using hne
    have hflat : (s.val.flatMap enc).length = acc2.val := by
      subst hne'
      rw [Slice.len_val] at hi1
      have : Slice.length (r1.1 : Slice Std.U8) = (r1.1 : Slice Std.U8).val.length := rfl
      omega
    have hvv : val.val = (s.val.flatMap enc).length := by rw [hflat]; exact hv.1
    refine ⟨by omega, ?_, hall⟩
    rw [hr1', List.map_append, ← hvv]
    exact congrArg (· ++ _) hpre

/-- The `<&[T]>::tls_serialize_bytes` on contents (see `Shared0Slice.serialize_content_all`). -/
theorem Shared0Slice.serialize_content {T : Type} (inst : SerializeBytes T)
    (enc : T → List Std.U8)
    (hs : ∀ x, ⦃ ⌜ True ⌝ ⦄ inst.tls_serialize_bytes x
      ⦃ ⇓? r => ⌜ ∀ b, r = .Ok b → (b : Slice Std.U8).val = enc x ⌝ ⦄) (s : Slice T) :
    ⦃ ⌜ True ⌝ ⦄ Shared0Slice.Insts.Tls_codecSerializeBytes.tls_serialize_bytes inst s
    ⦃ ⇓? r => ⌜ ∀ out, r = .Ok out → (s.val.flatMap enc).length ≤ 2 ^ 30 - 1 ∧
        out.val.map (·.val) = varint.encList (s.val.flatMap enc).length ++
          (s.val.flatMap enc).map (·.val) ⌝ ⦄ :=
  partial_triple_post_mono
    (Shared0Slice.serialize_content_all inst enc (fun _ => True)
      (fun x => partial_triple_post_mono (hs x) fun _ h b hb => ⟨h b hb, trivial⟩) s)
    fun _ h out ho => (fun ⟨a, b, _⟩ => ⟨a, b⟩) (h out ho)

/-- The `Vec<T>` serializer on contents with the element property `P`
(see `Shared0Slice.serialize_content_all`). -/
theorem alloc.vec.Vec.serialize_content_all {T : Type} (inst : SerializeBytes T)
    (enc : T → List Std.U8) (P : T → Prop)
    (hs : ∀ x, ⦃ ⌜ True ⌝ ⦄ inst.tls_serialize_bytes x
      ⦃ ⇓? r => ⌜ ∀ b, r = .Ok b → (b : Slice Std.U8).val = enc x ∧ P x ⌝ ⦄) (v : alloc.vec.Vec T) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.Tls_codecSerializeBytes.tls_serialize_bytes inst v
    ⦃ ⇓? r => ⌜ ∀ out, r = .Ok out → ((v : Slice T).val.flatMap enc).length ≤ 2 ^ 30 - 1 ∧
        out.val.map (·.val) = varint.encList ((v : Slice T).val.flatMap enc).length ++
          ((v : Slice T).val.flatMap enc).map (·.val) ∧ ∀ x ∈ (v : Slice T).val, P x ⌝ ⦄ := by
  rw [alloc.vec.Vec.ser_eq_slice]
  exact Shared0Slice.serialize_content_all inst enc P hs _

/-- The `Vec<T>` serializer on contents (see `Shared0Slice.serialize_content`). -/
theorem alloc.vec.Vec.serialize_content {T : Type} (inst : SerializeBytes T) (enc : T → List Std.U8)
    (hs : ∀ x, ⦃ ⌜ True ⌝ ⦄ inst.tls_serialize_bytes x
      ⦃ ⇓? r => ⌜ ∀ b, r = .Ok b → (b : Slice Std.U8).val = enc x ⌝ ⦄) (v : alloc.vec.Vec T) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.Tls_codecSerializeBytes.tls_serialize_bytes inst v
    ⦃ ⇓? r => ⌜ ∀ out, r = .Ok out → ((v : Slice T).val.flatMap enc).length ≤ 2 ^ 30 - 1 ∧
        out.val.map (·.val) = varint.encList ((v : Slice T).val.flatMap enc).length ++
          ((v : Slice T).val.flatMap enc).map (·.val) ⌝ ⦄ := by
  rw [alloc.vec.Vec.ser_eq_slice]
  exact Shared0Slice.serialize_content inst enc hs _

theorem alloc.vec.Vec.deserialize_bytes_loop_body_content {T : Type} (inst : DeserializeBytes T)
    (enc : T → List Std.U8)
    (hd : ∀ b, ⦃ ⌜ True ⌝ ⦄ inst.tls_deserialize_bytes b
      ⦃ ⇓? r => ⌜ ∀ x t, r = .Ok (x, t) → (b : Slice Std.U8).val = enc x ++ t.val ⌝ ⦄)
    (length : Std.Usize) (result : alloc.vec.Vec T) (remainder : Slice Std.U8) (read : Std.Usize)
    (hinv : (result : Slice T).val.length ≤ read.val) :
    ⦃ ⌜ True ⌝ ⦄
    alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop.body inst length
      remainder result read
    ⦃ ⇓? r => ⌜ match r with
      | .done (rem, res, rd, fl) => fl = core.option.Option.None →
          rem = remainder ∧ res = result ∧ rd = read
      | .cont (rem, res, rd) => ∃ x, remainder.val = enc x ++ rem.val ∧
          (res : Slice T).val = (result : Slice T).val ++ [x] ∧
          rd.val = read.val + (enc x).length ∧ (res : Slice T).val.length ≤ rd.val ⌝ ⦄ := by
  mvcgen [alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop.body, hd,
    core.convert.Into.Blanket.into]
  case vc1.h => rename_i hlt _ _ _ _ _ _ _ _ _ _; scalar_tac
  case vc2.h => exact toStr_utf8 _ _
  case vc3 => intro h; cases h
  case vc4.hQ =>
    rename_i hlt r p hx hpost r2 h2 r1 h1 r0 ha hb res hnz hpush rd hrd
    obtain ⟨e, nxt⟩ := p
    have hr := hpost e nxt rfl
    subst h2 h1
    have l1 := Slice.len_val remainder
    have l2 := Slice.len_val nxt
    simp only [Slice.length] at l1 l2
    have hnz' : r0.val ≠ 0 := fun h => hnz (UScalar.eq_of_val_eq (by simpa using h))
    have hlen : r0.val = (enc e).length := by
      have := congrArg List.length hr; simp only [List.length_append] at this; dsimp only at *; omega
    refine ⟨e, hr, hpush, by dsimp only at *; omega, ?_⟩
    rw [hpush]; simp; dsimp only at *; omega
  case vc7 => intro h; cases h

theorem alloc.vec.Vec.deserialize_bytes_loop_content {T : Type} (inst : DeserializeBytes T)
    (enc : T → List Std.U8)
    (hd : ∀ b, ⦃ ⌜ True ⌝ ⦄ inst.tls_deserialize_bytes b
      ⦃ ⇓? r => ⌜ ∀ x t, r = .Ok (x, t) → (b : Slice Std.U8).val = enc x ++ t.val ⌝ ⦄)
    (length : Std.Usize) (remainder : Slice Std.U8) (result : alloc.vec.Vec T) (read : Std.Usize)
    (hres : (result : Slice T).val = []) (hread : read.val = 0) :
    ⦃ ⌜ True ⌝ ⦄
    alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop inst remainder length
      result read
    ⦃ ⇓? r => ⌜ r.2.2.2 = core.option.Option.None →
        remainder.val = (r.2.1 : Slice T).val.flatMap enc ++ r.1.val ∧
        r.2.2.1.val = ((r.2.1 : Slice T).val.flatMap enc).length ⌝ ⦄ := by
  unfold alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop
  refine loop_partial_spec _ (remainder, result, read)
    (fun p => remainder.val = (p.2.1 : Slice T).val.flatMap enc ++ p.1.val ∧
      p.2.2.val = ((p.2.1 : Slice T).val.flatMap enc).length ∧
      (p.2.1 : Slice T).val.length ≤ p.2.2.val)
    _ ⟨by simp [hres], by simp [hres, hread], by simp [hres]⟩ ?_
  rintro ⟨rem, res, rd⟩ ⟨h1, h2, h3⟩
  dsimp only at h1 h2 h3
  apply partial_triple_post_mono
    (alloc.vec.Vec.deserialize_bytes_loop_body_content inst enc hd length res rem rd h3)
  intro r hr
  cases r with
  | done y =>
    obtain ⟨rem', res', rd', fl⟩ := y
    intro hfl
    obtain ⟨rfl, rfl, rfl⟩ := hr hfl
    exact ⟨h1, h2⟩
  | cont p =>
    obtain ⟨rem', res', rd'⟩ := p
    obtain ⟨x, hx, hres', hrd, hlen⟩ := hr
    refine ⟨?_, ?_, hlen⟩
    · simp only [hres', List.flatMap_append, List.flatMap_cons, List.flatMap_nil, List.append_nil,
        List.append_assoc]
      rw [h1, hx]
    · simp only [hres', List.flatMap_append, List.flatMap_cons, List.flatMap_nil, List.append_nil,
        List.length_append]
      omega

/-- The `Vec<T>` deserializer on contents, given the contents `enc` of the element deserializer:
on success the input is the length prefix of the total size, the concatenated elements and the
remainder. -/
theorem alloc.vec.Vec.deserialize_bytes_content {T : Type} (inst : DeserializeBytes T)
    (enc : T → List Std.U8)
    (hd : ∀ b, ⦃ ⌜ True ⌝ ⦄ inst.tls_deserialize_bytes b
      ⦃ ⇓? r => ⌜ ∀ x t, r = .Ok (x, t) → (b : Slice Std.U8).val = enc x ++ t.val ⌝ ⦄)
    (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes inst bytes
    ⦃ ⇓? r => ⌜ ∀ v t, r = .Ok (v, t) → ((v : Slice T).val.flatMap enc).length ≤ 2 ^ 30 - 1 ∧
        bytes.val.map (·.val) = varint.encList ((v : Slice T).val.flatMap enc).length ++
          ((v : Slice T).val.flatMap enc).map (·.val) ++ t.val.map (·.val) ⌝ ⦄ := by
  have hl := alloc.vec.Vec.deserialize_bytes_loop_content inst enc hd
  mvcgen [alloc.vec.Vec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes,
    quic_vec.ContentLength.deserialize_content, varint.TlsVarInt.value, hl,
    alloc.vec.Vec.new_spec, core.hint.must_use_spec]
  try_vcs
  all_goals (try simp only [continue_eq_tryCF] at *)
  all_goals (try (intro _ _ h; cases h; done))
  all_goals (try (intros; simp [PostCond.ok]; done))
  case vc1 =>
    rename_i r0 hP r1 p x1 r2 htf r3 val x2 hv0 rv hrv h3 h5
    intro v t h
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj (core.result.Result.Ok.inj h)
    have hp := hP p.1 p.2 h3
    have hy := htf.1 val h5
    have hv : val.val = 0 := by rw [hv0]; rfl
    have hrl : rv.val = [] := by rw [hrv]; simp [Slice.new]
    refine ⟨by simp [hrl], ?_⟩
    rw [hp.2]
    simp [hrl, show p.1.val = 0 by omega]
  case vc2.hres => subst_vars; rfl
  case vc5 =>
    rename_i r0 hP r1 p x1 r2 htf r3 val x2 hnz rv hrv res hnone hne hpost hr0 hr2
    intro v t h
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj (core.result.Result.Ok.inj h)
    have hp := hP p.1 p.2 hr0
    have hy := htf.1 val hr2
    obtain ⟨hrem, hrd⟩ := hpost hnone
    have hrv' : res.2.2.1.val = val.val := by simpa using hne
    have hlen : ((res.2.1 : Slice T).val.flatMap enc).length = p.1.val := by omega
    refine ⟨le_of_eq_of_le hlen hp.1, ?_⟩
    rw [hp.2, hlen, hrem, List.map_append, List.append_assoc]


/-- The prefix of `b` is `out`, when the contents (as naturals) agree. -/
theorem list_take_of_map (b out : List Std.U8) (E R : List Nat) (c : Nat)
    (hb : b.map (·.val) = E ++ R) (ho : out.map (·.val) = E) (hc : c = E.length) :
    b.take c = out := by
  apply List.map_injective_iff.mpr (fun a b h => UScalar.eq_of_val_eq h)
  rw [List.map_take, hb, hc, List.take_left, ho]

/-- The big-endian encoding of a `u16`. -/
def u16Enc (x : Std.U16) : List Std.U8 := (Aeneas.Std.core.num.U16.to_be_bytes x).val

theorem u16Enc_length (x : Std.U16) : (u16Enc x).length = 2 := by
  simpa [u16Enc] using (Aeneas.Std.core.num.U16.to_be_bytes x).property

theorem u16Enc_inj {x y : Std.U16} (h : u16Enc x = u16Enc y) : x = y := by
  rw [← U16_from_be_bytes_to_be_bytes x, ← U16_from_be_bytes_to_be_bytes y]
  exact congrArg _ (Subtype.ext h)

/-- The concatenated big-endian encodings determine the list of `u16`. -/
theorem u16Enc_flatMap_inj : ∀ (l l' : List Std.U16), l.flatMap u16Enc = l'.flatMap u16Enc → l = l'
  | [], [], _ => rfl
  | [], y :: ys, h => by
    have := congrArg List.length h
    simp [u16Enc_length] at this
  | x :: xs, [], h => by
    have := congrArg List.length h
    simp [u16Enc_length] at this
  | x :: xs, y :: ys, h => by
    simp only [List.flatMap_cons] at h
    obtain ⟨h1, h2⟩ := List.append_inj h (by rw [u16Enc_length, u16Enc_length])
    rw [u16Enc_inj h1, u16Enc_flatMap_inj xs ys h2]

/-- The element serializer of `u16`, on contents (partial form, for `Vec::serialize_content`). -/
theorem U16.serialize_content_partial (x : Std.U16) :
    ⦃ ⌜ True ⌝ ⦄ U16.Insts.Tls_codecSerializeBytes.tls_serialize_bytes x
    ⦃ ⇓? r => ⌜ ∀ b, r = .Ok b → (b : Slice Std.U8).val = u16Enc x ⌝ ⦄ := by
  apply partial_of_total
  apply triple_post_mono (U16_serialize_char x)
  rintro r ⟨v, rfl, hv⟩ b hb
  obtain rfl := core.result.Result.Ok.inj hb
  exact hv

/-- The element deserializer of `u16`, on contents (partial form). -/
theorem U16.deserialize_content_partial (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ U16.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓? r => ⌜ ∀ x t, r = .Ok (x, t) → bytes.val = u16Enc x ++ t.val ⌝ ⦄ := by
  apply partial_of_total
  apply triple_post_mono (U16_deserialize_char bytes)
  intro r hr x t hxt
  by_cases hl : 2 ≤ bytes.val.length
  · obtain ⟨a, t', ha, ht', rfl⟩ := hr.1 hl
    obtain ⟨hx, rfl⟩ := Prod.mk.inj (core.result.Result.Ok.inj hxt)
    subst hx
    rw [u16Enc, U16_to_be_bytes_from_be_bytes, ha, ht', List.take_append_drop]
  · rw [hr.2 (by omega)] at hxt
    cases hxt


/-- Round trip of a length-prefixed payload: if a serialized `A` (prefix of its length) is read as a
payload `B` followed by `R`, then `A = B` and nothing is left. -/
theorem varint.enc_roundtrip (A B R : List Std.U8) (hn : A.length ≤ 2 ^ 30 - 1)
    (hn' : B.length ≤ 2 ^ 30 - 1)
    (h : varint.encList A.length ++ A.map (·.val) =
      varint.encList B.length ++ B.map (·.val) ++ R.map (·.val)) : A = B ∧ R = [] := by
  rw [List.append_assoc] at h
  obtain ⟨hlen, happ⟩ := varint.encList_append_inj _ _ _ _ (by omega) (by omega) h
  have hR : R.length = 0 := by
    have := congrArg List.length happ
    simp only [List.length_append, List.length_map] at this
    omega
  have hR' : R = [] := List.length_eq_zero_iff.mp hR
  refine ⟨?_, hR'⟩
  apply List.map_injective_iff.mpr (fun a b h => UScalar.eq_of_val_eq h)
  rw [happ, hR', List.map_nil, List.append_nil]


/-- The `String` as a slice of its UTF-8 bytes, when that slice is short, is the whole encoding. -/
theorem alloc.string.String.take_max_utf8U8 (s : alloc.string.String)
    (h : ((alloc.string.String.utf8U8 s).take Usize.max).length ≤ 2 ^ 30 - 1) :
    (alloc.string.String.utf8U8 s).take Usize.max = alloc.string.String.utf8U8 s := by
  apply List.take_of_length_le
  by_contra hc
  rw [List.length_take] at h
  have : 2 ^ 30 - 1 < Usize.max := by scalar_tac
  omega

/-- `String::tls_serialize_bytes` on contents: the length prefix and the UTF-8 bytes. -/
theorem alloc.string.String.serialize_content (s : alloc.string.String) :
    ⦃ ⌜ True ⌝ ⦄ alloc.string.String.Insts.Tls_codecSerializeBytes.tls_serialize_bytes s
    ⦃ ⇓ r => ⌜ ∀ out, r = .Ok out → (alloc.string.String.utf8U8 s).length ≤ 2 ^ 30 - 1 ∧
        out.val.map (·.val) = varint.encList (alloc.string.String.utf8U8 s).length ++
          (alloc.string.String.utf8U8 s).map (·.val) ⌝ ⦄ := by
  mvcgen [alloc.string.String.Insts.Tls_codecSerializeBytes.tls_serialize_bytes,
    alloc.string.String.as_bytes_spec, quic_vec.VLByteSlice.serialize_content]
  rename_i b hb r
  intro h out hr
  obtain ⟨hl, hc⟩ := h out hr
  rw [hb] at hl hc
  have ht := alloc.string.String.take_max_utf8U8 s hl
  rw [ht] at hl hc
  exact ⟨hl, hc⟩

/-- `String::tls_deserialize_bytes` on contents: the length prefix, the UTF-8 bytes of the string and
the remainder. -/
theorem alloc.string.String.deserialize_content (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ alloc.string.String.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ t rem, r = .Ok (t, rem) →
        (alloc.string.String.utf8U8 t).length ≤ 2 ^ 30 - 1 ∧ bytes.val.map (·.val) =
          varint.encList (alloc.string.String.utf8U8 t).length ++
            (alloc.string.String.utf8U8 t).map (·.val) ++ rem.val.map (·.val) ⌝ ⦄ := by
  apply triple_post_mono (alloc.string.String.deserialize_char bytes)
  intro r h t rem hr
  obtain ⟨raw, hraw, hu⟩ := h t rem hr
  obtain ⟨r0, hr0, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (quic_vec.VLByteVec.deserialize_content bytes)
  rw [hraw] at hr0
  cases hr0
  rw [hu]
  exact hP raw rem rfl

end tls_codec
