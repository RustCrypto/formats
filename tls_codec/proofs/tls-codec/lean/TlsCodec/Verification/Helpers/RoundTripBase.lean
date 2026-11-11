/- Round trips on the bytes path: the `RoundTrip` / `NonEmpty` lemma methods, the varint / `VLBytes`
/ `String` decoders on encodings followed by a rest, and `T`'s codecs from `T`'s `RoundTrip.Lawful`
for the generic `Option` / `Vec`.

Obligations: none directly; the bytes-path halves of `PanicFreedom.lean` /
`FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): ASSUMED
`alloc.string.FromUtf8Error.Insts.CoreFmtDisplay.fmt.ok_spec`, `size_of`, `size_of_U8`; 1 signature-only
stub (`alloc.string.FromUtf8Error.Insts.CoreFmtDisplay.fmt`). -/
import TlsCodec.Verification.Helpers.ContentVec
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-- The `requires` of `RoundTrip::round_trip`: `tls_serialized_len self` returns `n` and
`rest.len + n` fits in a `usize`. -/
theorem spec.RoundTrip.round_trip.pre_elim {T : Type} (RT : spec.RoundTrip T) (x : T)
    (rest : Slice Std.U8)
    (h : (spec.RoundTrip.round_trip.pre RT.SerializeBytesInst RT.DeserializeBytesInst
      RT.corecmpPartialEqInst RT x rest).holds) :
    ∃ n, RT.SerializeBytesInst.SizeInst.tls_serialized_len x = ok n ∧
      rest.val.length + n.val ≤ Std.Usize.max := by
  have hl : core.slice.Slice.len rest = ok (Slice.len rest) := rfl
  unfold spec.RoundTrip.round_trip.pre at h
  cases hn : RT.SerializeBytesInst.SizeInst.tls_serialized_len x with
  | ok n =>
    refine ⟨n, rfl, ?_⟩
    simp only [hl, hn, bind_tc_ok] at h
    cases hs : (core.num.Usize.MAX - n : RustM Std.Usize) with
    | ok m =>
      have := Aeneas.Std.UScalar.sub_equiv (core.num.Usize.MAX) n
      rw [hs] at this
      simp only [hs, bind_tc_ok] at h
      have h2 := holds_ok_iff.mp h
      obtain ⟨_, hm, _⟩ := this
      simp only [decide_eq_true_eq] at h2
      scalar_tac
    | fail e =>
      exfalso
      have := h trivial
      simp [hs, Functor.map, Std.Do.wp, Std.Do.PredTrans.apply] at this
    | div =>
      exfalso
      have := h trivial
      simp [hs, Functor.map, Std.Do.wp, Std.Do.PredTrans.apply] at this
  | fail e =>
    exfalso
    have := h trivial
    simp [hl, hn, Functor.map, Std.Do.wp, Std.Do.PredTrans.apply] at this
  | div =>
    exfalso
    have := h trivial
    simp [hl, hn, Functor.map, Std.Do.wp, Std.Do.PredTrans.apply] at this

/-- `RoundTrip::round_trip`, PF: the lemma method returns `()`. -/
theorem spec.RoundTrip.round_trip.default_pf {Self : Type} (self : Self) (rest : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ spec.RoundTrip.round_trip.default self rest ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  unfold spec.RoundTrip.round_trip.default
  mvcgen

/-- `NonEmpty::nonempty`, PF: the lemma method returns `()`. -/
theorem spec.NonEmpty.nonempty.default_pf {Self : Type} (self : Self) :
    ⦃ ⌜ True ⌝ ⦄ spec.NonEmpty.nonempty.default self ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  unfold spec.NonEmpty.nonempty.default
  mvcgen

/-- A total triple under a proposition precondition: assume it. -/
theorem triple_pre_prop {α : Type} {m : RustM α} {P : Prop} {Q : α → Prop}
    (h : P → ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓ r => ⌜ Q r ⌝ ⦄) : ⦃ ⌜ P ⌝ ⦄ m ⦃ ⇓ r => ⌜ Q r ⌝ ⦄ :=
  SPred.pure_elim' h

/-- `RoundTrip::round_trip`, FC: the post of the (unit) lemma method evaluates the free function
`spec.encode_decode_rest`. If every `Ok` output of the serializer satisfies `Enc`, and the
deserializer recovers the value and the remainder from any `Enc` output followed by `rest`, then the
post holds (the calls are total: `hser_pf`, `hser_fc`, `hdes`). -/
theorem spec.RoundTrip.round_trip.default_fc_enc {T : Type} (RT : spec.RoundTrip T) (x : T)
    (rest : Slice Std.U8) (Enc : alloc.vec.Vec Std.U8 → Prop)
    (hpre : (spec.RoundTrip.round_trip.pre RT.SerializeBytesInst RT.DeserializeBytesInst
      RT.corecmpPartialEqInst RT x rest).holds)
    (heq : ⦃ ⌜ True ⌝ ⦄ RT.corecmpPartialEqInst.eq x x ⦃ ⇓ r => ⌜ r = true ⌝ ⦄)
    (hser_pf : ⦃ ⌜ True ⌝ ⦄ RT.SerializeBytesInst.tls_serialize_bytes x ⦃ ⇓ _ => ⌜ True ⌝ ⦄)
    (hser_fc : ⦃ ⌜ True ⌝ ⦄ RT.SerializeBytesInst.tls_serialize_bytes x
      ⦃ ⇓? res => ⌜ (SerializeBytes.tls_serialize_bytes.post RT.SerializeBytesInst.SizeInst
        RT.SerializeBytesInst x res).holds ⌝ ⦄)
    (hser : ⦃ ⌜ True ⌝ ⦄ RT.SerializeBytesInst.tls_serialize_bytes x
      ⦃ ⇓? r => ⌜ ∀ v, r = .Ok v → Enc v ⌝ ⦄)
    (hdes : ∀ s : Slice Std.U8, ⦃ ⌜ ∃ v, Enc v ∧ s.val = (v : Slice Std.U8).val ++ rest.val ⌝ ⦄
      RT.DeserializeBytesInst.tls_deserialize_bytes s
      ⦃ ⇓ r => ⌜ ∃ p, r = .Ok p ∧ p.1 = x ∧ p.2.val = rest.val ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ spec.RoundTrip.round_trip.default x rest
    ⦃ ⇓? _ => ⌜ (spec.RoundTrip.round_trip.post RT.SerializeBytesInst
      RT.DeserializeBytesInst RT.corecmpPartialEqInst RT x rest ()).holds ⌝ ⦄ := by
  obtain ⟨n, hn, hle⟩ := spec.RoundTrip.round_trip.pre_elim RT x rest hpre
  have hser' := triple_and (total_of_pf_partial hser_pf hser_fc) (total_of_pf_partial hser_pf hser)
  unfold spec.RoundTrip.round_trip.default
  mvcgen
  unfold spec.RoundTrip.round_trip.post RustM.holds
  mvcgen [spec.encode_decode_rest, hser', hdes, alloc.vec.Vec.extend_from_slice_U8_spec]
  · rename_i res hp _ _ _ hc
    have hr := continue_eq_tryCF.mp hc
    subst hr
    obtain ⟨m, hm, hl⟩ := SerializeBytes.post_ok_elim _ _ _ _ hp.1
    have := ok.inj (hn.symm.trans hm)
    subst this
    scalar_tac
  · rename_i res hp _ val1 _ hc _ hrest _ hr
    exact ⟨val1, hp.2 _ (continue_eq_tryCF.mp hc), by rw [hr, hrest]⟩
  · rename_i hex _ hrv _ _
    obtain ⟨p, hp, hx, hr⟩ := hex
    cases hp
    subst hx
    intro _
    have hs := core.Slice.Insts.CoreCmpPartialEqSlice.eq_spec core.U8.Insts.CoreCmpPartialEqU8
      (heq := core.U8.Insts.CoreCmpPartialEqU8.eq_decide_spec)
    mvcgen [heq, hs, core.result.Result.is_ok_and, core.option.Option.is_some_and,
      spec.__1.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleOptionPairSelf_VecU8Bool.call_once,
      spec.__1.ensures.closure.closure.Insts.CoreOpsFunctionFnOnceTuplePairSelf_VecU8Bool.call_once]
    all_goals simp_all
  · rename_i hex _ _
    obtain ⟨_, hp, _⟩ := hex
    cases hp
  · apply try_break_vc
    intros
    mvcgen

/-- `default_fc_enc` with a total deserializer lemma, stated for one `Enc` output and the input
`enc ++ rest`. -/
theorem spec.RoundTrip.round_trip.default_fc_enc_total {T : Type} (RT : spec.RoundTrip T)
    (x : T) (rest : Slice Std.U8) (Enc : alloc.vec.Vec Std.U8 → Prop)
    (hpre : (spec.RoundTrip.round_trip.pre RT.SerializeBytesInst RT.DeserializeBytesInst
      RT.corecmpPartialEqInst RT x rest).holds)
    (heq : ⦃ ⌜ True ⌝ ⦄ RT.corecmpPartialEqInst.eq x x ⦃ ⇓ r => ⌜ r = true ⌝ ⦄)
    (hser_pf : ⦃ ⌜ True ⌝ ⦄ RT.SerializeBytesInst.tls_serialize_bytes x ⦃ ⇓ _ => ⌜ True ⌝ ⦄)
    (hser_fc : ⦃ ⌜ True ⌝ ⦄ RT.SerializeBytesInst.tls_serialize_bytes x
      ⦃ ⇓? res => ⌜ (SerializeBytes.tls_serialize_bytes.post RT.SerializeBytesInst.SizeInst
        RT.SerializeBytesInst x res).holds ⌝ ⦄)
    (hser : ⦃ ⌜ True ⌝ ⦄ RT.SerializeBytesInst.tls_serialize_bytes x
      ⦃ ⇓? r => ⌜ ∀ v, r = .Ok v → Enc v ⌝ ⦄)
    (hdes : ∀ (v : alloc.vec.Vec Std.U8) (s : Slice Std.U8), Enc v →
      s.val = (v : Slice Std.U8).val ++ rest.val →
      ⦃ ⌜ True ⌝ ⦄ RT.DeserializeBytesInst.tls_deserialize_bytes s
      ⦃ ⇓ r => ⌜ ∃ p, r = .Ok p ∧ p.1 = x ∧ p.2.val = rest.val ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ spec.RoundTrip.round_trip.default x rest
    ⦃ ⇓? _ => ⌜ (spec.RoundTrip.round_trip.post RT.SerializeBytesInst
      RT.DeserializeBytesInst RT.corecmpPartialEqInst RT x rest ()).holds ⌝ ⦄ :=
  spec.RoundTrip.round_trip.default_fc_enc RT x rest Enc hpre heq hser_pf hser_fc hser fun s =>
    triple_pre_prop fun ⟨v, hE, hs⟩ => hdes v s hE hs

/-- Discharge the proposition precondition of a partial triple. -/
theorem partial_triple_of_pre {α : Type} {m : RustM α} {P : Prop} {Q : α → Prop}
    (h : ⦃ ⌜ P ⌝ ⦄ m ⦃ ⇓? r => ⌜ Q r ⌝ ⦄) (hp : P) : ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓? r => ⌜ Q r ⌝ ⦄ :=
  Triple.of_entails_left _ h (SPred.pure_mono fun _ => hp)

/-- `default_fc_enc` with the exact serializer output `enc`; the deserializer's total triple comes
from its panic freedom `hdes_pf` and its partial triple `hdes`. -/
theorem spec.RoundTrip.round_trip.default_fc {T : Type} (RT : spec.RoundTrip T) (x : T)
    (rest : Slice Std.U8) (enc : List Std.U8)
    (hpre : (spec.RoundTrip.round_trip.pre RT.SerializeBytesInst RT.DeserializeBytesInst
      RT.corecmpPartialEqInst RT x rest).holds)
    (heq : ⦃ ⌜ True ⌝ ⦄ RT.corecmpPartialEqInst.eq x x ⦃ ⇓ r => ⌜ r = true ⌝ ⦄)
    (hser_pf : ⦃ ⌜ True ⌝ ⦄ RT.SerializeBytesInst.tls_serialize_bytes x ⦃ ⇓ _ => ⌜ True ⌝ ⦄)
    (hser_fc : ⦃ ⌜ True ⌝ ⦄ RT.SerializeBytesInst.tls_serialize_bytes x
      ⦃ ⇓? res => ⌜ (SerializeBytes.tls_serialize_bytes.post RT.SerializeBytesInst.SizeInst
        RT.SerializeBytesInst x res).holds ⌝ ⦄)
    (hser : ⦃ ⌜ True ⌝ ⦄ RT.SerializeBytesInst.tls_serialize_bytes x
      ⦃ ⇓? r => ⌜ ∀ v, r = .Ok v → (v : Slice Std.U8).val = enc ⌝ ⦄)
    (hdes_pf : ∀ s : Slice Std.U8,
      ⦃ ⌜ True ⌝ ⦄ RT.DeserializeBytesInst.tls_deserialize_bytes s ⦃ ⇓ _ => ⌜ True ⌝ ⦄)
    (hdes : ∀ s : Slice Std.U8, ⦃ ⌜ s.val = enc ++ rest.val ⌝ ⦄
      RT.DeserializeBytesInst.tls_deserialize_bytes s
      ⦃ ⇓? r => ⌜ ∃ p, r = .Ok p ∧ p.1 = x ∧ p.2.val = rest.val ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ spec.RoundTrip.round_trip.default x rest
    ⦃ ⇓? _ => ⌜ (spec.RoundTrip.round_trip.post RT.SerializeBytesInst
      RT.DeserializeBytesInst RT.corecmpPartialEqInst RT x rest ()).holds ⌝ ⦄ :=
  spec.RoundTrip.round_trip.default_fc_enc_total RT x rest (fun v => (v : Slice Std.U8).val = enc)
    hpre heq hser_pf hser_fc hser fun _ s hv hs =>
      total_of_pf_partial (hdes_pf s) (partial_triple_of_pre (hdes s) (by rw [hs, hv]))

/-- `RoundTrip::round_trip` of a `TlsByteVecU*`-style wrapper, from the facts about its
serializer (`hser`: an `Ok` output is `enc a` followed by the payload, `pval a` the payload length)
and deserializer (the generic `TlsByteVecGen.deser`, `hdes`). -/
theorem TlsByteVecGen.rt_fc {W P E : Type} (RT : spec.RoundTrip W) (vec : W → alloc.vec.Vec Std.U8)
    (mk : alloc.vec.Vec Std.U8 → W) (hmk : ∀ v, vec (mk v) = v) (hinj : ∀ a b, vec a = vec b → a = b)
    (enc : P → List Std.U8) (pval : P → Nat) (w : Std.Usize) (henc : ∀ a, (enc a).length = w.val)
    (readLen : Slice Std.U8 → RustM (core.result.Result (P × Slice Std.U8) Error))
    (hread : ∀ (bytes : Slice Std.U8) (a : P) (X : List Std.U8), bytes.val = enc a ++ X →
      ⦃ ⌜ True ⌝ ⦄ readLen bytes ⦃ ⇓ r => ⌜ ∃ t : Slice Std.U8, r = .Ok (a, t) ∧ t.val = X ⌝ ⦄)
    (conv : P → RustM (core.result.Result Std.Usize E))
    (hconv : ∀ p, ⦃ ⌜ True ⌝ ⦄ conv p ⦃ ⇓ r => ⌜ ∃ y, r = .Ok y ∧ y.val = pval p ⌝ ⦄)
    (dbg : core.fmt.Debug E)
    (hdes : RT.DeserializeBytesInst.tls_deserialize_bytes = TlsByteVecGen.deser mk readLen conv dbg w)
    (x : W) (rest : Slice Std.U8)
    (hpre : (spec.RoundTrip.round_trip.pre RT.SerializeBytesInst RT.DeserializeBytesInst
      RT.corecmpPartialEqInst RT x rest).holds)
    (heq : ⦃ ⌜ True ⌝ ⦄ RT.corecmpPartialEqInst.eq x x ⦃ ⇓ r => ⌜ r = true ⌝ ⦄)
    (hser_pf : ⦃ ⌜ True ⌝ ⦄ RT.SerializeBytesInst.tls_serialize_bytes x ⦃ ⇓ _ => ⌜ True ⌝ ⦄)
    (hser_fc : ⦃ ⌜ True ⌝ ⦄ RT.SerializeBytesInst.tls_serialize_bytes x
      ⦃ ⇓? res => ⌜ (SerializeBytes.tls_serialize_bytes.post RT.SerializeBytesInst.SizeInst
        RT.SerializeBytesInst x res).holds ⌝ ⦄)
    (hser : ⦃ ⌜ True ⌝ ⦄ RT.SerializeBytesInst.tls_serialize_bytes x
      ⦃ ⇓? r => ⌜ ∀ out : alloc.vec.Vec Std.U8, r = .Ok out →
        ∃ a, pval a = (vec x).val.length ∧ out.val = enc a ++ (vec x).val ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ spec.RoundTrip.round_trip.default x rest
    ⦃ ⇓? _ => ⌜ (spec.RoundTrip.round_trip.post RT.SerializeBytesInst
      RT.DeserializeBytesInst RT.corecmpPartialEqInst RT x rest ()).holds ⌝ ⦄ := by
  refine spec.RoundTrip.round_trip.default_fc_enc_total RT x rest
    (fun v => ∃ a, pval a = (vec x).val.length ∧ v.val = enc a ++ (vec x).val) hpre heq hser_pf
    hser_fc hser ?_
  rintro v s ⟨a, hp, hv⟩ hs
  have hmax : w.val + (vec x).val.length ≤ Std.Usize.max := by
    have := v.property
    rw [hv] at this
    simpa [henc] using this
  rw [hdes]
  refine triple_post_mono (TlsByteVecGen.ok vec mk enc pval w readLen hread conv hconv dbg s a
    (vec x) rest.val (by rw [hs, hv, List.append_assoc]) hp (henc a) hmax) ?_
  rintro r ⟨t, rfl, ht⟩
  exact ⟨_, rfl, hinj _ _ (hmk _), ht⟩

/-- `varint.TlsVarInt.deserialize_enc` together with `deserialize_ok`: on an encoding of a value at
most `MAX` the call is `Ok`, and every `Ok` result is an encoding followed by the remainder. -/
theorem varint.TlsVarInt.deserialize_enc_ok (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ (∀ (v : varint.TlsVarInt) (t : Slice Std.U8), r = .Ok (v, t) →
        v.val ≤ 2 ^ 62 - 1 ∧ bytes.val.map (·.val) = varint.encList v.val ++ t.val.map (·.val)) ∧
        ((∃ (n : Nat) (rest : List Nat), n ≤ 2 ^ 62 - 1 ∧
            bytes.val.map (·.val) = varint.encList n ++ rest) → ∃ p, r = .Ok p) ⌝ ⦄ := by
  refine triple_and (varint.TlsVarInt.deserialize_enc bytes) ?_
  by_cases h : ∃ (n : Nat) (rest : List Nat), n ≤ 2 ^ 62 - 1 ∧
      bytes.val.map (·.val) = varint.encList n ++ rest
  · obtain ⟨n, rest, hn, hb⟩ := h
    exact triple_post_mono (varint.TlsVarInt.deserialize_ok bytes n rest hn hb) fun _ h _ => h
  · exact triple_post_mono (varint.TlsVarInt.deserialize_enc bytes) fun _ _ h' => absurd h' h

/-- `TlsVarInt::tls_deserialize_bytes` on the encoding of `x` (at most `MAX`) followed by `rest`:
succeeds, returns `x` and `rest`. -/
theorem varint.TlsVarInt.deserialize_enc_rest (x : varint.TlsVarInt) (rest s : Slice Std.U8)
    (hx : x.val ≤ 2 ^ 62 - 1)
    (hs : s.val.map (·.val) = varint.encList x.val ++ rest.val.map (·.val)) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes s
    ⦃ ⇓ r => ⌜ ∃ p, r = .Ok p ∧ p.1 = x ∧ p.2.val = rest.val ⌝ ⦄ := by
  refine triple_post_mono (varint.TlsVarInt.deserialize_enc_ok s) ?_
  rintro r ⟨h1, h2⟩
  obtain ⟨⟨v, t⟩, rfl⟩ := h2 ⟨x.val, rest.val.map (·.val), hx, hs⟩
  obtain ⟨hv, hst⟩ := h1 v t rfl
  obtain ⟨hn, hr⟩ := varint.encList_append_inj x.val v.val _ _ hx hv (hs.symm.trans hst)
  exact ⟨(v, t), rfl, UScalar.eq_of_val_eq hn.symm,
    List.map_injective_iff.mpr (fun a b h => UScalar.eq_of_val_eq h) hr.symm⟩

/-- `ContentLength::tls_deserialize_bytes` succeeds on the encoding of a length at most `MAX_MLS_LEN`
(followed by anything). -/
theorem quic_vec.ContentLength.deserialize_ok (bytes : Slice Std.U8) (n : Nat) (rest : List Nat)
    (hn : n ≤ 2 ^ 30 - 1) (hb : bytes.val.map (·.val) = varint.encList n ++ rest) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.ContentLength.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ ∃ p, r = .Ok p ⌝ ⦄ := by
  mvcgen [quic_vec.ContentLength.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes,
    varint.TlsVarInt.deserialize_enc_ok, quic_vec.ContentLength.new, varint.TlsVarInt.value,
    quic_vec.ContentLength.MAX, quic_vec.MAX_MLS_LEN_spec]
  try_vcs
  all_goals (try simp only [continue_eq_tryCF] at *)
  · rename_i _ hP _ p _ _ hlt hmax _ _ _ _ _ _ hr
    obtain ⟨hv, hp⟩ := hP.1 p.1 p.2 (by rw [hr])
    have := (varint.encList_append_inj _ _ _ _ (by omega) hv (hb.symm.trans hp)).1
    exfalso
    scalar_tac
  · exact ⟨_, rfl⟩
  · rename_i _ hP _ _ _ _ ha _
    intro _
    obtain ⟨p, hp⟩ := hP.2 ⟨n, rest, by omega, hb⟩
    rw [hp] at ha
    cases ha

/-- `ContentLength::deserialize_content` together with `deserialize_ok`. -/
theorem quic_vec.ContentLength.deserialize_content_ok (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.ContentLength.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ (∀ (v : quic_vec.ContentLength) (t : Slice Std.U8), r = .Ok (v, t) →
        v.val ≤ 2 ^ 30 - 1 ∧ bytes.val.map (·.val) = varint.encList v.val ++ t.val.map (·.val)) ∧
        ((∃ (n : Nat) (rest : List Nat), n ≤ 2 ^ 30 - 1 ∧
            bytes.val.map (·.val) = varint.encList n ++ rest) → ∃ p, r = .Ok p) ⌝ ⦄ := by
  refine triple_and (quic_vec.ContentLength.deserialize_content bytes) ?_
  by_cases h : ∃ (n : Nat) (rest : List Nat), n ≤ 2 ^ 30 - 1 ∧
      bytes.val.map (·.val) = varint.encList n ++ rest
  · obtain ⟨n, rest, hn, hb⟩ := h
    exact triple_post_mono (quic_vec.ContentLength.deserialize_ok bytes n rest hn hb) fun _ h _ => h
  · exact triple_post_mono (quic_vec.ContentLength.deserialize_content bytes) fun _ _ h' => absurd h' h

/-- A decoded length prefix of an encoding `varint.encList n ++ X` is `n`, and `X` is the remainder
(here at least as long as the prefix says). -/
theorem quic_vec.length_prefix_facts (bytes : Slice Std.U8) (n : Nat) (X : List Nat)
    (hn : n ≤ 2 ^ 30 - 1) (hX : n ≤ X.length) (hb : bytes.val.map (·.val) = varint.encList n ++ X)
    (p : quic_vec.ContentLength × Slice Std.U8)
    (hp : p.1.val ≤ 2 ^ 30 - 1 ∧ bytes.val.map (·.val) = varint.encList p.1.val ++ p.2.val.map (·.val)) :
    p.1.val = n ∧ X = p.2.val.map (·.val) ∧ n ≤ p.2.val.length := by
  obtain ⟨h1, h2⟩ := varint.encList_append_inj _ _ _ _ (by omega) (by omega) (hb.symm.trans hp.2)
  subst h2
  exact ⟨h1.symm, rfl, by simpa using hX⟩

/-- Proof of `VLBytes.deserialize_ok` and `VLByteVec.deserialize_ok` (the two deserializers are the
same code up to the wrapper `new`). Hygiene is off: the names of the theorem statement are used. -/
syntax "vl_deserialize_ok " ident ident : tactic
set_option hygiene false in
macro_rules
  | `(tactic| vl_deserialize_ok $fn $new) => `(tactic| (
    mvcgen [$fn:ident, quic_vec.ContentLength.deserialize_content_ok, varint.TlsVarInt.value,
      $new:ident, core.option.Option.ok_or_spec,
      core.Slice.Insts.CoreOpsIndexIndex.index_spec, alloc.vec.Vec.new_spec,
      core.hint.must_use_spec]
    try_vcs
    all_goals (try simp only [continue_eq_tryCF] at *)
    · exact ⟨_, rfl⟩
    · rename_i _ hP _ p _ _ husz _ val _ _ _ _ _ _ _ _ _ _ _ hr hv5
      have := quic_vec.length_prefix_facts bytes n X hn hX hb p (hP.1 p.1 p.2 (by rw [hr]))
      have hv := husz.1 val hv5
      intro hA _
      obtain ⟨t, ht, -⟩ := hA (by omega)
      refine ⟨t, ht, ?_⟩
      simp only [PostCond.ok]
      mvcgen
      exact ⟨_, rfl⟩
    · rename_i _ hP _ p _ _ husz _ val _ _ _ hopt _ _ _ h4 _ _ _ _ _ _ _ _ hr hv5
      have := quic_vec.length_prefix_facts bytes n X hn hX hb p (hP.1 p.1 p.2 (by rw [hr]))
      have hv := husz.1 val hv5
      obtain ⟨t, ht, -⟩ := hopt.1 (by omega)
      rw [ht] at h4
      cases h4
    · rename_i _ hP _ p _ _ husz _ _ _ _ ha hr
      have := quic_vec.length_prefix_facts bytes n X hn hX hb p (hP.1 p.1 p.2 (by rw [hr]))
      exfalso
      obtain ⟨y, hy⟩ := husz.2 (by omega)
      rw [hy] at ha
      cases ha
    · rename_i _ hP _ _ _ _ ha _
      intro _
      obtain ⟨p, hp⟩ := hP.2 ⟨n, X, hn, hb⟩
      rw [hp] at ha
      cases ha))

/-- `VLBytes::tls_deserialize_bytes` succeeds on a length prefix `n ≤ MAX_MLS_LEN` followed by at
least `n` bytes. -/
theorem quic_vec.VLBytes.deserialize_ok (bytes : Slice Std.U8) (n : Nat) (X : List Nat)
    (hn : n ≤ 2 ^ 30 - 1) (hX : n ≤ X.length) (hb : bytes.val.map (·.val) = varint.encList n ++ X) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLBytes.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ ∃ p, r = .Ok p ⌝ ⦄ := by
  vl_deserialize_ok quic_vec.VLBytes.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
    quic_vec.VLBytes.new

/-- `VLByteVec::tls_deserialize_bytes` succeeds on a length prefix `n ≤ MAX_MLS_LEN` followed by at
least `n` bytes. -/
theorem quic_vec.VLByteVec.deserialize_ok (bytes : Slice Std.U8) (n : Nat) (X : List Nat)
    (hn : n ≤ 2 ^ 30 - 1) (hX : n ≤ X.length) (hb : bytes.val.map (·.val) = varint.encList n ++ X) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLByteVec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ ∃ p, r = .Ok p ⌝ ⦄ := by
  vl_deserialize_ok quic_vec.VLByteVec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
    quic_vec.VLByteVec.new

/-- Proof of the `deserialize_list` lemmas: the call is `Ok` and, with `deserialize_content`, returns
the payload `P` and `rest` (hygiene is off, as for `vl_deserialize_ok`). -/
syntax "vl_deserialize_list " ident ident : tactic
set_option hygiene false in
macro_rules
  | `(tactic| vl_deserialize_list $content $ok) => `(tactic| (
    refine triple_post_mono (triple_and ($content s)
      ($ok s _ (P.map (·.val) ++ rest.val.map (·.val)) hn
        (by simp) (by rw [hs, List.append_assoc]))) ?_
    rintro r ⟨hc, p, rfl⟩
    obtain ⟨hb, hm⟩ := hc p.1 p.2 rfl
    have h := hs.symm.trans hm
    simp only [List.append_assoc] at h
    obtain ⟨hlen, happ⟩ := varint.encList_append_inj _ _ _ _ (by omega) (by omega) h
    obtain ⟨hv, hr⟩ := List.append_inj happ (by simp [hlen])
    exact ⟨p.1, p.2, rfl, (List.map_injective_iff.mpr (fun a b h => UScalar.eq_of_val_eq h) hv).symm,
      (List.map_injective_iff.mpr (fun a b h => UScalar.eq_of_val_eq h) hr).symm⟩))

/-- `VLBytes::tls_deserialize_bytes` on the encoding of the payload `P` followed by `rest`: succeeds,
returns `P` and `rest`. -/
theorem quic_vec.VLBytes.deserialize_list (P : List Std.U8) (rest s : Slice Std.U8)
    (hn : P.length ≤ 2 ^ 30 - 1)
    (hs : s.val.map (·.val) = varint.encList P.length ++ P.map (·.val) ++ rest.val.map (·.val)) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLBytes.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes s
    ⦃ ⇓ r => ⌜ ∃ raw rem, r = .Ok (raw, rem) ∧ raw.vec.val = P ∧ rem.val = rest.val ⌝ ⦄ := by
  vl_deserialize_list quic_vec.VLBytes.deserialize_content quic_vec.VLBytes.deserialize_ok

/-- `VLByteVec::tls_deserialize_bytes` on the encoding of the payload `P` followed by `rest`. -/
theorem quic_vec.VLByteVec.deserialize_list (P : List Std.U8) (rest s : Slice Std.U8)
    (hn : P.length ≤ 2 ^ 30 - 1)
    (hs : s.val.map (·.val) = varint.encList P.length ++ P.map (·.val) ++ rest.val.map (·.val)) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLByteVec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes s
    ⦃ ⇓ r => ⌜ ∃ raw rem, r = .Ok (raw, rem) ∧ raw.vec.val = P ∧ rem.val = rest.val ⌝ ⦄ := by
  vl_deserialize_list quic_vec.VLByteVec.deserialize_content quic_vec.VLByteVec.deserialize_ok

/-- `VLBytes::tls_deserialize_bytes` on the encoding of `x` followed by `rest`: succeeds, returns `x`
and `rest`. -/
theorem quic_vec.VLBytes.deserialize_enc_rest (x : quic_vec.VLBytes) (rest s : Slice Std.U8)
    (hn : x.vec.val.length ≤ 2 ^ 30 - 1)
    (hs : s.val.map (·.val) =
      varint.encList x.vec.val.length ++ x.vec.val.map (·.val) ++ rest.val.map (·.val)) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLBytes.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes s
    ⦃ ⇓ r => ⌜ ∃ p, r = .Ok p ∧ p.1 = x ∧ p.2.val = rest.val ⌝ ⦄ := by
  refine triple_post_mono (quic_vec.VLBytes.deserialize_list x.vec.val rest s hn hs) ?_
  rintro r ⟨⟨raw⟩, rem, rfl, hv, hr⟩
  obtain ⟨⟨c, hc⟩⟩ := x
  simp only at hv
  subst hv
  exact ⟨_, rfl, rfl, hr⟩

/-- `String::tls_deserialize_bytes` on the encoding of `t` followed by `rest`: succeeds, returns `t`
and `rest`. -/
theorem alloc.string.String.deserialize_enc_rest (t : alloc.string.String) (rest s : Slice Std.U8)
    (hn : (alloc.string.String.utf8U8 t).length ≤ 2 ^ 30 - 1)
    (hs : s.val.map (·.val) = varint.encList (alloc.string.String.utf8U8 t).length ++
      (alloc.string.String.utf8U8 t).map (·.val) ++ rest.val.map (·.val)) :
    ⦃ ⌜ True ⌝ ⦄ alloc.string.String.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes s
    ⦃ ⇓ r => ⌜ ∃ p, r = .Ok p ∧ p.1 = t ∧ p.2.val = rest.val ⌝ ⦄ := by
  obtain ⟨_, hr0, raw, rem, rfl, hraw, hrem⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (quic_vec.VLByteVec.deserialize_list _ rest s hn hs)
  unfold alloc.string.String.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
  rw [hr0]
  mvcgen [core.result.Result.map_err_spec, alloc.vec.VecU8.Insts.CoreConvertFromVLByteVec.from,
    string.DeserializeBytesString.tls_deserialize_bytes.closure.Insts.CoreOpsFunctionFnOnceTupleFromUtf8ErrorError.call_once]
  all_goals (try simp only [continue_eq_tryCF, core.result.Result.Ok.injEq] at *)
  all_goals (try subst_vars)
  · rename_i v h
    rcases h with ⟨t', ht', hu⟩ | ⟨h, -⟩
    · cases ht'
      exact ⟨_, rfl, alloc.string.String.utf8U8_inj (hu.trans hraw), hrem⟩
    · cases h
  · intro h
    simp [tryCF] at h
  · rename_i e _ _ _ h
    exfalso
    rcases h with ⟨t', ht', -⟩ | ⟨-, hne⟩
    · cases ht'
    · exact hne t hraw.symm
  · intro h
    simp [tryCF] at h

/-! ### `RoundTrip`: T's codecs from T's `RoundTrip.Lawful`, for the generic `Option` / `Vec` -/

/-- Converse of `round_trip.pre_elim`. -/
theorem spec.RoundTrip.round_trip.pre_intro {T : Type} (RT : spec.RoundTrip T) (x : T)
    (rest : Slice Std.U8) (n : Std.Usize)
    (hn : RT.SerializeBytesInst.SizeInst.tls_serialized_len x = ok n)
    (hle : rest.val.length + n.val ≤ Std.Usize.max) :
    (spec.RoundTrip.round_trip.pre RT.SerializeBytesInst RT.DeserializeBytesInst
      RT.corecmpPartialEqInst RT x rest).holds := by
  unfold spec.RoundTrip.round_trip.pre
  apply pre_holds_of_ok_true
  have hl : core.slice.Slice.len rest = ok (Slice.len rest) := rfl
  have hsub := Aeneas.Std.UScalar.sub_equiv (core.num.Usize.MAX) n
  simp only [hl, hn, bind_tc_ok]
  cases hs : (core.num.Usize.MAX - n : RustM Std.Usize) with
  | ok m =>
    rw [hs] at hsub
    obtain ⟨_, hm, _⟩ := hsub
    have : rest.len ≤ m := by scalar_tac
    simp; scalar_tac
  | fail _ => rw [hs] at hsub; have := hsub.2; scalar_tac
  | div => rw [hs] at hsub; exact hsub.elim

/-- The free function `spec.encode_decode_rest` on a serializer output `b`: it deserializes
`b ++ rest` and wraps the result. -/
theorem spec.encode_decode_rest.char {T : Type} (S : SerializeBytes T) (D : DeserializeBytes T)
    (hdpf : ∀ s : Slice Std.U8, ⦃ ⌜ True ⌝ ⦄ D.tls_deserialize_bytes s ⦃ ⇓ _ => ⌜ True ⌝ ⦄)
    (x : T) (rest : Slice Std.U8) (b : alloc.vec.Vec Std.U8)
    (hb : S.tls_serialize_bytes x = ok (.Ok b))
    (hlen : b.val.length + rest.val.length ≤ Std.Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ spec.encode_decode_rest S D x rest
    ⦃ ⇓ r => ⌜ ∃ (s : Slice Std.U8) (r1 : core.result.Result (T × Slice Std.U8) Error),
        s.val = b.val ++ rest.val ∧ D.tls_deserialize_bytes s = ok r1 ∧
        (∀ out rem, r1 = .Ok (out, rem) → ∃ v : alloc.vec.Vec Std.U8, v.val = rem.val ∧
          r = .Ok (.Some (out, v))) ∧
        (∀ e, r1 = .Err e → r = .Ok .None) ⌝ ⦄ := by
  have hs : ⦃ ⌜ True ⌝ ⦄ S.tls_serialize_bytes x ⦃ ⇓ r => ⌜ r = .Ok b ⌝ ⦄ := by
    rw [hb]; apply RustM.ok_spec; rfl
  have hd : ∀ s : Slice Std.U8, ⦃ ⌜ True ⌝ ⦄ D.tls_deserialize_bytes s
      ⦃ ⇓ r => ⌜ D.tls_deserialize_bytes s = ok r ⌝ ⦄ := fun s => by
    obtain ⟨v, hv, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (hdpf s)
    rw [hv]; apply RustM.ok_spec; rfl
  mvcgen [spec.encode_decode_rest, hs, hd, alloc.vec.Vec.extend_from_slice_U8_spec]
  · rename_i _ h1 _ val1 _ h2
    subst h1
    cases continue_eq_tryCF.mp h2
    exact hlen
  · rename_i _ h1 _ val1 _ h2 _ h3 _ h4 _ p _ hd _ h5
    subst h1 h4 h5
    cases continue_eq_tryCF.mp h2
    refine ⟨_, _, h3, hd, ?_, by simp⟩
    rintro out rem h
    cases h
    exact ⟨_, rfl, rfl⟩
  · rename_i _ h1 _ val1 _ h2 _ h3 _ h4 _ e _ hd
    subst h1 h4
    cases continue_eq_tryCF.mp h2
    exact ⟨_, _, h3, hd, by simp, by simp⟩
  · rename_i _ h1 _ _ _
    subst h1
    intro h
    simp [tryCF] at h

/-- The closure of the `ensures` of `RoundTrip::round_trip`, on an `Option`. -/
theorem spec.RoundTrip.call_once_char {T : Type} {RT : spec.RoundTrip T}
    (hl : spec.RoundTrip.Lawful T RT) (x : T) (rest : Slice Std.U8)
    (o : core.option.Option (T × alloc.vec.Vec Std.U8)) :
    ⦃ ⌜ True ⌝ ⦄ spec.__1.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleOptionPairSelf_VecU8Bool.call_once
      RT.SerializeBytesInst RT.DeserializeBytesInst RT.corecmpPartialEqInst RT (x, rest) o
    ⦃ ⇓ r => ⌜ r = true ↔ ∃ out w, o = .Some (out, w) ∧ out = x ∧ w.val = rest.val ⌝ ⦄ := by
  classical
  have hs := core.Slice.Insts.CoreCmpPartialEqSlice.eq_spec core.U8.Insts.CoreCmpPartialEqU8
    (heq := core.U8.Insts.CoreCmpPartialEqU8.eq_decide_spec)
  have he := hl.corecmpPartialEqInstLawful.eq_spec
  cases o with
  | none =>
    mvcgen [spec.__1.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleOptionPairSelf_VecU8Bool.call_once,
      core.option.Option.is_some_and]
    simp
  | some p =>
    obtain ⟨out, w⟩ := p
    mvcgen [spec.__1.ensures.closure.Insts.CoreOpsFunctionFnOnceTupleOptionPairSelf_VecU8Bool.call_once,
      core.option.Option.is_some_and,
      spec.__1.ensures.closure.closure.Insts.CoreOpsFunctionFnOnceTuplePairSelf_VecU8Bool.call_once,
      he, hs]
    · rename_i hb hiff _ hw _
      subst hw
      intro hr
      have := eq_of_heq (hiff.mp hb)
      simp [hr, this]
    · rename_i hn hiff
      simp only [Bool.false_eq_true, false_iff, not_exists]
      rintro o w' ⟨h, ho, _⟩
      cases h
      exact hn (hiff.mpr (heq_of_eq ho))

/-- The container-facing form of `RoundTrip.Lawful`: if `T`'s serializer returns `Ok b` on `x`, then
`T`'s deserializer, on any `b ++ rest` that fits in a slice, returns `x` and `rest`. -/
theorem spec.RoundTrip.Lawful.dec {T : Type} {RT : spec.RoundTrip T}
    (hl : spec.RoundTrip.Lawful T RT) (x : T) (rest : Slice Std.U8) (b : alloc.vec.Vec Std.U8)
    (hb : RT.SerializeBytesInst.tls_serialize_bytes x = ok (.Ok b))
    (hlen : b.val.length + rest.val.length ≤ Std.Usize.max) (s : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ RT.DeserializeBytesInst.tls_deserialize_bytes s
    ⦃ ⇓ r => ⌜ s.val = b.val ++ rest.val → ∃ p, r = .Ok p ∧ p.1 = x ∧ p.2.val = rest.val ⌝ ⦄ := by
  have hdpf := fun s => pf_of_total
    (hl.DeserializeBytesInstLawful.tls_deserialize_bytes_spec s (pre_holds_of_ok_true rfl))
  by_cases hs : s.val = b.val ++ rest.val
  swap
  · exact triple_post_mono (hdpf s) fun _ _ h => absurd h hs
  obtain ⟨v, hv, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (hl.SerializeBytesInstLawful.tls_serialize_bytes_spec x (pre_holds_of_ok_true rfl))
  rw [hb] at hv
  cases hv
  obtain ⟨n, hn, hnl⟩ := SerializeBytes.post_ok_elim _ _ _ _ hP
  have hpre := spec.RoundTrip.round_trip.pre_intro RT x rest n hn (by scalar_tac)
  obtain ⟨u, hu, hpost⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (hl.round_trip_spec x rest hpre)
  obtain ⟨r0, hr0, hc⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (spec.encode_decode_rest.char RT.SerializeBytesInst RT.DeserializeBytesInst hdpf x rest b hb hlen)
  unfold spec.RoundTrip.round_trip.post at hpost
  rw [hr0] at hpost
  obtain ⟨s', r1, hs', hd, hok, herr⟩ := hc
  obtain rfl : s' = s := Subtype.ext (hs'.trans hs.symm)
  rw [hd]
  apply RustM.ok_spec
  intro _
  have hcall := fun o => Aeneas.Std.WP.triple_iff_exists_ok.mp (spec.RoundTrip.call_once_char hl x rest o)
  cases r1 with
  | Err e =>
    obtain rfl := herr e rfl
    simp [core.result.Result.is_err, core.result.Result.is_ok_and, Functor.map] at hpost
    obtain ⟨c, hc, hiff⟩ := hcall .None
    rw [hc] at hpost
    have := hiff.mp (holds_ok_iff.mp hpost)
    simp at this
  | Ok p =>
    obtain ⟨out, rem⟩ := p
    obtain ⟨w, hw, rfl⟩ := hok out rem rfl
    simp [core.result.Result.is_err, core.result.Result.is_ok_and, Functor.map] at hpost
    obtain ⟨c, hc, hiff⟩ := hcall (.Some (out, w))
    rw [hc] at hpost
    obtain ⟨o, w', h, ho, hw'⟩ := hiff.mp (holds_ok_iff.mp hpost)
    cases h
    exact ⟨_, rfl, ho, hw.symm.trans hw'⟩

/-- `Option<T>::tls_serialize_bytes`: an `Ok out` is `[0]` (`None`) or `1 :: b` for an `Ok b` of `T`'s
serializer on the payload. -/
theorem Option_serialize_rt {T : Type} (inst : SerializeBytes T)
    (hlaw : SerializeBytes.Lawful T inst) (o : core.option.Option T) :
    ⦃ ⌜ True ⌝ ⦄ core.option.Option.Insts.Tls_codecSerializeBytes.tls_serialize_bytes inst o
    ⦃ ⇓ r => ⌜ ∀ out, r = .Ok out →
        (o = .None ∧ (out : Slice Std.U8).val = [0#u8]) ∨
        ∃ (e : T) (b : alloc.vec.Vec Std.U8), o = .Some e ∧ inst.tls_serialize_bytes e = ok (.Ok b) ∧
          (out : Slice Std.U8).val = 1#u8 :: b.val ⌝ ⦄ := by
  have hsz := hlaw.SizeInstLawful.tls_serialized_len_spec
  have hs : ∀ x, ⦃ ⌜ True ⌝ ⦄ inst.tls_serialize_bytes x
      ⦃ ⇓ r => ⌜ inst.tls_serialize_bytes x = ok r ∧ (SerializeBytes.tls_serialize_bytes.post
        inst.SizeInst inst x r).holds ⌝ ⦄ := fun x => by
    obtain ⟨v, hv, hp⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (hlaw.tls_serialize_bytes_spec x (pre_holds_of_ok_true rfl))
    rw [hv]; apply RustM.ok_spec; exact ⟨rfl, hp⟩
  cases o with
  | none =>
    exact triple_post_mono (Option_serialize_char inst hlaw .None) fun r h out hr =>
      (h.1 out hr).elim (fun h => Or.inl h) (fun ⟨_, _, _, ho, _⟩ => by cases ho)
  | some e =>
    obtain ⟨n, hn, -⟩ := (Aeneas.Std.WP.triple_iff_exists_ok).1
      (hsz e (pre_holds_of_ok_true rfl))
    mvcgen [core.option.Option.Insts.Tls_codecSerializeBytes.tls_serialize_bytes, hn, hs,
      checked_alloc_len_ok, alloc.vec.Vec.with_capacity, alloc.vec.Vec.append,
      rust_primitives.sequence.seq_concat]
    try_vcs
    all_goals (try simp only [continue_eq_tryCF] at *)
    all_goals (try (intros; simp [PostCond.ok]; done))
    · rename_i _ _ _ _ _ _ hr3 _
      subst hr3
      simp [Slice.new]
      scalar_tac
    · rename_i r5 hchk cf0 val x1 r3 hr3 out1 hout1 r1 hpost cf1 val1 x2 comb hlen hcv hr1
      intro out hout
      have hout' := core.result.Result.Ok.inj hout
      subst hout' hr1
      refine Or.inr ⟨e, val1, rfl, hpost.1, ?_⟩
      simp [comb, hout1, hr3, Slice.new]
    · rename_i r5 hchk cf0 val x1 r3 hr3 out1 hout1 r1 hpost cf1 val1 x2 comb hlen hcv hr1
      exfalso
      subst hr1
      obtain ⟨n', hn', hl⟩ := SerializeBytes.post_ok_elim _ _ _ _ hpost.2
      have hnn := ok.inj (hn.symm.trans hn')
      subst hnn
      have h1 := hchk val hcv
      subst hr3
      apply hlen
      simp only [comb, hout1, List.length_append, hl]
      simp [Slice.new]
      scalar_tac

/-- `Option<T>::tls_deserialize_bytes` on `0 :: rest`: `None` and `rest`. -/
theorem Option_deserialize_none {T : Type} (inst : DeserializeBytes T) (rest s : Slice Std.U8)
    (hs : s.val = 0#u8 :: rest.val) :
    ⦃ ⌜ True ⌝ ⦄ core.option.Option.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes inst s
    ⦃ ⇓ r => ⌜ ∃ p, r = .Ok p ∧ p.1 = .None ∧ p.2.val = rest.val ⌝ ⦄ := by
  mvcgen [core.option.Option.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes, U8_deserialize_char]
  · rename_i r1 hP cf p hx hz hr1
    obtain ⟨l, hb, hp2⟩ := U8_deserialize_ok hP hr1
    rw [hs] at hb
    exact ⟨_, rfl, rfl, by rw [hp2]; exact (List.cons.inj hb).2.symm⟩
  · rename_i r1 hP cf p hx hz hr1
    obtain ⟨l, hb, hp2⟩ := U8_deserialize_ok hP hr1
    simp only [hs, List.cons.injEq, hz] at hb
    exact absurd hb.1 (by decide)
  · rename_i r1 hP cf p hx t h0 h1 hpt hr1 _ _ _ _ _
    obtain ⟨l, hb, hp2⟩ := U8_deserialize_ok hP hr1
    simp only [hs, List.cons.injEq] at hb
    exact absurd (hpt ▸ hb.1.symm) h0
  · rename_i r1 hP cf resid hx
    intro h
    have hb := hP.1 (by simp [hs])
    obtain ⟨a, t, -, -, hr⟩ := hb
    subst hr
    simp [tryCF] at h

/-- `Option<T>::tls_deserialize_bytes` on `1 :: (b ++ rest)`, when `T`'s deserializer returns `x`
and `rest` on `b ++ rest`: `Some x` and `rest`. -/
theorem Option_deserialize_some {T : Type} (inst : DeserializeBytes T) (rest s : Slice Std.U8)
    (x : T) (b : List Std.U8) (hs : s.val = 1#u8 :: (b ++ rest.val))
    (hd : ∀ t : Slice Std.U8, ⦃ ⌜ True ⌝ ⦄ inst.tls_deserialize_bytes t
      ⦃ ⇓ r => ⌜ t.val = b ++ rest.val → ∃ p, r = .Ok p ∧ p.1 = x ∧ p.2.val = rest.val ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ core.option.Option.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes inst s
    ⦃ ⇓ r => ⌜ ∃ p, r = .Ok p ∧ p.1 = .Some x ∧ p.2.val = rest.val ⌝ ⦄ := by
  mvcgen [core.option.Option.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes, U8_deserialize_char, hd]
  · rename_i r1 hP cf p hx hz hr1
    obtain ⟨l, hb, hp2⟩ := U8_deserialize_ok hP hr1
    simp only [hs, List.cons.injEq, hz] at hb
    exact absurd hb.1 (by decide)
  · rename_i r1 hP cf p hx hz hr1 r2 hP2 cf2 p2 hx2 hr2
    obtain ⟨l, hb, hp2⟩ := U8_deserialize_ok hP hr1
    rw [hs] at hb
    obtain ⟨q, hq, hq1, hq2⟩ := hP2 (by rw [hp2]; exact (List.cons.inj hb).2.symm)
    subst hq
    cases continue_eq_tryCF.mp hr2
    exact ⟨_, rfl, by rw [hq1], hq2⟩
  · rename_i r1 hP cf p hx hz hr1 r2 hP2 cf2 resid hx2
    intro h
    obtain ⟨l, hb, hp2⟩ := U8_deserialize_ok hP hr1
    rw [hs] at hb
    obtain ⟨q, hq, -⟩ := hP2 (by rw [hp2]; exact (List.cons.inj hb).2.symm)
    subst hq
    simp [tryCF] at h
  · rename_i r1 hP cf p hx t h0 h1 hpt hr1 _ _ _ _ _
    obtain ⟨l, hb, hp2⟩ := U8_deserialize_ok hP hr1
    simp only [hs, List.cons.injEq] at hb
    exact absurd (hpt ▸ hb.1.symm) h1
  · rename_i r1 hP cf resid hx
    intro h
    have hb := hP.1 (by simp [hs])
    obtain ⟨a, t, -, -, hr⟩ := hb
    subst hr
    simp [tryCF] at h

end tls_codec
