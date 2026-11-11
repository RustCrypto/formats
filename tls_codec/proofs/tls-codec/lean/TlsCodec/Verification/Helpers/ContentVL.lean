/- Contents of the varint-prefixed codecs (`TlsVarInt`, `ContentLength`, `VLBytes`, `VLByteVec`,
`VLByteSlice`): what the serializers write and the deserializers read.

Obligations: none directly; the bytes-path halves of `PanicFreedom.lean` /
`FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): ASSUMED `size_of`, `size_of_U8`. -/
import TlsCodec.Verification.Helpers.VarIntContent
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! ### Content of the length-prefixed serializers and deserializers

Encoding form: bytes are compared through `(·.val)` as naturals, the length prefix is
`varint.encList n`. -/

/-- The varint encoding is prefix-free: equal encodings followed by anything determine the value. -/
theorem varint.encList_append_inj (n v : Nat) (X Y : List Nat) (hn : n ≤ 2 ^ 62 - 1)
    (hv : v ≤ 2 ^ 62 - 1) (h : varint.encList n ++ X = varint.encList v ++ Y) : n = v ∧ X = Y := by
  obtain ⟨e0, tl, he, he0, htl, -, hD⟩ := varint.encList_dec n hn
  obtain ⟨e0', tl', he', he0', htl', -, hD'⟩ := varint.encList_dec v hv
  rw [he, he', List.cons_append, List.cons_append] at h
  obtain ⟨rfl, h2⟩ := List.cons.inj h
  have hL : varint.lenOf n = varint.lenOf v :=
    varint.pfx_inj _ _ (varint.lenOf_mem n) (varint.lenOf_mem v) (he0.symm.trans he0')
  obtain ⟨rfl, rfl⟩ := List.append_inj h2 (by rw [htl, htl', hL])
  exact ⟨hD.symm.trans hD', rfl⟩

/-- `TlsVarInt::tls_deserialize_bytes` on contents, in encoding form: on success the input is the
minimal encoding of the value followed by the remainder. -/
theorem varint.TlsVarInt.deserialize_enc (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ (v : varint.TlsVarInt) (t : Slice Std.U8), r = .Ok (v, t) →
        v.val ≤ 2 ^ 62 - 1 ∧
        bytes.val.map (·.val) = varint.encList v.val ++ t.val.map (·.val) ⌝ ⦄ := by
  apply triple_post_mono (varint.TlsVarInt.deserialize_content bytes)
  intro r hr v t hrt
  obtain ⟨b0, l, L, hbl, hL, hLv, hpfx, hle, ht, hval, hmax⟩ := hr v t hrt
  refine ⟨hmax, ?_⟩
  have hb0 : b0.val < 256 := by have := b0.hBounds; simpa using this
  have hl : ∀ x ∈ l.map (·.val), x < 256 := by
    simp only [List.mem_map]; rintro _ ⟨a, -, rfl⟩; have := a.hBounds; simpa using this
  have hE := varint.enc_of_dec b0.val (l.map (·.val)) L v.val hmax hb0 hl hLv hpfx
    (by simpa using hle) (by rw [hval, ← List.map_take, List.foldl_map])
  rw [← hE, hbl, ht, List.map_cons, List.cons_append, ← List.map_take, ← List.map_append,
    List.take_append_drop]

/-- One iteration of the varint loop with enough input left (`len - i` bytes): it does not fail. -/
theorem varint.deserialize_loop.body_total (len : Std.Usize) (remainder : Slice Std.U8)
    (value : Std.U64) (i : Std.Usize) (hi : 1 ≤ i.val) (hil : i.val ≤ len.val) (hl : len.val ≤ 8)
    (hv : value.val < 2 ^ (8 * i.val - 2)) (hrem : len.val - i.val ≤ remainder.val.length) :
    ⦃ ⌜ True ⌝ ⦄
    varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop.body len remainder value i
    ⦃ ⇓ r => ⌜ match r with
      | .done (_, _, f) => f = core.option.Option.None
      | .cont (r', v', i') => r'.val.length + 1 = remainder.val.length ∧ i'.val = i.val + 1 ∧
          i'.val ≤ len.val ∧ v'.val < 2 ^ (8 * i'.val - 2) ⌝ ⦄ := by
  unfold varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop.body
  mvcgen [U8_deserialize_char]
  · rename_i hlt r0 p hr hP r3 h3 h3b h3c r2 h2 r1 h1 r h0
    have hb := varint.step_bound value.val r2.val i.val hi (by scalar_tac) hv (by scalar_tac)
    obtain ⟨a, t, ha, ht, hpt⟩ := hP.1 (by scalar_tac)
    rw [(congrArg Prod.snd (core.result.Result.Ok.inj hpt)).trans rfl, ht]
    simp only [List.length_drop]
    have h1' : (1#usize).val = 1 := by simp
    refine ⟨by scalar_tac, by scalar_tac, by scalar_tac, ?_⟩
    have : r.val = i.val + 1 := by scalar_tac
    rw [this]
    scalar_tac
  · rename_i hlt r0 p hr hP r3 h3 h3b h3c r2 h2 r1 h1 hov
    exfalso
    have hb := varint.step_bound value.val r2.val i.val hi (by scalar_tac) hv (by scalar_tac)
    scalar_tac
  · rename_i hlt r0 p hr hP r3 h3 h3b h3c r2 h2 hov
    exfalso
    have hb := varint.step_bound value.val r2.val i.val hi (by scalar_tac) hv (by scalar_tac)
    scalar_tac
  · rename_i hlt r0 e hr hP
    obtain ⟨a, t, -, -, h⟩ := hP.1 (by scalar_tac)
    cases h

/-- The varint loop does not fail when `len - i` bytes are available. -/
theorem varint.deserialize_loop_total (remainder : Slice Std.U8) (len : Std.Usize)
    (value : Std.U64) (i : Std.Usize) (hi : 1 ≤ i.val) (hil : i.val ≤ len.val) (hl : len.val ≤ 8)
    (hv : value.val < 2 ^ (8 * i.val - 2)) (hrem : len.val - i.val ≤ remainder.val.length) :
    ⦃ ⌜ True ⌝ ⦄
    varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop remainder len value i
    ⦃ ⇓ r => ⌜ r.2.2 = core.option.Option.None ⌝ ⦄ := by
  unfold varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.loop.spec_decr_nat
    (fun x : Slice Std.U8 × Std.U64 × Std.Usize => len.val - x.2.2.val)
    (fun x : Slice Std.U8 × Std.U64 × Std.Usize =>
      1 ≤ x.2.2.val ∧ x.2.2.val ≤ len.val ∧ x.2.1.val < 2 ^ (8 * x.2.2.val - 2) ∧
      len.val - x.2.2.val ≤ x.1.val.length)
    (fun y : Slice Std.U8 × Std.U64 × (core.option.Option Error) => y.2.2 = core.option.Option.None)
  · rintro ⟨b, v, j⟩ ⟨hj1, hjl, hjv, hjr⟩
    dsimp only at hj1 hjl hjv hjr
    obtain ⟨r, hr, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (varint.deserialize_loop.body_total len b v j hj1 hjl hl hjv hjr)
    dsimp only
    rw [hr, Aeneas.Std.WP.spec_ok]
    cases r with
    | done y => exact hP
    | cont x =>
      obtain ⟨b', v', j'⟩ := x
      obtain ⟨h1, h2, h3, h4⟩ := hP
      dsimp only at h1 h2 h3 h4 ⊢
      exact ⟨⟨by omega, h3, h4, by omega⟩, by omega⟩
  · exact ⟨hi, hil, hv, hrem⟩

/-- The varint loop on enough input: it succeeds, and the content facts hold. -/
theorem varint.deserialize_loop_full (remainder : Slice Std.U8) (len : Std.Usize)
    (value : Std.U64) (i : Std.Usize) (hi : 1 ≤ i.val) (hil : i.val ≤ len.val) (hl : len.val ≤ 8)
    (hv : value.val < 2 ^ (8 * i.val - 2)) (hrem : len.val - i.val ≤ remainder.val.length) :
    ⦃ ⌜ True ⌝ ⦄
    varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_loop remainder len value i
    ⦃ ⇓ r => ⌜ r.2.2 = core.option.Option.None ∧
        r.1.val = remainder.val.drop (len.val - i.val) ∧
        r.2.1.val = (remainder.val.take (len.val - i.val)).foldl (fun a b => a * 256 + b.val) value.val ⌝ ⦄ :=
  triple_post_mono
    (triple_and (varint.deserialize_loop_total remainder len value i hi hil hl hv hrem)
      (varint.deserialize_loop_content remainder len value i hi hil hl hv))
    fun _ ⟨h1, h2⟩ => ⟨h1, (h2 h1).2⟩

/-- Facts shared by the verification conditions of `deserialize_ok`: the first byte `p.1` read by
`u8::tls_deserialize_bytes` heads the encoding of `n`, `calculate_value` recovers the length and the
low 6 bits, and the fold of the next bytes gives `n`. -/
theorem varint.deserialize_ok_facts {bytes : Slice Std.U8} {n : Nat} {rest : List Nat}
    {r0 : core.result.Result (Std.U8 × Slice Std.U8) Error} {p : Std.U8 × Slice Std.U8}
    {r1 : core.result.Result (Std.Usize × Std.Usize) Error} {val : Std.Usize × Std.Usize}
    {r2 : core.result.Result Std.U64 core.num.error.TryFromIntError} {t val1 : Std.U64}
    (hn : n ≤ 2 ^ 62 - 1) (hb : bytes.val.map (·.val) = varint.encList n ++ rest)
    (hP : (1 ≤ bytes.val.length → ∃ (a : Aeneas.Std.Array Std.U8 1#usize) (t : Slice Std.U8),
          a.val = bytes.val.take 1 ∧ t.val = bytes.val.drop 1 ∧
          r0 = .Ok (Aeneas.Std.core.num.U8.from_be_bytes a, t)) ∧
        (bytes.val.length < 1 → r0 = .Err Error.EndOfStream))
    (hcf : core.ops.control_flow.ControlFlow.Continue p = tryCF r0)
    (hvl : ∃ v l : Std.Usize, r1 = .Ok (v, l) ∧ v.val = p.1.val % 64 ∧
        (l.val = 1 ∨ l.val = 2 ∨ l.val = 4 ∨ l.val = 8) ∧ varint.pfx l.val = p.1.val / 64 * 64)
    (hcf1 : core.ops.control_flow.ControlFlow.Continue val = tryCF r1)
    (h2 : r2 = .Ok (UScalar.cast .U64 val.1)) (ha : r2 = .Ok t)
    (hcf2 : core.ops.control_flow.ControlFlow.Continue val1 =
      tryCF (core.result.Result.Ok t : core.result.Result Std.U64 Error)) :
    ∃ tl, varint.encList n = p.1.val :: tl ∧ p.2.val.map (·.val) = tl ++ rest ∧
      val.2.val = varint.lenOf n ∧ tl.length = varint.lenOf n - 1 ∧ val1.val = p.1.val % 64 ∧
      (p.2.val.take (val.2.val - 1)).foldl (fun a b => a * 256 + b.val) val1.val = n := by
  obtain ⟨l, hbl, hp2⟩ := U8_deserialize_ok hP hcf
  obtain ⟨e0, tl, he, he0, htl, -, hD⟩ := varint.encList_dec n hn
  rw [hbl, he, List.map_cons, List.cons_append, List.cons.injEq] at hb
  obtain ⟨hb0, hbl'⟩ := hb
  obtain ⟨v, l', hr1, hv, hl', hpf⟩ := hvl
  rw [continue_eq_tryCF, hr1, core.result.Result.Ok.injEq] at hcf1
  subst hcf1
  rw [continue_eq_tryCF, core.result.Result.Ok.injEq] at hcf2
  subst hcf2
  have hLL : l'.val = varint.lenOf n :=
    varint.pfx_inj _ _ hl' (varint.lenOf_mem n) (hpf.trans (by rw [hb0, he0]))
  have hv1 : t.val = p.1.val % 64 := by
    have := core.result.Result.Ok.inj (h2.symm.trans ha)
    rw [← this]; simpa using hv
  have hk : l'.val - 1 = tl.length := by rw [hLL, htl]
  refine ⟨tl, by rw [he, hb0], by rw [hp2]; exact hbl', hLL, htl, hv1, ?_⟩
  simp only
  rw [hk, hp2, hv1, show (l.take tl.length).foldl (fun a (b : Std.U8) => a * 256 + b.val) (p.1.val % 64) =
      ((l.map (·.val)).take tl.length).foldl (fun a b => a * 256 + b) (p.1.val % 64) by
    rw [← List.map_take, List.foldl_map], hbl', List.take_left' rfl, varint.foldl_eq, ← hD,
    varint.D_cons, hb0]

set_option hygiene false in
/-- Context of the verification conditions of `varint.TlsVarInt.deserialize_ok`: names the
hypotheses and derives `varint.deserialize_ok_facts` (hygiene is off on purpose, the names are used
by the callers). -/
macro "deser_ok_ctx" : tactic =>
  `(tactic| (rename_i r0 hP cf0 p hx hcf r1 hvl cf1 val hx1 hcf1 r2 h2 t ha cf2 val1 hx2 hcf2
             obtain ⟨tl, -, hp2, hL, htl, hv1, hfold⟩ :=
               varint.deserialize_ok_facts hn hb hP hcf hvl hcf1 h2 ha hcf2
             have hlm := varint.lenOf_mem n))

/-- `TlsVarInt::tls_deserialize_bytes` succeeds on the encoding of a value at most `MAX`
(followed by anything). -/
theorem varint.TlsVarInt.deserialize_ok (bytes : Slice Std.U8) (n : Nat) (rest : List Nat)
    (hn : n ≤ 2 ^ 62 - 1) (hb : bytes.val.map (·.val) = varint.encList n ++ rest) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ ∃ p, r = .Ok p ⌝ ⦄ := by
  mvcgen [varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes,
    U8_deserialize_char, varint.calculate_value_content,
    core.result.Result.map_err_spec, varint.deserialize_loop_full,
    varint.DeserializeBytesTlsVarInt.tls_deserialize_bytes.closure.Insts.CoreOpsFunctionFnOnceTupleTryFromIntErrorError.call_once]
  · deser_ok_ctx
    scalar_tac
  · deser_ok_ctx
    scalar_tac
  · deser_ok_ctx
    have h1 : (1#usize).val = 1 := by simp
    rw [h1]
    omega
  · deser_ok_ctx
    have := congrArg List.length hp2
    simp only [List.length_map, List.length_append] at this
    scalar_tac
  · rename_i r hnone hloop
    deser_ok_ctx
    have hr : r.2.1.val = n := by rw [hloop.2.2]; simpa using hfold
    have hc := varint.check_min_len_total r.2.1 val.2 (by omega) (by rw [hr]; omega)
    mvcgen [hc]
    · exact ⟨_, rfl⟩
    · rename_i r4 h4 cf3 resid hx3
      intro hbr
      exfalso
      rw [h4] at hbr
      simp only [tryCF, reduceCtorEq] at hbr
  · rename_i r0 hP cf0 p hx hcf r1 hvl cf1 val hx1 hcf1 r2 h2 t ha cf2 val1 hx2 hcf2 r e hsome hloop
    rw [hloop.1] at hsome
    cases hsome
  · rename_i r0 hP cf0 p hx hcf r1 hvl cf1 val hx1 hcf1 r2 h2 t ha cf2 resid hx2
    intro hb
    exfalso
    simp only [tryCF, reduceCtorEq] at hb
  · rename_i r0 hP cf0 p hx hcf r1 hvl cf1 val hx1 hcf1 r2 h2 e ha
    exfalso
    rw [h2] at ha
    cases ha
  · rename_i r0 hP cf0 p hx hcf r1 hvl cf1 resid hx1
    obtain ⟨v, l, hr, -⟩ := hvl
    intro hb
    exfalso
    rw [hr] at hb
    simp only [tryCF, reduceCtorEq] at hb
  · rename_i r0 hP cf0 resid hx
    intro hbr
    exfalso
    obtain ⟨e0, tl, he, -⟩ := varint.encList_dec n hn
    have hlen := congrArg List.length hb
    simp only [he, List.length_map, List.length_append, List.length_cons] at hlen
    obtain ⟨a, t, -, -, hr⟩ := hP.1 (by omega)
    rw [hr] at hbr
    simp only [tryCF, reduceCtorEq] at hbr

/-- `varint.TlsVarInt.deserialize_content` together with `deserialize_ok`: a round-trip proof needs
both the content of an `Ok` result and that the call is `Ok` on an encoding. -/
theorem varint.TlsVarInt.deserialize_content_ok (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ (∀ (v : varint.TlsVarInt) (t : Slice Std.U8), r = .Ok (v, t) →
        ∃ (b0 : Std.U8) (l : List Std.U8) (L : Nat), bytes.val = b0 :: l ∧
          (L = 1 ∨ L = 2 ∨ L = 4 ∨ L = 8) ∧ L = varint.lenOf v.val ∧ varint.pfx L = b0.val / 64 * 64 ∧
          L - 1 ≤ l.length ∧ t.val = l.drop (L - 1) ∧
          v.val = (l.take (L - 1)).foldl (fun a b => a * 256 + b.val) (b0.val % 64) ∧
          v.val ≤ 2 ^ 62 - 1) ∧
        ((∃ (n : Nat) (rest : List Nat), n ≤ 2 ^ 62 - 1 ∧
            bytes.val.map (·.val) = varint.encList n ++ rest) → ∃ p, r = .Ok p) ⌝ ⦄ := by
  refine triple_and (varint.TlsVarInt.deserialize_content bytes) ?_
  by_cases h : ∃ (n : Nat) (rest : List Nat), n ≤ 2 ^ 62 - 1 ∧
      bytes.val.map (·.val) = varint.encList n ++ rest
  · obtain ⟨n, rest, hn, hb⟩ := h
    exact triple_post_mono (varint.TlsVarInt.deserialize_ok bytes n rest hn hb) fun _ h _ => h
  · exact triple_post_mono (varint.TlsVarInt.deserialize_content bytes) fun _ _ h' => absurd h' h

/-- `ContentLength::tls_deserialize_bytes` on contents, in encoding form. -/
theorem quic_vec.ContentLength.deserialize_content (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.ContentLength.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ (v : quic_vec.ContentLength) (t : Slice Std.U8), r = .Ok (v, t) →
        v.val ≤ 2 ^ 30 - 1 ∧ bytes.val.map (·.val) = varint.encList v.val ++ t.val.map (·.val) ⌝ ⦄ := by
  mvcgen [quic_vec.ContentLength.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes,
    varint.TlsVarInt.deserialize_enc, quic_vec.ContentLength.new, varint.TlsVarInt.value,
    quic_vec.ContentLength.MAX, quic_vec.MAX_MLS_LEN_spec]
  try_vcs
  all_goals (try simp only [continue_eq_tryCF] at *)
  · intro _ v t h; cases h
  · rename_i r0 hP r1 p x1 r2 h2 h1 r3 val x2 hr0 hval
    have hv := core.result.Result.Ok.inj hval
    have hb : p.1.val ≤ 2 ^ 30 - 1 := by scalar_tac
    subst hv
    intro v t hvt
    obtain ⟨hv1, ht⟩ := Prod.mk.inj (core.result.Result.Ok.inj hvt)
    subst hv1; subst ht
    exact ⟨hb, (hP p.1 p.2 hr0).2⟩
  · intro _ v t h; cases h

/-- Proof of `VLBytes.deserialize_content` and `VLByteVec.deserialize_content` (the two
deserializers are the same code up to the wrapper `new`). -/
syntax "vl_deserialize_content " ident ident : tactic
macro_rules
  | `(tactic| vl_deserialize_content $fn $new) => `(tactic| (
    mvcgen [$fn:ident, quic_vec.ContentLength.deserialize_content, varint.TlsVarInt.value,
      $new:ident, core.option.Option.ok_or_spec, core.Slice.Insts.CoreOpsIndexIndex.index_spec,
      alloc.vec.Vec.new_spec, core.hint.must_use_spec]
    try_vcs
    all_goals (try simp only [continue_eq_tryCF] at *)
    · rename_i r0 hP r1 p x1 r2 htf r3 val x2 hv0 rv hrv h3 h5
      intro v t h
      obtain ⟨hv1, hv2⟩ := Prod.mk.inj (core.result.Result.Ok.inj h)
      subst hv1 hv2
      have hp := hP p.1 p.2 h3
      have hy := htf.1 val h5
      have hv : val.val = 0 := by rw [hv0]; rfl
      have hrl : rv.val = [] := by rw [hrv]; simp [Slice.new]
      refine ⟨by simp [hrl], ?_⟩
      rw [hp.2, hrl]
      simp [show p.1.val = 0 by omega]
    · rename_i r0 hP r1 p x1 r2 htf r3 val x2 hv0 o ho rr vec hrr hok rv hrv ro h3 h5
      intro hd hn
      have hb := hP p.1 p.2 h3
      have hy := htf.1 val h5
      have hvl : val.val ≤ p.2.val.length := by
        by_contra hc
        rw [ho.2 (by omega)] at hok
        cases hok
      obtain ⟨t, ht, ht'⟩ := ho.1 hvl
      rw [ht] at hok
      have hvec := core.result.Result.Ok.inj hok.symm
      obtain ⟨t2, h2, h2'⟩ := hd hvl
      refine ⟨t2, h2, ?_⟩
      simp only [PostCond.ok]
      mvcgen
      intro v t' h
      obtain ⟨hv1, hv2⟩ := Prod.mk.inj (core.result.Result.Ok.inj h)
      subst hv1 hv2
      have hrl : rv.val = p.2.val.take val.val := by rw [hrv, ← hvec, ht']
      have hlen : rv.val.length = p.1.val := by
        rw [hrl, List.length_take]; omega
      refine ⟨by simp only; omega, ?_⟩
      simp only
      rw [hb.2, hlen, hrl, h2', List.append_assoc, ← List.map_append, ← hy,
        List.take_append_drop]
    · intro v t h; cases h
    · exfalso
      rename_i r0 hP r1 p x1 r2 htf r3 residual x2 e hr2 h3
      have hb := hP p.1 p.2 h3
      obtain ⟨y, hy⟩ := htf.2 (by omega)
      rw [hy] at hr2
      cases hr2
    · intro _ v t h; cases h))

/-- `VLBytes::tls_deserialize_bytes` on contents: the input is the length prefix, the payload and
the remainder. -/
theorem quic_vec.VLBytes.deserialize_content (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLBytes.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ (v : quic_vec.VLBytes) (t : Slice Std.U8), r = .Ok (v, t) →
        v.vec.val.length ≤ 2 ^ 30 - 1 ∧ bytes.val.map (·.val) =
          varint.encList v.vec.val.length ++ v.vec.val.map (·.val) ++ t.val.map (·.val) ⌝ ⦄ := by
  vl_deserialize_content quic_vec.VLBytes.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
    quic_vec.VLBytes.new

/-- `VLByteVec::tls_deserialize_bytes` on contents. -/
theorem quic_vec.VLByteVec.deserialize_content (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLByteVec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ (v : quic_vec.VLByteVec) (t : Slice Std.U8), r = .Ok (v, t) →
        v.vec.val.length ≤ 2 ^ 30 - 1 ∧ bytes.val.map (·.val) =
          varint.encList v.vec.val.length ++ v.vec.val.map (·.val) ++ t.val.map (·.val) ⌝ ⦄ := by
  vl_deserialize_content quic_vec.VLByteVec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
    quic_vec.VLByteVec.new

/-- `Vec::<u8>::resize` of an empty vector: `n` copies of `x`. -/
theorem alloc.vec.Vec.resize_U8_content (v : alloc.vec.Vec Std.U8) (n : Std.Usize) (x : Std.U8)
    (hv : (v : Slice Std.U8).val = []) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.resize core.U8.Insts.CoreCloneClone v n x
    ⦃ ⇓ r => ⌜ (r : Slice Std.U8).val = List.replicate n.val x ⌝ ⦄ := by
  unfold alloc.vec.Vec.resize rust_primitives.sequence.seq_create
  simp only [mapM_clone_replicate_U8]
  mvcgen
  all_goals (simp_all +zetaDelta [Slice.new])
  all_goals (first | scalar_tac | (rw [← List.replicate_succ']; congr 1; omega))

/-- The prefix `write_bytes` writes into `lenOf n` zero bytes is the varint encoding of `n`. -/
theorem varint.write_prefix_content (n : Nat) (w : List Std.U8)
    (hk : ∀ k, (w[k]?).map (·.val) =
        ((List.replicate (varint.lenOf n) (0#u8))[k]?).map (fun x => if k < varint.lenOf n then
          (if k = 0 then varint.pfx (varint.lenOf n) else x.val) |||
            ((n >>> (8 * (varint.lenOf n - 1 - k))) % 256) else x.val)) :
    w.map (·.val) = varint.encList n := by
  apply List.ext_getElem?
  intro k
  rw [List.getElem?_map, hk, List.getElem?_replicate]
  unfold varint.encList
  rw [List.getElem?_map]
  by_cases hkL : k < varint.lenOf n
  · rw [List.getElem?_range hkL]
    simp [hkL, varint.encByte]
  · rw [List.getElem?_eq_none (by simp; omega)]
    simp [hkL]

/-- `VLBytes::tls_serialize_bytes` on contents: an `Ok` output is the length prefix and the
payload (and the payload is within the MLS bound). -/
theorem quic_vec.VLBytes.serialize_content (self : quic_vec.VLBytes) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLBytes.Insts.Tls_codecSerializeBytes.tls_serialize_bytes self
    ⦃ ⇓ r => ⌜ ∀ out, r = .Ok out → self.vec.val.length ≤ 2 ^ 30 - 1 ∧
        out.val.map (·.val) = varint.encList self.vec.val.length ++ self.vec.val.map (·.val) ⌝ ⦄ := by
  mvcgen [quic_vec.VLBytes.Insts.Tls_codecSerializeBytes.tls_serialize_bytes,
    quic_vec.VLBytes.as_slice, quic_vec.VLBytes.impl.vec, alloc.vec.Vec.with_capacity,
    alloc.vec.Vec.resize_U8_content, checked_alloc_len_small,
    alloc.vec.Vec.Insts.CoreOpsDerefDerefMutSlice.deref_mut, alloc.vec.Vec.as_mut_slice,
    rust_primitives.sequence.seq_to_slice_mut, varint.TlsVarInt.write_bytes_content,
    alloc.vec.Vec.Insts.CoreIterTraitsCollectExtendSharedAT.extend_slice_spec]
  all_goals (try simp only [continue_eq_tryCF] at *)
  all_goals subst_vars
  all_goals (try simp only [Slice.len_val] at *)
  case vc1.h => rename_i hr hv; have := hr.2.1; omega
  case vc2.hv => rfl
  case vc3.h =>
    have hc := varint.lenOf_char _ _ ‹1 ≤ _ ∧ _›
    simp_all <;> omega
  case vc4.h =>
    have hc := varint.lenOf_char _ _ ‹1 ≤ _ ∧ _›
    simp_all +zetaDelta
    scalar_tac
  case vc5.hQ => intro out h; cases h
  case vc6.hQ =>
    rename_i val2 ll hr cap v1 hrep back w hw u out2 out3 i hwr hout hne hv hcap hi1 hi2
    intro out h
    obtain rfl := core.result.Result.Ok.inj h
    have hc := varint.lenOf_char _ _ hr
    refine ⟨hv.2, ?_⟩
    have hpre := varint.write_prefix_content val2.val w.2.val (fun k => by
      have := hw.2.2 k
      rwa [hrep, hc.1] at this)
    have hlv : val2.val = self.vec.val.length := hv.1
    rw [hlv] at hpre
    rw [hout, List.map_append]
    exact congrArg (· ++ _) hpre
  case vc7.h_fail =>
    have hc := varint.lenOf_char _ _ ‹1 ≤ _ ∧ _›
    exfalso
    simp_all +zetaDelta [Slice.length]
  try_vcs
  all_goals (try (intros; simp [PostCond.ok]))

/-- `VLByteSlice::tls_serialize_bytes` on contents. -/
theorem quic_vec.VLByteSlice.serialize_content (self : quic_vec.VLByteSlice) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLByteSlice.Insts.Tls_codecSerializeBytes.tls_serialize_bytes self
    ⦃ ⇓ r => ⌜ ∀ out, r = .Ok out → self.val.length ≤ 2 ^ 30 - 1 ∧
        out.val.map (·.val) = varint.encList self.val.length ++ self.val.map (·.val) ⌝ ⦄ := by
  mvcgen [quic_vec.VLByteSlice.Insts.Tls_codecSerializeBytes.tls_serialize_bytes,
    quic_vec.ContentLength.Insts.Tls_codecSize.tls_serialized_len,
    varint.TlsVarInt.Insts.Tls_codecSize.tls_serialized_len,
    quic_vec.ContentLength.Insts.Tls_codecSerializeBytes.tls_serialize_bytes,
    varint.TlsVarInt.serialize_content, varint.TlsVarInt.serialize_len_char,
    alloc.vec.Vec.with_capacity, checked_alloc_len_small,
    alloc.vec.Vec.append, rust_primitives.sequence.seq_concat,
    alloc.vec.Vec.Insts.CoreIterTraitsCollectExtendSharedAT.extend_slice_spec]
  all_goals (try simp only [continue_eq_tryCF] at *)
  all_goals subst_vars
  all_goals (try simp only [Slice.len_val] at *)
  case vc1.h => rename_i hr hv; have := hr.2.1; omega
  case vc2.hv => omega -- `value <= MAX`
  case vc3.h =>
    rename_i val r hr _ v1 comb hcomb hv1 hv _
    obtain ⟨v, hv', hl⟩ := hv1
    cases hv'
    have hv2 : self.val.length ≤ 2 ^ 30 - 1 := hv.2
    have hlo : varint.lenOf val.val ≤ 8 := by unfold varint.lenOf; split_ifs <;> omega
    have := congrArg List.length hl
    simp only [comb, List.length_append, List.length_map, List.length_range, Slice.new,
      List.length_nil] at this ⊢
    scalar_tac
  case vc4 =>
    rename_i val r hr _ v1 out comb hcomb hout hv1 hv _
    obtain ⟨v, hv', hl⟩ := hv1
    cases hv'
    intro o h
    obtain rfl := core.result.Result.Ok.inj h
    refine ⟨hv.2, ?_⟩
    have hlv : val.val = self.val.length := hv.1
    rw [hout, List.map_append]
    simp only [comb, hl, varint.encList, hlv, Slice.new, List.nil_append]
  case vc5.hQ =>
    exfalso
    rename_i val r hr _ v1 comb hcomb hv1 hv _
    obtain ⟨v, hv', hl⟩ := hv1
    cases hv'
    have hv2 : self.val.length ≤ 2 ^ 30 - 1 := hv.2
    have hlo : varint.lenOf val.val ≤ 8 := by unfold varint.lenOf; split_ifs <;> omega
    have := congrArg List.length hl
    apply hcomb
    simp only [comb, List.length_append, List.length_map, List.length_range, Slice.new,
      List.length_nil] at this ⊢
    scalar_tac
  try_vcs
  all_goals (try (intros; simp [PostCond.ok]))

end tls_codec
