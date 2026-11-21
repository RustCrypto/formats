/- `VLBytes`: the deserializer (`VLGen.de`, shared with `VLByteVec`), its spec lemmas, and the
lemma traits (`RoundTripStd`, `NonEmptyStd`, `SameBytes`), including the cases where `encode`
fails.

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
import TlsCodec.Verification.Std.Bridge
import TlsCodec.Verification.Std.VarInt
import TlsCodec.Verification.Std.VarIntDe
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! ### `VLBytes`: deserializer -/

/-- What a successful `VLBytes` decode read: the canonical length prefix followed by the payload. -/
def VLDe (l : List Std.U8) (x : quic_vec.VLBytes) (n : Nat) : Prop :=
  n ≤ l.length ∧ x.vec.val.length ≤ 2 ^ 30 - 1 ∧
    l.take n = varint.enc x.vec.val.length ++ x.vec.val ∧
    n = varint.lenOf x.vec.val.length + x.vec.val.length

/-- What a successful decode of the varint-prefixed payload `b` read from `l`: the canonical
length prefix followed by `b`, `n` bytes in all (`VLDe` and `VLDeV` are this, for `x.vec`). -/
def VLPayloadDe (l b : List Std.U8) (n : Nat) : Prop :=
  n ≤ l.length ∧ b.length ≤ 2 ^ 30 - 1 ∧ l.take n = varint.enc b.length ++ b ∧
    n = varint.lenOf b.length + b.length

namespace VLGen

/-- The `std` deserializer of `VLBytes` and `VLByteVec`, up to the wrapper type `W` (`newW`: its
`new`, `mk`: its constructor). Each is an instance by `rfl` (`VLBytes.de_eq`, `VLByteVec.de_eq`). -/
noncomputable def de {W : Type} (newW : alloc.vec.Vec Std.U8 → RustM W) (mk : alloc.vec.Vec Std.U8 → W)
    {R : Type} (RI : alloc.io.read.Read R) (bytes : R) :
    RustM ((core.result.Result W Error) × R) := do
  let (r, bytes1) ← quic_vec.ContentLength.Insts.Tls_codecDeserialize.tls_deserialize RI bytes
  let cf ← core.result.Result.Insts.CoreOpsTry_traitTry.branch r
  match cf with
  | core.ops.control_flow.ControlFlow.Continue val =>
    let i ← varint.TlsVarInt.value val
    if i = 0#u64
    then
      let v ← alloc.vec.Vec.new Std.U8
      let v1 ← newW v
      ok (core.result.Result.Ok v1, bytes1)
    else
      let r1 ← core.Usize.Insts.CoreConvertTryFromU64TryFromIntError.try_from i
      let cf1 ← core.result.Result.Insts.CoreOpsTry_traitTry.branch r1
      match cf1 with
      | core.ops.control_flow.ControlFlow.Continue val1 =>
        let (r2, bytes2) ← read_bytes_bounded RI bytes1 val1
        let cf2 ← core.result.Result.Insts.CoreOpsTry_traitTry.branch r2
        match cf2 with
        | core.ops.control_flow.ControlFlow.Continue val2 =>
          ok (core.result.Result.Ok (mk val2), bytes2)
        | core.ops.control_flow.ControlFlow.Break residual =>
          let r3 ← core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
            W (core.convert.From.Blanket Error) residual
          ok (r3, bytes2)
      | core.ops.control_flow.ControlFlow.Break residual =>
        let r2 ← core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
          W Error.Insts.CoreConvertFromTryFromIntError residual
        ok (r2, bytes1)
  | core.ops.control_flow.ControlFlow.Break residual =>
    let r1 ← core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
      W (core.convert.From.Blanket Error) residual
    ok (r1, bytes1)

/-- On success, `VLGen.de` read a canonical length prefix and the payload `b` of the result
`mk b`. -/
theorem de_content {W : Type} (newW : alloc.vec.Vec Std.U8 → RustM W)
    (mk : alloc.vec.Vec Std.U8 → W) (hnew : ∀ b, newW b = ok (mk b))
    {R : Type} {RI : alloc.io.read.Read R} {v : R → List Std.U8}
    {a : R → Nat → R} (law : StdIo.RLaw RI v a) (r : R) :
    ⦃ ⌜ True ⌝ ⦄ de newW mk RI r
    ⦃ ⇓ p => ⌜ ∀ x, p.1 = .Ok x → ∃ b n, x = mk b ∧ n ≤ (v r).length ∧ p.2 = a r n ∧
      VLPayloadDe (v r) b.val n ⌝ ⦄ := by
  have hde := ContentLength.std_de_content law r
  have hrbb := fun (r' : R) (len : Std.Usize) => read_bytes_bounded_law law r' len
  mvcgen [de, hde, hrbb, varint.TlsVarInt.value, hnew, alloc.vec.Vec.new_spec]
  all_goals (try simp only [continue_eq_tryCF] at *)
  · rename_i r1 hde' _ val _ hz vec hvec hk
    intro x hx
    rw [core.result.Result.Ok.injEq] at hx
    subst hx
    obtain ⟨n, hn, hadv, hd, hle⟩ := hde' val hk
    have hv0 : val.val = 0 := by rw [hz]; rfl
    have hvv : vec.val = [] := by rw [hvec]; simp [Slice.new]
    obtain ⟨htk, -⟩ := VarintDe.take_enc hd
    have hLv : n = varint.lenOf val.val := by obtain ⟨_, _, _, _, h, -⟩ := hd; exact h
    refine ⟨vec, n, rfl, hn, hadv, hn, by simp [hvv], ?_, ?_⟩
    · simp only [hvv, List.length_nil, List.append_nil]; rw [htk, hv0]
    · simp only [hvv, List.length_nil]; rw [hv0] at hLv; omega
  · rename_i r1 hde' _ val1 _ hnz rtry htry _ u _ rbb hrbb' _ w _ hk hrc hrbk
    intro x hx
    rw [core.result.Result.Ok.injEq] at hx
    subst hx
    obtain ⟨n, hn, hadv, hd, hle⟩ := hde' val1 hk
    have hu := htry.1 u hrc
    have hview : v r1.2 = (v r).drop n := by rw [hadv]; exact law.adv_view r n hn
    have hlenv : (v r1.2).length = (v r).length - n := by rw [hview, List.length_drop]
    have hule : u.val ≤ (v r1.2).length := by
      by_contra hlt
      rcases hrbb'.2 (by omega) with h | h <;> rw [hrbk] at h <;> cases h
    have hmax : 2 * u.val < UScalar.max UScalarTy.Usize := by
      have := Usize.hcast_Isize_MAX_val
      have h32 : 2 ^ 31 ≤ UScalar.max UScalarTy.Usize := by
        rcases System.Platform.numBits_eq with h' | h' <;> simp [UScalar.max, UScalarTy.numBits, h']
      omega
    obtain ⟨w', hw', hw'v, hrb2⟩ := hrbb'.1 hule hmax
    rw [hrbk, core.result.Result.Ok.injEq] at hw'
    subst hw'
    have hlw : w.val.length = u.val := by
      rw [hw'v, List.length_take, hview, List.length_drop]; omega
    have hLv : n = varint.lenOf val1.val := by obtain ⟨_, _, _, _, h, -⟩ := hd; exact h
    obtain ⟨htk, -⟩ := VarintDe.take_enc hd
    refine ⟨w, n + u.val, rfl, by omega, ?_, ?_⟩
    · rw [hrb2, hadv, law.adv_adv r n u.val (by omega)]
    · have e : varint.enc w.val.length = varint.enc val1.val := by rw [hlw, hu]
      refine ⟨by omega, by omega, ?_, ?_⟩
      · rw [e, List.take_add, htk, hw'v, hview]
      · rw [hlw, hu, ← hLv]
  · rename_i r1 hde' _ val1 _ hnz rtry htry _ u _ rbb hrbb' _ res _ hcf hk hrc
    cases h1 : rbb.1 with
    | Ok y => rw [h1] at hcf; simp [tryCF] at hcf
    | Err e =>
      rw [h1] at hcf
      simp [tryCF] at hcf
      subst hcf
      refine ⟨_, rfl, ?_⟩
      refine triple_post_mono (core.convert.From.Blanket.from_spec _) ?_
      intro f hf
      subst hf
      simp only [PostCond.ok]
      mvcgen
      intro x h; cases h
  · rename_i r1 hde' _ val1 _ hnz rtry htry _ res _ hcf hk
    obtain ⟨n, hn, hadv, hd, hle⟩ := hde' val1 hk
    obtain ⟨y, hy⟩ := htry.2 (by omega)
    rw [hy] at hcf
    simp [tryCF] at hcf
  · rename_i r1 _ _ res _ hcf
    cases h1 : r1.1 with
    | Ok u => rw [h1] at hcf; simp [tryCF] at hcf
    | Err e =>
      rw [h1] at hcf
      simp [tryCF] at hcf
      subst hcf
      refine ⟨_, rfl, ?_⟩
      refine triple_post_mono (core.convert.From.Blanket.from_spec _) ?_
      intro f hf
      subst hf
      simp only [PostCond.ok]
      mvcgen
      intro x h; cases h

end VLGen

theorem VLBytes.de_eq {R : Type} (RI : alloc.io.read.Read R) (r : R) :
    quic_vec.VLBytes.Insts.Tls_codecDeserialize.tls_deserialize RI r =
      VLGen.de quic_vec.VLBytes.new (fun b => { vec := b }) RI r := rfl

theorem VLBytes.std_de_content {R : Type} {RI : alloc.io.read.Read R} {v : R → List Std.U8}
    {a : R → Nat → R} (law : StdIo.RLaw RI v a) (r : R) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLBytes.Insts.Tls_codecDeserialize.tls_deserialize RI r
    ⦃ ⇓ p => ⌜ ∀ x, p.1 = .Ok x → ∃ n, n ≤ (v r).length ∧ p.2 = a r n ∧ VLDe (v r) x n ⌝ ⦄ := by
  rw [VLBytes.de_eq]
  refine triple_post_mono (VLGen.de_content _ _ (fun _ => rfl) law r) fun p hp x hx => ?_
  obtain ⟨b, n, rfl, hn, hadv, hde⟩ := hp x hx
  exact ⟨n, hn, hadv, hde⟩

/-- After the length prefix, the reader holds the payload and the rest. -/
theorem VLBytes.ok_prefix {R : Type} {RI : alloc.io.read.Read R} {v : R → List Std.U8}
    {a : R → Nat → R} (law : StdIo.RLaw RI v a) (r : R) (x : quic_vec.VLBytes)
    (rest : List Std.U8) (hv : v r = varint.enc x.vec.val.length ++ x.vec.val ++ rest)
    (r1 : core.result.Result quic_vec.ContentLength Error × R) (val1 : quic_vec.ContentLength)
    (hc : ∀ val, r1.1 = core.result.Result.Ok val → ∃ n, n ≤ (v r).length ∧ r1.2 = a r n ∧
        VarintDe (v r) val n ∧ val.val ≤ 2 ^ 30 - 1)
    (hk : r1.1 = core.result.Result.Ok val1) (hvN : val1.val = x.vec.val.length) :
    v r1.2 = x.vec.val ++ rest ∧ ∃ n, r1.2 = a r n ∧ n = varint.lenOf x.vec.val.length := by
  obtain ⟨n, hn, hadv, hd, -⟩ := hc val1 hk
  have hLv : n = varint.lenOf val1.val := by obtain ⟨_, _, _, _, h, -⟩ := hd; exact h
  refine ⟨?_, n, hadv, by rw [hLv, hvN]⟩
  rw [hadv, law.adv_view r n hn, hv, hLv, hvN, List.append_assoc, ← varint.enc_length,
    List.drop_left]

theorem VLBytes.std_de_ok {R : Type} {RI : alloc.io.read.Read R} {v : R → List Std.U8}
    {a : R → Nat → R} (law : StdIo.RLaw RI v a) (r : R) (x : quic_vec.VLBytes)
    (hx : x.vec.val.length ≤ 2 ^ 30 - 1) (rest : List Std.U8)
    (hv : v r = varint.enc x.vec.val.length ++ x.vec.val ++ rest) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLBytes.Insts.Tls_codecDeserialize.tls_deserialize RI r
    ⦃ ⇓ p => ⌜ ∃ y : quic_vec.VLBytes, p.1 = .Ok y ∧ y.vec.val = x.vec.val ⌝ ⦄ := by
  have hde := triple_and (ContentLength.std_de_content law r)
    (ContentLength.std_de_ok law r x.vec.val.length hx (varint.enc x.vec.val.length)
      (x.vec.val ++ rest) (varint.enc_map _ (by omega)) (by rw [hv, List.append_assoc]))
  have hrbb := fun (r' : R) (len : Std.Usize) => read_bytes_bounded_law law r' len
  mvcgen [quic_vec.VLBytes.Insts.Tls_codecDeserialize.tls_deserialize, hde, hrbb,
    varint.TlsVarInt.value, quic_vec.VLBytes.new, alloc.vec.Vec.new_spec]
  all_goals (try simp only [continue_eq_tryCF] at *)
  · rename_i r1 hde' _ val _ hz vec hvec hk
    obtain ⟨-, val', hval', hvN⟩ := hde'
    rw [hk, core.result.Result.Ok.injEq] at hval'
    subst hval'
    have hv0 : val.val = 0 := by rw [hz]; rfl
    have hvv : vec.val = [] := by rw [hvec]; simp [Slice.new]
    have hxl : x.vec.val = [] := List.eq_nil_of_length_eq_zero (by omega)
    exact ⟨_, rfl, by rw [hvv, hxl]⟩
  · rename_i r1 hde' _ val1 _ hnz rtry htry _ u _ rbb hrbb' _ w _ hk hrc hrbk
    obtain ⟨hc, val', hval', hvN⟩ := hde'
    rw [hk, core.result.Result.Ok.injEq] at hval'
    subst hval'
    obtain ⟨hview, n, hadv, hLv⟩ := VLBytes.ok_prefix law r x rest hv r1 val1 hc hk hvN
    have hu := htry.1 u hrc
    have hule : u.val ≤ (v r1.2).length := by rw [hview, List.length_append]; omega
    have hmax : 2 * u.val < UScalar.max UScalarTy.Usize := by
      have h32 : 2 ^ 31 ≤ UScalar.max UScalarTy.Usize := by
        rcases System.Platform.numBits_eq with h' | h' <;> simp [UScalar.max, UScalarTy.numBits, h']
      omega
    obtain ⟨w', hw', hw'v, -⟩ := hrbb'.1 hule hmax
    rw [hrbk, core.result.Result.Ok.injEq] at hw'
    subst hw'
    refine ⟨_, rfl, ?_⟩
    rw [hw'v, hview, hu, hvN, List.take_left' rfl]
  · rename_i r1 hde' _ val1 _ hnz rtry htry _ u _ rbb hrbb' _ res _ hcf hk hrc
    obtain ⟨hc, val', hval', hvN⟩ := hde'
    rw [hk, core.result.Result.Ok.injEq] at hval'
    subst hval'
    obtain ⟨hview, n, hadv, hLv⟩ := VLBytes.ok_prefix law r x rest hv r1 val1 hc hk hvN
    have hu := htry.1 u hrc
    have hule : u.val ≤ (v r1.2).length := by rw [hview, List.length_append]; omega
    have hmax : 2 * u.val < UScalar.max UScalarTy.Usize := by
      have h32 : 2 ^ 31 ≤ UScalar.max UScalarTy.Usize := by
        rcases System.Platform.numBits_eq with h' | h' <;> simp [UScalar.max, UScalarTy.numBits, h']
      omega
    obtain ⟨w', hw', -, -⟩ := hrbb'.1 hule hmax
    rw [hw'] at hcf
    simp [tryCF] at hcf
  · rename_i r1 hde' _ val1 _ hnz rtry htry _ res _ hcf hk
    obtain ⟨hc, val', hval', hvN⟩ := hde'
    rw [hk, core.result.Result.Ok.injEq] at hval'
    subst hval'
    obtain ⟨y, hy⟩ := htry.2 (by omega)
    rw [hy] at hcf
    simp [tryCF] at hcf
  · rename_i r1 hde' _ res _ hcf
    obtain ⟨-, val', hval', -⟩ := hde'
    rw [hval'] at hcf
    simp [tryCF] at hcf

theorem VLBytes.de_runs : DeRuns quic_vec.VLBytes.Insts.Tls_codecDeserialize VLDe := by
  intro R RI v a law r
  refine triple_post_mono (VLBytes.std_de_content law r) fun p hp x hx => ?_
  obtain ⟨n, hn, hadv, hde⟩ := hp x hx
  obtain ⟨sz, hsz, hszv⟩ : ∃ sz : Std.Usize,
      quic_vec.VLBytes.Insts.Tls_codecSize.tls_serialized_len x = ok sz ∧
        sz.val = x.vec.val.length + varint.lenOf x.vec.val.length := by
    obtain ⟨sz, hsz, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (quic_vec.VLBytes.serialized_len_char x hde.2.1)
    exact ⟨sz, hsz, hP⟩
  exact ⟨n, sz, hn, hadv, hsz, by rw [hszv, hde.2.2.2]; omega, hde⟩

theorem VLBytes.decodes (x : quic_vec.VLBytes) (hx : x.vec.val.length ≤ 2 ^ 30 - 1) :
    DecodesTo quic_vec.VLBytes.Insts.Tls_codecDeserialize
      (varint.enc x.vec.val.length ++ x.vec.val) x := by
  intro R RI v a law r rest hv
  refine triple_post_mono (triple_and (VLBytes.std_de_content law r)
    (VLBytes.std_de_ok law r x hx rest hv)) ?_
  rintro p ⟨hc, y, hp1, hy⟩
  obtain ⟨n, hn, hadv, hl, -, -, hnv⟩ := hc y hp1
  have hyx : y = x := by
    obtain ⟨⟨yv, yp⟩⟩ := y
    obtain ⟨⟨xv, xp⟩⟩ := x
    simp only at hy
    subst hy
    rfl
  subst hyx
  refine ⟨hp1, ?_⟩
  rw [hadv, law.adv_view r n hn, hv, hnv, ← varint.enc_length, ← List.length_append, List.drop_left]

/-! ### Spec lemmas -/

theorem VLBytes.partialEq_lawful : core.cmp.PartialEq.Lawful quic_vec.VLBytes quic_vec.VLBytes
    quic_vec.VLBytes.Insts.CoreCmpPartialEqVLBytes where
  eq_spec x y := by
    refine triple_post_mono (quic_vec.VLBytes.Insts.CoreCmpPartialEqVLBytes.eq_decide_spec x y) ?_
    intro r hr
    rw [hr]
    simp only [decide_eq_true_eq]
    constructor
    · intro h
      obtain ⟨⟨a, ha⟩⟩ := x
      obtain ⟨⟨b, hb⟩⟩ := y
      simp only at h
      subst h
      rfl
    · intro h
      rw [eq_of_heq h]
  ne_spec x y := by
    mvcgen [quic_vec.VLBytes.Insts.CoreCmpPartialEqVLBytes, core.cmp.PartialEq.ne.default,
      quic_vec.VLBytes.Insts.CoreCmpPartialEqVLBytes.eq]

theorem VLBytes.ser_spec {W : Type} (WI : core.io.write.Write W)
    (hWI : core.io.write.Write.Lawful W WI) (x : quic_vec.VLBytes) (w : W)
    (hpre : (Serialize.tls_serialize.pre WI quic_vec.VLBytes.Insts.Tls_codecSerialize.SizeInst
      quic_vec.VLBytes.Insts.Tls_codecSerialize x w).holds) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLBytes.Insts.Tls_codecSerialize.tls_serialize WI x w
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize.post WI quic_vec.VLBytes.Insts.Tls_codecSerialize.SizeInst
      quic_vec.VLBytes.Insts.Tls_codecSerialize x w r).holds ⌝ ⦄ := by
  obtain ⟨sz, hsz, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (quic_vec.VLBytes.size_pos x)
  refine Serialize.tls_serialize_spec_of_runs' quic_vec.VLBytes.Insts.Tls_codecSerialize x sz hsz
    (VLBytes.out x) (fun _ b hb => ?_) (VLBytes.ser_runs x sz hsz) WI hWI w hpre
  unfold VLBytes.out at hb
  split at hb
  · rename_i hn
    cases hb
    obtain ⟨r, hr, hrv⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (quic_vec.VLBytes.serialized_len_char x hn)
    rw [hsz] at hr
    cases hr
    simp [varint.enc_length]
    omega
  · cases hb

theorem VLBytes.de_spec {R : Type} (RI : alloc.io.read.Read R)
    (hRI : alloc.io.read.Read.Lawful R RI) (r : R) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLBytes.Insts.Tls_codecDeserialize.tls_deserialize RI r
    ⦃ ⇓ p => ⌜ (Deserialize.tls_deserialize.post RI quic_vec.VLBytes.Insts.Tls_codecDeserialize.SizeInst
      quic_vec.VLBytes.Insts.Tls_codecDeserialize r p).holds ⌝ ⦄ :=
  Deserialize.tls_deserialize_spec_of_runs quic_vec.VLBytes.Insts.Tls_codecDeserialize
    VLBytes.de_runs RI hRI r

/-- `tls_serialize_detached` (the default body) of a `VLBytes`. -/
theorem VLBytes.detached_spec (x : quic_vec.VLBytes) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default quic_vec.VLBytes.Insts.Tls_codecSerialize x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post
      quic_vec.VLBytes.Insts.Tls_codecSerialize.SizeInst quic_vec.VLBytes.Insts.Tls_codecSerialize
      x r).holds ⌝ ⦄ := by
  obtain ⟨sz, hsz, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (quic_vec.VLBytes.size_pos x)
  exact Serialize.tls_serialize_detached.default_spec quic_vec.VLBytes.Insts.Tls_codecSerialize x sz
    hsz (fun w hpre => VLBytes.ser_spec _ StdIo.vec_lawful x w hpre)

theorem VLBytes.exact_spec {T1 : Type} (AI : core.convert.AsRef T1 (Slice Std.U8))
    (hAI : core.convert.AsRef.Lawful T1 (Slice Std.U8) AI) (bytes : T1) :
    ⦃ ⌜ True ⌝ ⦄ Deserialize.tls_deserialize_exact.default quic_vec.VLBytes.Insts.Tls_codecDeserialize AI bytes
    ⦃ ⇓ r => ⌜ (Deserialize.tls_deserialize_exact.post quic_vec.VLBytes.Insts.Tls_codecSize
      quic_vec.VLBytes.Insts.Tls_codecDeserialize AI bytes r).holds ⌝ ⦄ :=
  Deserialize.tls_deserialize_exact.default_spec quic_vec.VLBytes.Insts.Tls_codecDeserialize AI hAI
    bytes (fun s => VLBytes.de_spec _ StdIo.slice_lawful s)

/-! ### Lemma traits -/

theorem VLBytes.encode_ok (x : quic_vec.VLBytes) (hx : x.vec.val.length ≤ 2 ^ 30 - 1) :
    ∃ bv : alloc.vec.Vec Std.U8, spec.io.encode quic_vec.VLBytes.Insts.Tls_codecSerialize x =
      ok (.Ok bv) ∧ (bv : Slice Std.U8).val = varint.enc x.vec.val.length ++ x.vec.val := by
  obtain ⟨sz, hsz, hszv⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (quic_vec.VLBytes.serialized_len_char x hx)
  have := imax_ge
  have := varint.lenOf_le x.vec.val.length
  obtain ⟨e, he, hs, -⟩ := encode_of_runs _ x sz (VLBytes.out x) (VLBytes.ser_runs x sz hsz)
    (by omega)
  obtain ⟨bv, rfl, hbv⟩ := hs (varint.enc x.vec.val.length ++ x.vec.val)
    (by unfold VLBytes.out; rw [if_pos hx])
  exact ⟨bv, he, hbv⟩

theorem VLBytes.encode_big (x : quic_vec.VLBytes) (hx : 2 ^ 30 - 1 < x.vec.val.length) :
    ∃ err, spec.io.encode quic_vec.VLBytes.Insts.Tls_codecSerialize x = ok (.Err err) := by
  obtain ⟨⟨r, w'⟩, hr, hpost⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (VLBytes.ser_triple StdIo.vec_law (⟨[], by simp⟩ : alloc.vec.Vec Std.U8) x (fun h => by omega))
  obtain ⟨e, hre⟩ := (hpost.2 hx).1
  have hnew : CoreModels.alloc.vec.Vec.new Std.U8 = ok ⟨[], by simp⟩ := rfl
  unfold spec.io.encode
  rw [hnew]
  simp only [bind_tc_ok]
  rw [hr]
  simp only [bind_tc_ok]
  simp only at hre
  subst hre
  exact ⟨_, rfl⟩

/-! #### Lemma traits when `encode` fails -/

theorem spec.io.RoundTripStd.round_trip_std.pre_err {T R : Type} (RT : spec.io.RoundTripStd T)
    (RI : alloc.io.read.Read R) (x : T) (reader : R) (rest : Slice Std.U8) (e : Error)
    (henc : spec.io.encode RT.SerializeInst x = ok (.Err e))
    (h : (spec.io.RoundTripStd.round_trip_std.pre RI RT.SerializeInst RT.DeserializeInst
      RT.corecmpPartialEqInst RT x reader rest).holds) : False := by
  apply holds_imp' h
  have he' : ⦃ ⌜ True ⌝ ⦄ spec.io.encode RT.SerializeInst x ⦃ ⇓? r => ⌜ r = .Err e ⌝ ⦄ :=
    partial_triple_of_ok fun r hr => by rw [henc] at hr; cases hr; rfl
  unfold spec.io.RoundTripStd.round_trip_std.pre
  mvcgen [he', core.result.Result.is_ok_and]
  intro hh; cases hh

theorem spec.io.RoundTripStd.round_trip_exact_err {T : Type} (RT : spec.io.RoundTripStd T) (x : T)
    (e : Error) (henc : spec.io.encode RT.SerializeInst x = ok (.Err e)) :
    ⦃ ⌜ True ⌝ ⦄ spec.io.RoundTripStd.round_trip_exact.default x
    ⦃ ⇓ r => ⌜ (spec.io.RoundTripStd.round_trip_exact.post RT.SerializeInst RT.DeserializeInst
      RT.corecmpPartialEqInst RT x r).holds ⌝ ⦄ := by
  unfold spec.io.RoundTripStd.round_trip_exact.default
  refine ok_triple_of ?_
  simp only [spec.io.RoundTripStd.round_trip_exact.post, henc, core.result.Result.is_err,
    RustM.holds]
  mvcgen

theorem spec.io.NonEmptyStd.nonempty_std_err {T : Type} (NE : spec.io.NonEmptyStd T) (x : T)
    (e : Error) (henc : spec.io.encode NE.RoundTripStdInst.SerializeInst x = ok (.Err e)) :
    ⦃ ⌜ True ⌝ ⦄ spec.io.NonEmptyStd.nonempty_std.default x
    ⦃ ⇓ r => ⌜ (spec.io.NonEmptyStd.nonempty_std.post NE.RoundTripStdInst NE x r).holds ⌝ ⦄ := by
  unfold spec.io.NonEmptyStd.nonempty_std.default
  refine ok_triple_of ?_
  simp only [spec.io.NonEmptyStd.nonempty_std.post, henc, core.result.Result.is_err, RustM.holds]
  mvcgen

theorem spec.io.SameBytes.same_bytes_err {T : Type} (SB : spec.io.SameBytes T) (x : T)
    (e e' : Error) (henc : spec.io.encode SB.SerializeInst x = ok (.Err e))
    (hbytes : SB.SerializeBytesInst.tls_serialize_bytes x = ok (.Err e')) :
    ⦃ ⌜ True ⌝ ⦄ spec.io.SameBytes.same_bytes.default x
    ⦃ ⇓ r => ⌜ (spec.io.SameBytes.same_bytes.post SB.SerializeInst SB.SerializeBytesInst SB x
      r).holds ⌝ ⦄ := by
  unfold spec.io.SameBytes.same_bytes.default
  refine ok_triple_of ?_
  simp only [spec.io.SameBytes.same_bytes.post, henc, hbytes, core.result.Result.is_err,
    RustM.holds]
  mvcgen

theorem VLBytes.round_trip_std {R : Type} (RI : alloc.io.read.Read R)
    (hRI : alloc.io.read.Read.Lawful R RI) (x : quic_vec.VLBytes) (reader : R) (rest : Slice Std.U8)
    (hpre : (spec.io.RoundTripStd.round_trip_std.pre RI
      quic_vec.VLBytes.Insts.Tls_codecSpecIoRoundTripStd.SerializeInst
      quic_vec.VLBytes.Insts.Tls_codecSpecIoRoundTripStd.DeserializeInst
      quic_vec.VLBytes.Insts.Tls_codecSpecIoRoundTripStd.corecmpPartialEqInst
      quic_vec.VLBytes.Insts.Tls_codecSpecIoRoundTripStd x reader rest).holds) :
    ⦃ ⌜ True ⌝ ⦄ spec.io.RoundTripStd.round_trip_std.default RI x reader rest
    ⦃ ⇓ r => ⌜ (spec.io.RoundTripStd.round_trip_std.post RI
      quic_vec.VLBytes.Insts.Tls_codecSpecIoRoundTripStd.SerializeInst
      quic_vec.VLBytes.Insts.Tls_codecSpecIoRoundTripStd.DeserializeInst
      quic_vec.VLBytes.Insts.Tls_codecSpecIoRoundTripStd.corecmpPartialEqInst
      quic_vec.VLBytes.Insts.Tls_codecSpecIoRoundTripStd x reader rest r).holds ⌝ ⦄ := by
  by_cases hx : x.vec.val.length ≤ 2 ^ 30 - 1
  · obtain ⟨bv, he, hbv⟩ := VLBytes.encode_ok x hx
    exact spec.io.RoundTripStd.round_trip_std_of _ VLBytes.partialEq_lawful x bv he
      (hbv ▸ VLBytes.decodes x hx) RI hRI reader rest hpre
  · obtain ⟨e, he⟩ := VLBytes.encode_big x (by omega)
    exact (spec.io.RoundTripStd.round_trip_std.pre_err _ RI x reader rest e he hpre).elim

theorem VLBytes.round_trip_exact (x : quic_vec.VLBytes) :
    ⦃ ⌜ True ⌝ ⦄ spec.io.RoundTripStd.round_trip_exact.default x
    ⦃ ⇓ r => ⌜ (spec.io.RoundTripStd.round_trip_exact.post
      quic_vec.VLBytes.Insts.Tls_codecSpecIoRoundTripStd.SerializeInst
      quic_vec.VLBytes.Insts.Tls_codecSpecIoRoundTripStd.DeserializeInst
      quic_vec.VLBytes.Insts.Tls_codecSpecIoRoundTripStd.corecmpPartialEqInst
      quic_vec.VLBytes.Insts.Tls_codecSpecIoRoundTripStd x r).holds ⌝ ⦄ := by
  by_cases hx : x.vec.val.length ≤ 2 ^ 30 - 1
  · obtain ⟨bv, he, hbv⟩ := VLBytes.encode_ok x hx
    exact spec.io.RoundTripStd.round_trip_exact_of _ VLBytes.partialEq_lawful x bv he
      fun s hs => Deserialize.tls_deserialize_exact.default_decodes
        quic_vec.VLBytes.Insts.Tls_codecDeserialize _ x (VLBytes.decodes x hx) s (hs.trans hbv)
  · obtain ⟨e, he⟩ := VLBytes.encode_big x (by omega)
    exact spec.io.RoundTripStd.round_trip_exact_err _ x e he

theorem VLBytes.nonempty_std (x : quic_vec.VLBytes) :
    ⦃ ⌜ True ⌝ ⦄ spec.io.NonEmptyStd.nonempty_std.default x
    ⦃ ⇓ r => ⌜ (spec.io.NonEmptyStd.nonempty_std.post
      quic_vec.VLBytes.Insts.Tls_codecSpecIoNonEmptyStd.RoundTripStdInst
      quic_vec.VLBytes.Insts.Tls_codecSpecIoNonEmptyStd x r).holds ⌝ ⦄ := by
  by_cases hx : x.vec.val.length ≤ 2 ^ 30 - 1
  · obtain ⟨bv, he, hbv⟩ := VLBytes.encode_ok x hx
    refine spec.io.NonEmptyStd.nonempty_std_of _ x bv he ?_
    rw [hbv]
    intro h
    have h1 := congrArg List.length h
    have h2 := varint.lenOf_pos x.vec.val.length
    simp only [List.length_append, varint.enc_length, List.length_nil] at h1
    omega
  · obtain ⟨e, he⟩ := VLBytes.encode_big x (by omega)
    exact spec.io.NonEmptyStd.nonempty_std_err _ x e he

theorem VLBytes.same_bytes (x : quic_vec.VLBytes) :
    ⦃ ⌜ True ⌝ ⦄ spec.io.SameBytes.same_bytes.default x
    ⦃ ⇓ r => ⌜ (spec.io.SameBytes.same_bytes.post
      quic_vec.VLBytes.Insts.Tls_codecSpecIoSameBytes.SerializeInst
      quic_vec.VLBytes.Insts.Tls_codecSpecIoSameBytes.SerializeBytesInst
      quic_vec.VLBytes.Insts.Tls_codecSpecIoSameBytes x r).holds ⌝ ⦄ := by
  obtain ⟨_, hb, hch⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (quic_vec.VLBytes.serialize_char x)
  by_cases hx : x.vec.val.length ≤ 2 ^ 30 - 1
  · obtain ⟨bv, he, hbv⟩ := VLBytes.encode_ok x hx
    obtain ⟨bv', rfl, -⟩ := hch.1 hx
    obtain ⟨_, hb2, hcont⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (quic_vec.VLBytes.serialize_content x)
    rw [hb] at hb2
    cases hb2
    obtain ⟨-, hm⟩ := hcont bv' rfl
    refine spec.io.SameBytes.same_bytes_of _ x bv bv' he hb ?_
    rw [hbv]
    apply List.map_injective_iff.mpr (fun a b h => UScalar.eq_of_val_eq h)
    rw [hm, List.map_append, varint.enc_map _ (by omega)]
  · obtain ⟨e, he⟩ := VLBytes.encode_big x (by omega)
    obtain ⟨e', rfl⟩ := hch.2 (by omega)
    exact spec.io.SameBytes.same_bytes_err _ x e e' he hb

end tls_codec

