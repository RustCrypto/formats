/- `TlsByteVecU*`, `TlsByteSliceU*` (bytes written / read in one go). As `Std/TlsVec.lean`: one
generic serializer (`serB`) / deserializer (`deB`) up to the wrapper, the prefix codec and its
conversion, linked to each width by `rfl`.

Obligations: none directly; the `std`-path halves (`Serialize` / `Deserialize` `Lawful` fields,
lemma traits) of `PanicFreedom.lean` / `FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): nothing ASSUMED; 1 signature-only stub
(`core.io.error.Error.Insts.CoreFmtDebug.fmt`). -/
import TlsCodec.Verification.Std.TlsVec
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

namespace TlsVecStd

/-- `TlsByteVecU*::serialize_bytes` (pieces as `ser`; the payload is written with `write_all`). -/
noncomputable def serB {W P E : Type} (gcl : RustM (core.result.Result (Std.Usize × Std.Usize) Error))
    (tryP : Std.Usize → RustM (core.result.Result P E)) (dbg : core.fmt.Debug E)
    (PSI : Serialize P) (slc : RustM (Slice Std.U8))
    (aw : Std.Usize → Std.Usize → RustM (core.result.Result Unit Error))
    (WI : core.io.write.Write W) (writer : W) :
    RustM ((core.result.Result Std.Usize Error) × W) := do
  let r ← gcl
  let cf ← core.result.Result.Insts.CoreOpsTry_traitTry.branch r
  match cf with
  | core.ops.control_flow.ControlFlow.Continue val =>
    let (tls_serialized_len, byte_length) := val
    let r1 ← tryP byte_length
    let i ← core.result.Result.unwrap dbg r1
    let (r2, writer1) ← PSI.tls_serialize WI i writer
    let cf1 ← core.result.Result.Insts.CoreOpsTry_traitTry.branch r2
    match cf1 with
    | core.ops.control_flow.ControlFlow.Continue val1 =>
      let bytes ← slc
      let (r3, writer2) ← write_all WI writer1 bytes
      let cf2 ← core.result.Result.Insts.CoreOpsTry_traitTry.branch r3
      match cf2 with
      | core.ops.control_flow.ControlFlow.Continue _ =>
        let i1 ← core.slice.Slice.len bytes
        let written ← val1 + i1
        let r4 ← aw tls_serialized_len written
        let cf3 ← core.result.Result.Insts.CoreOpsTry_traitTry.branch r4
        match cf3 with
        | core.ops.control_flow.ControlFlow.Continue _ =>
          ok (core.result.Result.Ok written, writer2)
        | core.ops.control_flow.ControlFlow.Break residual =>
          let r5 ←
            core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
              Std.Usize (core.convert.From.Blanket Error) residual
          ok (r5, writer2)
      | core.ops.control_flow.ControlFlow.Break residual =>
        let r4 ←
          core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
            Std.Usize (core.convert.From.Blanket Error) residual
        ok (r4, writer2)
    | core.ops.control_flow.ControlFlow.Break residual =>
      let r3 ←
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
          Std.Usize (core.convert.From.Blanket Error) residual
      ok (r3, writer1)
  | core.ops.control_flow.ControlFlow.Break residual =>
    let r1 ←
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
        Std.Usize (core.convert.From.Blanket Error) residual
    ok (r1, writer)

/-- The size of a byte is `1`. -/
theorem u8_size_lawful : Size.Lawful Std.U8 U8.Insts.Tls_codecSize :=
  ⟨fun _ _ => by mvcgen [U8.Insts.Tls_codecSize, U8.Insts.Tls_codecSize.tls_serialized_len,
    Size.tls_serialized_len.post]⟩

theorem serB_runs {P E X : Type} (SI' : Serialize X) (x : X) (s : Slice Std.U8) (k : Std.Usize)
    (M : Nat) (_hkM : M + k.val ≤ Usize.max)
    (gcl : RustM (core.result.Result (Std.Usize × Std.Usize) Error))
    (hgcl : ⦃ ⌜ True ⌝ ⦄ gcl
      ⦃ ⇓ r => ⌜ (s.val.length ≤ M → ∃ a b : Std.Usize, r = .Ok (a, b) ∧
          a.val = s.val.length + k.val ∧ b.val = s.val.length) ∧
        (M < s.val.length → ∃ e, r = .Err e) ⌝ ⦄)
    (tryP : Std.Usize → RustM (core.result.Result P E)) (dbg : core.fmt.Debug E)
    (PSI : Serialize P) (pre : List Std.U8)
    (hpre0 : s.val.length ≤ M → pre.length = k.val ∧
      ∃ n0 p, n0.val = s.val.length ∧ tryP n0 = ok (.Ok p) ∧ SerRuns PSI p k (some pre))
    (slc : RustM (Slice Std.U8)) (hslc : slc = ok s)
    (aw : Std.Usize → Std.Usize → RustM (core.result.Result Unit Error))
    (haw : ∀ a, aw a a = ok (.Ok ()))
    (hser : ∀ (W : Type) (WI : core.io.write.Write W) w,
      SI'.tls_serialize WI x w = serB gcl tryP dbg PSI slc aw WI w)
    (sz : Std.Usize) (hszv : s.val.length ≤ M → sz.val = s.val.length + k.val) :
    SerRuns SI' x sz (if s.val.length ≤ M then some (pre ++ s.val) else none) := by
  intro W WI hWI w hroom
  suffices H : ⦃ ⌜ True ⌝ ⦄ SI'.tls_serialize WI x w
      ⦃ ⇓ p => ⌜ (∀ b, (if s.val.length ≤ M then some (pre ++ s.val) else none) = some b →
          (∃ n : Std.Usize, p.1 = .Ok n ∧ n.val = b.length) ∧
          core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w ++ b) ∧
        ((if s.val.length ≤ M then some (pre ++ s.val) else none) = none → ∃ e, p.1 = .Err e) ⌝ ⦄ by
    obtain ⟨⟨r, w'⟩, h1, h2⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp H
    exact ⟨r, w', h1, h2⟩
  rw [hser]
  obtain ⟨g, hg, hgP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp hgcl
  by_cases hNM : s.val.length ≤ M
  · obtain ⟨a, b, rfl, ha, hb⟩ := hgP.1 hNM
    obtain ⟨hencP, n0, p, hn0, ht, hrun⟩ := hpre0 hNM
    obtain rfl : b = n0 := UScalar.eq_of_val_eq (by omega)
    have hroom' : (core.io.write.Write.view WI w).length + (s.val.length + k.val) ≤ imax := by
      rw [← hszv hNM]; exact hroom
    have hpre : ∀ (i : P) (w' : W), ⦃ ⌜ i = p ∧
          (core.io.write.Write.view WI w').length + k.val ≤ imax ⌝ ⦄ PSI.tls_serialize WI i w'
        ⦃ ⇓ p => ⌜ (∃ n : Std.Usize, p.1 = .Ok n ∧ n.val = k.val) ∧
          core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w' ++ pre ⌝ ⦄ := by
      intro i w' ⟨hi, hroom''⟩
      subst hi
      refine triple_post_mono (hrun.spec WI hWI w' hroom'') (fun p hp => ?_) trivial
      obtain ⟨⟨n, hn, hnv⟩, hv⟩ := hp.1 _ rfl
      exact ⟨⟨n, hn, by rw [hnv, hencP]⟩, hv⟩
    have hwa : ∀ (w' : W) (s' : Slice Std.U8), ⦃ ⌜ s' = s ∧
          (core.io.write.Write.view WI w').length + s.val.length ≤ imax ⌝ ⦄ write_all WI w' s'
        ⦃ ⇓ q => ⌜ q.1 = .Ok () ∧
          core.io.write.Write.view WI q.2 = core.io.write.Write.view WI w' ++ s.val ⌝ ⦄ := by
      intro w' s' ⟨hs, hr⟩
      subst hs
      exact write_all_spec hWI w' _ (by have := imax_le; omega) trivial
    have hawt : ∀ c d : Std.Usize, ⦃ ⌜ c = d ⌝ ⦄ aw c d ⦃ ⇓ r => ⌜ r = .Ok () ⌝ ⦄ := by
      intro c d hcd; subst hcd; rw [haw]; mvcgen
    have hgt : ⦃ ⌜ True ⌝ ⦄ gcl ⦃ ⇓ r => ⌜ r = .Ok (a, b) ⌝ ⦄ := by rw [hg]; mvcgen
    have htp : ∀ n, ⦃ ⌜ n = b ⌝ ⦄ tryP n ⦃ ⇓ r => ⌜ r = .Ok p ⌝ ⦄ := by
      intro n hn; subst hn; rw [ht]; mvcgen
    have hv1 : ∀ (q : core.result.Result Std.Usize Error × W) v1,
        (∃ n : Std.Usize, q.1 = .Ok n ∧ n.val = k.val) →
        core.ops.control_flow.ControlFlow.Continue v1 = tryCF q.1 → v1.val = k.val := by
      intro q v1 ⟨n, hn, hnk⟩ hcf1
      rw [continue_eq_tryCF.mp hcf1] at hn; cases hn; exact hnk
    have hab : ∀ (g' : core.result.Result (Std.Usize × Std.Usize) Error) val, g' = .Ok (a, b) →
        core.ops.control_flow.ControlFlow.Continue val = tryCF g' → val = (a, b) := by
      intro g' val hg' hcf
      rw [hg'] at hcf; cases continue_eq_tryCF.mp hcf; rfl
    have hlen : ∀ l : Std.Usize, l = s.len → l.val = s.val.length := by
      intro l hl; rw [hl]; simp
    mvcgen [serB, hgt, htp, hslc, hpre, hwa, hawt, core.result.Result.unwrap_ok_spec,
      CoreModels.core.slice.Slice.len_spec]
    · rename_i g' hg' _ val _ hcf
      rw [hab g' val hg' hcf]
    · rename_i h; exact ⟨_, h⟩
    · rename_i h1 _ h2
      rw [h1] at h2; cases h2
      exact ⟨rfl, by omega⟩
    · rename_i q hq _ _ _ _
      refine ⟨trivial, ?_⟩
      rw [hq.2, List.length_append, hencP]; omega
    · rename_i g' hg' _ val _ hcf _ _ _ _ q hq _ v1 _ hcf1 e he _ u _ hcf2 l hl wr hwr
      rw [hab g' val hg' hcf]
      have := hv1 q v1 hq.1 hcf1
      have := hlen l hl
      exact UScalar.eq_of_val_eq (by simp only; omega)
    · rename_i g' hg' _ val _ hcf _ _ _ _ q hq _ v1 _ hcf1 e he _ u _ hcf2 l hl wr hwr _ _ _ _ _ _
      have h1 := hv1 q v1 hq.1 hcf1
      have h2 := hlen l hl
      simp only [hNM, if_true]
      refine ⟨fun b' hb' => ?_, fun h => by cases h⟩
      cases hb'
      refine ⟨⟨wr, rfl, ?_⟩, ?_⟩
      · rw [List.length_append, hencP]; omega
      · rw [he.2, hq.2, List.append_assoc]
    · rename_i hr1 _ _ _ hbr
      rw [hr1] at hbr; simp [tryCF] at hbr
    · rename_i _ _ _ _ _ _ _ _ _ _ q hq _ v1 _ hcf1 e he _ u _ hcf2 l hl hov
      have h1 := hv1 q v1 hq.1 hcf1
      have h2 := hlen l hl
      exfalso; scalar_tac
    · rename_i e he _ res _ hbr
      rw [he.1] at hbr; simp [tryCF] at hbr
    · rename_i q hq _ res _ hbr
      obtain ⟨n, hn, -⟩ := hq.1
      rw [hn] at hbr; simp [tryCF] at hbr
    · rename_i g' hg' _ res _ hbr
      rw [hg'] at hbr; simp [tryCF] at hbr
  · obtain ⟨e, rfl⟩ := hgP.2 (by omega)
    unfold serB
    rw [hg]
    simp only [hNM, if_false]
    mvcgen
    rename_i hbr
    refine ⟨e, by simpa [tryCF] using hbr, ?_⟩
    mvcgen
    intro _
    mvcgen
    exact ⟨fun b h => (by simp at h), _, rfl⟩

/-- The trait-level contract of `TlsByteVecU*::tls_serialize` (as `serSpec`). -/
theorem serSpecB {P E X : Type} (SI' : Serialize X) (x : X) (s : Slice Std.U8) (k : Std.Usize)
    (M : Nat) (hkM : M + k.val ≤ Usize.max)
    (mx : RustM Std.Usize) (hmx : ⦃ ⌜ True ⌝ ⦄ mx ⦃ ⇓ r => ⌜ r.val = M ⌝ ⦄)
    (gcl : RustM (core.result.Result (Std.Usize × Std.Usize) Error))
    (hgcl : gcl = tls_codec.HandTranslated.get_content_lengths_std
      U8.Insts.Tls_codecSize.tls_serialized_len k mx s)
    (tryP : Std.Usize → RustM (core.result.Result P E)) (dbg : core.fmt.Debug E) (PSI : Serialize P)
    (hP : ∀ n : Std.Usize, n.val ≤ M → ∃ p pre, tryP n = ok (.Ok p) ∧ SerRuns PSI p k (some pre) ∧
      pre.length = k.val)
    (slc : RustM (Slice Std.U8)) (hslc : slc = ok s)
    (aw : Std.Usize → Std.Usize → RustM (core.result.Result Unit Error))
    (haw : ∀ a, aw a a = ok (.Ok ()))
    (hser : ∀ (W : Type) (WI : core.io.write.Write W) w,
      SI'.tls_serialize WI x w = serB gcl tryP dbg PSI slc aw WI w)
    (hsz : SI'.SizeInst.tls_serialized_len x = len_add (Slice.len s) k) : SerSpec SI' x := by
  have hsz' : SI'.SizeInst.tls_serialized_len x = ok (lenAddVal (Slice.len s) k) := by
    rw [hsz, len_add_ok]
  have hszm := lenAddVal_min (Slice.len s) k
  have hls : (Slice.len s).val = s.val.length := by simp
  have hszv : s.val.length ≤ M → (lenAddVal (Slice.len s) k).val = s.val.length + k.val := by
    intro h; omega
  have hg := gcl_spec u8_size_lawful s (SizeNat.u8 s.val) k mx M hmx hkM
  rw [← hgcl] at hg
  obtain ⟨pre, hpre0⟩ : ∃ pre, s.val.length ≤ M → pre.length = k.val ∧
      ∃ n0 p, n0.val = s.val.length ∧ tryP n0 = ok (.Ok p) ∧ SerRuns PSI p k (some pre) := by
    by_cases h : s.val.length ≤ M
    · obtain ⟨g, -, hgP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp hg
      obtain ⟨a, b, -, -, hb⟩ := hgP.1 h
      obtain ⟨p, pre, ht, hr, hl⟩ := hP b (by omega)
      exact ⟨pre, fun _ => ⟨hl, b, p, hb, ht, hr⟩⟩
    · exact ⟨[], fun h' => absurd h' h⟩
  have hruns := serB_runs SI' x s k M hkM gcl hg tryP dbg PSI pre hpre0 slc hslc aw haw hser _ hszv
  intro W WI hWI w hpre
  refine Serialize.tls_serialize_spec_of_runs' SI' x _ hsz' _ (fun hle b hb => ?_) hruns WI hWI w hpre
  split at hb
  · rename_i hNM
    cases hb
    rw [List.length_append, (hpre0 hNM).1, hszv hNM, Nat.add_comm]
  · cases hb

/-- `TlsByteVecU*::deserialize_bytes` (`mk`: the wrapper, `PDI` / `conv` / `dbg`: the prefix). -/
noncomputable def deB {R P E V : Type} (mk : alloc.vec.Vec Std.U8 → V) (PDI : Deserialize P)
    (conv : P → RustM (core.result.Result Std.Usize E)) (dbg : core.fmt.Debug E)
    (RI : alloc.io.read.Read R) (bytes : R) : RustM ((core.result.Result V Error) × R) := do
  let (r, bytes1) ← PDI.tls_deserialize RI bytes
  let cf ← core.result.Result.Insts.CoreOpsTry_traitTry.branch r
  match cf with
  | core.ops.control_flow.ControlFlow.Continue val =>
    let r1 ← conv val
    let len ← core.result.Result.unwrap dbg r1
    let (r2, bytes2) ← read_bytes_bounded RI bytes1 len
    let cf1 ← core.result.Result.Insts.CoreOpsTry_traitTry.branch r2
    match cf1 with
    | core.ops.control_flow.ControlFlow.Continue val1 =>
      ok (core.result.Result.Ok (mk val1), bytes2)
    | core.ops.control_flow.ControlFlow.Break residual =>
      let r3 ←
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
          V (core.convert.From.Blanket Error) residual
      ok (r3, bytes2)
  | core.ops.control_flow.ControlFlow.Break residual =>
    let r1 ←
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
        V (core.convert.From.Blanket Error) residual
    ok (r1, bytes1)

/-- `TlsByteVecU*::tls_deserialize` on lawful readers: an `Ok` consumes exactly its size. -/
theorem deB_runs {P E V : Type} (vec : V → alloc.vec.Vec Std.U8) (mk : alloc.vec.Vec Std.U8 → V)
    (hmk : ∀ v, vec (mk v) = v) (PDI : Deserialize P) {Q : List Std.U8 → P → Nat → Prop}
    (hP : DeRuns PDI Q) (kz : Std.Usize) (hk : ∀ x, PDI.SizeInst.tls_serialized_len x = ok kz)
    (M : Nat) (hM : 2 * M < UScalar.max UScalarTy.Usize)
    (conv : P → RustM (core.result.Result Std.Usize E))
    (hconv : ∀ p, ⦃ ⌜ True ⌝ ⦄ conv p ⦃ ⇓ r => ⌜ ∃ y, r = .Ok y ∧ y.val ≤ M ⌝ ⦄)
    (dbg : core.fmt.Debug E) (DI' : Deserialize V)
    (hde : ∀ (R : Type) (RI : alloc.io.read.Read R) r,
      DI'.tls_deserialize RI r = deB mk PDI conv dbg RI r)
    (hsz : ∀ x, DI'.SizeInst.tls_serialized_len x = len_add (Slice.len (vec x)) kz) :
    DeRuns DI' (fun _ _ _ => True) := by
  intro R RI v a law r
  rw [hde]
  have hr := hP R RI v a law r
  have hrbb := fun (r' : R) (len : Std.Usize) => read_bytes_bounded_law law r' len
  mvcgen [deB, hr, hconv, hrbb, core.result.Result.unwrap_ok_spec]
  · rename_i h; obtain ⟨y, hy, -⟩ := h; exact ⟨y, hy⟩
  · rename_i q hq _ val _ hcf rc hrc u hu rb hrb _ w _ hcf1
    intro x hx; cases hx
    obtain ⟨n, sz, hn, hq2, hsz', hszn, -⟩ := hq val (continue_eq_tryCF.mp hcf)
    obtain rfl : kz = sz := ok.inj ((hk val).symm.trans hsz')
    obtain ⟨y, hy, hyM⟩ := hrc
    rw [hy] at hu; cases hu
    have hview : v q.2 = (v r).drop n := by rw [hq2]; exact law.adv_view r n hn
    have hrbw := continue_eq_tryCF.mp hcf1
    have hule : u.val ≤ (v q.2).length := by
      by_contra hlt
      rcases hrb.2 (by omega) with h | h <;> rw [hrbw] at h <;> cases h
    obtain ⟨w', hw', hw'v, hrb2⟩ := hrb.1 hule (by omega)
    rw [hrbw] at hw'; cases hw'
    have hlw : (Slice.len w).val = u.val := by
      rw [Slice.len_val]; simp only [Slice.length]
      rw [hw'v, List.length_take, hview, List.length_drop] at *; omega
    rw [hview, List.length_drop] at hule
    have hmax := law.view_le r
    refine ⟨n + u.val, lenAddVal (Slice.len w) kz, by omega, ?_, ?_, ?_⟩
    · rw [hrb2, hq2, law.adv_adv r _ _ (by omega)]
    · rw [hsz, hmk, len_add_ok]
    · rw [lenAddVal_val _ _ (by omega), hlw]; omega
  · rename_i rb _ _ res _ hbr
    refine try_break_vc (x := rb.1) (fun e _ => ?_) hbr
    mvcgen
    intro _
    mvcgen
    exact fun x hx => by cases hx
  · rename_i q _ _ res _ hbr
    refine try_break_vc (x := q.1) (fun e _ => ?_) hbr
    mvcgen
    intro _
    mvcgen
    exact fun x hx => by cases hx

/-- The default `tls_serialize_detached`, from the contract and a `len_add` size. -/
theorem detachedB {X : Type} {SI : Serialize X} {x : X} {a k : Std.Usize} (h : SerSpec SI x)
    (hsz : SI.SizeInst.tls_serialized_len x = len_add a k) :
    ⦃ ⌜ True ⌝ ⦄ Serialize.tls_serialize_detached.default SI x
    ⦃ ⇓ r => ⌜ (Serialize.tls_serialize_detached.post SI.SizeInst SI x r).holds ⌝ ⦄ :=
  h.detached ⟨_, hsz.trans (len_add_ok _ _)⟩

end TlsVecStd

end tls_codec
