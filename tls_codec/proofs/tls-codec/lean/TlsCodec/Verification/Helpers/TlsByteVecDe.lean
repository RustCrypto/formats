/- `TlsByteVecU*::tls_deserialize_bytes`: the generic proof `TlsByteVecGen` and its per-width
instances.

Obligations: none directly; the bytes-path halves of `PanicFreedom.lean` /
`FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): ASSUMED `size_of`, `size_of_U16`, `size_of_U24`,
`size_of_U32`, `size_of_U8`, `size_of_Usize`, `numBits_eq_64`; 2 signature-only stubs
(`core.convert.Infallible.Insts.CoreFmtDebug.fmt`,
`core.num.error.TryFromIntError.Insts.CoreFmtDebug.fmt`). -/
import TlsCodec.Verification.Helpers.TlsVecGen
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! ### Generic `TlsByteVecU*::deserialize_bytes_bytes` (`TlsByteVecGen`)

As `TlsVecGen`: the per-width functions are one generic function (`TlsByteVecGen.deser`) up to the
wrapper, the prefix codec / conversion and the width, linked by `rfl` after a case split on the first
`?` match. `content` (partial) and `pf` are proved once; per width `deserialize_content` combines
them, and `deserialize_char(_le)` follow from it by `Content.len`. -/

namespace TlsByteVecGen

variable {W : Type}

/-- `TlsByteVecU*::deserialize_bytes_bytes` over an abstract wrapper (`mk`), length prefix `readLen`
of width `w`, and its conversion `conv` to `usize` (unwrapped with `dbg`). -/
def deser {P E : Type} (mk : alloc.vec.Vec Std.U8 → W)
    (readLen : Slice Std.U8 → RustM (core.result.Result (P × Slice Std.U8) Error))
    (conv : P → RustM (core.result.Result Std.Usize E)) (dbg : core.fmt.Debug E) (w : Std.Usize)
    (bytes : Slice Std.U8) : RustM (core.result.Result (W × Slice Std.U8) Error) := do
  let r ← readLen bytes
  let cf ← core.result.Result.Insts.CoreOpsTry_traitTry.branch r
  match cf with
  | core.ops.control_flow.ControlFlow.Continue p =>
    let (type_len, remainder) := p
    let r1 ← conv type_len
    let len ← core.result.Result.unwrap dbg r1
    let o ← core.num.Usize.checked_add len w
    let r2 ← core.option.Option.ok_or o Error.InvalidVectorLength
    let cf1 ← core.result.Result.Insts.CoreOpsTry_traitTry.branch r2
    match cf1 with
    | core.ops.control_flow.ControlFlow.Continue val =>
      let o1 ←
        core.slice.Slice.get
          (core.ops.range.RangeUsize.Insts.CoreSliceIndexSliceIndexSliceSlice
          Std.U8) bytes { start := w, «end» := val }
      let r3 ← core.option.Option.ok_or o1 Error.EndOfStream
      let cf2 ← core.result.Result.Insts.CoreOpsTry_traitTry.branch r3
      match cf2 with
      | core.ops.control_flow.ControlFlow.Continue val1 =>
        let v ← alloc.slice.Slice.to_vec core.U8.Insts.CoreCloneClone val1
        let o2 ←
          core.slice.Slice.get
            (core.ops.range.RangeFromUsize.Insts.CoreSliceIndexSliceIndexSliceSlice
            Std.U8) remainder { start := len }
        let r4 ← core.option.Option.ok_or o2 Error.EndOfStream
        let cf3 ← core.result.Result.Insts.CoreOpsTry_traitTry.branch r4
        match cf3 with
        | core.ops.control_flow.ControlFlow.Continue val2 =>
          ok (core.result.Result.Ok (mk v, val2))
        | core.ops.control_flow.ControlFlow.Break residual =>
          core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
            (W × Slice Std.U8) (core.convert.From.Blanket Error) residual
      | core.ops.control_flow.ControlFlow.Break residual =>
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
          (W × Slice Std.U8) (core.convert.From.Blanket Error) residual
    | core.ops.control_flow.ControlFlow.Break residual =>
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
        (W × Slice Std.U8) (core.convert.From.Blanket Error) residual
  | core.ops.control_flow.ControlFlow.Break residual =>
    core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
      (W × Slice Std.U8) (core.convert.From.Blanket Error) residual


theorem content_rel {P E : Type} (vec : W → alloc.vec.Vec Std.U8) (mk : alloc.vec.Vec Std.U8 → W)
    (hmk : ∀ v, vec (mk v) = v) (enc : P → List Std.U8) (R : P → Nat → Prop) (w : Std.Usize)
    (henc : ∀ p, (enc p).length = w.val)
    (readLen : Slice Std.U8 → RustM (core.result.Result (P × Slice Std.U8) Error))
    (hread : ∀ bytes, ⦃ ⌜ True ⌝ ⦄ readLen bytes ⦃ ⇓ r => ⌜ ∀ p, r = .Ok p →
      bytes.val = enc p.1 ++ p.2.val ⌝ ⦄)
    (conv : P → RustM (core.result.Result Std.Usize E))
    (hconv : ∀ p, ⦃ ⌜ True ⌝ ⦄ conv p ⦃ ⇓? r => ⌜ ∃ y, r = .Ok y ∧ R p y.val ⌝ ⦄)
    (dbg : core.fmt.Debug E) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ deser mk readLen conv dbg w bytes
    ⦃ ⇓? r => ⌜ ∀ v t, r = .Ok (v, t) → ∃ p : P, R p (vec v).val.length ∧
        bytes.val = enc p ++ ((vec v).val ++ t.val) ⌝ ⦄ := by
  mvcgen [-core.ops.range.RangeUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get_some_spec,
    deser, hread, hconv, core.option.Option.ok_or_spec,
    core.ops.range.RangeUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get_content_spec]
  try_vcs
  all_goals (try simp only [continue_eq_tryCF] at *)
  all_goals (try (intros; simp [PostCond.ok]; done))
  case vc1.h => obtain ⟨y, hy, -⟩ := ‹∃ y, _ ∧ _›; exact ⟨y, hy⟩
  case vc2 =>
    rename_i r0 hP r1 p _ r2 hc len hlen o hca r3 hr3 _ val _ o1 hget1 r5 hr5 _ val1 _ v0 hv0 o2 hget2
      r6 hr6 _ val2 _ e0 e1 e2 e3
    rintro v t ⟨⟩
    have hb := hP p e0
    have hw := henc p.1
    obtain ⟨y, rfl, hyv⟩ := hc
    cases hlen
    have h1 := hget1 val1 (ok_or_eq_ok hr5 e2)
    have ho := ok_or_eq_ok hr3 e1
    have h2 : val.val = len.val + w.val := by
      by_cases hov : len.val + w.val ≤ Usize.max
      · obtain ⟨z, hz, hzv⟩ := hca.1 hov
        rw [hz] at ho; cases ho; exact hzv
      · rw [hca.2 (by omega)] at ho; cases ho
    have ho2 := ok_or_eq_ok hr6 e3
    have hle : len.val ≤ p.2.val.length := by
      by_contra hn; rw [hget2.2 (by omega)] at ho2; cases ho2
    obtain ⟨t2, ht2, ht2'⟩ := hget2.1 hle
    rw [ht2] at ho2; cases ho2
    have hd : bytes.val.drop w.val = p.2.val := by rw [hb, ← hw, List.drop_left]
    have hv : (vec (mk v0)).val = p.2.val.take len.val := by
      rw [hmk, hv0, h1.2.2, hd, h2, Nat.add_sub_cancel]
    refine ⟨p.1, ?_, ?_⟩
    · rw [hv, List.length_take, Nat.min_eq_left hle]; exact hyv
    · rw [hv, ht2', List.take_append_drop]; exact hb

/-- `content_rel` with the prefix value `pval p` as the payload length. -/
theorem content {P E : Type} (vec : W → alloc.vec.Vec Std.U8) (mk : alloc.vec.Vec Std.U8 → W)
    (hmk : ∀ v, vec (mk v) = v) (enc : P → List Std.U8) (pval : P → Nat) (w : Std.Usize)
    (henc : ∀ p, (enc p).length = w.val)
    (readLen : Slice Std.U8 → RustM (core.result.Result (P × Slice Std.U8) Error))
    (hread : ∀ bytes, ⦃ ⌜ True ⌝ ⦄ readLen bytes ⦃ ⇓ r => ⌜ ∀ p, r = .Ok p →
      bytes.val = enc p.1 ++ p.2.val ⌝ ⦄)
    (conv : P → RustM (core.result.Result Std.Usize E))
    (hconv : ∀ p, ⦃ ⌜ True ⌝ ⦄ conv p ⦃ ⇓? r => ⌜ ∃ y, r = .Ok y ∧ y.val = pval p ⌝ ⦄)
    (dbg : core.fmt.Debug E) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ deser mk readLen conv dbg w bytes
    ⦃ ⇓? r => ⌜ ∀ v t, r = .Ok (v, t) → ∃ p : P, pval p = (vec v).val.length ∧
        bytes.val = enc p ++ ((vec v).val ++ t.val) ⌝ ⦄ := by
  have h := content_rel vec mk hmk enc (fun p n => n = pval p) w henc readLen hread conv hconv dbg bytes
  refine partial_triple_of_ok fun r hr v t hv => ?_
  obtain ⟨p, hp, hb⟩ := ok_of_partial_triple h hr v t hv
  exact ⟨p, hp.symm, hb⟩

theorem pf {P E : Type} (mk : alloc.vec.Vec Std.U8 → W) (w : Std.Usize)
    (readLen : Slice Std.U8 → RustM (core.result.Result (P × Slice Std.U8) Error))
    (hread : ∀ bytes, ⦃ ⌜ True ⌝ ⦄ readLen bytes ⦃ ⇓ _ => ⌜ True ⌝ ⦄)
    (conv : P → RustM (core.result.Result Std.Usize E))
    (hconv : ∀ p, ⦃ ⌜ True ⌝ ⦄ conv p ⦃ ⇓ r => ⌜ ∃ y, r = .Ok y ⌝ ⦄)
    (dbg : core.fmt.Debug E) (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ deser mk readLen conv dbg w bytes ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  mvcgen [deser, hread, hconv, core.option.Option.ok_or_spec]
  try_vcs


/-- The post of `content`: the input is the encoded prefix, the payload, then the remainder. -/
abbrev Content {P : Type} (vec : W → alloc.vec.Vec Std.U8) (enc : P → List Std.U8) (pval : P → Nat)
    (bytes : Slice Std.U8) (r : core.result.Result (W × Slice Std.U8) Error) : Prop :=
  ∀ v t, r = .Ok (v, t) → ∃ p : P, pval p = (vec v).val.length ∧
    bytes.val = enc p ++ ((vec v).val ++ t.val)

theorem Content.len {P : Type} {vec : W → alloc.vec.Vec Std.U8} {enc : P → List Std.U8}
    {pval : P → Nat} {bytes : Slice Std.U8} {r : core.result.Result (W × Slice Std.U8) Error}
    (h : Content vec enc pval bytes r) (n : Nat) (henc : ∀ p, (enc p).length = n) (bound : Nat)
    (hb : ∀ p, pval p ≤ bound) :
    ∀ v t, r = .Ok (v, t) → t.val.length + n + (vec v).val.length = bytes.val.length ∧
      (vec v).val.length ≤ bound := by
  intro v t hr
  obtain ⟨p, hp, hb'⟩ := h v t hr
  have := congrArg List.length hb'
  simp only [List.length_append, henc] at this
  exact ⟨by omega, hp ▸ hb p⟩

/-- `bytes = enc x ++ rest` after a successful prefix read (from a `U*_deserialize_char`). -/
theorem prefix_split {U X : Type} (n : Nat) {f : X → U} {g : X → List Std.U8} (enc : U → List Std.U8)
    (hrt : ∀ a, enc (f a) = g a)
    {readLen : Slice Std.U8 → RustM (core.result.Result (U × Slice Std.U8) Error)}
    (h : ∀ bytes, ⦃ ⌜ True ⌝ ⦄ readLen bytes
      ⦃ ⇓ r => ⌜ (n ≤ bytes.val.length → ∃ (a : X) (t : Slice Std.U8),
          g a = bytes.val.take n ∧ t.val = bytes.val.drop n ∧ r = .Ok (f a, t)) ∧
        (bytes.val.length < n → r = .Err Error.EndOfStream) ⌝ ⦄)
    (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ readLen bytes ⦃ ⇓ r => ⌜ ∀ p, r = .Ok p → bytes.val = enc p.1 ++ p.2.val ⌝ ⦄ := by
  refine triple_post_mono (h bytes) fun r hP p hp => ?_
  by_cases hn : n ≤ bytes.val.length
  · obtain ⟨a, t, ha, ht, rfl⟩ := hP.1 hn
    cases hp
    rw [hrt, ha, ht, List.take_append_drop]
  · rw [hP.2 (by omega)] at hp; cases hp

/-- Totality of a prefix read (from a `U*_deserialize_char`): on `enc u ++ Xs` it returns `u` and
`Xs`. `e` is a section of `g`, and `f` inverts it. -/
theorem prefix_ok {U X : Type} (n : Nat) {f : X → U} {g : X → List Std.U8} (enc : U → List Std.U8)
    (e : U → X) (hge : ∀ u, g (e u) = enc u) (hf : ∀ u, f (e u) = u)
    (hginj : ∀ a b, g a = g b → a = b) (hlen : ∀ u, (enc u).length = n)
    {readLen : Slice Std.U8 → RustM (core.result.Result (U × Slice Std.U8) Error)}
    (h : ∀ bytes, ⦃ ⌜ True ⌝ ⦄ readLen bytes
      ⦃ ⇓ r => ⌜ (n ≤ bytes.val.length → ∃ (a : X) (t : Slice Std.U8),
          g a = bytes.val.take n ∧ t.val = bytes.val.drop n ∧ r = .Ok (f a, t)) ∧
        (bytes.val.length < n → r = .Err Error.EndOfStream) ⌝ ⦄)
    (bytes : Slice Std.U8) (u : U) (Xs : List Std.U8) (hb : bytes.val = enc u ++ Xs) :
    ⦃ ⌜ True ⌝ ⦄ readLen bytes ⦃ ⇓ r => ⌜ ∃ t : Slice Std.U8, r = .Ok (u, t) ∧ t.val = Xs ⌝ ⦄ := by
  refine triple_post_mono (h bytes) fun r hP => ?_
  have hu := hlen u
  obtain ⟨a, t, ha, ht, rfl⟩ := hP.1 (by rw [hb]; simp [hu])
  have hae : a = e u := hginj _ _ (by rw [ha, hge, hb]; exact List.take_left' hu)
  subst hae
  exact ⟨t, by rw [hf], by rw [ht, hb]; exact List.drop_left' hu⟩

/-- A conversion returning `Ok (g p)`, with `g p` of value `pval p`. -/
theorem conv_val {P E : Type} {conv : P → RustM (core.result.Result Std.Usize E)} {g : P → Std.Usize}
    (pval : P → Nat) (h : ∀ p, ⦃ ⌜ True ⌝ ⦄ conv p ⦃ ⇓ r => ⌜ r = .Ok (g p) ⌝ ⦄)
    (hg : ∀ p, (g p).val = pval p) (p : P) :
    ⦃ ⌜ True ⌝ ⦄ conv p ⦃ ⇓? r => ⌜ ∃ y, r = .Ok y ∧ y.val = pval p ⌝ ⦄ := by
  obtain ⟨r, hr, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (h p)
  refine partial_triple_of_ok fun r' hr' => ⟨g p, ?_, hg p⟩
  rw [hr] at hr'; cases hr'; exact hP

/-- Totality of `deser`: on `enc a ++ (payload ++ rest)` it returns the wrapper of `payload` and
`rest`, provided the prefix reader and the conversion succeed there. -/
theorem ok {P E : Type} (vec : W → alloc.vec.Vec Std.U8) (mk : alloc.vec.Vec Std.U8 → W)
    (enc : P → List Std.U8) (pval : P → Nat) (w : Std.Usize)
    (readLen : Slice Std.U8 → RustM (core.result.Result (P × Slice Std.U8) Error))
    (hread : ∀ (bytes : Slice Std.U8) (a : P) (X : List Std.U8), bytes.val = enc a ++ X →
      ⦃ ⌜ True ⌝ ⦄ readLen bytes ⦃ ⇓ r => ⌜ ∃ t : Slice Std.U8, r = .Ok (a, t) ∧ t.val = X ⌝ ⦄)
    (conv : P → RustM (core.result.Result Std.Usize E))
    (hconv : ∀ p, ⦃ ⌜ True ⌝ ⦄ conv p ⦃ ⇓ r => ⌜ ∃ y, r = .Ok y ∧ y.val = pval p ⌝ ⦄)
    (dbg : core.fmt.Debug E) (bytes : Slice Std.U8) (a : P) (payload : alloc.vec.Vec Std.U8)
    (rest : List Std.U8) (hb : bytes.val = enc a ++ (payload.val ++ rest))
    (hp : pval a = payload.val.length) (henc : (enc a).length = w.val)
    (hmax : w.val + payload.val.length ≤ Std.Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ deser mk readLen conv dbg w bytes
    ⦃ ⇓ r => ⌜ ∃ t : Slice Std.U8, r = .Ok (mk payload, t) ∧ t.val = rest ⌝ ⦄ := by
  obtain ⟨_, hrv, t, rfl, ht⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (hread bytes a _ hb)
  have hbl : bytes.val.length = w.val + (payload.val.length + rest.length) := by
    rw [hb]; simp [henc]
  have htl : t.val.length = payload.val.length + rest.length := by rw [ht]; simp
  have hdrop : bytes.val.drop w.val = payload.val ++ rest := by
    rw [hb, ← henc, List.drop_left]
  unfold deser
  rw [hrv]
  simp only [bind_tc_ok]
  mvcgen [-core.ops.range.RangeUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get_some_spec,
    hconv, core.option.Option.ok_or_spec, core.num.Usize.checked_add_spec,
    core.ops.range.RangeUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get_total_spec,
    core.ops.range.RangeFromUsize.Insts.CoreSliceIndexSliceIndexSliceSlice.get_spec,
    core.result.Result.unwrap_ok_spec]
  all_goals (try simp only [continue_eq_tryCF, core.result.Result.Ok.injEq] at *)
  all_goals (try subst_vars)
  · obtain ⟨y, hy, -⟩ := ‹∃ y, _ ∧ _›
    exact ⟨y, hy⟩
  · rename_i u o hca val o2 hget v o3 val1 hget2 hy hm1 hm2 hm3
    obtain ⟨y, hy', hyv⟩ := hy
    cases hy'
    have hl : u.val = payload.val.length := hyv.trans hp
    obtain ⟨z, hz, hzv⟩ := hca.1 (by omega)
    simp only [hz, core.result.Result.Ok.injEq] at hm1
    subst hm1
    obtain ⟨t', ht', ht'v⟩ := hget (by omega) (by omega)
    obtain ⟨t'', ht'', ht''v⟩ := hget2.1 (by first | omega | (dsimp only; omega))
    simp only [ht', core.result.Result.Ok.injEq] at hm2
    simp only [ht'', core.result.Result.Ok.injEq] at hm3
    subst hm3
    have hv : v = payload := Subtype.ext (by
      rw [← hm2, ht'v, hzv, hl, hdrop, Nat.add_sub_cancel, List.take_left' rfl])
    subst hv
    exact ⟨_, rfl, by rw [ht''v]; simp only [] at *; rw [ht, hl, List.drop_left' rfl]⟩
  · rename_i u o hca val o2 hget v o3 _ hget2 hy hm1 hm2
    obtain ⟨y, hy', hyv⟩ := hy
    cases hy'
    have hl : u.val = payload.val.length := hyv.trans hp
    obtain ⟨t'', ht'', -⟩ := hget2.1 (by first | omega | (dsimp only; omega))
    rw [ht'']
    intro h
    simp [tryCF] at h
  · rename_i u o hca val o2 hget _ hy hm1
    obtain ⟨y, hy', hyv⟩ := hy
    cases hy'
    have hl : u.val = payload.val.length := hyv.trans hp
    obtain ⟨z, hz, hzv⟩ := hca.1 (by omega)
    simp only [hz, core.result.Result.Ok.injEq] at hm1
    subst hm1
    obtain ⟨t', ht', -⟩ := hget (by omega) (by omega)
    rw [ht']
    intro h
    simp [tryCF] at h
  · rename_i u o hca _ hy
    obtain ⟨y, hy', hyv⟩ := hy
    cases hy'
    have hl : u.val = payload.val.length := hyv.trans hp
    obtain ⟨z, hz, -⟩ := hca.1 (by omega)
    rw [hz]
    intro h
    simp [tryCF] at h
  · intro h
    simp [tryCF] at h

/-- A conversion returning `Ok (g p)`, with `g p` of value `pval p` (total version of `conv_val`). -/
theorem conv_total {P E : Type} {conv : P → RustM (core.result.Result Std.Usize E)} {g : P → Std.Usize}
    (pval : P → Nat) (h : ∀ p, ⦃ ⌜ True ⌝ ⦄ conv p ⦃ ⇓ r => ⌜ r = .Ok (g p) ⌝ ⦄)
    (hg : ∀ p, (g p).val = pval p) (p : P) :
    ⦃ ⌜ True ⌝ ⦄ conv p ⦃ ⇓ r => ⌜ ∃ y, r = .Ok y ∧ y.val = pval p ⌝ ⦄ :=
  triple_post_mono (h p) fun _ hr => ⟨g p, hr, hg p⟩

end TlsByteVecGen

/-! #### `TlsByteVecU16` -/

/-- `TlsByteVecU16::deserialize_bytes_bytes` is the generic one. -/
theorem tls_vec.TlsByteVecU16.deserialize_bytes_bytes_eq : tls_vec.TlsByteVecU16.deserialize_bytes_bytes =
    TlsByteVecGen.deser tls_vec.TlsByteVecU16.mk U16.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
      (core.convert.TryFromTUInfallible.Blanket.try_from
        (core.convert.Into.Blanket core.Usize.Insts.CoreConvertFromU16))
      core.convert.Infallible.Insts.CoreFmtDebug 2#usize := by
  funext bytes
  unfold tls_vec.TlsByteVecU16.deserialize_bytes_bytes TlsByteVecGen.deser
  congr 1; funext r; congr 1; funext cf; cases cf <;> rfl

/-- `TlsByteVecU16::deserialize_bytes_bytes` never panics; on success the input is the 2-byte length prefix, the payload, then the remainder. -/
theorem tls_vec.TlsByteVecU16.deserialize_content (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU16.deserialize_bytes_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ (v : tls_vec.TlsByteVecU16) (t : Slice Std.U8), r = .Ok (v, t) →
        ∃ n : Std.U16, n.val = v.vec.val.length ∧
          bytes.val = (Aeneas.Std.core.num.U16.to_be_bytes n).val ++ (v.vec.val ++ t.val) ⌝ ⦄ := by
  rw [tls_vec.TlsByteVecU16.deserialize_bytes_bytes_eq]
  have hread := TlsByteVecGen.prefix_split 2 (fun n : Std.U16 => (Aeneas.Std.core.num.U16.to_be_bytes n).val)
    (fun a => congrArg Subtype.val (U16_to_be_bytes_from_be_bytes a)) U16_deserialize_char
  exact total_of_pf_partial
    (TlsByteVecGen.pf _ _ _ (fun b => pf_of_total (hread b)) _
      (TlsVecGen.conv_ok core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U16_spec) _ bytes)
    (TlsByteVecGen.content tls_vec.TlsByteVecU16.vec _ (fun _ => rfl) _ (fun n : Std.U16 => n.val) 2#usize
      (fun n => (Aeneas.Std.core.num.U16.to_be_bytes n).property) _ hread _
      (TlsByteVecGen.conv_val _ core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U16_spec
        (fun _ => by simp)) _ bytes)

theorem tls_vec.TlsByteVecU16.deserialize_char_le (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU16.deserialize_bytes_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ (v : tls_vec.TlsByteVecU16) (t : Slice Std.U8), r = .Ok (v, t) →
        t.val.length + 2 + v.vec.val.length = bytes.val.length ∧
          v.vec.val.length ≤ 65535 ⌝ ⦄ :=
  triple_post_mono (tls_vec.TlsByteVecU16.deserialize_content bytes) fun _ h =>
    TlsByteVecGen.Content.len (vec := tls_vec.TlsByteVecU16.vec) h 2 (fun n => by simp) 65535 (fun n => by scalar_tac)

theorem tls_vec.TlsByteVecU16.deserialize_char (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU16.deserialize_bytes_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ (v : tls_vec.TlsByteVecU16) (t : Slice Std.U8), r = .Ok (v, t) →
        t.val.length + 2 + v.vec.val.length = bytes.val.length ⌝ ⦄ :=
  triple_post_mono (tls_vec.TlsByteVecU16.deserialize_char_le bytes) fun _ h v t hr => (h v t hr).1

/-! #### `TlsByteVecU8` -/

/-- `TlsByteVecU8::deserialize_bytes_bytes` is the generic one. -/
theorem tls_vec.TlsByteVecU8.deserialize_bytes_bytes_eq : tls_vec.TlsByteVecU8.deserialize_bytes_bytes =
    TlsByteVecGen.deser tls_vec.TlsByteVecU8.mk U8.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
      (core.convert.TryFromTUInfallible.Blanket.try_from
        (core.convert.Into.Blanket core.Usize.Insts.CoreConvertFromU8))
      core.convert.Infallible.Insts.CoreFmtDebug 1#usize := by
  funext bytes
  unfold tls_vec.TlsByteVecU8.deserialize_bytes_bytes TlsByteVecGen.deser
  congr 1; funext r; congr 1; funext cf; cases cf <;> rfl

/-- `TlsByteVecU8::deserialize_bytes_bytes` never panics; on success the input is the 1-byte length prefix, the payload, then the remainder. -/
theorem tls_vec.TlsByteVecU8.deserialize_content (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU8.deserialize_bytes_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ (v : tls_vec.TlsByteVecU8) (t : Slice Std.U8), r = .Ok (v, t) →
        ∃ n : Std.U8, n.val = v.vec.val.length ∧ bytes.val = n :: (v.vec.val ++ t.val) ⌝ ⦄ := by
  rw [tls_vec.TlsByteVecU8.deserialize_bytes_bytes_eq]
  have hread := TlsByteVecGen.prefix_split 1 (fun n : Std.U8 => [n])
    (fun a => by
      have := congrArg Subtype.val (U8_to_be_bytes_from_be_bytes a)
      rwa [U8_to_be_bytes_val] at this) U8_deserialize_char
  exact total_of_pf_partial
    (TlsByteVecGen.pf _ _ _ (fun b => pf_of_total (hread b)) _
      (TlsVecGen.conv_ok core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U8_spec) _ bytes)
    (TlsByteVecGen.content tls_vec.TlsByteVecU8.vec _ (fun _ => rfl) (fun n : Std.U8 => [n]) (fun n : Std.U8 => n.val) 1#usize
      (fun n => rfl) _ hread _
      (TlsByteVecGen.conv_val _ core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U8_spec
        (fun _ => by simp)) _ bytes)

theorem tls_vec.TlsByteVecU8.deserialize_char_le (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU8.deserialize_bytes_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ (v : tls_vec.TlsByteVecU8) (t : Slice Std.U8), r = .Ok (v, t) →
        t.val.length + 1 + v.vec.val.length = bytes.val.length ∧
          v.vec.val.length ≤ 255 ⌝ ⦄ :=
  triple_post_mono (tls_vec.TlsByteVecU8.deserialize_content bytes) fun _ h =>
    TlsByteVecGen.Content.len (vec := tls_vec.TlsByteVecU8.vec) (enc := fun n : Std.U8 => [n]) (pval := fun n => n.val)
      (fun v t hr => h v t hr) 1 (fun n => rfl) 255 (fun n => by scalar_tac)

theorem tls_vec.TlsByteVecU8.deserialize_char (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU8.deserialize_bytes_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ (v : tls_vec.TlsByteVecU8) (t : Slice Std.U8), r = .Ok (v, t) →
        t.val.length + 1 + v.vec.val.length = bytes.val.length ⌝ ⦄ :=
  triple_post_mono (tls_vec.TlsByteVecU8.deserialize_char_le bytes) fun _ h v t hr => (h v t hr).1

/-! #### `TlsByteVecU32` -/

/-- `TlsByteVecU32::deserialize_bytes_bytes` is the generic one. -/
theorem tls_vec.TlsByteVecU32.deserialize_bytes_bytes_eq : tls_vec.TlsByteVecU32.deserialize_bytes_bytes =
    TlsByteVecGen.deser tls_vec.TlsByteVecU32.mk U32.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
      core.Usize.Insts.CoreConvertTryFromU32TryFromIntError.try_from
      core.num.error.TryFromIntError.Insts.CoreFmtDebug 4#usize := by
  funext bytes
  unfold tls_vec.TlsByteVecU32.deserialize_bytes_bytes TlsByteVecGen.deser
  congr 1; funext r; congr 1; funext cf; cases cf <;> rfl

/-- `TlsByteVecU32::deserialize_bytes_bytes` never panics; on success the input is the 4-byte length prefix, the payload, then the remainder. -/
theorem tls_vec.TlsByteVecU32.deserialize_content (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU32.deserialize_bytes_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ (v : tls_vec.TlsByteVecU32) (t : Slice Std.U8), r = .Ok (v, t) →
        ∃ n : Std.U32, n.val = v.vec.val.length ∧
          bytes.val = (Aeneas.Std.core.num.U32.to_be_bytes n).val ++ (v.vec.val ++ t.val) ⌝ ⦄ := by
  rw [tls_vec.TlsByteVecU32.deserialize_bytes_bytes_eq]
  have hread := TlsByteVecGen.prefix_split 4 (fun n : Std.U32 => (Aeneas.Std.core.num.U32.to_be_bytes n).val)
    (fun a => congrArg Subtype.val (U32_to_be_bytes_from_be_bytes a)) U32_deserialize_char
  exact total_of_pf_partial
    (TlsByteVecGen.pf _ _ _ (fun b => pf_of_total (hread b)) _
      (TlsVecGen.conv_ok core.Usize.Insts.CoreConvertTryFromU32TryFromIntError.try_from_spec) _ bytes)
    (TlsByteVecGen.content tls_vec.TlsByteVecU32.vec _ (fun _ => rfl) _ (fun n : Std.U32 => n.val) 4#usize
      (fun n => (Aeneas.Std.core.num.U32.to_be_bytes n).property) _ hread _
      (TlsByteVecGen.conv_val _ core.Usize.Insts.CoreConvertTryFromU32TryFromIntError.try_from_spec
        (fun _ => by simp)) _ bytes)

theorem tls_vec.TlsByteVecU32.deserialize_char_le (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU32.deserialize_bytes_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ (v : tls_vec.TlsByteVecU32) (t : Slice Std.U8), r = .Ok (v, t) →
        t.val.length + 4 + v.vec.val.length = bytes.val.length ∧
          v.vec.val.length ≤ 4294967295 ⌝ ⦄ :=
  triple_post_mono (tls_vec.TlsByteVecU32.deserialize_content bytes) fun _ h =>
    TlsByteVecGen.Content.len (vec := tls_vec.TlsByteVecU32.vec) h 4 (fun n => by simp) 4294967295 (fun n => by scalar_tac)

theorem tls_vec.TlsByteVecU32.deserialize_char (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU32.deserialize_bytes_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ (v : tls_vec.TlsByteVecU32) (t : Slice Std.U8), r = .Ok (v, t) →
        t.val.length + 4 + v.vec.val.length = bytes.val.length ⌝ ⦄ :=
  triple_post_mono (tls_vec.TlsByteVecU32.deserialize_char_le bytes) fun _ h v t hr => (h v t hr).1

/-! #### `TlsByteVecU24` -/

/-- `TlsByteVecU24::deserialize_bytes_bytes` is the generic one. -/
theorem tls_vec.TlsByteVecU24.deserialize_bytes_bytes_eq : tls_vec.TlsByteVecU24.deserialize_bytes_bytes =
    TlsByteVecGen.deser tls_vec.TlsByteVecU24.mk U24.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
      (core.convert.TryFromTUInfallible.Blanket.try_from
        (core.convert.Into.Blanket Usize.Insts.CoreConvertFromU24))
      core.convert.Infallible.Insts.CoreFmtDebug 3#usize := by
  funext bytes
  unfold tls_vec.TlsByteVecU24.deserialize_bytes_bytes TlsByteVecGen.deser
  congr 1; funext r; congr 1; funext cf; cases cf <;> rfl

/-- The big-endian value of a 3-byte prefix. -/
def U24.pval (a : Aeneas.Std.Array Std.U8 3#usize) : Nat :=
  a.val[0]!.val * 65536 + a.val[1]!.val * 256 + a.val[2]!.val

/-- `usize::try_from(U24)` (blanket `Into` impl) never fails: it is `Ok` of `U24.pval`. -/
theorem core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U24_val (x : Aeneas.Std.Array Std.U8 3#usize) :
    ⦃ ⌜ True ⌝ ⦄
    core.convert.TryFromTUInfallible.Blanket.try_from
      (core.convert.Into.Blanket Usize.Insts.CoreConvertFromU24) x
    ⦃ ⇓ r => ⌜ ∃ y, r = .Ok y ∧ y.val = U24.pval x ⌝ ⦄ :=
  triple_post_mono (core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U24_content x)
    fun _ ⟨y, hy, hh⟩ => ⟨y, hy, by
      have hl : x.val.length = 3 := by simpa using x.property
      match hx : x.val, hl with
      | [b0, b1, b2], _ => rw [hh b0 b1 b2 hx]; simp [U24.pval, hx]⟩

/-- `TlsByteVecU24::deserialize_bytes_bytes` never panics; on success the input is the 3-byte length prefix, the payload, then the remainder. -/
theorem tls_vec.TlsByteVecU24.deserialize_content (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU24.deserialize_bytes_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ (v : tls_vec.TlsByteVecU24) (t : Slice Std.U8), r = .Ok (v, t) →
        ∃ b0 b1 b2 : Std.U8, b0.val * 65536 + b1.val * 256 + b2.val = v.vec.val.length ∧
          bytes.val = b0 :: b1 :: b2 :: (v.vec.val ++ t.val) ⌝ ⦄ := by
  rw [tls_vec.TlsByteVecU24.deserialize_bytes_bytes_eq]
  have hread := TlsByteVecGen.prefix_split (U := Aeneas.Std.Array Std.U8 3#usize) 3
    (fun a => a.val) (f := id) (fun _ => rfl) U24_deserialize_char
  refine total_of_pf_partial
    (TlsByteVecGen.pf _ _ _ (fun b => pf_of_total (hread b)) _ (fun p =>
      triple_post_mono (core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U24_val p)
        fun _ ⟨y, hy, _⟩ => ⟨y, hy⟩) _ bytes) ?_
  refine partial_triple_of_ok fun r hr => ?_
  intro v t hv
  obtain ⟨p, hp, hb⟩ := ok_of_partial_triple
    (TlsByteVecGen.content tls_vec.TlsByteVecU24.vec _ (fun _ => rfl) (fun a => a.val) U24.pval 3#usize
      (fun a => a.property) _ hread _
      (fun p => partial_of_total (core.convert.TryFromTUInfallible.Blanket.try_from_Usize_U24_val p)) _ bytes) hr v t hv
  have hl : p.val.length = 3 := by simpa using p.property
  match hx : p.val, hl with
  | [b0, b1, b2], _ => exact ⟨b0, b1, b2, by simpa [U24.pval, hx] using hp, by simpa [hx] using hb⟩

/-- `TlsByteVecU24::deserialize_bytes_bytes` returns; on success the remainder plus the length prefix plus the payload is the input, and the payload is within the prefix bound. -/
theorem tls_vec.TlsByteVecU24.deserialize_char_le (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU24.deserialize_bytes_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ (v : tls_vec.TlsByteVecU24) (t : Slice Std.U8), r = .Ok (v, t) →
        t.val.length + 3 + v.vec.val.length = bytes.val.length ∧
          v.vec.val.length ≤ 16777215 ⌝ ⦄ :=
  triple_post_mono (tls_vec.TlsByteVecU24.deserialize_content bytes) fun _ h v t hr => by
    obtain ⟨b0, b1, b2, hl, hb⟩ := h v t hr
    have := congrArg List.length hb
    simp only [List.length_cons, List.length_append] at this
    have := b0.hmax; have := b1.hmax; have := b2.hmax
    refine ⟨by omega, ?_⟩
    scalar_tac

theorem tls_vec.TlsByteVecU24.deserialize_char (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU24.deserialize_bytes_bytes bytes
    ⦃ ⇓ r => ⌜ ∀ (v : tls_vec.TlsByteVecU24) (t : Slice Std.U8), r = .Ok (v, t) →
        t.val.length + 3 + v.vec.val.length = bytes.val.length ⌝ ⦄ :=
  triple_post_mono (tls_vec.TlsByteVecU24.deserialize_char_le bytes) fun _ h v t hr => (h v t hr).1

/-- Partial form of `deserialize_char`. -/
theorem tls_vec.TlsByteVecU24.deserialize_char_partial (bytes : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ tls_vec.TlsByteVecU24.deserialize_bytes_bytes bytes
    ⦃ ⇓? r => ⌜ ∀ (v : tls_vec.TlsByteVecU24) (t : Slice Std.U8), r = .Ok (v, t) →
        t.val.length + 3 + v.vec.val.length = bytes.val.length ⌝ ⦄ :=
  partial_of_total (tls_vec.TlsByteVecU24.deserialize_char bytes)

end tls_codec
