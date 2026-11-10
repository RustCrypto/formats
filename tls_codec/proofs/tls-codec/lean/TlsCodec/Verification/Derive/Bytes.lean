/- Generic lemmas and tactics for the per-impl `Lawful` obligations of the impls the `tls_codec`
derives emit (`TlsSize`, `TlsSerializeBytes`, `TlsDeserializeBytes`, `PartialEq`) and of the
`RoundTrip` / `NonEmpty` impls, in any crate that uses them. Entry
points: `derive_size_lawful`, `derive_ser_lawful`, `derive_deser_lawful`, `derive_eq_lawful`,
`derive_rt_lawful`, `derive_ne_lawful`.

Obligations: none in TlsCodec; the downstream projects' derive obligations are one call each.
Axioms reached (`scripts/axiom_whitelist.txt`): ASSUMED `append_bytes_spec`; 1 signature-only stub
(`append_bytes`). -/
import Aeneas
import CoreModels
import Hax
import TlsCodec.Extraction
import TlsCodec.Verification.Helpers
import TlsCodec.Verification.Helpers.RoundTrip
import TlsCodec.Verification.Derive.SimpAttr
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

/-! ## Core operations of the derived serializers -/

/-- `Vec::with_capacity` (CoreModels: an empty vector; the capacity is not modelled). -/
theorem vec_with_capacity_spec (T : Type) (c : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.with_capacity T c ⦃ ⇓ r => ⌜ (r : Slice T).val = [] ⌝ ⦄ := by
  mvcgen [alloc.vec.Vec.with_capacity, alloc.vec.Vec.new_spec]
  simp_all [Slice.new]

/-- `Vec::append`: the concatenation, when it fits in a `usize`. -/
theorem vec_append_spec {T : Type} (a b : alloc.vec.Vec T) :
    ⦃ ⌜ (a : Slice T).val.length + (b : Slice T).val.length ≤ Std.Usize.max ⌝ ⦄
    alloc.vec.Vec.append a b
    ⦃ ⇓ r => ⌜ (r.1 : Slice T).val = (a : Slice T).val ++ (b : Slice T).val ⌝ ⦄ := by
  apply triple_pre_prop; intro h
  mvcgen [alloc.vec.Vec.append, rust_primitives.sequence.seq_concat]
  rename_i hc
  simp +zetaDelta only [List.length_append] at hc
  omega

/-- `Vec::append`, partial (for the `⇓?` triples of the round-trip proofs: no fit condition). -/
theorem vec_append_spec_partial {T : Type} (a b : alloc.vec.Vec T) :
    ⦃ ⌜ True ⌝ ⦄ alloc.vec.Vec.append a b
    ⦃ ⇓? r => ⌜ (r.1 : Slice T).val = (a : Slice T).val ++ (b : Slice T).val ⌝ ⦄ := by
  mvcgen [alloc.vec.Vec.append, rust_primitives.sequence.seq_concat]

/-! ## The crate's length helpers

The derived `Size` sums go through `tls_codec::len_add` and the derived serializers append
through `tls_codec::append_bytes` (`len_add` extracted, its specs theorems; `append_bytes`
opaque with an ASSUMED spec, TlsCodec's
`Assumptions/CrateAssumptions.lean`). Restated here in the flat form of the field facts. -/

/-- `len_add`: total; the exact sum when it fits (from `len_add_spec`, a theorem). -/
theorem len_add_flat (a b : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ len_add a b
    ⦃ ⇓ r => ⌜ a.val + b.val ≤ Std.Usize.max → r.val = a.val + b.val ⌝ ⦄ := by
  obtain ⟨r, hr, h⟩ := len_add_spec a b
  rw [hr]; apply RustM.ok_spec; exact h

/-- `append_bytes`: total; an `Ok` result is the concatenation, which fits (from the ASSUMED
`append_bytes_spec`). -/
theorem append_bytes_flat (out b : alloc.vec.Vec Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ append_bytes out b
    ⦃ ⇓ r => ⌜ r.1 = .Ok () → (r.2 : Slice Std.U8).val = (out : Slice Std.U8).val ++ (b : Slice Std.U8).val ∧
      (out : Slice Std.U8).val.length + (b : Slice Std.U8).val.length ≤ Std.Usize.max ⌝ ⦄ := by
  by_cases h : (out : Slice Std.U8).val.length + (b : Slice Std.U8).val.length ≤ Std.Usize.max
  · obtain ⟨v, hv, hc⟩ := (append_bytes_spec out b).1 h
    rw [hv]; apply RustM.ok_spec; intro _; exact ⟨hc, h⟩
  · rw [(append_bytes_spec out b).2 (by omega)]; apply RustM.ok_spec; intro h'; cases h'

/-! ## Field facts from a field type's `Lawful`

The derived code calls each field's codec method directly. The triples below restate a field
type's trait-level contracts in a flat form for `mvcgen` (`have h := ser_spec hlaw` then
`mvcgen [d, h]`): sizes are named by the pure value `szv Sz x` (the result of the total call
`Sz.tls_serialized_len x`), so that after `mvcgen` every fact is an equation between values. -/

/-- The value of a `Size` call, when it returns one (it always does under `Size.Lawful`). -/
noncomputable def szv {T : Type} (Sz : Size T) (x : T) : Std.Usize :=
  open Classical in if h : ∃ n, Sz.tls_serialized_len x = ok n then h.choose else 0#usize

theorem szv_eq {T : Type} {Sz : Size T} {x : T} {n : Std.Usize}
    (h : Sz.tls_serialized_len x = ok n) : szv Sz x = n := by
  have h' : ∃ n, Sz.tls_serialized_len x = ok n := ⟨n, h⟩
  unfold szv; rw [dif_pos h']; exact ok.inj (h'.choose_spec.symm.trans h)

theorem size_ok {T : Type} {Sz : Size T} (h : Size.Lawful T Sz) (x : T) :
    Sz.tls_serialized_len x = ok (szv Sz x) := by
  obtain ⟨n, hn, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (h.tls_serialized_len_spec x (pre_holds_of_ok_true rfl))
  rw [hn, szv_eq hn]

/-- A `Size` call returns `szv`. -/
theorem size_spec {T : Type} {Sz : Size T} (h : Size.Lawful T Sz) (x : T) :
    ⦃ ⌜ True ⌝ ⦄ Sz.tls_serialized_len x ⦃ ⇓ n => ⌜ n = szv Sz x ⌝ ⦄ := by
  rw [size_ok h x]; apply RustM.ok_spec; rfl

/-- "An `Ok` output has `n` bytes" (`Err` says nothing). -/
def OkLen (r : core.result.Result (alloc.vec.Vec Std.U8) tls_codec.Error) (n : Nat) : Prop :=
  ∀ b, r = .Ok b → (b : Slice Std.U8).val.length = n

@[simp] theorem OkLen_ok (b : alloc.vec.Vec Std.U8) (n : Nat) :
    OkLen (.Ok b) n ↔ (b : Slice Std.U8).val.length = n := by
  simp [OkLen]

@[simp] theorem OkLen_err (e : tls_codec.Error) (n : Nat) : OkLen (.Err e) n ↔ True := by
  simp [OkLen]

/-- "An `Ok (v, rem)` consumed `szv v` bytes of `s`, and `rem` is a suffix of `s`". -/
def OkRem {T : Type} (Sz : Size T) (s : Slice Std.U8)
    (r : core.result.Result (T × Slice Std.U8) tls_codec.Error) : Prop :=
  ∀ v rem, r = .Ok (v, rem) → rem.val.length + (szv Sz v).val = s.val.length ∧ rem.val <:+ s.val

@[simp] theorem OkRem_ok {T : Type} (Sz : Size T) (s : Slice Std.U8) (p : T × Slice Std.U8) :
    OkRem Sz s (.Ok p) ↔ p.2.val.length + (szv Sz p.1).val = s.val.length ∧ p.2.val <:+ s.val := by
  obtain ⟨v, rem⟩ := p; simp [OkRem]

@[simp] theorem OkRem_err {T : Type} (Sz : Size T) (s : Slice Std.U8) (e : tls_codec.Error) :
    OkRem Sz s (.Err e) ↔ True := by
  simp [OkRem]

/-- A serializer call returns `ok r`; an `Ok b` has `szv` bytes. -/
theorem ser_spec {T : Type} {S : SerializeBytes T} (h : SerializeBytes.Lawful T S) (x : T) :
    ⦃ ⌜ True ⌝ ⦄ S.tls_serialize_bytes x ⦃ ⇓ r => ⌜ OkLen r (szv S.SizeInst x).val ⌝ ⦄ := by
  obtain ⟨r, hr, hp⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (h.tls_serialize_bytes_spec x (pre_holds_of_ok_true rfl))
  rw [hr]; apply RustM.ok_spec
  intro b hb
  obtain ⟨n, hn, hl⟩ := SerializeBytes.post_ok_elim _ _ _ _ (hb ▸ hp)
  rw [szv_eq hn, hl]

/-- A deserializer call returns `ok r`; an `Ok (v, rem)` consumed `szv v` bytes. -/
theorem deser_spec {T : Type} {D : DeserializeBytes T} (h : DeserializeBytes.Lawful T D)
    (s : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ D.tls_deserialize_bytes s ⦃ ⇓ r => ⌜ OkRem D.SizeInst s r ⌝ ⦄ := by
  obtain ⟨r, hr, hp⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (h.tls_deserialize_bytes_spec s (pre_holds_of_ok_true rfl))
  rw [hr]; apply RustM.ok_spec
  intro v rem hv
  obtain ⟨n, hn, hl⟩ := DeserializeBytes.post_ok_elim _ _ _ _ _ (hv ▸ hp)
  exact ⟨by rw [szv_eq hn, hl], DeserializeBytes.post_ok_suffix _ _ _ _ _ (hv ▸ hp)⟩

/-! ### Constant sizes (`szv_simps`) -/

@[szv_simps] theorem szv_U8 (x : Std.U8) : szv U8.Insts.Tls_codecSize x = 1#usize := szv_eq rfl
@[szv_simps] theorem szv_U16 (x : Std.U16) : szv U16.Insts.Tls_codecSize x = 2#usize := szv_eq rfl
@[szv_simps] theorem szv_U32 (x : Std.U32) : szv U32.Insts.Tls_codecSize x = 4#usize := szv_eq rfl
@[szv_simps] theorem szv_U64 (x : Std.U64) : szv U64.Insts.Tls_codecSize x = 8#usize := szv_eq rfl

/-- The trait-level post of `tls_serialize_bytes` on `Ok out`, from a size triple. -/
theorem ser_post_ok {T : Type} (Sz : Size T) (S : SerializeBytes T) (x : T)
    (out : alloc.vec.Vec Std.U8)
    (hsz : ⦃ ⌜ True ⌝ ⦄ Sz.tls_serialized_len x ⦃ ⇓ n => ⌜ n.val = (out : Slice Std.U8).val.length ⌝ ⦄) :
    (SerializeBytes.tls_serialize_bytes.post Sz S x (.Ok out)).holds := by
  obtain ⟨n, hn, hl⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp hsz
  exact SerializeBytes.post_ok _ _ _ _ n hn hl.symm

/-- The trait-level post of `tls_serialize_bytes` on any result whose `Ok` has `n` bytes, from a
size triple (for a serializer that passes another one's result through). -/
theorem ser_post_of_oklen {T : Type} (Sz : Size T) (S : SerializeBytes T) (x : T)
    (r : core.result.Result (alloc.vec.Vec Std.U8) tls_codec.Error) (n : Nat)
    (hsz : ⦃ ⌜ True ⌝ ⦄ Sz.tls_serialized_len x ⦃ ⇓ m => ⌜ m.val = n ⌝ ⦄) (h : OkLen r n) :
    (SerializeBytes.tls_serialize_bytes.post Sz S x r).holds := by
  cases r with
  | Err e => exact SerializeBytes.post_err _ _ _ _
  | Ok b => exact ser_post_ok _ _ _ _ (triple_post_mono hsz fun m hm => by rw [hm, (OkLen_ok b n).mp h])

/-- The trait-level post of `tls_deserialize_bytes` on `Ok (v, rem)`, from a suffix fact and a
size triple (in this order: the suffix goal comes first after `apply`). -/
theorem deser_post_ok {T : Type} (Sz : Size T) (D : DeserializeBytes T) (s : Slice Std.U8) (v : T)
    (rem : Slice Std.U8) (hsuf : rem.val <:+ s.val)
    (hsz : ⦃ ⌜ True ⌝ ⦄ Sz.tls_serialized_len v ⦃ ⇓ n => ⌜ rem.val.length + n.val = s.val.length ⌝ ⦄) :
    (DeserializeBytes.tls_deserialize_bytes.post Sz D s (.Ok (v, rem))).holds := by
  obtain ⟨n, hn, hl⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp hsz
  exact DeserializeBytes.post_ok _ _ _ _ _ n hn hl hsuf

/-- The provided `tls_deserialize_exact_bytes` meets its trait-level spec when
`tls_deserialize_bytes` does. -/
theorem exact_bytes_spec {T : Type} (D : DeserializeBytes T)
    (hd : ∀ b, ⦃ ⌜ True ⌝ ⦄ D.tls_deserialize_bytes b
      ⦃ ⇓ r => ⌜ (DeserializeBytes.tls_deserialize_bytes.post D.SizeInst D b r).holds ⌝ ⦄)
    (b : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ DeserializeBytes.tls_deserialize_exact_bytes.default D b
    ⦃ ⇓ r => ⌜ (DeserializeBytes.tls_deserialize_exact_bytes.post D.SizeInst D b r).holds ⌝ ⦄ :=
  total_of_pf_partial (DeserializeBytes.exact_default_pf D (fun b => pf_of_total (hd b)) b)
    (DeserializeBytes.exact_default_fc D b (partial_of_total (hd b)))

/-! ## Round trips: the decoding fact `Dec`

`Dec D x b`: on any input that starts with `b`, the deserializer `D` returns `x` and the rest.
A field type's `RoundTrip.Lawful` gives `Dec` for every `Ok` output of its serializer
(`ser_dec_spec`); a derived struct's `Dec` follows by running its deserializer on the
concatenation, one field at a time (`dec_spec` + `dec_forward`). Both triples are
value-agnostic, so fields of the same type do not confuse `mvcgen`. -/

def Dec {T : Type} (D : DeserializeBytes T) (x : T) (b : List Std.U8) : Prop :=
  ∀ (s : Slice Std.U8) (R : List Std.U8), s.val = b ++ R →
    ∃ s' : Slice Std.U8, D.tls_deserialize_bytes s = ok (.Ok (x, s')) ∧ s'.val = R

/-- From `RoundTrip.Lawful`: an `Ok b` of the serializer decodes back (TlsCodec's `Lawful.dec`). -/
theorem Dec_of_lawful {T : Type} {RT : spec.RoundTrip T} (hl : spec.RoundTrip.Lawful T RT)
    (x : T) (b : alloc.vec.Vec Std.U8)
    (hb : RT.SerializeBytesInst.tls_serialize_bytes x = ok (.Ok b)) :
    Dec RT.DeserializeBytesInst x (b : Slice Std.U8).val := by
  intro s R hs
  have hR : R.length ≤ Std.Usize.max := by
    have := s.property; rw [hs, List.length_append] at this; omega
  have hlen : (b : Slice Std.U8).val.length + R.length ≤ Std.Usize.max := by
    have := s.property; rw [hs, List.length_append] at this; omega
  obtain ⟨r, hr, hp⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (hl.dec x ⟨R, hR⟩ b hb hlen s)
  obtain ⟨p, rfl, h1, h2⟩ := hp hs
  obtain ⟨v, s'⟩ := p
  simp only at h1 h2
  subst h1
  exact ⟨s', hr, h2⟩

/-- The `∃` of `Dec`, from a total triple. -/
theorem dec_of_triple {T : Type} {m : RustM (core.result.Result (T × Slice Std.U8) tls_codec.Error)}
    {x : T} {R : List Std.U8}
    (h : ⦃ ⌜ True ⌝ ⦄ m ⦃ ⇓ r => ⌜ ∃ s' : Slice Std.U8, r = .Ok (x, s') ∧ s'.val = R ⌝ ⦄) :
    ∃ s' : Slice Std.U8, m = ok (.Ok (x, s')) ∧ s'.val = R := by
  obtain ⟨r, hr, s', rfl, hs'⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp h
  exact ⟨s', hr, hs'⟩

/-- Scalar equality by value (for the decoded discriminant against the `match` literals). -/
theorem uscalar_eq_iff {ty : UScalarTy} (a b : UScalar ty) : a = b ↔ a.val = b.val :=
  ⟨congrArg _, UScalar.eq_of_val_eq⟩

/-- The value of a `match` literal `n#w#uscalar`. -/
theorem uscalar_mk_val {ty : UScalarTy} (bv : BitVec ty.numBits) : (UScalar.mk bv).val = bv.toNat :=
  rfl

/-- "An `Ok b` has `n` bytes and decodes back to `x`". -/
def OkDec {T : Type} (D : DeserializeBytes T) (x : T)
    (r : core.result.Result (alloc.vec.Vec Std.U8) tls_codec.Error) (n : Nat) : Prop :=
  ∀ b, r = .Ok b → (b : Slice Std.U8).val.length = n ∧ Dec D x (b : Slice Std.U8).val

@[simp] theorem OkDec_ok {T : Type} (D : DeserializeBytes T) (x : T) (b : alloc.vec.Vec Std.U8)
    (n : Nat) : OkDec D x (.Ok b) n ↔ (b : Slice Std.U8).val.length = n ∧ Dec D x (b : Slice Std.U8).val := by
  simp [OkDec]

@[simp] theorem OkDec_err {T : Type} (D : DeserializeBytes T) (x : T) (e : tls_codec.Error)
    (n : Nat) : OkDec D x (.Err e) n ↔ True := by
  simp [OkDec]

/-- A field serializer call, for round trips: an `Ok b` has `szv` bytes and decodes back. -/
theorem ser_dec_spec {T : Type} {RT : spec.RoundTrip T} (hl : spec.RoundTrip.Lawful T RT) (x : T) :
    ⦃ ⌜ True ⌝ ⦄ RT.SerializeBytesInst.tls_serialize_bytes x
    ⦃ ⇓ r => ⌜ OkDec RT.DeserializeBytesInst x r (szv RT.SerializeBytesInst.SizeInst x).val ⌝ ⦄ := by
  obtain ⟨r, hr, hp⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (ser_spec hl.SerializeBytesInstLawful x)
  rw [hr]; apply RustM.ok_spec
  intro b hb
  subst hb
  exact ⟨(OkLen_ok _ _).mp hp, Dec_of_lawful hl x b hr⟩

/-- A field deserializer call, for round trips: on an input `b ++ R` with `Dec D x b`, it
returned `x` and `R`. -/
theorem dec_spec {T : Type} {D : DeserializeBytes T} (h : DeserializeBytes.Lawful T D)
    (s : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ D.tls_deserialize_bytes s
    ⦃ ⇓ r => ⌜ ∀ (b R : List Std.U8) (x : T), s.val = b ++ R → Dec D x b →
      ∃ s' : Slice Std.U8, r = .Ok (x, s') ∧ s'.val = R ⌝ ⦄ := by
  obtain ⟨r, hr, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (h.tls_deserialize_bytes_spec s (pre_holds_of_ok_true rfl))
  rw [hr]; apply RustM.ok_spec
  intro b R x hs hd
  obtain ⟨s', hs', hR⟩ := hd s R hs
  exact ⟨s', ok.inj (hr.symm.trans hs'), hR⟩

open Lean Elab Tactic Meta in
/-- Instantiate the `dec_spec` facts left by `mvcgen` (`∀ b R x, s = b ++ R → Dec D x b → …`):
the first premise by the input-shape hypothesis `s = b ++ R` (which fixes `b` as a prefix, so
same-type fields are told apart), the second by the matching `Dec` fact. Each used fact is
cleared; repeats until none applies. -/
elab "dec_forward" : tactic => do
  let mut progress := true
  while progress do
    progress := false
    if (← getGoals).isEmpty then break
    let g ← getMainGoal
    let hyps ← g.withContext do
      let lctx ← getLCtx
      return lctx.foldl (init := #[]) fun acc d =>
        if !d.isImplementationDetail && d.type.isForall &&
            (d.type.find? (fun e => e.isConstOf ``Dec)).isSome then acc.push d.fvarId else acc
    for h in hyps do
      let ok ← g.withContext do
        let s ← saveState
        try
          let t ← Term.exprToSyntax (mkFVar h)
          -- `withoutErrToSorry`: a failed `assumption` must throw, not become `sorry`
          Term.withoutErrToSorry <|
            evalTactic (← `(tactic| obtain ⟨_, _, _⟩ := $t _ _ _ (by assumption) (by assumption)))
          (← getMainGoal).withContext do
            evalTactic (← `(tactic| clear $t))
          evalTactic (← `(tactic| try simp only [core.result.Result.Ok.injEq, reduceCtorEq] at *))
          evalTactic (← `(tactic| try subst_vars))
          pure true
        catch _ => s.restore; pure false
      if ok then progress := true; break

/-- The `RoundTrip` lemma method of the OpenMLS copies (`fn round_trip(&self, _rest) {}`). -/
theorem rt_of_dec {T : Type} (RT : spec.RoundTrip T)
    (hS : SerializeBytes.Lawful T RT.SerializeBytesInst)
    (hD : DeserializeBytes.Lawful T RT.DeserializeBytesInst)
    (hE : core.cmp.PartialEq.Lawful T T RT.corecmpPartialEqInst)
    (hrt : ∀ x rest, RT.round_trip x rest = ok ())
    (x : T) (rest : Slice Std.U8)
    (hpre : (spec.RoundTrip.round_trip.pre RT.SerializeBytesInst RT.DeserializeBytesInst
      RT.corecmpPartialEqInst RT x rest).holds)
    (hdec : ⦃ ⌜ True ⌝ ⦄ RT.SerializeBytesInst.tls_serialize_bytes x
      ⦃ ⇓? r => ⌜ ∀ b, r = .Ok b → Dec RT.DeserializeBytesInst x (b : Slice Std.U8).val ⌝ ⦄) :
    ⦃ ⌜ True ⌝ ⦄ RT.round_trip x rest
    ⦃ ⇓ res => ⌜ (spec.RoundTrip.round_trip.post RT.SerializeBytesInst RT.DeserializeBytesInst
      RT.corecmpPartialEqInst RT x rest res).holds ⌝ ⦄ := by
  have hser := hS.tls_serialize_bytes_spec x (pre_holds_of_ok_true rfl)
  have hfc := spec.RoundTrip.round_trip.default_fc_enc_total RT x rest
    (fun v => Dec RT.DeserializeBytesInst x (v : Slice Std.U8).val) hpre
    (triple_post_mono (hE.eq_spec x x) fun _ h => h.mpr HEq.rfl)
    (pf_of_total hser) (partial_of_total hser) hdec
    (fun v s hv hs => by
      obtain ⟨s', hd, hR⟩ := hv s rest.val hs
      rw [hd]; apply RustM.ok_spec; exact ⟨_, rfl, rfl, hR⟩)
  have he : RT.round_trip x rest = spec.RoundTrip.round_trip.default x rest := by
    rw [hrt]; rfl
  rw [he]
  exact total_of_pf_partial (spec.RoundTrip.round_trip.default_pf x rest) hfc

/-! ## Non-empty encodings -/

/-- "An `Ok b` has `n` bytes, at least one". -/
def OkLenPos (r : core.result.Result (alloc.vec.Vec Std.U8) tls_codec.Error) (n : Nat) : Prop :=
  ∀ b, r = .Ok b → (b : Slice Std.U8).val.length = n ∧ 0 < (b : Slice Std.U8).val.length

@[simp] theorem OkLenPos_ok (b : alloc.vec.Vec Std.U8) (n : Nat) :
    OkLenPos (.Ok b) n ↔ (b : Slice Std.U8).val.length = n ∧ 0 < (b : Slice Std.U8).val.length := by
  simp [OkLenPos]

@[simp] theorem OkLenPos_err (e : tls_codec.Error) (n : Nat) : OkLenPos (.Err e) n ↔ True := by
  simp [OkLenPos]

/-- A `NonEmpty` field's serializer call: an `Ok b` has `szv` bytes, at least one. -/
theorem ser_ne_spec {T : Type} {NE : spec.NonEmpty T} (h : spec.NonEmpty.Lawful T NE) (x : T) :
    ⦃ ⌜ True ⌝ ⦄ NE.RoundTripInst.SerializeBytesInst.tls_serialize_bytes x
    ⦃ ⇓ r => ⌜ OkLenPos r (szv NE.RoundTripInst.SerializeBytesInst.SizeInst x).val ⌝ ⦄ := by
  obtain ⟨r, hr, hp⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (ser_spec h.RoundTripInstLawful.SerializeBytesInstLawful x)
  rw [hr]; apply RustM.ok_spec
  intro b hb
  subst hb
  exact ⟨(OkLen_ok _ _).mp hp, h.ser_pos x b hr⟩

/-- `NonEmpty.Lawful` of a copy (lemma method overridden by `ok ()`) from the positivity of
its serializer's `Ok` outputs. -/
theorem ne_of_pos {T : Type} (NE : spec.NonEmpty T) (hrt : spec.RoundTrip.Lawful T NE.RoundTripInst)
    (hne : ∀ x, NE.nonempty x = ok ())
    (hpos : ∀ x, ⦃ ⌜ True ⌝ ⦄ NE.RoundTripInst.SerializeBytesInst.tls_serialize_bytes x
      ⦃ ⇓? r => ⌜ ∀ v, r = .Ok v → 0 < v.val.length ⌝ ⦄) :
    spec.NonEmpty.Lawful T NE := by
  refine ⟨hrt, fun x _ => ?_⟩
  have hpf := pf_of_total
    (hrt.SerializeBytesInstLawful.tls_serialize_bytes_spec x (pre_holds_of_ok_true rfl))
  have he : NE.nonempty x = spec.NonEmpty.nonempty.default x := by rw [hne]; rfl
  rw [he]
  exact total_of_pf_partial (spec.NonEmpty.nonempty.default_pf x)
    (spec.NonEmpty.nonempty.default_fc NE.RoundTripInst NE x hpf (hpos x))

/-! ## Tactics, one per obligation kind

Each takes `[ds]`, the derived definitions to unfold (the method itself and the derived size
defs it calls, e.g. `Shared0X.Insts.Tls_codecSize.tls_serialized_len`), and `[Ls]`, the fields'
`Lawful` theorems (applied, for a generic field type: `(alloc.vec.Vec.….Lawful _ L)`). Each
`L` gives `mvcgen` the flat triple of `size_spec` / `ser_spec` / `deser_spec`. A field type
of constant size also needs its `szv` value (`szv_U64` …, the `@[simp]` lemmas below). -/

/-- TlsCodec's global `@[spec]`s on field methods (exact bytes, `decide` forms). `mvcgen` prefers
them over the local field facts, whose flat shape the closing tactics expect, so every derive
tactic erases them. -/
def conflictSpecs : Array Lean.Name := #[
  `tls_codec.ArrayU8LEN.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes_spec,
  `tls_codec.U8_serialize_char, `tls_codec.U16_serialize_char, `tls_codec.U32_serialize_char,
  `tls_codec.U64_serialize_char, `tls_codec.U24_serialize_char, `tls_codec.ArrayU8LEN_serialize_char,
  `tls_codec.Array_U8_eq_spec, `tls_codec.alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq_U8_spec,
  `tls_codec.alloc.vec.Vec.Insts.CoreCmpPartialEqVec.eq_U16_spec,
  `tls_codec.tls_vec.TlsByteVecU8.Insts.CoreCmpPartialEqTlsByteVecU8.eq_spec,
  `tls_codec.tls_vec.TlsByteVecU16.Insts.CoreCmpPartialEqTlsByteVecU16.eq_spec,
  `tls_codec.tls_vec.TlsByteVecU24.Insts.CoreCmpPartialEqTlsByteVecU24.eq_spec,
  `tls_codec.tls_vec.TlsByteVecU32.Insts.CoreCmpPartialEqTlsByteVecU32.eq_spec,
  `tls_codec.quic_vec.VLBytes.Insts.CoreCmpPartialEqVLBytes.eq_decide_spec,
  -- pins `len_add`'s result as `lenAddVal a b`; the derive tactics use `len_add_flat` instead
  `tls_codec.len_add_triple,
  `CoreModels.core.Array.Insts.CoreCmpPartialEqArray.eq_spec]

/-- The element kind of `mvcgen`'s lemma list. -/
abbrev MvArg := Lean.TSyntax [`Lean.Parser.Tactic.simpStar, `Lean.Parser.Tactic.simpErase,
  `Lean.Parser.Tactic.simpLemma]

/-- `mvcgen`'s list from user arguments `ds` and local fact names `ns`. -/
def mvArgs (ds : Array MvArg) (ns : Array Lean.Ident) :
    Lean.MacroM (Array MvArg) := do
  let ns ← ns.mapM fun n => do
    let l ← `(Lean.Parser.Tactic.simpLemma| $n:term)
    pure (⟨l.raw⟩ : MvArg)
  let es ← conflictSpecs.mapM fun n => do
    let e ← `(Lean.Parser.Tactic.simpErase| -$(Lean.mkIdent n):ident)
    pure (⟨e.raw⟩ : MvArg)
  let ks ← #[``CoreModels.core.mem.size_of_U8, ``CoreModels.core.mem.size_of_U16,
      ``len_add_flat, ``append_bytes_flat].mapM fun n => do
    let l ← `(Lean.Parser.Tactic.simpLemma| $(Lean.mkIdent n):term)
    pure (⟨l.raw⟩ : MvArg)
  pure (es ++ ks ++ ds ++ ns)

/-- `have n₀ := f l₀; …` (or `skip` when empty); `f` maps a field `Lawful` term to the fact. -/
def haves (ns : Array Lean.Ident) (ls : Array Lean.Term) (f : Lean.Term → Lean.MacroM Lean.Term) :
    Lean.MacroM (Lean.TSyntax `tactic) := do
  if ns.isEmpty then `(tactic| skip) else
  let ts ← (ns.zip ls).mapM fun (n, l) => do
    let t ← f l
    `(tactic| have $n := $t)
  `(tactic| ($[$ts];*))

/-- Fresh names `<p>0 …`. -/
def freshNames (p : String) (n : Nat) : Array Lean.Ident :=
  (Array.range n).map fun i => Lean.mkIdent (Lean.Name.mkSimple s!"{p}{i}")

/-- Close the VCs left by `mvcgen` on derived code: `?` breaks, `tryCF` continues, the
`OkLen` / `OkRem` facts of `Ok` results, then arithmetic. -/
macro "derive_vcs" : tactic => `(tactic| (
  all_goals (first | (apply try_break_vc; intro e he; (try subst he); mvcgen) | skip)
  all_goals (try simp only [continue_eq_tryCF] at *)
  all_goals (try subst_vars)
  all_goals (try simp only [OkLen_ok, OkRem_ok, OkDec_ok, szv_simps] at *)
  all_goals (try casesm* _ ∧ List.IsSuffix _ _)))

open Lean Elab Tactic in
/-- `scalar_tac`, with its runtime exceptions (e.g. "maximum recursion depth", hit on some goals with
`saturating_add`) turned into ordinary failures, so that `first` can try the next alternative
(`first` does not catch runtime exceptions). -/
elab "safe_scalar_tac" : tactic => do
  let s ← saveState
  tryCatchRuntimeEx (evalTactic (← `(tactic| scalar_tac))) fun e => do
    s.restore
    throwError "safe_scalar_tac: {e.toMessageData}"

/-- Arithmetic closer of the derive tactics (`isize::MAX as usize` for the serializer guard). -/
macro "derive_arith" : tactic => `(tactic| (
  all_goals (have := tls_codec.Usize.hcast_Isize_MAX_val; first
    | safe_scalar_tac
    | (intros; subst_vars; simp only [uscalar_eq_iff, Slice.len_val, Slice.length] at *; omega)
    | (intros; subst_vars; safe_scalar_tac)
    | (simp only [*, List.length_append, List.length_nil, zero_add]; omega)
    | (simp_all only [List.length_append, List.length_nil, zero_add]; omega)
    | (simp_all only [List.length_append, List.length_nil, zero_add]; safe_scalar_tac)
    | (exfalso; safe_scalar_tac)
    -- the range checks of the discriminant constants (`n < repr::MIN || n > repr::MAX`)
    | (exfalso; simp [core.num.U8.MAX, core.num.U8.MIN, core.num.U16.MAX, core.num.U16.MIN,
         U8.rMax, U16.rMax] at *; all_goals safe_scalar_tac)
    | (exfalso; simp_all only [List.length_append, List.length_nil, zero_add]; safe_scalar_tac))))

/-- `Size.tls_serialized_len_spec` of a derived `Size` impl (`Ls`: the fields' `Size.Lawful`). -/
syntax "derive_size " "[" Lean.Parser.Tactic.simpArg,* "]" " [" term,* "]" : tactic
macro_rules
  | `(tactic| derive_size [$ds,*] [$ls,*]) => do
    let ls := ls.getElems
    let ns := freshNames "h_sz" ls.size
    let hs ← haves ns ls fun l => `(size_spec $l)
    let xs ← mvArgs ds.getElems ns
    `(tactic| (
      intro x _
      $hs:tactic
      mvcgen [$xs,*]
      derive_vcs
      derive_arith))

/-- `SerializeBytes.tls_serialize_bytes_spec` of a derived serializer (`Ls`: the fields'
`SerializeBytes.Lawful`; `ds` must contain the derived size defs, which are run twice: inline
by the serializer, and for the post). -/
syntax "derive_ser " "[" Lean.Parser.Tactic.simpArg,* "]" " [" term,* "]" : tactic
macro_rules
  | `(tactic| derive_ser [$ds,*] [$ls,*]) => do
    let ls := ls.getElems
    let ns := freshNames "h_ser" ls.size
    let ms := freshNames "h_sz" ls.size
    let hs ← haves ns ls fun l => `(ser_spec $l)
    let hm ← haves ms ls fun l => `(size_spec (SerializeBytes.Lawful.SizeInstLawful $l))
    let xs ← mvArgs ds.getElems ms
    let ys ← mvArgs ds.getElems (ns ++ ms ++ #[Lean.mkIdent ``vec_with_capacity_spec,
      Lean.mkIdent ``vec_append_spec])
    `(tactic| (
      intro x _
      $hs:tactic
      $hm:tactic
      mvcgen [$ys,*]
      derive_vcs
      all_goals (first
        | (apply ser_post_ok; mvcgen [$xs,*]; derive_vcs; derive_arith; done)
        | (intro h; apply ser_post_of_oklen _ _ _ _ _ _ h; mvcgen [$xs,*]; derive_vcs; derive_arith; done)
        | skip)
      derive_arith))

/-- Close `rem <:+ s` from a chain of suffix hypotheses `rem <:+ r₁`, `r₁ <:+ r₂`, …, `rₖ <:+ s`
(the remainders of the field deserializers, from `OkRem`). -/
syntax "suffix_chain" : tactic
macro_rules
  | `(tactic| suffix_chain) => `(tactic| first
    | exact List.suffix_refl _
    | assumption
    | (refine List.IsSuffix.trans (by assumption) ?_; suffix_chain))

/-- The suffix goal of `deser_post_ok`: split the conjunctions of the `OkRem` facts, then chain. -/
macro "derive_suffix" : tactic => `(tactic| (
  (try subst_vars)
  (try casesm* _ ∧ List.IsSuffix _ _)
  suffix_chain))

/-- `DeserializeBytes.tls_deserialize_bytes_spec` of a derived deserializer (`Ls`: the fields'
`DeserializeBytes.Lawful`; `ds`: the deserializer and the derived size defs, for the post). -/
syntax "derive_deser " "[" Lean.Parser.Tactic.simpArg,* "]" " [" term,* "]" : tactic
macro_rules
  | `(tactic| derive_deser [$ds,*] [$ls,*]) => do
    let ls := ls.getElems
    let ns := freshNames "h_des" ls.size
    let ms := freshNames "h_sz" ls.size
    let hs ← haves ns ls fun l => `(deser_spec $l)
    let hm ← haves ms ls fun l => `(size_spec (DeserializeBytes.Lawful.SizeInstLawful $l))
    let xs ← mvArgs ds.getElems ns
    let ys ← mvArgs ds.getElems ms
    `(tactic| (
      intro b _
      $hs:tactic
      $hm:tactic
      mvcgen [$xs,*]
      derive_vcs
      all_goals (first
        | (apply deser_post_ok; derive_suffix; mvcgen [$ys,*]; derive_vcs; derive_arith; done)
        | exact DeserializeBytes.post_err _ _ _ _
        | skip)
      derive_arith))

/-- `PartialEq.Lawful` of a derived `PartialEq` (`ds`: its `eq`, and for an enum the type's
`read_discriminant`; `Ls`: the `PartialEq.Lawful` of the fields compared through an instance; fields
of primitive type are compared with `=`). -/
syntax "derive_eq_lawful " "[" Lean.Parser.Tactic.simpArg,* "]" " [" term,* "]" : tactic
macro_rules
  | `(tactic| derive_eq_lawful [$ds,*] [$ls,*]) => do
    let ls := ls.getElems
    let ns := freshNames "h_eq" ls.size
    let hs ← haves ns ls fun l => `(CoreModels.core.cmp.PartialEq.Lawful.eq_spec $l)
    let xs ← mvArgs ds.getElems ns
    let ys ← mvArgs ds.getElems (ns.push (Lean.mkIdent ``CoreModels.core.cmp.PartialEq.ne.default))
    `(tactic| (
      $hs:tactic
      constructor
      · intro x y
        mvcgen [$xs,*]
        all_goals (cases x <;> cases y <;> simp +zetaDelta [read_discriminant, heq_iff_eq, $ds,*] at * <;>
          first | done | simp_all | decide)
      · intro x y
        mvcgen [$ys,*]
        -- mismatched variants of an enum with several data variants: the `panic` arm, absurd by `h`
        all_goals (first | done | (exfalso; subst_vars; simp +zetaDelta at *; done))))

/-- After the serializer's `mvcgen` in a round-trip proof: an `Ok b` decodes back. Normalises the
input shape `s = b₁ ++ (b₂ ++ … ++ R)`, runs `mvcgen` on the deserializer (`xs`: its def and the
fields' `dec_spec`s), then chains the field facts with `dec_forward`. -/
syntax "derive_dec_close " "[" Lean.Parser.Tactic.simpArg,* "]" : tactic
macro_rules
  | `(tactic| derive_dec_close [$xs,*]) => `(tactic| (
      intro b hb
      first
        | (cases hb; done)
        | (injection hb with hb
           subst hb
           intro s R hs
           try simp_all only [List.nil_append, List.append_assoc]
           apply dec_of_triple
           mvcgen [$xs,*]
           derive_vcs
           all_goals (try casesm* _ ∧ _)
           all_goals dec_forward
           all_goals (first
             | (exact ⟨_, rfl, rfl⟩)
             | (exfalso; simp only [uscalar_eq_iff, UScalar.cast_val_eq, uscalar_mk_val] at *
                (try simp at *); all_goals safe_scalar_tac)
             | (exact ⟨_, rfl, by assumption⟩)
             | (cases x <;> exact ⟨_, rfl, rfl⟩)
             | (intro _; simp_all; done)
             | (exfalso; simp_all; done)))))

/-- `RoundTrip.Lawful` of a derived type, from its `SerializeBytes.Lawful` `sl`,
`DeserializeBytes.Lawful` `dl` and `PartialEq.Lawful` `el` theorems (`ds`: the serializer and
derived size defs; `es`: the deserializer; `Ls`: the fields' `RoundTrip.Lawful`). -/
syntax "derive_rt_lawful " term:max term:max term:max " [" Lean.Parser.Tactic.simpArg,* "]"
  " [" Lean.Parser.Tactic.simpArg,* "]" " [" term,* "]" : tactic
macro_rules
  | `(tactic| derive_rt_lawful $sl $dl $el [$ds,*] [$es,*] [$ls,*]) => do
    let ls := ls.getElems
    let ns := freshNames "h_rt" ls.size
    let ms := freshNames "h_sz" ls.size
    let ks := freshNames "h_dec" ls.size
    let hs ← haves ns ls fun l => `(ser_dec_spec $l)
    let hm ← haves ms ls fun l =>
      `(size_spec (SerializeBytes.Lawful.SizeInstLawful (spec.RoundTrip.Lawful.SerializeBytesInstLawful $l)))
    let hk ← haves ks ls fun l => `(dec_spec (spec.RoundTrip.Lawful.DeserializeBytesInstLawful $l))
    let ys ← mvArgs ds.getElems (ns ++ ms ++ #[Lean.mkIdent ``vec_with_capacity_spec,
      Lean.mkIdent ``vec_append_spec_partial])
    let zs ← mvArgs es.getElems ks
    `(tactic| (
      refine ⟨$sl, $dl, $el, fun x rest hpre =>
        rt_of_dec _ $sl $dl $el (fun _ _ => rfl) x rest hpre ?_⟩
      $hs:tactic
      $hm:tactic
      $hk:tactic
      mvcgen [$ys,*]
      derive_vcs
      all_goals (try simp only [OkDec_ok] at *)
      all_goals (first
        | (intro _; simp [PostCond.mayThrow, PostCond.ok]; done)
        | (intro _; simp only [PostCond.mayThrow]; intro b hb; cases hb)
        | derive_dec_close [$zs,*]
        | skip)
      derive_arith))

/-- `NonEmpty.Lawful` of a derived type from its `RoundTrip.Lawful` `rl` (`ds`: the serializer and
derived size defs; `Ns`: the `NonEmpty.Lawful` of the fields that have one, including the `u8`
discriminant of an enum; `Ls`: the `SerializeBytes.Lawful` of the other fields). -/
syntax "derive_ne_lawful " term:max " [" Lean.Parser.Tactic.simpArg,* "]" " [" term,* "]"
  " [" term,* "]" : tactic
macro_rules
  | `(tactic| derive_ne_lawful $rl [$ds,*] [$nes,*] [$ls,*]) => do
    let nes := nes.getElems
    let ls := ls.getElems
    let ns := freshNames "h_ne" nes.size
    let ms := freshNames "h_ser" ls.size
    let ps := freshNames "h_sz" (nes.size + ls.size)
    let hn ← haves ns nes fun l => `(ser_ne_spec $l)
    let hs ← haves ms ls fun l => `(ser_spec $l)
    let szs ← (nes.map fun l => (l, true)) ++ (ls.map fun l => (l, false)) |>.mapM fun (l, b) =>
      if b then `(size_spec (SerializeBytes.Lawful.SizeInstLawful
          (spec.RoundTrip.Lawful.SerializeBytesInstLawful (spec.NonEmpty.Lawful.RoundTripInstLawful $l))))
      else `(size_spec (SerializeBytes.Lawful.SizeInstLawful $l))
    let hp ← haves ps szs pure
    let ys ← mvArgs ds.getElems (ns ++ ms ++ ps ++ #[Lean.mkIdent ``vec_with_capacity_spec,
      Lean.mkIdent ``vec_append_spec_partial])
    `(tactic| (
      refine ne_of_pos _ $rl (fun _ => rfl) fun x => ?_
      $hn:tactic
      $hs:tactic
      $hp:tactic
      mvcgen [$ys,*]
      derive_vcs
      all_goals (try simp only [OkLenPos_ok] at *)
      all_goals (try casesm* _ ∧ _)
      all_goals (first
        | (intro _; simp [PostCond.mayThrow, PostCond.ok]; done)
        | (intro b hb; cases hb; done)
        | (intro b hb; injection hb with hb; subst hb)
        | skip)
      derive_arith))

/-! ### Whole `Lawful`s (what the generated obligations call) -/

/-- `Size.Lawful` of a derived impl. -/
syntax "derive_size_lawful " "[" Lean.Parser.Tactic.simpArg,* "]" " [" term,* "]" : tactic
macro_rules
  | `(tactic| derive_size_lawful [$ds,*] [$ls,*]) =>
    `(tactic| (constructor; derive_size [$ds,*] [$ls,*]))

/-- `SerializeBytes.Lawful` of a derived impl, from its `Size.Lawful` theorem `sz`. -/
syntax "derive_ser_lawful " term:max " [" Lean.Parser.Tactic.simpArg,* "]" " [" term,* "]" : tactic
macro_rules
  | `(tactic| derive_ser_lawful $sz [$ds,*] [$ls,*]) =>
    `(tactic| (refine ⟨$sz, ?_⟩; derive_ser [$ds,*] [$ls,*]))

/-- `DeserializeBytes.Lawful` of a derived impl, from its `Size.Lawful` theorem `sz`; the
provided `tls_deserialize_exact_bytes` follows from `tls_deserialize_bytes`. -/
syntax "derive_deser_lawful " term:max " [" Lean.Parser.Tactic.simpArg,* "]" " [" term,* "]" : tactic
macro_rules
  | `(tactic| derive_deser_lawful $sz [$ds,*] [$ls,*]) =>
    `(tactic| (
      refine ⟨$sz, ?hd, fun b _ => exact_bytes_spec _ (fun b => ?hd b (pre_holds_of_ok_true rfl)) b⟩
      case hd => derive_deser [$ds,*] [$ls,*]))

end tls_codec.Derive
