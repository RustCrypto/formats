/- The varint and `ContentLength` deserializers on lawful readers (`VarintDe`: what a decode
read), and their round trips.

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
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! ### Varint: deserializer -/

/-- A one-byte `read_exact` into a fresh array buffer: the byte read is the head of the view. -/
theorem read1_facts {R : Type} {v : R → List Std.U8}
    {a : R → Nat → R} (r : R)
    (s : Slice Std.U8 × (Slice Std.U8 → Aeneas.Std.Array Std.U8 1#usize))
    (hs : s.1.val = (Array.repeat 1#usize 0#u8).val ∧ s.2 = (Array.repeat 1#usize 0#u8).from_slice)
    (r5 : core.result.Result Unit core.io.error.Error × R × Slice Std.U8) (u : Unit)
    (hx : r5.1 = .Ok u)
    (hpost : (s.1.val.length ≤ (v r).length →
        r5 = (.Ok (), a r s.1.val.length, alloc.io.read.cut (v r) s.1)) ∧
      ((v r).length < s.1.val.length → r5.1 = .Err core.io.error.Error.READ_EXACT_EOF)) :
    ∃ (b : Std.U8) (t : List Std.U8), v r = b :: t ∧ r5.2.1 = a r 1 ∧ (s.2 r5.2.2).val = [b] := by
  have hl : s.1.val.length = 1 := by rw [hs.1]; simp
  have hv1 : 1 ≤ (v r).length := by
    by_contra hn
    have := hpost.2 (by omega)
    rw [hx] at this; cases this
  have hr5 := hpost.1 (by omega)
  have hs2 : s = (Array.repeat 1#usize 0#u8).to_slice_mut :=
    Prod.ext (Subtype.ext (hs.1.trans (by simp [Array.to_slice_mut, Array.to_slice]))) hs.2
  cases hvr : v r with
  | nil => rw [hvr] at hv1; simp at hv1
  | cons b t =>
    refine ⟨b, t, rfl, ?_, ?_⟩
    · rw [hr5, hl]
    · rw [hr5]
      have := read_fixed (Array.repeat 1#usize 0#u8) (v r) (by simpa using hv1)
      rw [← hs2, hvr] at this
      rw [hvr]
      simpa using this

/-- One iteration of the std varint loop (one `read_exact` of a single byte). -/
theorem varint.std_loop.body_spec {R : Type} {RI : alloc.io.read.Read R} {v : R → List Std.U8}
    {a : R → Nat → R} (law : StdIo.RLaw RI v a) (len : Std.Usize) (r : R) (value : Std.U64)
    (i : Std.Usize) (hi : 1 ≤ i.val) (hil : i.val ≤ len.val) (hl : len.val ≤ 8)
    (hv : value.val < 2 ^ (8 * i.val - 2)) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.Insts.Tls_codecDeserialize.tls_deserialize_loop.body RI len r value i
    ⦃ ⇓ res => ⌜ match res with
      | .done (r', v', f) => (f = core.option.Option.None → i = len ∧ r' = r ∧ v' = value) ∧
          (∀ e, f = core.option.Option.Some e → i.val < len.val ∧ (v r).length = 0)
      | .cont (r', v', i') => ∃ (b : Std.U8) (t : List Std.U8), v r = b :: t ∧ r' = a r 1 ∧
          i'.val = i.val + 1 ∧ i'.val ≤ len.val ∧ v'.val < 2 ^ (8 * i'.val - 2) ∧
          v'.val = value.val * 256 + b.val ⌝ ⦄ := by
  have hre := fun s => read_exact_spec law r s
  unfold varint.TlsVarInt.Insts.Tls_codecDeserialize.tls_deserialize_loop.body
  mvcgen [hre]
  · rename_i hlt s hs r5 _ hx hpost sh h4 h5 h6 byte hidx c hc sum hsum inew hinew
    obtain ⟨b, t, hvr, hr1, hsl⟩ := read1_facts r s hs r5 _ hx hpost
    have hbb : byte = b := by
      obtain ⟨hx0, hbyte⟩ := hidx
      simp [hsl] at hbyte
      exact hbyte
    have hlt' : i.val < len.val := hlt
    have h64 : U64.size = 2 ^ 64 := by simp [U64.size, U64.numBits]
    have h8 : (8#i32).toNat = 8 := rfl
    have hb := varint.step_bound value.val byte.val i.val hi (by omega) hv (by scalar_tac)
    have h4' : sh.val = value.val * 256 := by rw [h4, h8, h64]; exact hb.1
    have h1 : (1#usize).val = 1 := by simp
    have hi' : inew.val = i.val + 1 := by rw [hinew, h1]
    have hsum' : sum.val = value.val * 256 + byte.val := by omega
    refine ⟨b, t, hvr, hr1, hi', by rw [hi']; omega, ?_, by rw [hsum', hbb]⟩
    rw [hi', hsum']
    exact hb.2.1
  · rename_i hlt _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ hov
    exfalso
    have hlt' : i.val < len.val := hlt
    scalar_tac
  · rename_i hlt s hs r5 _ hx hpost sh h4 h5 h6 byte hidx c hc hov
    exfalso
    have hlt' : i.val < len.val := hlt
    have hb := varint.step_bound value.val byte.val i.val hi (by omega) hv (by scalar_tac)
    scalar_tac
  · rename_i hlt s hs r5 _ hx hpost _ _ _ _ hov
    exfalso
    obtain ⟨b, t, hvr, hr1, hsl⟩ := read1_facts r s hs r5 _ hx hpost
    have : (s.2 r5.2.2).length = 1 := by simp [hsl]
    simp at hov
  · rename_i hlt s hs r5 e hx hpost
    have hl : s.1.val.length = 1 := by rw [hs.1]; simp
    have hv0 : (v r).length = 0 := by
      by_contra hn
      have := hpost.1 (by omega)
      rw [this] at hx; cases hx
    have he := hpost.2 (by omega)
    rw [hx] at he
    cases he
    rw [from_io_eof]
    mvcgen
    exact ⟨fun h => (by cases h), fun e _ => ⟨hlt, hv0⟩⟩
  · refine ⟨UScalar.eq_of_val_eq ?_, fun e h => by cases h⟩
    have h' : ¬ i.val < len.val := ‹¬ i < len›
    omega

/-- The std varint loop on a lawful reader: with enough input it reads `len - i` bytes and folds them
into the value; otherwise it fails (having consumed what was there). -/
theorem varint.std_loop_spec {R : Type} {RI : alloc.io.read.Read R} {v : R → List Std.U8}
    {a : R → Nat → R} (law : StdIo.RLaw RI v a) (len : Std.Usize) (r : R) (value : Std.U64)
    (i : Std.Usize) (hi : 1 ≤ i.val) (hil : i.val ≤ len.val) (hl : len.val ≤ 8)
    (hv : value.val < 2 ^ (8 * i.val - 2)) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.Insts.Tls_codecDeserialize.tls_deserialize_loop RI r len value i
    ⦃ ⇓ y => ⌜ (y.2.2 = core.option.Option.None → len.val - i.val ≤ (v r).length ∧
          y.1 = a r (len.val - i.val) ∧
          y.2.1.val = ((v r).take (len.val - i.val)).foldl (fun a b => a * 256 + b.val) value.val) ∧
        (∀ e, y.2.2 = core.option.Option.Some e → (v r).length < len.val - i.val) ⌝ ⦄ := by
  unfold varint.TlsVarInt.Insts.Tls_codecDeserialize.tls_deserialize_loop
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.loop.spec_decr_nat
    (fun x : R × Std.U64 × Std.Usize => len.val - x.2.2.val)
    (fun x : R × Std.U64 × Std.Usize =>
      1 ≤ x.2.2.val ∧ i.val ≤ x.2.2.val ∧ x.2.2.val ≤ len.val ∧ x.2.1.val < 2 ^ (8 * x.2.2.val - 2) ∧
      x.2.2.val - i.val ≤ (v r).length ∧ x.1 = a r (x.2.2.val - i.val) ∧
      x.2.1.val = ((v r).take (x.2.2.val - i.val)).foldl (fun a b => a * 256 + b.val) value.val)
    (fun y : R × Std.U64 × (core.option.Option Error) =>
      (y.2.2 = core.option.Option.None → len.val - i.val ≤ (v r).length ∧
          y.1 = a r (len.val - i.val) ∧
          y.2.1.val = ((v r).take (len.val - i.val)).foldl (fun a b => a * 256 + b.val) value.val) ∧
        (∀ e, y.2.2 = core.option.Option.Some e → (v r).length < len.val - i.val))
  · rintro ⟨rr, vv, j⟩ ⟨hj1, hij, hjl, hjv, hjlen, hjr, hjv'⟩
    dsimp only at hj1 hij hjl hjv hjlen hjr hjv'
    obtain ⟨res, hres, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (varint.std_loop.body_spec law len rr vv j hj1 hjl hl hjv)
    dsimp only
    rw [hres, Aeneas.Std.WP.spec_ok]
    have hview : v rr = (v r).drop (j.val - i.val) := by rw [hjr]; exact law.adv_view r _ hjlen
    cases res with
    | done y =>
      obtain ⟨r', v', f⟩ := y
      obtain ⟨hnone, hsome⟩ := hP
      refine ⟨fun hf => ?_, fun e he => ?_⟩
      · obtain ⟨h1, h2, h3⟩ := hnone hf
        subst h2; subst h3
        have : j.val = len.val := by rw [h1]
        rw [← this]
        exact ⟨hjlen, hjr, hjv'⟩
      · obtain ⟨hlt, h0⟩ := hsome e he
        rw [hview, List.length_drop] at h0
        omega
    | cont x =>
      obtain ⟨r', v', j'⟩ := x
      obtain ⟨b, t, hvb, hr', hj', hj'l, hv'', hvv⟩ := hP
      dsimp only at hr' hj' hj'l hv'' hvv ⊢
      rw [hview] at hvb
      have hb : (v r)[j.val - i.val]? = some b := by
        have := congrArg (fun l => l[0]?) hvb
        simpa using this
      have hlen1 : j.val - i.val + 1 ≤ (v r).length := by
        have := congrArg List.length hvb
        simp only [List.length_drop, List.length_cons] at this
        omega
      refine ⟨⟨by omega, by omega, hj'l, hv'', by omega, ?_, ?_⟩, by omega⟩
      · rw [hr', hjr, law.adv_adv r _ _ (by omega), show j'.val - i.val = j.val - i.val + 1 by omega]
      · rw [show j'.val - i.val = (j.val - i.val) + 1 by omega, List.take_add, List.foldl_append,
          ← hjv', hvv]
        rw [hvb]; simp
  · exact ⟨hi, le_refl _, hil, hv, by simp, by simp [law.adv_zero], by simp⟩

/-- What a successful varint decode read, from the bytes before: the first byte `b0` carries the
length prefix, the value is the big-endian fold of its low 6 bits and the next bytes, and the length
is the minimal one (same content as the bytes path, `varint.TlsVarInt.deserialize_content`). -/
def VarintDe (l : List Std.U8) (val : varint.TlsVarInt) (n : Nat) : Prop :=
  ∃ (b0 : Std.U8) (t : List Std.U8), l = b0 :: t ∧ (n = 1 ∨ n = 2 ∨ n = 4 ∨ n = 8) ∧
    n = varint.lenOf val.val ∧ varint.pfx n = b0.val / 64 * 64 ∧ n - 1 ≤ t.length ∧
    val.val = (t.take (n - 1)).foldl (fun a b => a * 256 + b.val) (b0.val % 64) ∧
    val.val ≤ 2 ^ 62 - 1

/-- The first byte of a varint, read by `read_exact` into a fresh one-byte buffer. -/
theorem read_first {R : Type} {v : R → List Std.U8} {a : R → Nat → R}
    (r : R)
    (r1 : core.result.Result Unit core.io.error.Error × R × Slice Std.U8) (u : Unit)
    (h : ((Array.repeat 1#usize 0#u8).to_slice_mut.1.val.length ≤ (v r).length →
        r1 = (.Ok (), a r (Array.repeat 1#usize 0#u8).to_slice_mut.1.val.length,
          alloc.io.read.cut (v r) (Array.repeat 1#usize 0#u8).to_slice_mut.1)) ∧
      ((v r).length < (Array.repeat 1#usize 0#u8).to_slice_mut.1.val.length →
        r1.1 = .Err core.io.error.Error.READ_EXACT_EOF))
    (hk : r1.1 = .Ok u) :
    ∃ (b : Std.U8) (t : List Std.U8), v r = b :: t ∧ r1.2.1 = a r 1 ∧
      ((Array.repeat 1#usize 0#u8).to_slice_mut.2 r1.2.2).val = [b] := by
  have hl : (Array.repeat 1#usize 0#u8).to_slice_mut.1.val.length = 1 := to_slice_mut_len _
  have hv1 : 1 ≤ (v r).length := by
    by_contra hn
    have := h.2 (by omega)
    rw [hk] at this; cases this
  have hr1 := h.1 (by omega)
  cases hvr : v r with
  | nil => rw [hvr] at hv1; simp at hv1
  | cons b t =>
    refine ⟨b, t, rfl, by rw [hr1, hl], ?_⟩
    rw [hr1, hvr]
    have := read_fixed (Array.repeat 1#usize 0#u8) (v r) (by simpa using hv1)
    rw [hvr] at this
    simpa using this

theorem calc_facts {rc : core.result.Result (Std.Usize × Std.Usize) Error}
    {val : Std.Usize × Std.Usize} {byte : Std.U8}
    (h : ∃ v l : Std.Usize, rc = .Ok (v, l) ∧ v.val = byte.val % 64 ∧
        (l.val = 1 ∨ l.val = 2 ∨ l.val = 4 ∨ l.val = 8) ∧ varint.pfx l.val = byte.val / 64 * 64)
    (h2 : rc = .Ok val) :
    val.1.val = byte.val % 64 ∧ (val.2.val = 1 ∨ val.2.val = 2 ∨ val.2.val = 4 ∨ val.2.val = 8) ∧
      varint.pfx val.2.val = byte.val / 64 * 64 := by
  obtain ⟨v0, l0, h1, h2', h3, h4⟩ := h
  rw [h2, core.result.Result.Ok.injEq] at h1
  subst h1
  exact ⟨h2', h3, h4⟩

theorem cast_small {x : Std.Usize} {t : Std.U64} (hx : x.val < 64)
    (h : core.result.Result.Ok t = (core.result.Result.Ok (UScalar.cast UScalarTy.U64 x) :
      core.result.Result Std.U64 core.num.error.TryFromIntError)) : t.val = x.val := by
  rw [core.result.Result.Ok.injEq] at h
  subst h
  rw [UScalar.cast_val_eq]
  simp only [UScalarTy.U64_numBits_eq]
  exact Nat.mod_eq_of_lt (by omega)

theorem byte_of_idx {lb1 : Std.Array Std.U8 1#usize} {byte b : Std.U8}
    (hidx : ∃ (x : ↑0#usize < lb1.length), byte = (↑lb1)[↑0#usize]'x) (hl : (↑lb1 : List Std.U8) = [b]) :
    byte = b := by
  obtain ⟨hx0, hbyte⟩ := hidx
  simp [hl] at hbyte
  exact hbyte

theorem view_after_first {R : Type} {RI : alloc.io.read.Read R} {v : R → List Std.U8}
    {a : R → Nat → R} (law : StdIo.RLaw RI v a) (r r' : R) (b0 : Std.U8) (t0 : List Std.U8)
    (hvr : v r = b0 :: t0) (hra : r' = a r 1) : v r' = t0 := by
  have hl1 : 1 ≤ (v r).length := by rw [hvr]; exact Nat.succ_le_succ (Nat.zero_le _)
  rw [hra, law.adv_view r 1 hl1, hvr]
  exact List.drop_succ_cons.trans List.drop_zero

/-- The facts the existence proof extracts from the first byte and `calculate_value`, on a
canonical encoding `b0 :: t0` of `N`. -/
theorem std_de_ok_facts {R : Type} {RI : alloc.io.read.Read R} {v : R → List Std.U8} {a : R → Nat → R}
    (law : StdIo.RLaw RI v a) (r : R) (N : Nat) (b0 : Std.U8) (t0 : List Std.U8)
    (hvr : v r = b0 :: t0) (hpf : varint.pfx (varint.lenOf N) = b0.val / 64 * 64)
    (hlt : b0.val % 64 < 64) (r1 : core.result.Result Unit core.io.error.Error × R × Slice Std.U8)
    (u : Unit)
    (hr1 : ((Array.repeat 1#usize 0#u8).to_slice_mut.1.val.length ≤ (v r).length →
        r1 = (.Ok (), a r (Array.repeat 1#usize 0#u8).to_slice_mut.1.val.length,
          alloc.io.read.cut (v r) (Array.repeat 1#usize 0#u8).to_slice_mut.1)) ∧
      ((v r).length < (Array.repeat 1#usize 0#u8).to_slice_mut.1.val.length →
        r1.1 = .Err core.io.error.Error.READ_EXACT_EOF))
    (hk : r1.1 = .Ok u)
    (lb1 : Std.Array Std.U8 1#usize) (hlb1 : lb1 = (Array.repeat 1#usize 0#u8).to_slice_mut.2 r1.2.2)
    (byte : Std.U8)
    (hidx : ∃ (x : ↑0#usize < lb1.length), byte = (↑lb1)[↑0#usize]'x)
    (rc : core.result.Result (Std.Usize × Std.Usize) Error) (val : Std.Usize × Std.Usize)
    (hrc : ∃ v l : Std.Usize, rc = .Ok (v, l) ∧ v.val = byte.val % 64 ∧
        (l.val = 1 ∨ l.val = 2 ∨ l.val = 4 ∨ l.val = 8) ∧ varint.pfx l.val = byte.val / 64 * 64)
    (hrc2 : rc = .Ok val)
    (rcast : core.result.Result Std.U64 core.num.error.TryFromIntError) (t val1 : Std.U64)
    (hrcast : rcast = .Ok (UScalar.cast UScalarTy.U64 val.1)) (hat : rcast = .Ok t)
    (hcast : (core.result.Result.Ok t : core.result.Result Std.U64 Error) = .Ok val1) :
    val.2.val = varint.lenOf N ∧ v r1.2.1 = t0 ∧ r1.2.1 = a r 1 ∧ val1.val = b0.val % 64 := by
  obtain ⟨b, t, hvr', hra, hbs⟩ := read_first r r1 u hr1 hk
  rw [hvr] at hvr'
  obtain ⟨rfl, rfl⟩ := List.cons.inj hvr'
  have hbb := byte_of_idx hidx (by rw [hlb1]; exact hbs)
  subst hbb
  have hc := calc_facts hrc hrc2
  have ht := cast_small (by omega) (hat.symm.trans hrcast)
  have hv1 := core.result.Result.Ok.inj hcast
  subst hv1
  refine ⟨?_, ?_, hra, by rw [ht, hc.1]⟩
  · exact varint.pfx_inj _ _ hc.2.1 (varint.lenOf_mem N) (hc.2.2.trans hpf.symm)
  · exact view_after_first law r r1.2.1 _ _ hvr hra

/-- Closes the arithmetic VCs of the varint decoder (the loop's preconditions, from the first
byte): instantiates `calc_facts` on the hypotheses of the right shape (found by `assumption`, not
by name or position), substitutes the `Ok` equations, then `scalar_tac`. -/
macro "varint_std_vc_arith" : tactic => `(tactic| (
  have := calc_facts (by assumption) (by assumption)
  subst_vars
  simp only [core.result.Result.Ok.injEq] at *
  subst_vars
  scalar_tac))

theorem varint.std_de_content {R : Type} {RI : alloc.io.read.Read R} {v : R → List Std.U8}
    {a : R → Nat → R} (law : StdIo.RLaw RI v a) (r : R) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.Insts.Tls_codecDeserialize.tls_deserialize RI r
    ⦃ ⇓ p => ⌜ ∀ val, p.1 = .Ok val → ∃ n, n ≤ (v r).length ∧ p.2 = a r n ∧
        VarintDe (v r) val n ⌝ ⦄ := by
  have hre := fun buf => read_exact_spec law r buf
  have hloop := varint.std_loop_spec law
  mvcgen [varint.TlsVarInt.Insts.Tls_codecDeserialize.tls_deserialize, hre, hloop,
    varint.calculate_value_content, varint.check_min_len_char,
    core.result.Result.map_err_spec,
    varint.DeserializeTlsVarInt.tls_deserialize.closure.Insts.CoreOpsFunctionFnOnceTupleTryFromIntErrorError.call_once]
  all_goals (try simp only [continue_eq_tryCF] at *)
  all_goals (first | (intro h; cases h) | skip)
  · varint_std_vc_arith
  · varint_std_vc_arith
  · varint_std_vc_arith
  · rename_i lb r1 hr1 _ u _ lb1 byte hidx rc hrc _ val _ rcast hrcast t hat _ val1 _ rl hnone hloop' rcheck hchk _ _ _ hk hrc2 hcast hcheck bv
    intro hval
    have hv1 := core.result.Result.Ok.inj hval
    rw [← hv1]
    obtain ⟨b, t0, hvr, hra, hbs⟩ := read_first r r1 u hr1 hk
    have hb' : (↑lb1 : List Std.U8) = [b] := hbs
    have hbb : byte = b := by
      obtain ⟨hx0, hbyte⟩ := hidx
      simp [hb'] at hbyte
      exact hbyte
    subst hbb
    have hc := calc_facts hrc hrc2
    have ht := cast_small (by omega) (hat.symm.trans hrcast)
    have hv1' := core.result.Result.Ok.inj hcast
    subst hv1'
    have h1 : (1#usize).val = 1 := by simp
    have hlen1 : 1 ≤ (v r).length := by rw [hvr]; simp
    have hview : v r1.2.1 = t0 := by
      rw [hra, law.adv_view r 1 hlen1, hvr]; simp
    obtain ⟨hlen, hadv, hfold⟩ := hloop'.1 hnone
    rw [h1, hview] at hlen hfold
    rw [h1, hra] at hadv
    obtain ⟨hmax, hL⟩ := hchk hcheck
    have hLpos := hc.2.1
    have hlenv : (v r).length = t0.length + 1 := by rw [hvr]; simp
    refine ⟨val.2.val, by omega, ?_, ?_⟩
    · rw [hadv, law.adv_adv r 1 _ (by omega)]
      congr 1
      omega
    · refine ⟨byte, t0, hvr, hc.2.1, hL, hc.2.2, hlen, ?_, hmax⟩
      rw [hfold, ht, hc.1]
  · rename_i rcheck hchk _ res _ hcf _ _ _
    cases rcheck with
    | Ok u => simp [tryCF] at hcf
    | Err e =>
      simp [tryCF] at hcf
      subst hcf
      refine ⟨_, rfl, ?_⟩
      refine triple_post_mono (core.convert.From.Blanket.from_spec _) ?_
      intro f hf
      subst hf
      simp only [PostCond.ok]
      mvcgen
      intro val h; cases h
  · intro h; cases h
  · intro h; cases h
  · rename_i rc hrc _ res _ hcf hk
    obtain ⟨v0, l0, h1, -⟩ := hrc
    rw [h1] at hcf
    simp [tryCF] at hcf
  · rename_i lb1 hov _
    exfalso
    have h := lb1.property
    simp at h hov
  · rename_i lb r1 hr1 _ res _ hcf
    have hl : (lb.to_slice_mut.1 : Slice Std.U8).val.length = 1 := to_slice_mut_len lb
    by_cases h1 : 1 ≤ (v r).length
    · rw [hr1.1 (by rw [hl]; exact h1)] at hcf; simp [tryCF] at hcf
    · rw [hr1.2 (by rw [hl]; omega)] at hcf
      simp only [tryCF] at hcf
      cases hcf
      refine ⟨_, rfl, ?_⟩
      rw [from_io_eof]
      refine ok_triple_of ?_
      mvcgen
      intro _ h; cases h

/-- A canonical encoding of `N` at the head of a reader's view decodes as the varint decoder
computes it. -/
theorem varint.canon_facts (N : Nat) (hN : N ≤ 2 ^ 62 - 1) (view b rest : List Std.U8)
    (hb : b.map (·.val) = varint.encList N) (hv : view = b ++ rest) :
    ∃ (b0 : Std.U8) (t0 : List Std.U8), view = b0 :: t0 ∧ varint.lenOf N - 1 ≤ t0.length ∧
      varint.pfx (varint.lenOf N) = b0.val / 64 * 64 ∧ b0.val % 64 < 64 ∧
      (t0.take (varint.lenOf N - 1)).foldl (fun a x => a * 256 + x.val) (b0.val % 64) = N := by
  obtain ⟨e0, tl, he, he0, htl, -, hD⟩ := varint.encList_dec N hN
  rw [he] at hb
  cases b with
  | nil => simp at hb
  | cons b0 bt =>
    simp only [List.map_cons, List.cons.injEq] at hb
    obtain ⟨hb0, hbt⟩ := hb
    have hbl : bt.length = varint.lenOf N - 1 := by
      have := congrArg List.length hbt
      simp at this; omega
    refine ⟨b0, bt ++ rest, by simp [hv], by simp; omega, ?_, by omega, ?_⟩
    · rw [hb0]; exact he0.symm
    · have hfm : bt.foldl (fun a x => a * 256 + x.val) (b0.val % 64) =
          (bt.map (·.val)).foldl (fun a b => a * 256 + b) (b0.val % 64) := by
        rw [List.foldl_map]
      rw [← hbl, List.take_left' rfl, hfm, hbt, varint.foldl_eq, hb0, ← hD, varint.D_cons]

/-- The decoder succeeds on a canonical encoding (followed by anything), with the encoded value. -/
theorem varint.std_de_ok {R : Type} {RI : alloc.io.read.Read R} {v : R → List Std.U8}
    {a : R → Nat → R} (law : StdIo.RLaw RI v a) (r : R) (N : Nat) (hN : N ≤ 2 ^ 62 - 1)
    (b rest : List Std.U8) (hb : b.map (·.val) = varint.encList N) (hv : v r = b ++ rest) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.Insts.Tls_codecDeserialize.tls_deserialize RI r
    ⦃ ⇓ p => ⌜ ∃ val : varint.TlsVarInt, p.1 = .Ok val ∧ val.val = N ⌝ ⦄ := by
  obtain ⟨b0, t0, hvr, hlen, hpf, hlt64, hfold⟩ := varint.canon_facts N hN (v r) b rest hb hv
  have hre := fun buf => read_exact_spec law r buf
  have hloop := varint.std_loop_spec law
  have hchk := fun (value : Std.U64) (len : Std.Usize) hv hl => varint.check_min_len_total value len hv hl
  mvcgen [varint.TlsVarInt.Insts.Tls_codecDeserialize.tls_deserialize, hre, hloop, hchk,
    varint.calculate_value_content,
    core.result.Result.map_err_spec,
    varint.DeserializeTlsVarInt.tls_deserialize.closure.Insts.CoreOpsFunctionFnOnceTupleTryFromIntErrorError.call_once]
  all_goals (try simp only [continue_eq_tryCF] at *)
  · varint_std_vc_arith
  · varint_std_vc_arith
  · varint_std_vc_arith
  · rename_i lb r1 hr1 _ u _ lb1 byte hidx rc hrc _ val _ rcast hrcast t hat _ val1 _ rl hnone hloop' hk hrc2 hcast
    obtain ⟨hL, hview, hra, hv1⟩ := std_de_ok_facts law r N _ t0 hvr hpf hlt64 r1 u hr1 hk lb1 rfl
      byte hidx rc val hrc hrc2 rcast t val1 hrcast hat hcast
    have h1 : (1#usize).val = 1 := by simp
    obtain ⟨-, -, hfold'⟩ := hloop'.1 hnone
    rw [h1, hview, hL, hv1] at hfold'
    rw [hfold'.trans hfold]
    exact hN
  · rename_i lb r1 hr1 _ u _ lb1 byte hidx rc hrc _ val _ rcast hrcast t hat _ val1 _ rl hnone hloop' hk hrc2 hcast
    obtain ⟨hL, hview, hra, hv1⟩ := std_de_ok_facts law r N _ t0 hvr hpf hlt64 r1 u hr1 hk lb1 rfl
      byte hidx rc val hrc hrc2 rcast t val1 hrcast hat hcast
    have h1 : (1#usize).val = 1 := by simp
    obtain ⟨-, -, hfold'⟩ := hloop'.1 hnone
    rw [h1, hview, hL, hv1] at hfold'
    rw [hfold'.trans hfold]
    exact hL
  · rename_i lb r1 hr1 _ u _ lb1 byte hidx rc hrc _ val _ rcast hrcast t hat _ val1 _ rl hnone hloop' rcheck hchk _ _ _ hk hrc2 hcast hcheck
    obtain ⟨hL, hview, hra, hv1⟩ := std_de_ok_facts law r N _ t0 hvr hpf hlt64 r1 u hr1 hk lb1 rfl
      byte hidx rc val hrc hrc2 rcast t val1 hrcast hat hcast
    have h1 : (1#usize).val = 1 := by simp
    obtain ⟨-, -, hfold'⟩ := hloop'.1 hnone
    rw [h1, hview, hL, hv1] at hfold'
    exact ⟨rl.2.1, rfl, hfold'.trans hfold⟩
  · rename_i rcheck hchk _ res _ hcf _ _ _
    rw [hchk] at hcf
    simp [tryCF] at hcf
  · rename_i lb r1 hr1 _ u _ lb1 byte hidx rc hrc _ val _ rcast hrcast t hat _ val1 _ rl e hsome hloop' hk hrc2 hcast
    obtain ⟨hL, hview, hra, hv1⟩ := std_de_ok_facts law r N _ t0 hvr hpf hlt64 r1 u hr1 hk lb1 rfl
      byte hidx rc val hrc hrc2 rcast t val1 hrcast hat hcast
    have h1 : (1#usize).val = 1 := by simp
    have h2 := hloop'.2 e hsome
    rw [h1, hview, hL] at h2
    omega
  · rename_i rcast hrcast e hat _ _
    rw [hrcast] at hat
    cases hat
  · rename_i rc hrc _ res _ hcf hk
    obtain ⟨v0, l0, h1, -⟩ := hrc
    rw [h1] at hcf
    simp [tryCF] at hcf
  · rename_i lb1 hov _
    exfalso
    have h := lb1.property
    simp at h hov
  · rename_i lb r1 hr1 _ res _ hcf
    have hl : (lb.to_slice_mut.1 : Slice Std.U8).val.length = 1 := to_slice_mut_len lb
    rw [hr1.1 (by rw [hl, hvr]; simp)] at hcf
    simp [tryCF] at hcf

/-- A successful varint decode read the canonical encoding of the value. -/
theorem VarintDe.take_enc {l : List Std.U8} {val : varint.TlsVarInt} {n : Nat}
    (h : VarintDe l val n) : l.take n = varint.enc val.val ∧ n ≤ l.length := by
  obtain ⟨b0, t, hl, hL, hLv, hpfx, hle, hval, hmax⟩ := h
  have hb0 : b0.val < 256 := by have := b0.hBounds; simpa using this
  have ht : ∀ x ∈ t.map (·.val), x < 256 := by
    simp only [List.mem_map]; rintro _ ⟨a, -, rfl⟩; have := a.hBounds; simpa using this
  have hE := varint.enc_of_dec b0.val (t.map (·.val)) n val.val hmax hb0 ht hLv hpfx
    (by simpa using hle) (by rw [hval, ← List.map_take, List.foldl_map])
  have hn1 : n = (n - 1) + 1 := by have := varint.lenOf_pos val.val; omega
  refine ⟨?_, by rw [hl]; simp; omega⟩
  apply varint.eq_enc _ hmax
  rw [← hE, hl, hn1, List.take_succ_cons, List.map_cons, List.map_take]
  simp

/-- `VarintDe` of a `TlsVarInt`: the deserializer's content. -/
theorem varint.de_runs : DeRuns varint.TlsVarInt.Insts.Tls_codecDeserialize VarintDe := by
  intro R RI v a law r
  refine triple_post_mono (varint.std_de_content law r) fun p hp val hval => ?_
  obtain ⟨n, hn, hadv, hde⟩ := hp val hval
  obtain ⟨sz, hsz, hszv⟩ : ∃ sz : Std.Usize, varint.TlsVarInt.Insts.Tls_codecSize.tls_serialized_len val = ok sz ∧
      sz.val = varint.lenOf val.val := by
    obtain ⟨sz, hsz, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (varint.TlsVarInt.bytes_len_spec val)
    exact ⟨sz, hsz, (varint.lenOf_char _ _ hP).1⟩
  have hLv : n = varint.lenOf val.val := by obtain ⟨_, _, _, _, h, -⟩ := hde; exact h
  exact ⟨n, sz, hn, hadv, hsz, by rw [hszv, ← hLv], hde⟩

theorem varint.decodes (x : varint.TlsVarInt) (hx : x.val ≤ 2 ^ 62 - 1) :
    DecodesTo varint.TlsVarInt.Insts.Tls_codecDeserialize (varint.enc x.val) x := by
  intro R RI v a law r rest hv
  refine triple_post_mono (triple_and (varint.std_de_content law r)
    (varint.std_de_ok law r x.val hx (varint.enc x.val) rest (varint.enc_map _ hx) hv)) ?_
  rintro p ⟨hc, val, hp1, hval⟩
  obtain ⟨n, hn, hadv, hde⟩ := hc val hp1
  have hLv : n = varint.lenOf val.val := by obtain ⟨_, _, _, _, h, -⟩ := hde; exact h
  have hxv : val = x := UScalar.eq_of_val_eq hval
  subst hxv
  refine ⟨hp1, ?_⟩
  rw [hadv, law.adv_view r n hn, hv, hLv, ← varint.enc_length, List.drop_left]

/-! ### `ContentLength`, `read_length` -/

theorem ContentLength.new_spec (value : varint.TlsVarInt) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.ContentLength.new value
    ⦃ ⇓ r => ⌜ (value.val ≤ 2 ^ 30 - 1 → r = .Ok value) ∧
        (2 ^ 30 - 1 < value.val → ∃ e, r = .Err e) ⌝ ⦄ := by
  mvcgen [quic_vec.ContentLength.new, varint.TlsVarInt.value, quic_vec.ContentLength.MAX,
    quic_vec.MAX_MLS_LEN_spec]
  · rename_i r hlt hr
    have : r.val < value.val := hlt
    exact ⟨fun h => by omega, fun _ => ⟨_, rfl⟩⟩
  · rename_i r hlt hr
    have : ¬ r.val < value.val := hlt
    exact ⟨fun _ => trivial, fun h => by omega⟩

theorem ContentLength.std_de_content {R : Type} {RI : alloc.io.read.Read R} {v : R → List Std.U8}
    {a : R → Nat → R} (law : StdIo.RLaw RI v a) (r : R) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.ContentLength.Insts.Tls_codecDeserialize.tls_deserialize RI r
    ⦃ ⇓ p => ⌜ ∀ val, p.1 = .Ok val → ∃ n, n ≤ (v r).length ∧ p.2 = a r n ∧
        VarintDe (v r) val n ∧ val.val ≤ 2 ^ 30 - 1 ⌝ ⦄ := by
  have hde := varint.std_de_content law r
  mvcgen [quic_vec.ContentLength.Insts.Tls_codecDeserialize.tls_deserialize, hde,
    ContentLength.new_spec]
  all_goals (try simp only [continue_eq_tryCF] at *)
  · rename_i r1 hde' _ val1 _ rcl hnew hk
    intro val hval
    obtain ⟨n, hn, hadv, hd⟩ := hde' val1 hk
    by_cases hle : val1.val ≤ 2 ^ 30 - 1
    · have := hnew.1 hle
      rw [this, core.result.Result.Ok.injEq] at hval
      subst hval
      exact ⟨n, hn, hadv, hd, hle⟩
    · obtain ⟨e, he⟩ := hnew.2 (by omega)
      rw [he] at hval
      cases hval
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
      intro val h; cases h

theorem ContentLength.std_de_ok {R : Type} {RI : alloc.io.read.Read R} {v : R → List Std.U8}
    {a : R → Nat → R} (law : StdIo.RLaw RI v a) (r : R) (N : Nat) (hN : N ≤ 2 ^ 30 - 1)
    (b rest : List Std.U8) (hb : b.map (·.val) = varint.encList N) (hv : v r = b ++ rest) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.ContentLength.Insts.Tls_codecDeserialize.tls_deserialize RI r
    ⦃ ⇓ p => ⌜ ∃ val : quic_vec.ContentLength, p.1 = .Ok val ∧ val.val = N ⌝ ⦄ := by
  have hde := varint.std_de_ok law r N (by omega) b rest hb hv
  mvcgen [quic_vec.ContentLength.Insts.Tls_codecDeserialize.tls_deserialize, hde,
    ContentLength.new_spec]
  all_goals (try simp only [continue_eq_tryCF] at *)
  · rename_i r1 hde' _ val1 _ rcl hnew hk
    obtain ⟨val, hval, hvN⟩ := hde'
    rw [hk, core.result.Result.Ok.injEq] at hval
    subst hval
    rw [hnew.1 (by omega)]
    exact ⟨_, rfl, hvN⟩
  · rename_i r1 hde' _ res _ hcf
    obtain ⟨val, hval, -⟩ := hde'
    rw [hval] at hcf
    simp [tryCF] at hcf

theorem ContentLength.de_runs : DeRuns quic_vec.ContentLength.Insts.Tls_codecDeserialize
    (fun l c n => VarintDe l c n ∧ c.val ≤ 2 ^ 30 - 1) := by
  intro R RI v a law r
  refine triple_post_mono (ContentLength.std_de_content law r) fun p hp val hval => ?_
  obtain ⟨n, hn, hadv, hde, hle⟩ := hp val hval
  obtain ⟨sz, hsz, hszv⟩ : ∃ sz : Std.Usize,
      quic_vec.ContentLength.Insts.Tls_codecSize.tls_serialized_len val = ok sz ∧
        sz.val = varint.lenOf val.val := by
    obtain ⟨sz, hsz, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (varint.TlsVarInt.bytes_len_spec val)
    exact ⟨sz, hsz, (varint.lenOf_char _ _ hP).1⟩
  have hLv : n = varint.lenOf val.val := by obtain ⟨_, _, _, _, h, -⟩ := hde; exact h
  exact ⟨n, sz, hn, hadv, hsz, by rw [hszv, ← hLv], hde, hle⟩

theorem ContentLength.decodes (x : quic_vec.ContentLength) (hx : x.val ≤ 2 ^ 30 - 1) :
    DecodesTo quic_vec.ContentLength.Insts.Tls_codecDeserialize (varint.enc x.val) x := by
  intro R RI v a law r rest hv
  have hx' : x.val ≤ 2 ^ 62 - 1 := by omega
  refine triple_post_mono (triple_and (ContentLength.std_de_content law r)
    (ContentLength.std_de_ok law r x.val hx (varint.enc x.val) rest (varint.enc_map _ hx') hv)) ?_
  rintro p ⟨hc, val, hp1, hval⟩
  obtain ⟨n, hn, hadv, hde, -⟩ := hc val hp1
  have hLv : n = varint.lenOf val.val := by obtain ⟨_, _, _, _, h, -⟩ := hde; exact h
  have hxv : val = x := UScalar.eq_of_val_eq hval
  subst hxv
  refine ⟨hp1, ?_⟩
  rw [hadv, law.adv_view r n hn, hv, hLv, ← varint.enc_length, List.drop_left]

/-- `read_length` on a lawful reader: on `Ok (len, len_len)`, the reader advanced by `len_len`
bytes, which are the canonical varint encoding of `len` (at most `2^30 - 1`). -/
theorem read_length_content {R : Type} {RI : alloc.io.read.Read R} {v : R → List Std.U8}
    {a : R → Nat → R} (law : StdIo.RLaw RI v a) (r : R) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.rw.read_length RI r
    ⦃ ⇓ p => ⌜ ∀ pr, p.1 = .Ok pr → ∃ n, n ≤ (v r).length ∧ p.2 = a r n ∧ pr.2.val = n ∧
        pr.1.val ≤ 2 ^ 30 - 1 ∧ (v r).take n = varint.enc pr.1.val ⌝ ⦄ := by
  have hde := ContentLength.std_de_content law r
  mvcgen [quic_vec.rw.read_length, hde, varint.TlsVarInt.value]
  all_goals (try simp only [continue_eq_tryCF] at *)
  · rename_i r1 hde' _ val1 _ ll hll rconv hconv _ u _ hk hrc
    intro pr hpr
    rw [core.result.Result.Ok.injEq] at hpr
    subst hpr
    obtain ⟨n, hn, hadv, hd, hle⟩ := hde' val1 hk
    have hu := hconv.1 u hrc
    have hLv : n = varint.lenOf val1.val := by obtain ⟨_, _, _, _, h, -⟩ := hd; exact h
    obtain ⟨htk, -⟩ := VarintDe.take_enc hd
    refine ⟨n, hn, hadv, ?_, by simp only; omega, by simp only; rw [hu]; exact htk⟩
    simp only
    rw [(varint.lenOf_char _ _ hll).1, hLv]
  · rename_i r1 hde' _ val1 _ ll hll rconv hconv _ res _ hcf hk
    obtain ⟨n, hn, hadv, hd, hle⟩ := hde' val1 hk
    obtain ⟨y, hy⟩ := hconv.2 (by omega)
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
      intro pr h; cases h

theorem read_length_ok {R : Type} {RI : alloc.io.read.Read R} {v : R → List Std.U8}
    {a : R → Nat → R} (law : StdIo.RLaw RI v a) (r : R) (N : Nat) (hN : N ≤ 2 ^ 30 - 1)
    (b rest : List Std.U8) (hb : b.map (·.val) = varint.encList N) (hv : v r = b ++ rest) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.rw.read_length RI r
    ⦃ ⇓ p => ⌜ ∃ pr : Std.Usize × Std.Usize, p.1 = .Ok pr ∧ pr.1.val = N ⌝ ⦄ := by
  have hde := ContentLength.std_de_ok law r N hN b rest hb hv
  mvcgen [quic_vec.rw.read_length, hde, varint.TlsVarInt.value]
  all_goals (try simp only [continue_eq_tryCF] at *)
  · rename_i r1 hde' _ val1 _ ll hll rconv hconv _ u _ hk hrc
    obtain ⟨val, hval, hvN⟩ := hde'
    rw [hk, core.result.Result.Ok.injEq] at hval
    subst hval
    exact ⟨_, rfl, by rw [hconv.1 u hrc]; exact hvN⟩
  · rename_i r1 hde' _ val1 _ ll hll rconv hconv _ res _ hcf hk
    obtain ⟨val, hval, hvN⟩ := hde'
    rw [hk, core.result.Result.Ok.injEq] at hval
    subst hval
    obtain ⟨y, hy⟩ := hconv.2 (by omega)
    rw [hy] at hcf
    simp [tryCF] at hcf
  · rename_i r1 hde' _ res _ hcf
    obtain ⟨val, hval, -⟩ := hde'
    rw [hval] at hcf
    simp [tryCF] at hcf

/-- `read_length` on the canonical encoding of `N` (at most `2^30 - 1`) followed by `rest`:
`Ok (N, lenOf N)` and the reader is left at `rest`. -/
theorem read_length_decodes {R : Type} {RI : alloc.io.read.Read R} {v : R → List Std.U8}
    {a : R → Nat → R} (law : StdIo.RLaw RI v a) (r : R) (N : Nat) (hN : N ≤ 2 ^ 30 - 1)
    (rest : List Std.U8) (hv : v r = varint.enc N ++ rest) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.rw.read_length RI r
    ⦃ ⇓ p => ⌜ (∃ pr : Std.Usize × Std.Usize, p.1 = .Ok pr ∧ pr.1.val = N ∧
        pr.2.val = varint.lenOf N) ∧ v p.2 = rest ⌝ ⦄ := by
  refine triple_post_mono (triple_and (read_length_content law r)
    (read_length_ok law r N hN _ rest (varint.enc_map N (by omega)) hv)) ?_
  rintro p ⟨hc, pr, hp1, hpr⟩
  obtain ⟨n, hn, hadv, hn2, -, htk⟩ := hc pr hp1
  have hlen : n = varint.lenOf N := by
    have h2 : (List.take n (v r)).length = (varint.enc N).length := by rw [htk, hpr]
    rwa [List.length_take, Nat.min_eq_left hn, varint.enc_length] at h2
  refine ⟨⟨pr, hp1, hpr, by rw [hn2, hlen]⟩, ?_⟩
  rw [hadv, law.adv_view r n hn, hv, hlen, ← varint.enc_length, List.drop_left]

end tls_codec
