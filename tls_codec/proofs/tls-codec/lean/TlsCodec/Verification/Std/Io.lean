/- The `std::io` laws: lawful instances (`&[u8]`, `&mut R`, `Take<R>` readers, the `Vec<u8>`
writer), uniqueness of the views (so the ghost observers `spec::io::{sink, stream, advanced}` are
determined), and the reader loops (`default_read_exact`, `read_to_end`) on lawful readers.
Crate-independent.

Obligations: none directly; the `std`-path halves (`Serialize` / `Deserialize` `Lawful` fields,
lemma traits) of `PanicFreedom.lean` / `FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): nothing ASSUMED; 1 signature-only stub
(`core.io.error.Error.Insts.CoreFmtDebug.fmt`). -/
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

namespace tls_codec.StdIo

abbrev RLaw {R : Type} := @alloc.io.read.Read.Law R
abbrev WLaw {W : Type} := @core.io.write.Write.Law W

/-! ### Buffers -/

theorem cut_val (xs : List Std.U8) (buf : Slice Std.U8) :
    (alloc.io.read.cut xs buf).val = xs.take buf.val.length := rfl

theorem cut_self (buf : Slice Std.U8) : alloc.io.read.cut buf.val buf = buf := by
  apply Subtype.ext; simp [cut_val, Slice.length]

/-! ### Scalars and buffers -/

theorem usize_sub_ok (x y : Std.Usize) (h : y.val ≤ x.val) :
    ∃ z : Std.Usize, x - y = ok z ∧ z.val = x.val - y.val := by
  have hs := UScalar.sub_equiv x y
  revert hs
  cases hxy : x - y with
  | ok z => intro hs; exact ⟨z, rfl, by omega⟩
  | fail e => intro hs; omega
  | div => intro hs; exact hs.elim

theorem u64_sub_ok (x y : Std.U64) (h : y.val ≤ x.val) :
    ∃ z : Std.U64, x - y = ok z ∧ z.val = x.val - y.val := by
  have hs := UScalar.sub_equiv x y
  revert hs
  cases hxy : x - y with
  | ok z => intro hs; exact ⟨z, rfl, by omega⟩
  | fail e => intro hs; omega
  | div => intro hs; exact hs.elim

/-- Reading `k` bytes of `xs` into the first `m` bytes of `buf` (`k ≤ m ≤ |buf|`), then keeping
the rest of `buf`. -/
theorem take_cut_append (xs buf : List Std.U8) {k m m' : Nat} (hk : k ≤ xs.length) (hkm : k ≤ m)
    (hm : m ≤ buf.length) (hm' : m' = m) :
    (xs.take k ++ (buf.take m).drop k).take m' ++ buf.drop m =
      xs.take k ++ buf.drop k := by
  rw [hm']
  rw [List.take_of_length_le (by simp; omega), List.append_assoc]
  congr 1
  rw [List.drop_take]
  have : buf.drop m = (buf.drop k).drop (m - k) := by rw [List.drop_drop]; congr 1; omega
  rw [this, List.take_append_drop]

theorem usize_lt_2_64 (x : Std.Usize) : x.val < 2 ^ 64 := by
  have := x.hBounds
  rcases System.Platform.numBits_eq with h' | h' <;> simp_all [UScalarTy.numBits]; omega

/-- A buffer of `n` bytes. -/
def zeros (n : Nat) (h : n ≤ Usize.max) : Slice Std.U8 :=
  ⟨List.replicate n 0#u8, by simpa using h⟩

/-! ### `&[u8]` -/

/-- The state of a slice reader after `n` bytes. -/
def sliceAdv (s : Slice Std.U8) (n : Nat) : Slice Std.U8 :=
  ⟨s.val.drop n, by have := s.property; simp; omega⟩

theorem slice_law :
    RLaw alloc.Shared0SliceU8.Insts.AllocIoReadRead (fun s => s.val) sliceAdv where
  view_le r := r.property
  adv_zero r := by apply Subtype.ext; simp [sliceAdv]
  adv_view r n _ := rfl
  adv_adv r a b _ := by apply Subtype.ext; simp [sliceAdv, List.drop_drop]
  read r buf := by
    let a : Slice Std.U8 :=
      ⟨r.val.take (min buf.val.length r.val.length), by have := r.property; simp; omega⟩
    have hk : (Slice.len a).val = min buf.val.length r.val.length := by
      rw [Slice.len_val]; simp [a, Slice.length]
    refine ⟨Slice.len a, hk, ?_⟩
    rw [hk]
    rfl
  read_exact_ok r buf h := by
    simp only [alloc.Shared0SliceU8.Insts.AllocIoReadRead.read_exact, gt_iff_lt]
    rw [if_neg (by simp only [Slice.length]; omega)]
    rfl
  read_exact_eof r buf h := by
    simp only [alloc.Shared0SliceU8.Insts.AllocIoReadRead.read_exact, gt_iff_lt]
    rw [if_pos (by simp only [Slice.length]; omega)]
    exact ⟨_, _, rfl⟩

/-! ### Uniqueness of the views -/

/-- Two laws of one reader instance have the same view, and the same advance within it. -/
theorem read_law_unique {R : Type} {inst : alloc.io.read.Read R} {v1 v2 : R → List Std.U8}
    {a1 a2 : R → Nat → R} (h1 : RLaw inst v1 a1) (h2 : RLaw inst v2 a2) (r : R) :
    v1 r = v2 r ∧ ∀ n, n ≤ (v1 r).length → a1 r n = a2 r n := by
  -- reading `n` bytes succeeds under one law iff under the other
  have key : ∀ n (hn : n ≤ Usize.max), n ≤ (v1 r).length → n ≤ (v2 r).length ∧
      a1 r n = a2 r n ∧ (v1 r).take n = (v2 r).take n := by
    intro n hn h
    have e1 := h1.read_exact_ok r (zeros n hn) (by simpa [zeros] using h)
    by_cases h' : n ≤ (v2 r).length
    · have e2 := h2.read_exact_ok r (zeros n hn) (by simpa [zeros] using h')
      rw [e1] at e2
      simp only [ok.injEq, Prod.mk.injEq] at e2
      have := congrArg Subtype.val e2.2.2
      simp only [cut_val, zeros, List.length_replicate] at this
      exact ⟨h', by simpa [zeros] using e2.2.1, this⟩
    · obtain ⟨r', b', e2⟩ := h2.read_exact_eof r (zeros n hn) (by simp [zeros]; omega)
      rw [e1] at e2
      simp at e2
  have k1 := key (v1 r).length (h1.view_le r) le_rfl
  have k2 := (fun n hn h => key n hn h)
  -- symmetric bound
  have hle : (v2 r).length ≤ (v1 r).length := by
    by_contra hc
    have e2 := h2.read_exact_ok r (zeros (v2 r).length (h2.view_le r)) (by simp [zeros])
    obtain ⟨r', b', e1⟩ := h1.read_exact_eof r (zeros (v2 r).length (h2.view_le r))
      (by simp [zeros]; omega)
    rw [e1] at e2
    simp at e2
  have heq : (v1 r).length = (v2 r).length := le_antisymm k1.1 hle
  refine ⟨?_, fun n hn => (key n (le_trans hn (h1.view_le r)) hn).2.1⟩
  have := k1.2.2
  rwa [List.take_length, heq, List.take_length] at this

theorem view_eq {R : Type} {inst : alloc.io.read.Read R} {v : R → List Std.U8} {a : R → Nat → R}
    (h : RLaw inst v a) (r : R) : alloc.io.read.Read.view inst r = v r :=
  (read_law_unique (alloc.io.read.Read.Lawful.law' ⟨⟨v, a, h⟩⟩) h r).1

theorem adv_eq {R : Type} {inst : alloc.io.read.Read R} {v : R → List Std.U8} {a : R → Nat → R}
    (h : RLaw inst v a) (r : R) (n : Nat) (hn : n ≤ (v r).length) :
    alloc.io.read.Read.adv inst r n = a r n := by
  have hl := alloc.io.read.Read.Lawful.law' (⟨⟨v, a, h⟩⟩ : alloc.io.read.Read.Lawful R inst)
  exact (read_law_unique hl h r).2 n (by rw [(read_law_unique hl h r).1]; exact hn)

/-! ### The `Vec<u8>` writer -/

theorem vec_write_all_eq (w : alloc.vec.Vec Std.U8) (s : Slice Std.U8) :
    alloc.vec.VecU8.Insts.CoreIoWriteWrite.write_all w s =
      if h : w.val.length + s.val.length ≤ Usize.max then ok (.Ok (), ⟨w.val ++ s.val, by simpa using h⟩)
      else fail .panic := by
  simp only [alloc.vec.VecU8.Insts.CoreIoWriteWrite.write_all,
    CoreModels.alloc.vec.Vec.extend_from_slice, rust_primitives.sequence.seq_extend, mapM_clone_U8]
  by_cases h : w.val.length + s.val.length ≤ Usize.max
  · simp [h]
  · simp [h]

theorem vec_law : WLaw alloc.vec.VecU8.Insts.CoreIoWriteWrite (fun v => v.val) where
  view_le w := w.property
  write_all_ok w s h := ⟨_, by simp only [alloc.vec.VecU8.Insts.CoreIoWriteWrite]; rw [vec_write_all_eq, dif_pos h], rfl⟩
  write_all_bound w w' s he := by
    simp only [alloc.vec.VecU8.Insts.CoreIoWriteWrite] at he
    rw [vec_write_all_eq] at he
    split at he
    · assumption
    · cases he

theorem vec_lawful : core.io.write.Write.Lawful (alloc.vec.Vec Std.U8)
    alloc.vec.VecU8.Insts.CoreIoWriteWrite := ⟨⟨_, vec_law⟩⟩

/-- Every law of the `Vec<u8>` writer has the identity view. -/
theorem vec_view_unique {v : alloc.vec.Vec Std.U8 → List Std.U8}
    (h : WLaw alloc.vec.VecU8.Insts.CoreIoWriteWrite v) (w : alloc.vec.Vec Std.U8) : v w = w.val := by
  let e : alloc.vec.Vec Std.U8 := ⟨[], by simp⟩
  -- the empty vector has the empty view: a write of `usize::MAX` bytes onto it succeeds
  have he : v e = [] := by
    have hw := vec_write_all_eq e (zeros Usize.max le_rfl)
    rw [dif_pos (by simp [e, zeros])] at hw
    have := h.write_all_bound e _ _ hw
    simp only [zeros, List.length_replicate] at this
    exact List.eq_nil_of_length_eq_zero (by omega)
  let ws : Slice Std.U8 := ⟨w.val, w.property⟩
  obtain ⟨w', hw', hv⟩ := h.write_all_ok e ws (by rw [he]; simpa [ws] using w.property)
  have hw := vec_write_all_eq e ws
  rw [dif_pos (by simpa [e, ws] using w.property)] at hw
  have h2 := hw'.symm.trans hw
  simp only [ok.injEq, Prod.mk.injEq, true_and] at h2
  subst h2
  simpa [he, e, ws] using hv

theorem vec_sink (w : alloc.vec.Vec Std.U8) :
    core.io.write.Write.view alloc.vec.VecU8.Insts.CoreIoWriteWrite w = w.val :=
  vec_view_unique (core.io.write.Write.Lawful.law' vec_lawful) w

/-! ### `Take<R>` -/

section Take
variable {R : Type} {inst : alloc.io.read.Read R} {v : R → List Std.U8} {a : R → Nat → R}

/-- The view of a `Take`: the inner view cut at the limit. -/
def takeView (v : R → List Std.U8) (t : core.io.util.Take R) : List Std.U8 :=
  (v t.inner).take t.limit.val

/-- The state of a `Take` after `n` bytes: the inner reader advanced, the limit decreased. -/
def takeAdv (a : R → Nat → R) (t : core.io.util.Take R) (n : Nat) : core.io.util.Take R :=
  { t with inner := a t.inner n,
           limit := UScalar.ofNat (t.limit.val - n) (by have := t.limit.hBounds; scalar_tac) }

@[simp] theorem takeAdv_inner (t : core.io.util.Take R) (n : Nat) :
    (takeAdv a t n).inner = a t.inner n := rfl

@[simp] theorem takeAdv_limit (t : core.io.util.Take R) (n : Nat) :
    (takeAdv a t n).limit.val = t.limit.val - n := by simp [takeAdv]

theorem take_read (h : RLaw inst v a) (t : core.io.util.Take R) (buf : Slice Std.U8) :
    ∃ k : Std.Usize, k.val = min buf.val.length (takeView v t).length ∧
      alloc.core.io.util.Take.Insts.AllocIoReadRead.read inst t buf =
        ok (.Ok k, takeAdv a t k.val,
          alloc.io.read.cut ((takeView v t).take k.val ++ buf.val.drop k.val) buf) := by
  unfold alloc.core.io.util.Take.Insts.AllocIoReadRead.read
  by_cases hl : t.limit = 0#u64
  · have hl0 : t.limit.val = 0 := by rw [hl]; rfl
    refine ⟨0#usize, by simp [takeView, hl0], ?_⟩
    rw [if_pos hl]
    have e1 : takeAdv a t (0#usize).val = t := by
      obtain ⟨i, l, m⟩ := t
      have z : (0#usize).val = 0 := rfl
      simp only [takeAdv, z, h.adv_zero, Nat.sub_zero]
      congr 1
    rw [e1]
    simp [cut_self]
  · rw [if_neg hl]
    have hL : 0 < t.limit.val := by
      have : t.limit.val ≠ 0 := fun h0 => hl (UScalar.eq_of_val_eq (by simpa using h0))
      omega
    obtain ⟨k, hk, he⟩ := h.read t.inner
      ⟨buf.val.take (min buf.length t.limit.val), by have := buf.property; simp; omega⟩
    simp only [List.length_take] at hk
    have hkL : k.val ≤ t.limit.val := by simp only [Slice.length] at hk; omega
    have hc : (UScalar.cast .U64 k).val = k.val := by
      rw [UScalar.cast_val_eq]; apply Nat.mod_eq_of_lt
      scalar_tac
    obtain ⟨l, hl', hlv⟩ := u64_sub_ok t.limit (UScalar.cast .U64 k) (by omega)
    refine ⟨k, by simp only [takeView, List.length_take, Slice.length] at hk ⊢; omega, ?_⟩
    simp only [he, lift, bind_tc_ok, gt_iff_lt]
    show (if t.limit < UScalar.cast UScalarTy.U64 k then fail Error.panic else _) = _
    have hlt : ¬ t.limit < UScalar.cast UScalarTy.U64 k := by
      intro hlt; have : t.limit.val < (UScalar.cast UScalarTy.U64 k).val := hlt; omega
    rw [if_neg hlt, hl']
    erw [bind_tc_ok]
    have hmx : k.val ≤ min buf.length t.limit.val := by simp only [Slice.length] at hk ⊢; omega
    have hkv : k.val ≤ (v t.inner).length := by omega
    congr 3
    · obtain ⟨i, ln, m⟩ := t
      simp only [takeAdv]
      congr 1
      apply UScalar.eq_of_val_eq; simp [hlv, hc]
    · apply Subtype.ext
      simp only [cut_val, takeView, List.length_take]
      rw [take_cut_append (v t.inner) buf.val hkv hmx (by simp [Slice.length])
        (by simp [Slice.length]), List.take_take, Nat.min_eq_left hkL]

end Take

/-! ### `default_read_exact` over a lawful `read` -/

/-- The buffer after reading `k` more bytes at `pos` (`default_read_exact`'s loop step). -/
theorem read_step_buf (vr bufl : List Std.U8) (pos k : Nat) (hp : pos ≤ vr.length)
    (hpk : pos + k ≤ vr.length) (hpb : pos + k ≤ bufl.length) :
    let b := vr.take pos ++ bufl.drop pos
    let rest := b.drop pos
    (b.take pos ++ ((vr.drop pos).take k ++ rest.drop k).take rest.length).take b.length =
      vr.take (pos + k) ++ bufl.drop (pos + k) := by
  intro b rest
  have hb : b.take pos = vr.take pos := by
    simp only [b, List.take_append, List.length_take, Nat.min_eq_left hp, Nat.sub_self,
      List.take_zero, List.append_nil, List.take_take, Nat.min_self]
  have hr : rest = bufl.drop pos := by
    simp only [rest, b, List.drop_append, List.length_take, Nat.min_eq_left hp, Nat.sub_self,
      List.drop_zero, List.drop_take_self, List.nil_append]
  have hbl : b.length = bufl.length := by simp [b]; omega
  rw [hb, hr]
  have hX : ((vr.drop pos).take k ++ (bufl.drop pos).drop k).length ≤ (bufl.drop pos).length := by
    simp; omega
  rw [List.take_of_length_le hX, hbl, List.take_of_length_le (by simp; omega), ← List.append_assoc,
    ← List.take_add, List.drop_drop]

theorem default_read_exact_law {R : Type}
    (read : R → Slice Std.U8 →
      RustM ((core.result.Result Std.Usize core.io.error.Error) × R × Slice Std.U8))
    {v : R → List Std.U8} {a : R → Nat → R}
    (hread : ∀ r buf, ∃ k : Std.Usize, k.val = min buf.val.length (v r).length ∧
      read r buf = ok (.Ok k, a r k.val,
        alloc.io.read.cut ((v r).take k.val ++ buf.val.drop k.val) buf))
    (hzero : ∀ r, a r 0 = r)
    (hview : ∀ r n, n ≤ (v r).length → v (a r n) = (v r).drop n)
    (hadv : ∀ r x y, x + y ≤ (v r).length → a (a r x) y = a r (x + y))
    (r : R) (buf : Slice Std.U8) :
    ⦃ ⌜ True ⌝ ⦄ alloc.io.read.default_read_exact read r buf
    ⦃ ⇓ y => ⌜ (buf.val.length ≤ (v r).length →
          y = (.Ok (), a r buf.val.length, alloc.io.read.cut (v r) buf)) ∧
        ((v r).length < buf.val.length → y.1 = .Err core.io.error.Error.READ_EXACT_EOF) ⌝ ⦄ := by
  obtain ⟨bufl, hbufP⟩ := buf
  unfold alloc.io.read.default_read_exact
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.loop.spec_decr_nat (fun p : R × Slice Std.U8 × Nat => bufl.length - p.2.2)
    (fun p : R × Slice Std.U8 × Nat => p.1 = a r p.2.2 ∧
      p.2.1.val = (v r).take p.2.2 ++ bufl.drop p.2.2 ∧
      p.2.2 ≤ bufl.length ∧ p.2.2 ≤ (v r).length)
  · rintro ⟨s, ⟨bl, hbP⟩, pos⟩ ⟨hs, hb, hp1, hp2⟩
    dsimp only at hs hb hp1 hp2
    show Aeneas.Std.WP.spec (if pos ≥ Slice.length ⟨bl, hbP⟩ then _ else _) _
    simp only [Slice.length, ge_iff_le]
    have hbl : bl.length = bufl.length := by rw [hb]; simp; omega
    by_cases hd : bl.length ≤ pos
    · rw [if_pos hd, Aeneas.Std.WP.spec_ok]
      have hpb : pos = bufl.length := by omega
      refine ⟨fun hle => ?_, fun hlt => by omega⟩
      rw [hs, hpb]
      congr 2
      apply Subtype.ext
      simp [cut_val, hb, hpb]
    · rw [if_neg hd]
      obtain ⟨k, hk, he⟩ := hread s ⟨bl.drop pos, by simp; omega⟩
      rw [he]
      have hvs : v s = (v r).drop pos := by rw [hs]; exact hview r pos hp2
      simp only [hvs, List.length_drop, hbl] at hk
      simp only [bind_tc_ok]
      show Aeneas.Std.WP.spec (if k.val = 0 then _ else _) _
      by_cases hk0 : k.val = 0
      · rw [if_pos hk0, Aeneas.Std.WP.spec_ok]
        refine ⟨fun hle => by omega, fun _ => rfl⟩
      · rw [if_neg hk0, if_neg (by simp; omega), Aeneas.Std.WP.spec_ok]
        dsimp only
        refine ⟨⟨by rw [hs, hadv r pos k.val (by omega)], ?_, by omega, by omega⟩, by omega⟩
        simp only [cut_val, hvs, hb]
        exact read_step_buf (v r) bufl pos k.val hp2 (by omega) (by omega)
  · refine ⟨(hzero r).symm, ?_, ?_, ?_⟩ <;> simp

/-! ### `Take<R>` is lawful -/

section TakeLaw
variable {R : Type} {inst : alloc.io.read.Read R} {v : R → List Std.U8} {a : R → Nat → R}

theorem take_adv_zero (h : RLaw inst v a) (t : core.io.util.Take R) : takeAdv a t 0 = t := by
  obtain ⟨i, l, m⟩ := t
  simp only [takeAdv, h.adv_zero, Nat.sub_zero]
  congr 1

theorem take_adv_view (h : RLaw inst v a) (t : core.io.util.Take R) (n : Nat)
    (hn : n ≤ (takeView v t).length) : takeView v (takeAdv a t n) = (takeView v t).drop n := by
  simp only [takeView, List.length_take] at hn ⊢
  rw [takeAdv_inner, takeAdv_limit, h.adv_view _ _ (by omega), List.drop_take]

theorem take_adv_adv (h : RLaw inst v a) (t : core.io.util.Take R) (x y : Nat)
    (hxy : x + y ≤ (takeView v t).length) :
    takeAdv a (takeAdv a t x) y = takeAdv a t (x + y) := by
  obtain ⟨i, l, m⟩ := t
  simp only [takeView, List.length_take] at hxy
  have e := h.adv_adv i x y (by omega)
  simp only [takeAdv, e]
  congr 1
  apply UScalar.eq_of_val_eq; simp [Nat.sub_sub]

theorem take_law (h : RLaw inst v a) :
    RLaw (alloc.core.io.util.Take.Insts.AllocIoReadRead inst) (takeView v) (takeAdv a) where
  view_le t := le_trans (by simp [takeView]) (h.view_le t.inner)
  adv_zero := take_adv_zero h
  adv_view := take_adv_view h
  adv_adv := take_adv_adv h
  read := take_read h
  read_exact_ok t buf hb := by
    obtain ⟨y, hy, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (default_read_exact_law _ (take_read h) (take_adv_zero h) (take_adv_view h) (take_adv_adv h) t buf)
    exact hy.trans (congrArg ok (hP.1 hb))
  read_exact_eof t buf hb := by
    obtain ⟨y, hy, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (default_read_exact_law _ (take_read h) (take_adv_zero h) (take_adv_view h) (take_adv_adv h) t buf)
    obtain ⟨y1, y2, y3⟩ := y
    have := hP.2 hb
    simp only at this
    subst this
    exact ⟨y2, y3, hy⟩

theorem take_lawful (h : alloc.io.read.Read.Lawful R inst) :
    alloc.io.read.Read.Lawful (core.io.util.Take R)
      (alloc.core.io.util.Take.Insts.AllocIoReadRead inst) :=
  ⟨⟨_, _, take_law (alloc.io.read.Read.Lawful.law' h)⟩⟩

end TakeLaw

theorem slice_lawful : alloc.io.read.Read.Lawful (Slice Std.U8)
    alloc.Shared0SliceU8.Insts.AllocIoReadRead := ⟨⟨_, _, slice_law⟩⟩

/-- `&mut R` reads as `R` (aeneas represents `&mut R` as `R`). -/
theorem mut_lawful {R : Type} {inst : alloc.io.read.Read R} (h : alloc.io.read.Read.Lawful R inst) :
    alloc.io.read.Read.Lawful R (alloc.Mut0R.Insts.AllocIoReadRead inst) := h

/-! ### `read_to_end` on a lawful reader -/

theorem vec_extend_eq (w : alloc.vec.Vec Std.U8) (s : Slice Std.U8)
    (h : w.val.length + s.val.length ≤ Usize.max) :
    alloc.vec.Vec.extend_from_slice core.U8.Insts.CoreCloneClone w s =
      ok ⟨w.val ++ s.val, by simpa using h⟩ := by
  simp only [CoreModels.alloc.vec.Vec.extend_from_slice, rust_primitives.sequence.seq_extend,
    mapM_clone_U8]
  simp [h]

/-- `read_to_end` on a lawful reader appends everything the reader yields and leaves it at its
end, given room in the vector. -/
theorem read_to_end_law {R : Type} {inst : alloc.io.read.Read R} {v : R → List Std.U8}
    {a : R → Nat → R} (h : RLaw inst v a) (r : R) (buf : alloc.vec.Vec Std.U8)
    (hb : buf.val.length + (v r).length ≤ Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ alloc.io.read.Read.read_to_end.default inst r buf
    ⦃ ⇓ y => ⌜ (∃ n, y.1 = .Ok n) ∧ y.2.1 = a r (v r).length ∧
        y.2.2.1.val = buf.val ++ v r ∧ y.2.2.2 = fun x => x ⌝ ⦄ := by
  unfold alloc.io.read.Read.read_to_end.default
  apply Aeneas.Std.WP.spec_to_mvcgen
  apply Aeneas.Std.WP.spec_bind (Pₘ := fun y => ∃ w : alloc.vec.Vec Std.U8,
      y = (.Ok (), a r (v r).length, w) ∧ w.val = buf.val ++ v r)
  · apply Aeneas.Std.loop.spec_decr_nat (fun p : R × alloc.vec.Vec Std.U8 => (v p.1).length)
      (fun p : R × alloc.vec.Vec Std.U8 => ∃ m, m ≤ (v r).length ∧ p.1 = a r m ∧
        p.2.val = buf.val ++ (v r).take m)
    · rintro ⟨s, ⟨wl, hwP⟩⟩ ⟨m, hm, hs, hw⟩
      dsimp only at hs hw
      have hvs : v s = (v r).drop m := by rw [hs]; exact h.adv_view r m hm
      obtain ⟨k, hk, he⟩ := h.read s ⟨List.replicate 32 0#u8, by simp [Usize.max]; scalar_tac⟩
      simp only [hvs, List.length_drop, List.length_replicate] at hk
      show Aeneas.Std.WP.spec (Std.bind (inst.read s _) _) _
      rw [he]
      simp only [bind_tc_ok]
      show Aeneas.Std.WP.spec (if k.val = 0 then _ else _) _
      by_cases hk0 : k.val = 0
      · rw [if_pos hk0, Aeneas.Std.WP.spec_ok]
        have hmv : m = (v r).length := by omega
        refine ⟨⟨wl, hwP⟩, ?_, ?_⟩
        · show (_, a s k.val, _) = _
          rw [hk0, h.adv_zero, hs, hmv]
        · show wl = _
          rw [hw, hmv, List.take_length]
      · rw [if_neg hk0, if_neg (by omega)]
        rw [vec_extend_eq _ _ (by simp [cut_val, hw]; omega)]
        simp only [bind_tc_ok]
        rw [Aeneas.Std.WP.spec_ok]
        dsimp only
        refine ⟨⟨m + k.val, by omega, by rw [hs, h.adv_adv r m k.val (by omega)], ?_⟩, ?_⟩
        · simp only [hw, cut_val, hvs, List.append_assoc]
          rw [List.take_take, Nat.min_eq_left (by simp; omega), List.take_append_of_le_length
            (by simp; omega), List.take_take, Nat.min_self, ← List.take_add]
        · rw [h.adv_view s k.val (by rw [hvs]; simp; omega), hvs]; simp; omega
    · exact ⟨0, by omega, (h.adv_zero r).symm, by simp⟩
  · intro y ⟨w0, hy, hw0⟩
    rw [hy]
    obtain ⟨d, hd, hdv⟩ := usize_sub_ok (Slice.len ⟨w0.val, w0.property⟩)
      (Slice.len ⟨buf.val, buf.property⟩) (by simp [Slice.len_val, hw0])
    show Aeneas.Std.WP.spec (Std.bind (Slice.len ⟨w0.val, w0.property⟩ - Slice.len ⟨buf.val, buf.property⟩) _) _
    rw [hd]
    exact (Aeneas.Std.WP.spec_ok _).mpr ⟨⟨d, rfl⟩, rfl, hw0, rfl⟩

/-! ### `read_bytes_bounded` on a lawful reader -/

theorem min_usize_total (x y : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ core.cmp.min core.Usize.Insts.CoreCmpOrd x y ⦃ ⇓ _ => ⌜ True ⌝ ⦄ := by
  unfold CoreModels.core.cmp.min
  mvcgen [core.Usize.Insts.CoreCmpOrd, CoreModels.core.mkUOrd]

end tls_codec.StdIo

namespace tls_codec

/-- `read_bytes_bounded` on a lawful reader: `len` bytes (at most `isize::MAX`) if the reader has
them, with the reader advanced by `len`; `EndOfStream` otherwise. Never panics. -/
theorem read_bytes_bounded_law {R : Type} {inst : alloc.io.read.Read R} {v : R → List Std.U8}
    {a : R → Nat → R} (h : StdIo.RLaw inst v a) (r : R) (len : Std.Usize) :
    ⦃ ⌜ True ⌝ ⦄ read_bytes_bounded inst r len
    ⦃ ⇓ y => ⌜ (len.val ≤ (v r).length → 2 * len.val < UScalar.max UScalarTy.Usize →
          ∃ w : alloc.vec.Vec Std.U8, y.1 = .Ok w ∧ (w : Slice Std.U8).val = (v r).take len.val ∧
            y.2 = a r len.val) ∧
        ((v r).length < len.val → y.1 = .Err Error.EndOfStream ∨
          y.1 = .Err Error.InvalidVectorLength) ⌝ ⦄ := by
  have ht := StdIo.take_law h
  let t0 : core.io.util.Take R :=
    { inner := r, len := UScalar.cast .U64 len, limit := UScalar.cast .U64 len }
  have hc : (UScalar.cast .U64 len).val = len.val := by
    rw [UScalar.cast_val_eq]; apply Nat.mod_eq_of_lt
    simp only [UScalarTy.U64_numBits_eq]; exact StdIo.usize_lt_2_64 len
  have hte := StdIo.read_to_end_law (inst := alloc.core.io.util.Take.Insts.AllocIoReadRead
      (alloc.Mut0R.Insts.AllocIoReadRead inst)) ht t0 (Slice.new Std.U8)
    (by simp [StdIo.takeView, t0, Slice.new]; have := h.view_le r; omega)
  mvcgen [read_bytes_bounded, StdIo.min_usize_total, alloc.io.read.Read.take.default, hte,
    CoreModels.alloc.vec.Vec.with_capacity, CoreModels.alloc.vec.Vec.new,
    rust_primitives.sequence.seq_empty]
  · rename_i hgt
    have hm := Usize.hcast_Isize_MAX_val
    refine ⟨fun _ hle => ?_, fun _ => by simp⟩
    exfalso
    have : (IScalar.hcast UScalarTy.Usize core.num.Isize.MAX).val < len.val := hgt
    omega
  · rename_i hng _ y hy _ _ _ _ i3 hne _ hi3
    obtain ⟨_, _, hw, _⟩ := hy
    have hl : i3.val = min len.val (v r).length := by
      rw [hi3, Slice.len_val]; simp [hw, StdIo.takeView, t0, hc, Slice.new, Slice.length]
    refine ⟨fun hle _ => ?_, fun _ => by simp⟩
    exfalso
    have : i3 ≠ len := by simpa using hne
    exact this (UScalar.eq_of_val_eq (by omega))
  · rename_i hng _ y hy _ _ _ _ i3 hne _ hi3
    obtain ⟨_, hs, hw, hb⟩ := hy
    have hl : i3.val = min len.val (v r).length := by
      rw [hi3, Slice.len_val]; simp [hw, StdIo.takeView, t0, hc, Slice.new, Slice.length]
    have hil : i3 = len := UScalar.eq_of_val_eq (by simpa using hne)
    subst hil
    refine ⟨fun hle _ => ⟨_, rfl, ?_, ?_⟩, fun hlt => by omega⟩
    · show _ = _
      rw [hw]; simp [StdIo.takeView, t0, hc, Slice.new]
    · simp +zetaDelta only [hb, hs, StdIo.takeAdv_inner]
      congr 1; simp [StdIo.takeView, hc]; omega
  · rename_i _ _ y hy _ _ _ hbr
    obtain ⟨⟨n, hn⟩, _⟩ := hy
    rw [hn] at hbr
    simp [tryCF] at hbr

end tls_codec

namespace tls_codec.StdIo
end tls_codec.StdIo
