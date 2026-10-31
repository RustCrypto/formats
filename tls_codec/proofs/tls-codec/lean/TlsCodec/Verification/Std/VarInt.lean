/- The varint, `ContentLength` and `VLBytes` serializers (and their sizes) on lawful writers.

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
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-! ### Writers -/

/-- `write_all` on a lawful writer with room. -/
theorem write_all_law_spec {W : Type} {WI : core.io.write.Write W} {v : W → List Std.U8}
    (law : StdIo.WLaw WI v) (w : W) (s : Slice Std.U8)
    (h : (v w).length + s.val.length ≤ Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ WI.write_all w s ⦃ ⇓ p => ⌜ p.1 = .Ok () ∧ v p.2 = v w ++ s.val ⌝ ⦄ := by
  obtain ⟨w', hw, hv⟩ := law.write_all_ok w s h
  rw [hw]
  exact ok_triple_of ⟨rfl, hv⟩

/-! ### Varint: serializer -/

/-- The first `lenOf n` bytes of the 8-byte buffer `write_bytes` fills are the encoding of `n`. -/
theorem varint.lenOf_le (n : Nat) : varint.lenOf n ≤ 8 := by
  have := varint.lenOf_mem n; omega

theorem varint.encList_length (n : Nat) : (varint.encList n).length = varint.lenOf n := by
  simp [varint.encList]

theorem varint.write_prefix_take (n : Nat) (s : List Std.U8) (hL : varint.lenOf n ≤ 8)
    (hk : ∀ k, (s[k]?).map (·.val) =
        ((List.replicate 8 (0#u8))[k]?).map (fun x => if k < varint.lenOf n then
          (if k = 0 then varint.pfx (varint.lenOf n) else x.val) |||
            ((n >>> (8 * (varint.lenOf n - 1 - k))) % 256) else x.val)) :
    (s.take (varint.lenOf n)).map (·.val) = varint.encList n := by
  apply List.ext_getElem?
  intro k
  rw [List.getElem?_map, List.getElem?_take]
  unfold varint.encList
  rw [List.getElem?_map]
  by_cases hkL : k < varint.lenOf n
  · have h := hk k
    rw [List.getElem?_replicate, if_pos (by omega)] at h
    rw [List.getElem?_range hkL, if_pos hkL]
    simpa [varint.encByte, hkL] using h
  · have : (List.range (varint.lenOf n))[k]? = none := List.getElem?_eq_none (by simp; omega)
    rw [this, if_neg hkL]
    simp

theorem varint.ser_triple {W : Type} {WI : core.io.write.Write W} {v : W → List Std.U8}
    (law : StdIo.WLaw WI v) (self : varint.TlsVarInt) (w : W)
    (hv : self.val ≤ 2 ^ 62 - 1) (hroom : (v w).length + varint.lenOf self.val ≤ Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.Insts.Tls_codecSerialize.tls_serialize WI self w
    ⦃ ⇓ p => ⌜ (∃ l : Std.Usize, p.1 = .Ok l ∧ l.val = varint.lenOf self.val) ∧
        ∃ b : List Std.U8, b.map (·.val) = varint.encList self.val ∧ v p.2 = v w ++ b ⌝ ⦄ := by
  have hwb : ∀ buf : Slice Std.U8, varint.lenOf self.val ≤ buf.val.length →
      ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.write_bytes self buf
      ⦃ ⇓ r => ⌜ (∃ l : Std.Usize, r.1 = .Ok l ∧ l.val = varint.lenOf self.val) ∧
        r.2.val.length = buf.val.length ∧ ∀ k, (r.2.val[k]?).map (·.val) =
        (buf.val[k]?).map (fun x => if k < varint.lenOf self.val then
          (if k = 0 then varint.pfx (varint.lenOf self.val) else x.val) |||
            ((self.val >>> (8 * (varint.lenOf self.val - 1 - k))) % 256) else x.val) ⌝ ⦄ :=
    fun buf h => varint.TlsVarInt.write_bytes_content self buf ⟨hv, h⟩
  unfold varint.TlsVarInt.Insts.Tls_codecSerialize.tls_serialize
  have hwa := fun s => write_all_law_spec law w s
  mvcgen [hwb, hwa]
  · rename_i r hr
    have := varint.lenOf_mem self.val
    rw [hr.1]; simp; omega
  · rename_i r hr s1 hs1 _ val _ hcf o
    intro hget _
    have h8 : s1.2.val.length = 8 := by rw [hs1.2.1, hr.1]; simp
    have hfs : (((Array.repeat 8#usize 0#u8).from_slice s1.2).to_slice).val = s1.2.val := by
      rw [Array.to_slice, Array.from_slice_val _ _ (by simpa using h8)]
    obtain ⟨l, hl, hlv⟩ := hs1.1
    rw [continue_eq_tryCF, hl] at hcf
    simp at hcf
    subst hcf
    have hL8 := varint.lenOf_mem self.val
    obtain ⟨t, rfl, ht⟩ := hget (by simp [Array.to_slice] at hfs ⊢; omega)
    have hfs0 : (((Array.repeat 8#usize 0#u8).from_slice s1.2).to_slice).val = s1.2.val := hfs
    have hlen : t.val.length = varint.lenOf self.val := by
      rw [ht, List.length_take]; simp [h8, hr.2, hlv]; omega
    have henc : t.val.map (·.val) = varint.encList self.val := by
      have hrv : r.2 = (Array.repeat 8#usize 0#u8).from_slice := hr.2
      rw [ht, hrv, hfs0, hlv]
      apply varint.write_prefix_take _ _ (by omega)
      intro k
      have := hs1.2.2 k
      rw [hr.1] at this
      simpa using this
    refine ⟨t, rfl, ?_⟩
    simp only [PostCond.ok]
    mvcgen [hwa]
    · omega
    · rename_i p hp _ _ _ _
      exact ⟨⟨l, rfl, hlv⟩, t.val, henc, hp.2⟩
    · rename_i p hp _ res _ hcf
      rw [hp.1] at hcf
      simp [tryCF] at hcf
  · rename_i _ _ p hp _ _ _ hcf
    obtain ⟨l, hl, -⟩ := hp.1
    rw [hl] at hcf
    simp [tryCF] at hcf

/-- A value above `MAX` is refused and the writer is untouched. -/
theorem varint.ser_triple_gt {W : Type} (WI : core.io.write.Write W)
    (self : varint.TlsVarInt) (w : W) (hv : 2 ^ 62 - 1 < self.val) :
    ⦃ ⌜ True ⌝ ⦄ varint.TlsVarInt.Insts.Tls_codecSerialize.tls_serialize WI self w
    ⦃ ⇓ p => ⌜ (∃ e, p.1 = .Err e) ∧ p.2 = w ⌝ ⦄ := by
  unfold varint.TlsVarInt.Insts.Tls_codecSerialize.tls_serialize
  mvcgen [varint.TlsVarInt.write_bytes_spec]
  · rename_i _ _ s1 hs1 _ _ _ hcf _
    rw [hs1.1 (Or.inl hv)] at hcf
    simp [tryCF] at hcf
  · rename_i _ _ s1 hs1 _ res _ hcf
    rw [hs1.1 (Or.inl hv)] at hcf
    simp [tryCF] at hcf
    subst hcf
    refine ⟨_, rfl, ?_⟩
    refine triple_post_mono (core.convert.From.Blanket.from_spec _) ?_
    intro f hf
    subst hf
    simp only [PostCond.ok]
    mvcgen
    exact ⟨_, rfl⟩

/-! ### `write_length` -/

theorem write_length_triple {W : Type} {WI : core.io.write.Write W} {v : W → List Std.U8}
    (law : StdIo.WLaw WI v) (w : W) (n : Std.Usize) (hroom : (v w).length + 8 ≤ Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.rw.write_length WI w n
    ⦃ ⇓ p => ⌜ (n.val ≤ 2 ^ 30 - 1 →
          (∃ l : Std.Usize, p.1 = .Ok l ∧ l.val = varint.lenOf n.val) ∧
          ∃ b : List Std.U8, b.map (·.val) = varint.encList n.val ∧ v p.2 = v w ++ b) ∧
        (2 ^ 30 - 1 < n.val → (∃ e, p.1 = .Err e) ∧ p.2 = w) ⌝ ⦄ := by
  have hst : ∀ c : quic_vec.ContentLength, c.val ≤ 2 ^ 62 - 1 →
      ⦃ ⌜ True ⌝ ⦄ quic_vec.ContentLength.Insts.Tls_codecSerialize.tls_serialize WI c w
      ⦃ ⇓ p => ⌜ (∃ l : Std.Usize, p.1 = .Ok l ∧ l.val = varint.lenOf c.val) ∧
        ∃ b : List Std.U8, b.map (·.val) = varint.encList c.val ∧ v p.2 = v w ++ b ⌝ ⦄ :=
    fun c h1 => varint.ser_triple law c w h1 (by have := varint.lenOf_mem c.val; omega)
  unfold quic_vec.rw.write_length
  mvcgen [hst]
  · rename_i r hr _ val _ hcf p
    cases r with
    | Err e => simp [tryCF] at hcf
    | Ok c =>
      simp [tryCF] at hcf
      subst hcf
      obtain ⟨hc, hn⟩ := hr
      rw [hc]
      intro ha hb
      exact ⟨fun _ => ⟨ha, hb⟩, fun h => by omega⟩
  · rename_i r hr _ val _
    cases r with
    | Err e => intro hcf; simp [tryCF] at hcf
    | Ok c =>
      intro hcf
      simp [tryCF] at hcf
      subst hcf
      have := hr.1
      omega
  · rename_i r hr _ res _ hcf
    cases r with
    | Ok c => simp [tryCF] at hcf
    | Err e =>
      simp [tryCF] at hcf
      subst hcf
      refine ⟨_, rfl, ?_⟩
      refine triple_post_mono (core.convert.From.Blanket.from_spec _) ?_
      intro f hf
      subst hf
      simp only [PostCond.ok]
      mvcgen
      exact ⟨fun h => by omega, fun _ => ⟨_, rfl⟩⟩

/-! ### `tls_serialize_bytes` (the `VLBytes` writer) -/

theorem rw_bytes.ser_triple {W : Type} {WI : core.io.write.Write W} {v : W → List Std.U8}
    (law : StdIo.WLaw WI v) (w : W) (bytes : Slice Std.U8)
    (hroom : bytes.val.length ≤ 2 ^ 30 - 1 → (v w).length + (bytes.val.length + 8) ≤ Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.rw_bytes.tls_serialize_bytes WI w bytes
    ⦃ ⇓ p => ⌜ (bytes.val.length ≤ 2 ^ 30 - 1 →
          (∃ l : Std.Usize, p.1 = .Ok l ∧ l.val = bytes.val.length + varint.lenOf bytes.val.length) ∧
          ∃ b : List Std.U8, b.map (·.val) = varint.encList bytes.val.length ∧
            v p.2 = v w ++ b ++ bytes.val) ∧
        (2 ^ 30 - 1 < bytes.val.length → (∃ e, p.1 = .Err e) ∧ p.2 = w) ⌝ ⦄ := by
  have hst : ∀ c : quic_vec.ContentLength, c.val ≤ 2 ^ 62 - 1 →
      (v w).length + varint.lenOf c.val ≤ Usize.max →
      ⦃ ⌜ True ⌝ ⦄ quic_vec.ContentLength.Insts.Tls_codecSerialize.tls_serialize WI c w
      ⦃ ⇓ p => ⌜ (∃ l : Std.Usize, p.1 = .Ok l ∧ l.val = varint.lenOf c.val) ∧
        ∃ b : List Std.U8, b.map (·.val) = varint.encList c.val ∧ v p.2 = v w ++ b ⌝ ⦄ :=
    fun c h1 h2 => varint.ser_triple law c w h1 h2
  have hwa : ∀ (w1 : W) (s : Slice Std.U8), (v w1).length + s.val.length ≤ Usize.max →
      ⦃ ⌜ True ⌝ ⦄ WI.write_all w1 s
      ⦃ ⇓ p => ⌜ p.1 = .Ok () ∧ v p.2 = v w1 ++ s.val ⌝ ⦄ := fun w1 s h => write_all_law_spec law w1 s h
  unfold quic_vec.rw_bytes.tls_serialize_bytes
  mvcgen [hst, hwa, CoreModels.core.slice.Slice.len_spec]
  all_goals (try simp only [continue_eq_tryCF] at *)
  all_goals subst_vars
  all_goals (try simp only [Slice.len_val] at *)
  · simp at *; omega
  · have hr := hroom (‹_ ∧ bytes.length ≤ 2 ^ 30 - 1›).2
    exact le_trans (Nat.add_le_add_left (varint.lenOf_le _) _) (by omega)
  · have hr := hroom (‹_ ∧ bytes.length ≤ 2 ^ 30 - 1›).2
    obtain ⟨-, b, hb, hv⟩ := ‹(∃ l, _ ∧ _) ∧ _›
    have := congrArg List.length hb
    simp only [List.length_map, varint.encList_length] at this
    have := varint.lenOf_le (‹quic_vec.ContentLength›.val)
    simp only [hv, List.length_append] at *
    omega
  · rename_i c r2 h4 val r1 h3 _ r h2 _ ha hc
    obtain ⟨⟨l, hl, hlv⟩, b, hb, hv⟩ := h4
    rw [hl, core.result.Result.Ok.injEq] at h2
    subst h2
    have hc' : bytes.val.length ≤ 2 ^ 30 - 1 := hc.2
    refine ⟨fun _ => ⟨⟨_, rfl, ?_⟩, b, ?_, ?_⟩, fun h => absurd h (by omega)⟩
    · rw [ha, hlv, hc.1]
    · rw [hb, hc.1]
    · rw [h3.2, hv]
  · rename_i c r2 h4 val r1 h3 _ h2 _ ha hc
    obtain ⟨⟨l, hl, hlv⟩, -⟩ := h4
    rw [hl, core.result.Result.Ok.injEq] at h2
    subst h2
    have := varint.lenOf_le c.val
    have hm : UScalar.max UScalarTy.Usize = Usize.max := by
      simp [Usize.max, UScalar.max, UScalarTy.numBits, Usize.numBits]
    exfalso
    simp only [hm] at *
    have hbl : bytes.length = bytes.val.length := rfl
    omega
  · rename_i _ _ _ _ _ h3 _ hcf _ _
    rw [h3.1] at hcf; simp [tryCF] at hcf
  · obtain ⟨⟨l, hl, -⟩, -⟩ := ‹(∃ l, _ ∧ _) ∧ _›
    have hcf := ‹core.ops.control_flow.ControlFlow.Break _ = tryCF _›
    rw [hl] at hcf; simp [tryCF] at hcf
  · rename_i r res hcf hm
    cases r with
    | Ok c => simp [tryCF] at hcf
    | Err e =>
      simp [tryCF] at hcf
      subst hcf
      refine ⟨_, rfl, ?_⟩
      refine triple_post_mono (core.convert.From.Blanket.from_spec _) ?_
      intro f hf
      subst hf
      simp only [PostCond.ok]
      mvcgen
      exact ⟨fun h => by simp at hm; omega, fun _ => ⟨_, rfl⟩⟩

/-! ### Encoding as bytes -/

/-- The varint encoding of `n`, as bytes. -/
def varint.enc (n : Nat) : List Std.U8 :=
  (varint.encList n).map (fun k => (⟨BitVec.ofNat 8 k⟩ : Std.U8))

theorem varint.enc_map (n : Nat) (h : n ≤ 2 ^ 62 - 1) :
    (varint.enc n).map (·.val) = varint.encList n := by
  obtain ⟨e0, tl, he, -, -, hlt, -⟩ := varint.encList_dec n h
  unfold varint.enc
  rw [List.map_map]
  conv_rhs => rw [← List.map_id (varint.encList n)]
  apply List.map_congr_left
  intro k hk
  have := hlt k (he ▸ hk)
  show (BitVec.ofNat 8 k).toNat = k
  rw [BitVec.toNat_ofNat]
  exact Nat.mod_eq_of_lt this

theorem varint.enc_length (n : Nat) : (varint.enc n).length = varint.lenOf n := by
  simp [varint.enc, varint.encList]

theorem varint.eq_enc (n : Nat) (h : n ≤ 2 ^ 62 - 1) (b : List Std.U8)
    (hb : b.map (·.val) = varint.encList n) : b = varint.enc n :=
  List.map_injective_iff.mpr (fun _ _ h => UScalar.eq_of_val_eq h) (hb.trans (varint.enc_map n h).symm)

/-- `SerRuns` from a triple on every lawful writer, stated on the chosen view. -/
theorem SerRuns_of_triple {T : Type} (SI : Serialize T) (x : T) (sz : Std.Usize)
    (out : Option (List Std.U8))
    (h : ∀ (W : Type) (WI : core.io.write.Write W), core.io.write.Write.Lawful W WI →
      ∀ w, (core.io.write.Write.view WI w).length + sz.val ≤ imax →
      ⦃ ⌜ True ⌝ ⦄ SI.tls_serialize WI x w
      ⦃ ⇓ p => ⌜ (∀ b, out = some b → (∃ n : Std.Usize, p.1 = .Ok n ∧ n.val = b.length) ∧
          core.io.write.Write.view WI p.2 = core.io.write.Write.view WI w ++ b) ∧
        (out = none → ∃ e, p.1 = .Err e) ⌝ ⦄) :
    SerRuns SI x sz out := by
  intro W WI hWI w hroom
  obtain ⟨p, hp, hpost⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (h W WI hWI w hroom)
  exact ⟨p.1, p.2, hp, hpost⟩

theorem varint.ser_runs (x : varint.TlsVarInt) (hx : x.val ≤ 2 ^ 62 - 1) (sz : Std.Usize)
    (hsz : sz.val = varint.lenOf x.val) :
    SerRuns varint.TlsVarInt.Insts.Tls_codecSerialize x sz (some (varint.enc x.val)) := by
  apply SerRuns_of_triple
  intro W WI hWI w hroom
  have := imax_le
  refine triple_post_mono (varint.ser_triple hWI.law' x w hx (by omega)) ?_
  rintro p ⟨⟨l, hl, hlv⟩, b, hb, hv⟩
  have hbe := varint.eq_enc _ hx b hb
  subst hbe
  refine ⟨fun b' hb' => ?_, fun h => by cases h⟩
  cases hb'
  exact ⟨⟨l, hl, by rw [hlv, varint.enc_length]⟩, hv⟩

theorem ContentLength.ser_runs (x : quic_vec.ContentLength) (hx : x.val ≤ 2 ^ 62 - 1)
    (sz : Std.Usize) (hsz : sz.val = varint.lenOf x.val) :
    SerRuns quic_vec.ContentLength.Insts.Tls_codecSerialize x sz (some (varint.enc x.val)) :=
  varint.ser_runs x hx sz hsz

/-! ### `VLBytes`: serializer -/

theorem VLBytes.as_slice_val (x : quic_vec.VLBytes) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLBytes.as_slice x ⦃ ⇓ s => ⌜ s.val = x.vec.val ⌝ ⦄ := by
  mvcgen [quic_vec.VLBytes.as_slice, quic_vec.VLBytes.impl.vec]
  rename_i a h b
  intro hb
  rw [hb, h]

/-- The output of the `VLBytes` serializer: the length prefix and the payload, or an error. -/
def VLBytes.out (x : quic_vec.VLBytes) : Option (List Std.U8) :=
  if x.vec.val.length ≤ 2 ^ 30 - 1 then some (varint.enc x.vec.val.length ++ x.vec.val) else none

theorem VLBytes.ser_triple {W : Type} {WI : core.io.write.Write W} {v : W → List Std.U8}
    (law : StdIo.WLaw WI v) (w : W) (x : quic_vec.VLBytes)
    (hroom : x.vec.val.length ≤ 2 ^ 30 - 1 → (v w).length + (x.vec.val.length + 8) ≤ Usize.max) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLBytes.Insts.Tls_codecSerialize.tls_serialize WI x w
    ⦃ ⇓ p => ⌜ (x.vec.val.length ≤ 2 ^ 30 - 1 →
          (∃ l : Std.Usize, p.1 = .Ok l ∧
            l.val = x.vec.val.length + varint.lenOf x.vec.val.length) ∧
          v p.2 = v w ++ (varint.enc x.vec.val.length ++ x.vec.val)) ∧
        (2 ^ 30 - 1 < x.vec.val.length → (∃ e, p.1 = .Err e) ∧ p.2 = w) ⌝ ⦄ := by
  have hrw : ∀ s : Slice Std.U8, s.val = x.vec.val →
      ⦃ ⌜ True ⌝ ⦄ quic_vec.rw_bytes.tls_serialize_bytes WI w s
      ⦃ ⇓ p => ⌜ (x.vec.val.length ≤ 2 ^ 30 - 1 →
          (∃ l : Std.Usize, p.1 = .Ok l ∧
            l.val = x.vec.val.length + varint.lenOf x.vec.val.length) ∧
          v p.2 = v w ++ (varint.enc x.vec.val.length ++ x.vec.val)) ∧
        (2 ^ 30 - 1 < x.vec.val.length → (∃ e, p.1 = .Err e) ∧ p.2 = w) ⌝ ⦄ := by
    intro s hs
    refine triple_post_mono (rw_bytes.ser_triple law w s (by rw [hs]; exact hroom)) ?_
    rintro p ⟨h1, h2⟩
    rw [hs] at h1 h2
    refine ⟨fun hn => ?_, h2⟩
    obtain ⟨hl, b, hb, hv⟩ := h1 hn
    have hbe := varint.eq_enc _ (by omega) b hb
    subst hbe
    exact ⟨hl, by rw [hv, List.append_assoc]⟩
  unfold quic_vec.VLBytes.Insts.Tls_codecSerialize.tls_serialize
  mvcgen [VLBytes.as_slice_val, hrw]
  intro h
  exact h

theorem VLBytes.ser_runs (x : quic_vec.VLBytes) (sz : Std.Usize)
    (hsz : quic_vec.VLBytes.Insts.Tls_codecSize.tls_serialized_len x = ok sz) :
    SerRuns quic_vec.VLBytes.Insts.Tls_codecSerialize x sz (VLBytes.out x) := by
  apply SerRuns_of_triple
  intro W WI hWI w hroom
  have hI := imax_eq
  have hI' := imax_ge
  have hlen := quic_vec.VLBytes.serialized_len_char x
  refine triple_post_mono (VLBytes.ser_triple hWI.law' w x (fun hn => ?_)) ?_
  · obtain ⟨r, hr, hrv⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (hlen hn)
    rw [hsz] at hr
    cases hr
    have := varint.lenOf_le x.vec.val.length
    omega
  · rintro p ⟨h1, h2⟩
    unfold VLBytes.out
    by_cases hn : x.vec.val.length ≤ 2 ^ 30 - 1
    · rw [if_pos hn]
      obtain ⟨⟨l, hl, hlv⟩, hv⟩ := h1 hn
      refine ⟨fun b hb => ?_, fun h => by cases h⟩
      cases hb
      exact ⟨⟨l, hl, by rw [hlv]; simp [varint.enc_length]; omega⟩, hv⟩
    · rw [if_neg hn]
      exact ⟨fun b hb => (by cases hb), fun _ => (h2 (by omega)).1⟩

end tls_codec
