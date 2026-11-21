/- `String`: a `[u8]` with the `VLBytes` prefix, sized as a `&[u8]`.

Obligations: none directly; the `std`-path halves (`Serialize` / `Deserialize` `Lawful` fields,
lemma traits) of `PanicFreedom.lean` / `FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): ASSUMED
`alloc.string.FromUtf8Error.Insts.CoreFmtDisplay.fmt.ok_spec`; 2 signature-only stubs
(`alloc.string.FromUtf8Error.Insts.CoreFmtDisplay.fmt`,
`core.io.error.Error.Insts.CoreFmtDebug.fmt`). -/
import TlsCodec.Verification.Std.VLByteVec
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

theorem String.bytes_ok (x : alloc.string.String) :
    ∃ bs, alloc.string.String.as_bytes x = ok bs ∧
      bs.val = (alloc.string.String.utf8U8 x).take Usize.max := by
  obtain ⟨bs, hbs, hv⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (alloc.string.String.as_bytes_spec x)
  exact ⟨bs, hbs, hv⟩

theorem String.size_eq (x : alloc.string.String) (bs : Slice Std.U8)
    (hbs : alloc.string.String.as_bytes x = ok bs) :
    alloc.string.String.Insts.Tls_codecSize.tls_serialized_len x =
      (Shared0Slice.Insts.Tls_codecSize U8.Insts.Tls_codecSize).tls_serialized_len bs := by
  simp only [alloc.string.String.Insts.Tls_codecSize.tls_serialized_len, hbs, bind_tc_ok]

theorem String.ser_eq {W : Type} (WI : core.io.write.Write W) (x : alloc.string.String)
    (bs : Slice Std.U8) (hbs : alloc.string.String.as_bytes x = ok bs) (w : W) :
    (alloc.string.String.Insts.Tls_codecSerialize).tls_serialize WI x w =
      (quic_vec.VLByteSlice.Insts.Tls_codecSerialize).tls_serialize WI bs w := by
  show alloc.string.String.Insts.Tls_codecSerialize.tls_serialize WI x w =
      quic_vec.VLByteSlice.Insts.Tls_codecSerialize.tls_serialize WI bs w
  simp only [alloc.string.String.Insts.Tls_codecSerialize.tls_serialize, hbs, bind_tc_ok]

/-- The size of a `&[u8]` of at most `2^30 - 1` bytes: the length and its prefix. -/
theorem Slice.u8_sizeS (bs : Slice Std.U8) (hs : bs.val.length ≤ 2 ^ 30 - 1) (szS : Std.Usize)
    (hS : (Shared0Slice.Insts.Tls_codecSize U8.Insts.Tls_codecSize).tls_serialized_len bs = ok szS) :
    szS.val = bs.val.length + varint.lenOf bs.val.length := by
  have hmax : 2 ^ 32 ≤ Usize.max + 1 := by
    rcases System.Platform.numBits_eq with h | h <;> simp [Usize.max, Usize.numBits, h]
  obtain ⟨c, -, hc, hszv⟩ := Vec.size_exact U8.lawful bs szS hS (SizeNat.u8 bs.val)
  have hlen := varint.lenOf_le bs.val.length
  have hb : bs.val.length ≤ Usize.max := by omega
  rw [hszv, hc, min_eq_left hb, if_pos hs]
  omega

/-- The size of a `&[u8]` of at most `2^30 - 1` bytes is the `VLByteSlice` size. -/
theorem Slice.u8_size_small (bs : Slice Std.U8) (hs : bs.val.length ≤ 2 ^ 30 - 1)
    (szS szV : Std.Usize)
    (hS : (Shared0Slice.Insts.Tls_codecSize U8.Insts.Tls_codecSize).tls_serialized_len bs = ok szS)
    (hV : quic_vec.VLByteSlice.Insts.Tls_codecSize.tls_serialized_len bs = ok szV) :
    szS.val = szV.val := by
  have hmax : 2 ^ 32 ≤ Usize.max + 1 := by
    rcases System.Platform.numBits_eq with h | h <;> simp [Usize.max, Usize.numBits, h]
  obtain ⟨r, hr, hrv⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (quic_vec.tls_serialize_bytes_len_char bs hs)
  have : szV = r := ok.inj (hV.symm.trans hr)
  subst this
  obtain ⟨c, -, hc, hszv⟩ := Vec.size_exact U8.lawful bs szS hS (SizeNat.u8 bs.val)
  have hlen := varint.lenOf_le bs.val.length
  have hb : bs.val.length ≤ Usize.max := by omega
  rw [hszv, hc, min_eq_left hb, if_pos hs, hrv]
  omega

/-- The output of the `String` serializer. -/
noncomputable def String.out (bs : Slice Std.U8) : Option (List Std.U8) :=
  if bs.val.length ≤ 2 ^ 30 - 1 then encOut quic_vec.VLByteSlice.Insts.Tls_codecSerialize bs else none

theorem String.serSpec (x : alloc.string.String) :
    SerSpec alloc.string.String.Insts.Tls_codecSerialize x := by
  obtain ⟨bs, hbs, -⟩ := String.bytes_ok x
  obtain ⟨szS, hszS⟩ := Shared0Slice.size_ex U8.lawful bs
  have hSZ : alloc.string.String.Insts.Tls_codecSerialize.SizeInst.tls_serialized_len x = ok szS :=
    (String.size_eq x bs hbs).trans hszS
  obtain ⟨szV, hszV⟩ := VLByteSlice.size_ex bs
  have hV := VLByteSlice.serSpec bs
  intro W WI hWI w hpre
  refine Serialize.tls_serialize_spec_of_runs' _ x szS hSZ (String.out bs) ?_ ?_ WI hWI w hpre
  · intro hle b hb
    unfold String.out at hb
    split at hb
    · rename_i hs
      have := Slice.u8_size_small bs hs szS szV hszS hszV
      rw [this] at hle ⊢
      exact hV.enc_len szV hszV hle b hb
    · cases hb
  · intro W WI hWI w hroom
    rw [String.ser_eq WI x bs hbs]
    unfold String.out
    by_cases hs : bs.val.length ≤ 2 ^ 30 - 1
    · rw [if_pos hs]
      have := Slice.u8_size_small bs hs szS szV hszS hszV
      rw [this] at hroom
      exact hV.runs szV hszV W WI hWI w hroom
    · rw [if_neg hs]
      have := imax_le
      obtain ⟨p, hp, hpost⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
        (rw_bytes.ser_triple hWI.law' w bs (fun h => absurd h hs))
      refine ⟨p.1, p.2, hp, fun b hb => (by cases hb), fun _ => (hpost.2 (by omega)).1⟩

theorem String.size_ex (x : alloc.string.String) :
    ∃ sz, alloc.string.String.Insts.Tls_codecSize.tls_serialized_len x = ok sz := by
  obtain ⟨bs, hbs, -⟩ := String.bytes_ok x
  obtain ⟨sz, h⟩ := Shared0Slice.size_ex U8.lawful bs
  exact ⟨sz, (String.size_eq x bs hbs).trans h⟩

/-- What a successful `String` decode read: the bytes of a `VLByteVec` decode. -/
theorem String.std_de_content {R : Type} {RI : alloc.io.read.Read R} {v : R → List Std.U8}
    {a : R → Nat → R} (law : StdIo.RLaw RI v a) (r : R) :
    ⦃ ⌜ True ⌝ ⦄ alloc.string.String.Insts.Tls_codecDeserialize.tls_deserialize RI r
    ⦃ ⇓ p => ⌜ ∀ t, p.1 = .Ok t → ∃ n, n ≤ (v r).length ∧ p.2 = a r n ∧
        ∃ raw : quic_vec.VLByteVec, VLDeV (v r) raw n ∧ alloc.string.String.utf8U8 t = raw.vec.val ⌝ ⦄ := by
  have hde := VLByteVec.std_de_content law r
  mvcgen [alloc.string.String.Insts.Tls_codecDeserialize.tls_deserialize, hde,
    core.result.Result.map_err_spec, alloc.vec.VecU8.Insts.CoreConvertFromVLByteVec.from,
    string.std_only.DeserializeString.tls_deserialize.closure.Insts.CoreOpsFunctionFnOnceTupleFromUtf8ErrorError.call_once]
  · rename_i p hp _ val _ hcf r1 hr1 t ht
    intro t' h'
    have h2 := core.result.Result.Ok.inj h'
    subst h2
    obtain ⟨n, hn, hadv, hd⟩ := hp val (continue_eq_tryCF.mp hcf)
    obtain ⟨t2, h3, hu⟩ | ⟨h1, -⟩ := hr1
    · rw [ht] at h3; cases h3
      exact ⟨n, hn, hadv, val, hd, hu⟩
    · rw [ht] at h1; cases h1
  · simp only [PostCond.ok]
    mvcgen
    intro t h; cases h
  · rename_i p _ _ _ _ hcf
    refine try_break_vc (x := p.1) (fun e _ => ?_) hcf
    mvcgen
    intro _
    mvcgen
    all_goals simp

theorem String.de_runs :
    DeRuns alloc.string.String.Insts.Tls_codecDeserialize (fun _ _ _ => True) := by
  intro R RI v a law r
  refine triple_post_mono (String.std_de_content law r) fun p hp t ht => ?_
  obtain ⟨n, hn, hadv, raw, hd, hu⟩ := hp t ht
  obtain ⟨bs, hbs, hbv⟩ := String.bytes_ok t
  obtain ⟨sz, hsz⟩ := Shared0Slice.size_ex U8.lawful bs
  have hS := (String.size_eq t bs hbs).trans hsz
  obtain ⟨hnl, hle30, -, hnv⟩ := hd
  have hrl : raw.vec.val.length ≤ Usize.max := raw.vec.property
  have hbv' : bs.val = raw.vec.val := by
    rw [hbv, hu]; exact List.take_of_length_le hrl
  have := Slice.u8_sizeS bs (by rw [hbv']; exact hle30) sz hsz
  rw [hbv'] at this
  exact ⟨n, sz, hn, hadv, hS, by omega, trivial⟩

theorem String.deSpec : DeSpec alloc.string.String.Insts.Tls_codecDeserialize :=
  fun _ RI hRI r => Deserialize.tls_deserialize_spec_of_runs _ String.de_runs RI hRI r

end tls_codec
