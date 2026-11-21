/- `VLByteVec` (its deserializer is `VLGen.de`), `VLByteSlice`, `TlsVarInt`, `ContentLength`,
`SecretVLByteVec`, `&[T]` (as `Vec<T>`), `str` / `&str` (as `&[u8]`).

Obligations: none directly; the `std`-path halves (`Serialize` / `Deserialize` `Lawful` fields,
lemma traits) of `PanicFreedom.lean` / `FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): ASSUMED `size_of`; 1 signature-only stub
(`core.io.error.Error.Insts.CoreFmtDebug.fmt`). -/
import TlsCodec.Verification.Std.Misc
import TlsCodec.Verification.Std.VLBytes
import TlsCodec.Verification.Std.VecVarInt
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

/-- Transport across types: a serializer running as `SI`'s on another value, with the same size,
meets the contract. -/
theorem SerSpec.transportT {T T' : Type} {SI : Serialize T} {x : T} (h : SerSpec SI x)
    (SI' : Serialize T') (x' : T')
    (hser : ∀ (W : Type) (WI : core.io.write.Write W) w,
      SI'.tls_serialize WI x' w = SI.tls_serialize WI x w)
    (hsz : SI'.SizeInst.tls_serialized_len x' = SI.SizeInst.tls_serialized_len x)
    (hS : ∃ sz, SI.SizeInst.tls_serialized_len x = ok sz) : SerSpec SI' x' := by
  intro W WI hWI w hpre
  obtain ⟨sz, hsz0⟩ := hS
  have hr : SerRuns SI' x' sz (encOut SI x) := by
    intro W' WI' hWI' w' hroom
    rw [hser]
    exact h.runs sz hsz0 W' WI' hWI' w' hroom
  exact Serialize.tls_serialize_spec_of_runs' SI' x' sz (hsz.trans hsz0) _
    (fun hle b hb => h.enc_len sz hsz0 hle b hb) hr WI hWI w hpre

/-! ### `VLByteVec`: deserializer (the shared `VLGen.de` of `Std/VLBytes.lean`) -/

def VLDeV (l : List Std.U8) (x : quic_vec.VLByteVec) (n : Nat) : Prop :=
  n ≤ l.length ∧ x.vec.val.length ≤ 2 ^ 30 - 1 ∧
    l.take n = varint.enc x.vec.val.length ++ x.vec.val ∧
    n = varint.lenOf x.vec.val.length + x.vec.val.length

theorem VLByteVec.de_eq {R : Type} (RI : alloc.io.read.Read R) (r : R) :
    quic_vec.VLByteVec.Insts.Tls_codecDeserialize.tls_deserialize RI r =
      VLGen.de quic_vec.VLByteVec.new (fun b => { vec := b }) RI r := rfl

theorem VLByteVec.std_de_content {R : Type} {RI : alloc.io.read.Read R} {v : R → List Std.U8}
    {a : R → Nat → R} (law : StdIo.RLaw RI v a) (r : R) :
    ⦃ ⌜ True ⌝ ⦄ quic_vec.VLByteVec.Insts.Tls_codecDeserialize.tls_deserialize RI r
    ⦃ ⇓ p => ⌜ ∀ x, p.1 = .Ok x → ∃ n, n ≤ (v r).length ∧ p.2 = a r n ∧ VLDeV (v r) x n ⌝ ⦄ := by
  rw [VLByteVec.de_eq]
  refine triple_post_mono (VLGen.de_content _ _ (fun _ => rfl) law r) fun p hp x hx => ?_
  obtain ⟨b, n, rfl, hn, hadv, hde⟩ := hp x hx
  exact ⟨n, hn, hadv, hde⟩

theorem VLByteVec.de_runs : DeRuns quic_vec.VLByteVec.Insts.Tls_codecDeserialize VLDeV := by
  intro R RI v a law r
  refine triple_post_mono (VLByteVec.std_de_content law r) fun p hp x hx => ?_
  obtain ⟨n, hn, hadv, hde⟩ := hp x hx
  obtain ⟨sz, hsz, hszv⟩ : ∃ sz : Std.Usize,
      quic_vec.VLByteVec.Insts.Tls_codecSize.tls_serialized_len x = ok sz ∧
        sz.val = x.vec.val.length + varint.lenOf x.vec.val.length := by
    obtain ⟨sz, hsz, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
      (quic_vec.VLByteVec.serialized_len_char x hde.2.1)
    exact ⟨sz, hsz, hP⟩
  exact ⟨n, sz, hn, hadv, hsz, by rw [hszv, hde.2.2.2]; omega, hde⟩

/-! ### `VLByteVec`, `VLByteSlice` serializers: as `VLBytes` -/

theorem VLByteVec.deSpec : DeSpec quic_vec.VLByteVec.Insts.Tls_codecDeserialize :=
  fun _ RI hRI r => Deserialize.tls_deserialize_spec_of_runs _ VLByteVec.de_runs RI hRI r

theorem VLByteVec.size_ex (x : quic_vec.VLByteVec) :
    ∃ sz, quic_vec.VLByteVec.Insts.Tls_codecSize.tls_serialized_len x = ok sz :=
  VLBytes.size_ex ⟨x.vec⟩

theorem VLByteVec.serSpec (x : quic_vec.VLByteVec) :
    SerSpec quic_vec.VLByteVec.Insts.Tls_codecSerialize x :=
  (VLBytes.serSpec ⟨x.vec⟩).transportT _ x (fun _ _ _ => rfl) rfl (VLBytes.size_ex _)

theorem Shared0VLByteVec.serSpec (x : quic_vec.VLByteVec) :
    SerSpec Shared0VLByteVec.Insts.Tls_codecSerialize x :=
  (VLByteVec.serSpec x).transport _ (fun _ _ _ => rfl) rfl (VLByteVec.size_ex x)

theorem VLByteSlice.size_ex (s : quic_vec.VLByteSlice) :
    ∃ sz, quic_vec.VLByteSlice.Insts.Tls_codecSize.tls_serialized_len s = ok sz :=
  VLBytes.size_ex ⟨s⟩

theorem VLByteSlice.serSpec (s : quic_vec.VLByteSlice) :
    SerSpec quic_vec.VLByteSlice.Insts.Tls_codecSerialize s :=
  (VLBytes.serSpec ⟨s⟩).transportT _ s (fun _ _ _ => rfl) rfl (VLBytes.size_ex _)

theorem Shared0VLByteSlice.serSpec (s : quic_vec.VLByteSlice) :
    SerSpec Shared0VLByteSlice.Insts.Tls_codecSerialize s :=
  (VLByteSlice.serSpec s).transport _ (fun _ _ _ => rfl) rfl (VLByteSlice.size_ex s)

/-! ### `TlsVarInt`, `ContentLength` -/

theorem varint.size_ex (x : varint.TlsVarInt) :
    ∃ sz, varint.TlsVarInt.Insts.Tls_codecSize.tls_serialized_len x = ok sz ∧
      sz.val = varint.lenOf x.val := by
  obtain ⟨sz, hsz, hP⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp (varint.TlsVarInt.bytes_len_spec x)
  exact ⟨sz, hsz, (varint.lenOf_char _ _ hP).1⟩

/-- The output of the `TlsVarInt` serializer: its canonical encoding, or an error above `2^62 - 1`. -/
def varint.out (x : varint.TlsVarInt) : Option (List Std.U8) :=
  if x.val ≤ 2 ^ 62 - 1 then some (varint.enc x.val) else none

theorem varint.ser_runs' (x : varint.TlsVarInt) (sz : Std.Usize) (hsz : sz.val = varint.lenOf x.val) :
    SerRuns varint.TlsVarInt.Insts.Tls_codecSerialize x sz (varint.out x) := by
  unfold varint.out
  by_cases hx : x.val ≤ 2 ^ 62 - 1
  · rw [if_pos hx]; exact varint.ser_runs x hx sz hsz
  · rw [if_neg hx]
    apply SerRuns_of_triple
    intro W WI hWI w hroom
    refine triple_post_mono (varint.ser_triple_gt WI x w (by omega)) ?_
    rintro p ⟨h1, -⟩
    exact ⟨fun b hb => (by cases hb), fun _ => h1⟩

theorem varint.serSpec (x : varint.TlsVarInt) :
    SerSpec varint.TlsVarInt.Insts.Tls_codecSerialize x := by
  obtain ⟨sz, hsz, hszv⟩ := varint.size_ex x
  intro W WI hWI w hpre
  refine Serialize.tls_serialize_spec_of_runs' _ x sz hsz (varint.out x) ?_
    (varint.ser_runs' x sz hszv) WI hWI w hpre
  intro _ b hb
  unfold varint.out at hb
  split at hb
  · cases hb; rw [varint.enc_length, hszv]
  · cases hb

theorem varint.deSpec : DeSpec varint.TlsVarInt.Insts.Tls_codecDeserialize :=
  fun _ RI hRI r => Deserialize.tls_deserialize_spec_of_runs _ varint.de_runs RI hRI r

theorem ContentLength.serSpec (x : quic_vec.ContentLength) :
    SerSpec quic_vec.ContentLength.Insts.Tls_codecSerialize x :=
  (varint.serSpec x).transport _ (fun _ _ _ => rfl) rfl ((varint.size_ex x).imp fun _ h => h.1)

theorem ContentLength.size_ex (x : quic_vec.ContentLength) :
    ∃ sz, quic_vec.ContentLength.Insts.Tls_codecSize.tls_serialized_len x = ok sz :=
  (varint.size_ex x).imp fun _ h => h.1

theorem ContentLength.deSpec : DeSpec quic_vec.ContentLength.Insts.Tls_codecDeserialize :=
  fun _ RI hRI r => Deserialize.tls_deserialize_spec_of_runs _ ContentLength.de_runs RI hRI r

/-! ### `SecretVLByteVec`: as `VLByteVec` -/

theorem SecretVLByteVec.de_eq {R : Type} (RI : alloc.io.read.Read R) (r : R) :
    quic_vec.secret_byte_vec.SecretVLByteVec.Insts.Tls_codecDeserialize.tls_deserialize RI r =
      quic_vec.VLByteVec.Insts.Tls_codecDeserialize.tls_deserialize RI r := by
  unfold quic_vec.secret_byte_vec.SecretVLByteVec.Insts.Tls_codecDeserialize.tls_deserialize
  generalize quic_vec.VLByteVec.Insts.Tls_codecDeserialize.tls_deserialize RI r = m
  rcases m with ⟨res, b⟩ | e | _
  · cases res <;> rfl
  · rfl
  · rfl

theorem SecretVLByteVec.serSpec (x : quic_vec.secret_byte_vec.SecretVLByteVec) :
    SerSpec quic_vec.secret_byte_vec.SecretVLByteVec.Insts.Tls_codecSerialize x :=
  SerSpec.transport (T := quic_vec.secret_byte_vec.SecretVLByteVec)
    (SI := quic_vec.VLByteVec.Insts.Tls_codecSerialize) (VLByteVec.serSpec x) _
    (fun _ _ _ => rfl) rfl (VLByteVec.size_ex x)

theorem SecretVLByteVec.deSpec :
    DeSpec quic_vec.secret_byte_vec.SecretVLByteVec.Insts.Tls_codecDeserialize :=
  DeSpec.transport (T := quic_vec.secret_byte_vec.SecretVLByteVec)
    (DI := quic_vec.VLByteVec.Insts.Tls_codecDeserialize) VLByteVec.deSpec _
    (fun _ RI r => SecretVLByteVec.de_eq RI r) (fun _ => rfl)

/-! ### `&[T]`: as `Vec<T>` (aeneas represents both as a `Slice`) -/

theorem Vec.serSpec {T : Type} {SI : Serialize T} (Dbg : core.fmt.Debug T)
    (hL : Serialize.Lawful T SI) (v : alloc.vec.Vec T) :
    SerSpec (alloc.vec.Vec.Insts.Tls_codecSerialize SI Dbg) v :=
  fun _ WI hWI w hpre => Vec.ser_spec write_length_runs Dbg hL WI hWI v w hpre

theorem Vec.size_ex' {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI) (v : alloc.vec.Vec T) :
    ∃ sz, (alloc.vec.Vec.Insts.Tls_codecSize SI.SizeInst).tls_serialized_len v = ok sz := by
  obtain ⟨sz, hsz, -⟩ := Aeneas.Std.WP.triple_iff_exists_ok.mp
    (alloc.vec.Vec.size_rel SI.SizeInst hL.SizeInstLawful v)
  exact ⟨sz, hsz⟩

theorem Shared0Slice.size_ex {T : Type} {SI : Serialize T} (hL : Serialize.Lawful T SI)
    (x : Slice T) :
    ∃ sz, (Shared0Slice.Insts.Tls_codecSize SI.SizeInst).tls_serialized_len x = ok sz :=
  Vec.size_ex' hL x

theorem Shared0Slice.serSpec {T : Type} {SI : Serialize T} (Dbg : core.fmt.Debug T)
    (hL : Serialize.Lawful T SI) (x : Slice T) :
    SerSpec (Shared0Slice.Insts.Tls_codecSerialize SI Dbg) x :=
  (Vec.serSpec Dbg hL x).transportT _ x (fun _ _ _ => rfl) rfl (Vec.size_ex' hL x)

/-! ### `str`, `&str`: as `&[u8]` -/

theorem Size.lawful_of_ok {T : Type} (S : Size T) (h : ∀ x, ∃ sz, S.tls_serialized_len x = ok sz) :
    Size.Lawful T S :=
  ⟨fun x _ => by
    obtain ⟨sz, hs⟩ := h x
    rw [hs]
    exact ok_triple_of (by trivial)⟩

theorem U8.lawful : Serialize.Lawful Std.U8 U8.Insts.Tls_codecSerialize where
  SizeInstLawful := Size.lawful_of_ok _ fun _ => ⟨_, rfl⟩
  tls_serialize_spec := fun WI hWI x w h => U8.ser_spec WI hWI x w h
  tls_serialize_detached_spec := fun x _ => SerSpec.detached (U8.serSpec x) ⟨_, rfl⟩

theorem Str.serSpec (x : Str) : SerSpec Str.Insts.Tls_codecSerialize x :=
  (Shared0Slice.serSpec core.U8.Insts.CoreFmtDebug U8.lawful x).transportT _ x
    (fun _ _ _ => rfl) rfl (Shared0Slice.size_ex U8.lawful x)

theorem Shared0Str.serSpec (x : Str) : SerSpec Shared0Str.Insts.Tls_codecSerialize x :=
  (Shared0Slice.serSpec core.U8.Insts.CoreFmtDebug U8.lawful x).transportT _ x
    (fun _ _ _ => rfl) rfl (Shared0Slice.size_ex U8.lawful x)

/-! #### `SecretVLBytes`, `SecretVLByteVec`: `tls_deserialize_bytes` is the wrapped type's -/

theorem SecretVLBytes.deser_bytes_eq (bytes : Slice Std.U8) :
    quic_vec.secret_bytes.SecretVLBytes.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes =
      quic_vec.VLBytes.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes := by
  unfold quic_vec.secret_bytes.SecretVLBytes.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
  generalize quic_vec.VLBytes.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes = m
  rcases m with r | e | _
  · cases r <;> rfl
  · rfl
  · rfl

theorem SecretVLByteVec.deser_bytes_eq (bytes : Slice Std.U8) :
    quic_vec.secret_byte_vec.SecretVLByteVec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes =
      quic_vec.VLByteVec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes := by
  unfold quic_vec.secret_byte_vec.SecretVLByteVec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes
  generalize quic_vec.VLByteVec.Insts.Tls_codecDeserializeBytes.tls_deserialize_bytes bytes = m
  rcases m with r | e | _
  · cases r <;> rfl
  · rfl
  · rfl

end tls_codec
