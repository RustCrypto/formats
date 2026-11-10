/- Hand-written `DeserializeBytes` that run the type's `std` deserializer on a `&[u8]` reader and
return the reader left over (`let mut b = bytes; let x = T::tls_deserialize(&mut b)?; Ok((x, b))`).
OpenMLS's 11 hand-written bytes deserializers have this shape since its security fix of
2026-08 (upstream `3ad260d8d`); before, they returned `&bytes[x.tls_serialized_len()..]`
(`debytes_via_std` in `Derive/Std.lean`). No size reasoning is needed here: the remainder is the
reader's own state, so the `DeserializeBytes` post follows from the `std` deserializer's `DeRuns`.

Obligations: none directly (downstream projects use `debytes_via_reader`).
Axioms reached: none beyond those of `Derive/Std.lean`. -/
import TlsCodec.Verification.Derive.Std
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec.Derive
open tls_codec

/-- The bytes post of a run of a `std` deserializer on a slice reader: on `Ok val`, the reader left
is `bytes` without the `sz` bytes consumed, `sz` the size of `val`. -/
theorem debytes_reader_post_ok {T : Type} (SizeInst : Size T) (DB : DeserializeBytes T)
    (bytes : Slice Std.U8) (val : T) (n : Nat) (sz : Std.Usize) (hn : n ≤ bytes.val.length)
    (hsz : SizeInst.tls_serialized_len val = ok sz) (hszn : sz.val = n) :
    (DeserializeBytes.tls_deserialize_bytes.post SizeInst DB bytes
      (.Ok (val, StdIo.sliceAdv bytes n))).holds :=
  DeserializeBytes.post_ok _ _ _ _ _ sz hsz
    (by simp [StdIo.sliceAdv]; omega) (by simp [StdIo.sliceAdv]; exact List.drop_suffix _ _)

/-- `DeserializeBytes.Lawful` of a hand-written bytes deserializer that runs the type's `std`
`tls_deserialize` on the slice and returns the reader left over (`DB` the instance, `fn` its
function, `hDe` / `hS` the `std` `Deserialize.Lawful` / `Size.Lawful`). -/
macro "debytes_via_reader" DB:term "," fn:ident "," hDe:term "," hS:term : tactic => `(tactic| (
  have hd : ∀ bytes, ⦃ ⌜ True ⌝ ⦄ $fn bytes
      ⦃ ⇓ r => ⌜ (DeserializeBytes.tls_deserialize_bytes.post
        ($DB).SizeInst
        $DB bytes r).holds ⌝ ⦄ := by
    intro bytes
    have hT := ($hDe).runs _ _ _ _ StdIo.slice_law bytes
    mvcgen [$fn:ident, hT]
    · rename_i p _ u _ hcf hp
      obtain ⟨n, sz, hn, h2, hsz, hszn⟩ := hp u (continue_eq_tryCF.mp hcf)
      rw [h2]
      exact debytes_reader_post_ok _ _ bytes u n sz hn hsz hszn
    · rename_i q _ _ _ _
      intro hbr
      refine try_break_vc (x := q.1) (fun e he => ?_) hbr
      mvcgen
      intro _
      exact DeserializeBytes.post_err _ _ _ _
  exact ⟨$hS, fun b _ => hd b,
    fun b _ => exact_bytes_spec $DB hd b⟩))

end tls_codec.Derive
