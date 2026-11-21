/- The `Vec<T>` composition lemmas of `Std/Containers.lean` / `Std/VecSer.lean`, instantiated
with the varint length prefix.

Obligations: none directly; the `std`-path halves (`Serialize` / `Deserialize` `Lawful` fields,
lemma traits) of `PanicFreedom.lean` / `FunctionalCorrectness.lean` use them.
Axioms reached (`scripts/axiom_whitelist.txt`): nothing ASSUMED; 1 signature-only stub
(`core.io.error.Error.Insts.CoreFmtDebug.fmt`); `native_decide` (1). -/
import TlsCodec.Verification.Std.VLBytes
import TlsCodec.Verification.Std.VecSer
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option mvcgen.warning false
set_option hax_mvcgen.warnings false

namespace tls_codec

theorem write_length_runs : WriteLengthRuns varint.enc := by
  refine ⟨varint.enc_length, ?_⟩
  intro W WI hWI w n hroom
  refine triple_post_mono (write_length_triple hWI.law' w n hroom) ?_
  intro p ⟨h1, h2⟩
  refine ⟨fun hn => ?_, fun hn => (h2 hn).1⟩
  obtain ⟨hl, b, hb, hv⟩ := h1 hn
  refine ⟨hl, ?_⟩
  rw [hv, varint.eq_enc n.val (by omega) b hb]

theorem read_length_runs : ReadLengthRuns := by
  intro R RI v a law r
  refine triple_post_mono (read_length_content law r) ?_
  intro p hp len ll he
  obtain ⟨n, hn, hp2, hll, hlen, htake⟩ := hp (len, ll) he
  dsimp only at hll hlen htake
  have hl := congrArg List.length htake
  rw [List.length_take, varint.enc_length] at hl
  have hnl : n = varint.lenOf len.val := by omega
  subst hnl
  exact ⟨hlen, hn, hp2⟩

theorem Vec.de_spec {T : Type} {DI : Deserialize T} (hL : Deserialize.Lawful T DI) {R : Type}
    (RI : alloc.io.read.Read R) (hRI : alloc.io.read.Read.Lawful R RI) (r : R) :
    ⦃ ⌜ True ⌝ ⦄ (alloc.vec.Vec.Insts.Tls_codecDeserialize DI).tls_deserialize RI r
    ⦃ ⇓ p => ⌜ (Deserialize.tls_deserialize.post RI
      (alloc.vec.Vec.Insts.Tls_codecDeserialize DI).SizeInst
      (alloc.vec.Vec.Insts.Tls_codecDeserialize DI) r p).holds ⌝ ⦄ :=
  Deserialize.tls_deserialize_spec_of_runs _ (Vec.de_runs read_length_runs hL) RI hRI r

end tls_codec
